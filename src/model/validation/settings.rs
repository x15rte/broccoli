//! Validation rules of the settings scope.
//!
//! Split out of [`crate::model::validation`]; that module holds the taxonomy
//! and the vocabulary more than one scope reads.

use super::outbound::{validate_outbound, validate_sniffing};
use super::{
    FindingTarget, ValidationCode, ValidationIssue, Verdict, excerpt, issue, validate_finalmask,
    warning,
};
use crate::model::dns::parse_pool_cidr;
use crate::model::inbound::{
    API_INBOUND_TAG, BLOCK_OUTBOUND_TAG, DIRECT_OUTBOUND_TAG, DokodemoNetwork, LocalInboundCfg,
    LocalInboundProtocol, TUN_LEAK_DNS, TUN_LEAK_MISCONFIG_TUN, listen_endpoints_conflict,
};
use crate::model::{ServerProfile, ServersFile, Settings, TunCfg, emit, vocabulary_holds};
use std::collections::{BTreeMap, BTreeSet};

/// Validate a listen address: always a concrete IP literal.
pub fn validate_listen_address(s: &str) -> Result<(), ValidationCode> {
    match s.parse::<std::net::IpAddr>() {
        Ok(_) => Ok(()),
        Err(_) => Err(ValidationCode::ListenAddressInvalid),
    }
}

/// True when a file path the core opens is not a plain local path: a UNC or
/// device path, a URL, a drive-relative path, or a path holding a `..`
/// component. The core opens these paths at config load — Lua scripts through
/// its file resolver (`common/lua/program.go`), TLS certificates through
/// `ReadCert` (`infra/conf/transport_security.go`) — so a UNC path makes the
/// Windows client authenticate to the named SMB server before anything else
/// runs, and a `..` component leaves the folder the path appears to name. A
/// relative path without `..` stays legal: the core resolves it against its
/// own working directory.
pub fn file_path_remote(path: &str) -> bool {
    let path = path.trim();
    let bytes = path.as_bytes();
    // A leading pair of separators is a UNC path, in any mix Windows
    // accepts: `\\server`, `//server`, `/\server` and `\/server` all name
    // the same share after the Win32 path conversion, and Go's
    // `filepath.IsAbs` treats the pair as a volume name too.
    if bytes.len() >= 2 && matches!(bytes[0], b'/' | b'\\') && matches!(bytes[1], b'/' | b'\\') {
        return true;
    }
    if path.contains("://") {
        return true;
    }
    // Drive-relative: `C:x` names the current folder on that drive, while
    // `C:` alone and `C:\x` stay rooted.
    if bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && !matches!(bytes[2], b'\\' | b'/')
    {
        return true;
    }
    path.split(['\\', '/']).any(|component| component == "..")
}

/// The structural verdict for one configured Lua script path, mirroring the
/// two refusals the core's file resolver makes before it reads anything: the
/// blank path (`ResolveLuaFile`) and every extension other than `.lua`
/// (`resolveLuaTarget`, `common/platform/platform.go`). A path outside the
/// local folder ([`file_path_remote`]) is refused before either, because the
/// core opens it without asking. `None` — no script — never reaches this
/// rule. The extension compare is case-sensitive, exactly as the core's is.
pub fn lua_script_path_issue(script: &str) -> Option<ValidationCode> {
    if script.trim().is_empty() {
        Some(ValidationCode::LuaScriptPathRequired)
    } else if file_path_remote(script) {
        Some(ValidationCode::FilePathRemote(excerpt(script)))
    } else if !script.ends_with(".lua") {
        Some(ValidationCode::LuaScriptPathNotLua)
    } else {
        None
    }
}

/// Every blocking conflict a DNS script creates with the rest of the DNS
/// configuration, in the order the core names them (infra/conf/dns.go:
/// the two fallback flags, then each server carrying `domains`,
/// `skipFallback` or `finalQuery`). An absent script has no conflicts; an
/// empty one is the core's own "no script" spelling, so only its structural
/// finding fires.
pub fn dns_script_issues(
    script: Option<&str>,
    servers: &[crate::model::DnsServer],
    disable_fallback: bool,
    disable_fallback_if_match: bool,
) -> Vec<ValidationCode> {
    let Some(script) = script else {
        return Vec::new();
    };
    let mut issues: Vec<ValidationCode> = lua_script_path_issue(script).into_iter().collect();
    if script.is_empty() {
        return issues;
    }
    if disable_fallback || disable_fallback_if_match {
        issues.push(ValidationCode::DnsScriptFallbackConflict);
    }
    for (index, server) in servers.iter().enumerate() {
        for (set, field) in [
            (!server.domains.is_empty(), "domains"),
            (server.skip_fallback == Some(true), "skipFallback"),
            (server.final_query == Some(true), "finalQuery"),
        ] {
            if set {
                issues.push(ValidationCode::DnsScriptServerConflict(
                    index + 1,
                    field.into(),
                ));
            }
        }
    }
    issues
}

/// Every blocking conflict a routing script creates: the core refuses a
/// script beside any rule or any `domainStrategy` key
/// (infra/conf/router.go). The app's model stores `AsIs` as "no strategy"
/// (the key is omitted from the wire), so only a stored non-default strategy
/// conflicts. An empty script is the core's "no script" spelling, so only its
/// structural finding fires.
pub fn routing_script_issues(
    script: Option<&str>,
    rules: usize,
    domain_strategy: &str,
) -> Vec<ValidationCode> {
    let Some(script) = script else {
        return Vec::new();
    };
    let mut issues: Vec<ValidationCode> = lua_script_path_issue(script).into_iter().collect();
    if script.is_empty() {
        return issues;
    }
    if rules > 0 {
        issues.push(ValidationCode::RoutingScriptRulesConflict);
    }
    if domain_strategy != crate::model::DEFAULT_DOMAIN_STRATEGY {
        issues.push(ValidationCode::RoutingScriptStrategyConflict);
    }
    issues
}

/// Every blocking conflict a noise-mask script creates: the mask build
/// refuses a script beside any `noise` item and never reads the item list
/// when the script arm is taken (`infra/conf/transport_finalmask.go`,
/// `NoiseMask.Build`). Exactly one of the two reaches the core, so the app
/// blocks the pair instead of picking a winner. An empty script is the
/// core's "no script" spelling, so only its structural finding fires.
pub fn noise_script_issues(script: Option<&str>, noise_items: usize) -> Vec<ValidationCode> {
    let Some(script) = script else {
        return Vec::new();
    };
    let mut issues: Vec<ValidationCode> = lua_script_path_issue(script).into_iter().collect();
    if script.is_empty() {
        return issues;
    }
    if noise_items > 0 {
        issues.push(ValidationCode::FinalmaskNoiseScriptConflict);
    }
    issues
}

// ---------- settings-level verdict ----------
//
// The generator's former private pass, now the model's single answer to
// "is this configuration valid". It runs the profile set, then every
// settings-wide rule, in the exact order the generator walked them, and
// never short-circuits — every finding is reported with its severity.
// Callers gate on the first [`Severity::Error`] (generation's single-error
// surface) or render the whole list (editors, tests).
//
// Findings scoped to one model instance carry the human-readable location
// (a profile's display name, an inbound label) as their path; findings
// whose message already names the offender carry none. Generation renders
// a path-carrying finding as `"{location}: {rule message}"` — the same
// bytes the pre-pass generator emitted. The same findings carry the row they
// judge as their [`FindingTarget`], which is what a screen asks with
// [`Verdict::for_target`]; the path is presentation only and stays unchanged
// so the rendered text keeps its bytes.

/// True when a local inbound's "require authentication" intent never
/// reaches the wire: password mode with an empty account list. SOCKS
/// carries an `auth` key, so its password mode with zero accounts denies
/// every connection — genuinely safe and never trapped; HTTP carries no
/// auth key, so `accounts` is its only authentication and the empty list
/// leaves the listener open. Derived from [`LocalInboundCfg::authenticates`]
/// — the exposure rule and this gate share that one model truth, never
/// re-implemented.
fn inbound_auth_trap(entry: &LocalInboundCfg) -> bool {
    entry.auth == "password" && !entry.authenticates()
}

/// The finding one emitted local endpoint's authentication rule produces, or
/// `None` when the row is appliable: an emitted row that requires
/// authentication but whose wire form authenticates nobody — HTTP's accounts
/// are its only authentication, so an empty list serves everyone at any bind.
/// The settings walk reports the finding from here, so the Apply gate and the
/// row list read one rule.
fn local_inbound_auth_verdict(entry: &LocalInboundCfg) -> Option<ValidationCode> {
    (emit::local_inbound_emitted(entry) && inbound_auth_trap(entry))
        .then_some(ValidationCode::LocalInboundAuthRequiresAccounts)
}

/// The gateway list's IPv4 address: the first entry whose CIDR prefix is an
/// IPv4 literal. `None` for an empty or IPv6-only list — TUN then has no
/// adapter address and no in-subnet address for the in-tun DNS listeners
/// ([`ValidationCode::TunIpv4GatewayRequired`]); the generator derives the
/// IPv4 listener address from the same value.
pub fn tun_ipv4_gateway(tun: &TunCfg) -> Option<&str> {
    tun.gateway.iter().find_map(|entry| {
        entry
            .split('/')
            .next()
            .map(str::trim)
            .filter(|ip| ip.contains('.'))
    })
}

/// True when one gateway entry is a form Go's `netip.ParsePrefix` accepts.
/// `ipnet::IpNet` is wider: it reads each octet and the prefix length as
/// numbers, so it accepts a leading zero in either, while Go rejects the
/// entry ("IPv4 field has octet with leading zero", "bad bits after slash").
/// The core parses every entry with `netip.MustParsePrefix`, which panics on
/// those spellings, so the model refuses them before emission.
fn gateway_entry_go_compatible(entry: &str) -> bool {
    let entry = entry.trim();
    let Some((address, bits)) = entry.rsplit_once('/') else {
        return false;
    };
    if bits.is_empty()
        || !bits.chars().all(|ch| ch.is_ascii_digit())
        || (bits.len() > 1 && bits.starts_with('0'))
    {
        return false;
    }
    // A dotted quad, bare or as the tail of an IPv6 address, may not carry a
    // leading zero in any octet. The tail after the last colon is the only
    // place an IPv4 part can sit, so the hex prefix (`::ffff:010`) does not
    // hide the first octet.
    let dotted = address.rsplit(':').next().unwrap_or(address);
    if dotted.contains('.')
        && dotted.split('.').any(|octet| {
            !octet.is_empty()
                && octet.chars().all(|ch| ch.is_ascii_digit())
                && octet.len() > 1
                && octet.starts_with('0')
        })
    {
        return false;
    }
    entry.parse::<ipnet::IpNet>().is_ok()
}

/// The finding one TUN document's gateway rule produces, or `None` when the
/// tunnel can come up: a TUN-mode document without an IPv4 gateway has no
/// adapter address and no in-subnet address for the in-tun DNS listeners. The
/// settings walk reports the finding from here, so the Apply gate and the TUN
/// row's verdict read one rule.
fn tun_gateway_verdict(settings: &Settings) -> Option<ValidationCode> {
    (emit::tun_inbound_emitted(settings) && tun_ipv4_gateway(&settings.tun).is_none())
        .then_some(ValidationCode::TunIpv4GatewayRequired)
}

/// The gateway list's IPv6 address: the first entry whose CIDR prefix is an
/// IPv6 literal, without its prefix length. Every gateway entry becomes an
/// address on the adapter, and the tunnel serves IPv6 DNS on this one, so the
/// port-53 reservation covers it as it does the IPv4 address; the runtime's
/// IPv6 listener binds the same value.
pub fn tun_ipv6_gateway(tun: &TunCfg) -> Option<&str> {
    tun.gateway.iter().find_map(|entry| {
        entry
            .split('/')
            .next()
            .map(str::trim)
            .filter(|ip| ip.contains(':'))
    })
}

/// True when one `settings.env` key names a core location variable after the
/// normalization Windows and Xray's lookup apply: trim, uppercase, and a dot
/// read as an underscore. Those four variables move the core's asset,
/// configuration, and certificate lookup before the first connection.
fn env_key_overrides_core_path(key: &str) -> bool {
    let normalized = key.trim().to_uppercase().replace('.', "_");
    crate::model::settings::CORE_LOCATION_ENV_NAMES
        .iter()
        .any(|name| crate::model::equal_fold(&normalized, &name.replace('.', "_")))
}

/// The modeled wire keys of the top-level `dns` object. `fakedns` and
/// `bootstrap` are absent: the generator strips both before emission, so a
/// variant of either never reaches the core.
const DNS_WIRE_KEYS: [&str; 13] = [
    "servers",
    "hosts",
    "clientIp",
    "tag",
    "queryStrategy",
    "disableCache",
    "serveStale",
    "serveExpiredTTL",
    "disableFallback",
    "disableFallbackIfMatch",
    "enableParallelQuery",
    "useSystemHosts",
    "script",
];

/// The modeled wire keys of the TUN inbound's settings object.
const TUN_WIRE_KEYS: [&str; 10] = [
    "name",
    "desc",
    "mtu",
    "gateway",
    "dns",
    "userLevel",
    "autoSystemRoutingTable",
    "autoOutboundsInterface",
    "autoSystemDnsToGateway",
    "autoSystemWfpBlockLeak",
];

/// The modeled wire keys of a `sniffing` block.
const SNIFFING_WIRE_KEYS: [&str; 6] = [
    "enabled",
    "destOverride",
    "domainsExcluded",
    "ipsExcluded",
    "metadataOnly",
    "routeOnly",
];

/// Report flattened keys that fold onto a modeled field of the same settings
/// block. A variant (`Script`, `Gateway`) stays out of the typed field, is
/// emitted beside it, and Go's decoder binds it, so the core would read a
/// value the model never validated.
fn settings_extra_shadow(
    path: &str,
    extra: &serde_json::Map<String, serde_json::Value>,
    modeled: &[&str],
    issues: &mut Vec<ValidationIssue>,
) {
    for key in extra.keys() {
        if modeled
            .iter()
            .any(|wire| crate::model::equal_fold(key, wire))
        {
            issues.push(issue(
                ValidationCode::SettingsExtraShadow(key.clone()),
                Some(format!("{path}.{key}")),
            ));
        }
    }
}

/// True when the emitted document carries the leak block without the
/// unrouted-family half — the state [`ValidationCode::TunLeakMisconfigTunOff`]
/// reports. The generator writes the key only while the TUN inbound and the
/// DNS module are both present (`emit::dns_inbound_emitted`), so this is the
/// exact predicate the settings pass judges.
fn tun_leak_misconfig_tun_off(settings: &Settings) -> bool {
    emit::dns_inbound_emitted(settings) && !settings.tun.leak_blocks_misconfig_tun()
}

/// Canonical form of a Windows socket path (case-folded, `/` → `\`,
/// `.`/`..` resolved, separators collapsed) — the comparison key for the
/// dokodemo UNIX-listener conflict rule and the inbounds screen's row
/// highlight. One implementation, shared by both.
pub(crate) fn normalize_windows_socket_path(path: &str) -> String {
    let path: String = path
        .trim()
        .chars()
        .flat_map(|character| (if character == '/' { '\\' } else { character }).to_lowercase())
        .collect();
    let bytes = path.as_bytes();
    let unc = path.starts_with(r"\\");
    let has_drive = bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':';

    let (prefix, remainder, rooted, protected_components) = if unc {
        (r"\\", path.trim_start_matches('\\'), true, 2)
    } else if has_drive {
        let remainder = &path[2..];
        (
            &path[..2],
            remainder.trim_start_matches('\\'),
            remainder.starts_with('\\'),
            0,
        )
    } else if path.starts_with('\\') {
        ("", path.trim_start_matches('\\'), true, 0)
    } else {
        ("", path.as_str(), false, 0)
    };

    let mut components = Vec::new();
    for component in remainder
        .split('\\')
        .filter(|component| !component.is_empty())
    {
        let protected_unc_component = unc && components.len() < protected_components;
        if component == "." && !protected_unc_component {
            continue;
        }
        if component == ".." && !protected_unc_component {
            if components.len() > protected_components && components.last().copied() != Some("..") {
                components.pop();
            } else if !rooted {
                components.push(component);
            }
            continue;
        }
        components.push(component);
    }

    let mut normalized = String::with_capacity(path.len());
    normalized.push_str(prefix);
    if rooted && !normalized.ends_with('\\') {
        normalized.push('\\');
    }
    for (index, component) in components.into_iter().enumerate() {
        if index != 0 {
            normalized.push('\\');
        }
        normalized.push_str(component);
    }
    normalized
}

/// Protocol mask for dokodemo IP modes (TCP=1, UDP=2, TCP+UDP=3); UNIX
/// listeners are not IP listeners and have no mask.
fn dokodemo_ip_protocols(mode: DokodemoNetwork) -> Option<u8> {
    Some(match mode {
        DokodemoNetwork::Tcp => 1,
        DokodemoNetwork::Udp => 2,
        DokodemoNetwork::TcpUdp => 3,
        DokodemoNetwork::Unix => return None,
    })
}

/// A profile's human-readable location: its name when set, else its
/// generated tag — the same choice the pre-pass generator made when
/// prefixing a profile's first invalid-model finding. Bounded with [`excerpt`]
/// because both halves are user-authored and only the share-link importer
/// caps them: the value becomes the path of every finding scoped to that
/// profile (and the generator's invalid-model message).
fn profile_display_name(profile: &ServerProfile) -> String {
    if profile.name.is_empty() {
        excerpt(&profile.tag())
    } else {
        excerpt(&profile.name)
    }
}

/// Validate the server-profile set: identity and generated-tag rules, every
/// profile's outbound model (findings scoped to the profile's display name,
/// warnings included), and the chained-outbound graph. `require_nonempty`
/// is the latency probe's at-least-one-profile gate.
pub fn validate_profiles(
    profiles: &[ServerProfile],
    active_id: Option<&str>,
    require_nonempty: bool,
) -> Verdict {
    let outbound_tags = emit::profile_outbound_tags(profiles);
    profile_set_verdict(profiles, active_id, require_nonempty, &outbound_tags)
}

/// [`validate_profiles`]'s body: the profile-level findings, judged against
/// the outbound tags the given configuration carries (`outbound_tags`, so
/// every target check below reads the emission universe rather than a copy of
/// it).
fn profile_set_verdict(
    profiles: &[ServerProfile],
    active_id: Option<&str>,
    require_nonempty: bool,
    outbound_tags: &BTreeSet<String>,
) -> Verdict {
    let mut issues = Vec::new();
    if require_nonempty && profiles.is_empty() {
        issues.push(issue(ValidationCode::ProfilesRequired, None));
    }
    if let Some(active_id) = active_id {
        let active_matches = profiles
            .iter()
            .filter(|profile| profile.id == active_id)
            .count();
        match active_matches {
            1 => {}
            0 => issues.push(issue(
                ValidationCode::ActiveProfileMissing(excerpt(active_id)),
                None,
            )),
            count => issues.push(issue(
                ValidationCode::ActiveProfileAmbiguous(excerpt(active_id), count),
                None,
            )),
        }
    }

    let mut profile_ids = BTreeMap::<&str, usize>::new();
    let mut profile_tags = BTreeMap::<String, (&str, usize)>::new();
    for (index, profile) in profiles.iter().enumerate() {
        let profile_number = index + 1;
        if profile.id.trim().is_empty() {
            issues.push(issue(ValidationCode::ProfileIdEmpty(profile_number), None));
        }
        if let Some(first_number) = profile_ids.insert(profile.id.as_str(), profile_number) {
            issues.push(issue(
                ValidationCode::ProfileIdDuplicated(
                    first_number,
                    profile_number,
                    excerpt(&profile.id),
                ),
                None,
            ));
        }

        let tag = profile.tag();
        let tag_usable = if tag.trim().is_empty() {
            issues.push(issue(
                ValidationCode::ProfileTagEmpty(profile_number, excerpt(&profile.id)),
                None,
            ));
            false
        } else if tag
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
        {
            issues.push(issue(
                ValidationCode::ProfileTagInvalid(
                    profile_number,
                    excerpt(&profile.id),
                    excerpt(&tag),
                ),
                None,
            ));
            false
        } else if matches!(tag.as_str(), DIRECT_OUTBOUND_TAG | BLOCK_OUTBOUND_TAG) {
            issues.push(issue(
                ValidationCode::ProfileTagReserved(
                    profile_number,
                    excerpt(&profile.id),
                    excerpt(&tag),
                ),
                None,
            ));
            false
        } else {
            true
        };
        if tag_usable {
            if let Some(&(first_id, first_number)) = profile_tags.get(&tag) {
                issues.push(issue(
                    ValidationCode::ProfileTagDuplicated(
                        first_number,
                        excerpt(first_id),
                        profile_number,
                        excerpt(&profile.id),
                        excerpt(&tag),
                    ),
                    None,
                ));
            } else {
                profile_tags.insert(tag, (profile.id.as_str(), profile_number));
            }
        }
    }

    for profile in profiles {
        let location = profile_display_name(profile);
        for finding in validate_outbound(&profile.outbound) {
            issues.push(ValidationIssue {
                code: finding.code,
                path: Some(location.clone()),
                severity: finding.severity,
                target: FindingTarget::Document,
            });
        }
    }

    // The chain rules (dangling hop, cycle) belong to the dial graph, which
    // every other profile-set question reads (the generator's bootstrap
    // scope, the probe's staged child, the delete dialog's references).
    issues.extend(crate::model::dial::DialGraph::new(profiles, outbound_tags).chain_findings());

    Verdict::from_issues(issues)
}

/// One settings-level verdict for the whole configuration: the server
/// profiles the settings reference, then every settings-wide rule —
/// balancers, local inbounds, dokodemo listeners, TUN, listener collisions,
/// routing rules, DNS servers, fakeDNS pools, geodata — in the generator's
/// order. `api_port` is the loopback control-plane port generation will
/// bind; the API listener participates in the collision rule like every
/// other listener. `settings.mode` selects the TUN rules.
pub fn validate_settings(settings: &Settings, servers: &ServersFile, api_port: u16) -> Verdict {
    // The emitted outbound universe first: every check below — the profile
    // verdict's chain targets, the balancer fallbacks, the rules — judges the
    // tags the generated document carries.
    let outbound_tags = emit::outbound_tags(servers, settings);
    let issues = profile_set_verdict(
        &servers.profiles,
        servers.active.as_deref(),
        false,
        &outbound_tags,
    )
    .into_issues();
    SettingsWalk {
        settings,
        outbound_tags: &outbound_tags,
        issues,
        balancer_tags: BTreeSet::new(),
        // The emitted inbound universe: the control-plane listener, TUN,
        // dns-in, the emitted local endpoints, the emitted dokodemo
        // listeners. It is grown by insertion because the insert that fails
        // IS the duplicate rule — the arm that inserts second reports the
        // collision, in emission order, and `run` calls the families in that
        // order so the findings read as their refusal does. Which entries are
        // emitted and which tags the emitter adds itself are `emit`'s answers
        // (`local_inbound_emitted`, `dokodemo_emitted`,
        // `appended_inbound_tags`), so this universe and the generated
        // document can never drift apart.
        inbound_tags: BTreeSet::from([API_INBOUND_TAG.to_string()]),
        ip_listeners: vec![("API".to_string(), "127.0.0.1".to_string(), api_port, 1_u8)],
        unix_listeners: BTreeMap::new(),
        tun_gateway: tun_ipv4_gateway(&settings.tun),
    }
    .run()
}

/// The state one settings-level walk threads through its rule families: the
/// findings the profile verdict already contributed plus what the families
/// accumulate, and the listener bookkeeping they share — the emitted
/// inbound-tag set, the IP listeners the collision rule pairs against earlier
/// ones, the UNIX-socket paths it dedupes, and the balancer tags the routing
/// rules resolve against. Each family is one method, and
/// [`SettingsWalk::run`] calls them in the order the findings read; that order
/// is the walk's contract.
struct SettingsWalk<'a> {
    settings: &'a Settings,
    /// The outbound tags the generated document carries.
    outbound_tags: &'a BTreeSet<String>,
    issues: Vec<ValidationIssue>,
    balancer_tags: BTreeSet<String>,
    inbound_tags: BTreeSet<String>,
    ip_listeners: Vec<(String, String, u16, u8)>,
    unix_listeners: BTreeMap<String, String>,
    /// The TUN gateway's IPv4 address, when the settings carry one: the leak
    /// block's in-tun DNS listener anchors on it.
    tun_gateway: Option<&'a str>,
}

impl<'a> SettingsWalk<'a> {
    /// Run every rule family, in the order their findings read, and hand back
    /// the one verdict.
    fn run(mut self) -> Verdict {
        self.balancers();
        self.local_inbounds();
        self.dokodemo();
        self.tun();
        self.env();
        self.emitter_reserved_inbounds();
        self.listener_conflicts();
        self.routing_rules();
        self.dns();
        self.geodata();
        Verdict::from_issues(self.issues)
    }

    /// One balancer's own rules: a missing tag skips the entry (the checks
    /// below would name a tag that does not exist), a selector of only blanks,
    /// a duplicate tag, and a `fallbackTag` outside the emitted outbound
    /// universe.
    fn balancers(&mut self) {
        for (index, balancer) in self.settings.routing.balancers.iter().enumerate() {
            if balancer.tag.trim().is_empty() {
                self.issues
                    .push(issue(ValidationCode::BalancerTagMissing(index + 1), None));
                // The remaining checks would name a tag that does not exist.
                continue;
            }
            if balancer
                .selector
                .iter()
                .all(|selector| selector.trim().is_empty())
            {
                self.issues.push(issue(
                    ValidationCode::BalancerSelectorMissing(excerpt(&balancer.tag)),
                    None,
                ));
            }
            if !self.balancer_tags.insert(balancer.tag.clone()) {
                self.issues.push(issue(
                    ValidationCode::BalancerTagDuplicated(excerpt(&balancer.tag)),
                    None,
                ));
            }
            if !balancer.fallback_tag.is_empty()
                && !self.outbound_tags.contains(&balancer.fallback_tag)
            {
                self.issues.push(issue(
                    ValidationCode::BalancerFallbackMissing(
                        excerpt(&balancer.tag),
                        excerpt(&balancer.fallback_tag),
                    ),
                    None,
                ));
            }
        }
    }

    /// Local endpoints: every emitted entry must bind a valid listen address on
    /// a non-zero port, and its tag must be unique among all emitted inbound
    /// tags (local endpoints, TUN, dns-in, API, dokodemo).
    fn local_inbounds(&mut self) {
        for (index, entry) in self.settings.local_inbounds.iter().enumerate() {
            if !emit::local_inbound_emitted(entry) {
                continue;
            }
            let target = FindingTarget::LocalInbound(index);
            if let Some(code) = local_inbound_auth_verdict(entry) {
                self.issues.push(issue(code, None).at(target.clone()));
            }
            if entry.port == 0 {
                self.issues.push(
                    issue(
                        ValidationCode::LocalInboundPortZero(excerpt(&entry.tag)),
                        None,
                    )
                    .at(target.clone()),
                );
            }
            let listen_valid = validate_listen_address(&entry.listen).is_ok();
            if !listen_valid {
                self.issues.push(
                    issue(
                        ValidationCode::ListenAddressInvalid,
                        Some(format!("local inbound {:?}", excerpt(&entry.tag))),
                    )
                    .at(target.clone()),
                );
            }
            // Inbound sniffing vocabulary: Xray refuses the whole config at
            // load on an unknown destOverride protocol, so this gates
            // generate/apply exactly like the load refusal. The "fakedns" item
            // the generator appends at wire time is part of the accepted
            // vocabulary, so it can never false-positive here.
            for finding in
                validate_sniffing(&entry.sniffing, &format!("localInbounds[{index}].sniffing"))
            {
                self.issues.push(ValidationIssue {
                    code: finding.code,
                    path: Some(format!("local inbound {:?}", excerpt(&entry.tag))),
                    severity: finding.severity,
                    target: target.clone(),
                });
            }
            // The listener-side mask the core builds for this inbound. A
            // malformed `filter` rule aborts the whole configuration at load,
            // so it gates here like every other build refusal.
            if let Some(finalmask) = &entry.finalmask {
                for finding in validate_finalmask(finalmask) {
                    let path = finding.path.map_or_else(
                        || format!("localInbounds[{index}].finalmask"),
                        |path| format!("localInbounds[{index}].{path}"),
                    );
                    self.issues.push(ValidationIssue {
                        code: finding.code,
                        path: Some(path),
                        severity: finding.severity,
                        target: target.clone(),
                    });
                }
            }
            if listen_valid && entry.port != 0 {
                let protocols = match entry.protocol {
                    LocalInboundProtocol::Socks => 1 | if entry.udp { 2 } else { 0 },
                    LocalInboundProtocol::Http => 1,
                };
                self.ip_listeners.push((
                    format!("local inbound {:?}", excerpt(&entry.tag)),
                    entry.listen.clone(),
                    entry.port,
                    protocols,
                ));
            }
            if !self.inbound_tags.insert(entry.tag.clone()) {
                self.issues.push(
                    issue(
                        ValidationCode::InboundTagDuplicated(excerpt(&entry.tag)),
                        None,
                    )
                    .at(target),
                );
            }
        }
    }

    /// Dokodemo listeners: tag presence, the network-mode vocabulary and its
    /// transport-specific rules (UNIX-socket path required and unique, IP listen
    /// address and port), the sniffing vocabulary, and the tag uniqueness every
    /// emitted inbound shares.
    fn dokodemo(&mut self) {
        for (index, inbound) in self.settings.dokodemo.iter().enumerate() {
            if !emit::dokodemo_emitted(inbound) {
                continue;
            }
            let target = FindingTarget::Dokodemo(index);
            if inbound.tag.is_empty() {
                self.issues.push(
                    issue(ValidationCode::DokodemoTagMissing(index + 1), None).at(target.clone()),
                );
            }
            let tag = inbound.tag.clone();
            let mode = inbound.network_mode();
            if let Err(error) = &mode {
                self.issues.push(
                    warning(
                        ValidationCode::DokodemoNetworkInvalid(excerpt(&tag), excerpt(error)),
                        None,
                    )
                    .at(target.clone()),
                );
            }
            // Same sniffing gate as the local endpoints above.
            for finding in
                validate_sniffing(&inbound.sniffing, &format!("dokodemo[{index}].sniffing"))
            {
                self.issues.push(ValidationIssue {
                    code: finding.code,
                    path: Some(format!("dokodemo inbound {:?}", excerpt(&tag))),
                    severity: finding.severity,
                    target: target.clone(),
                });
            }
            match mode {
                Ok(DokodemoNetwork::Unix) => {
                    let path = inbound.unix_socket_path.trim();
                    if path.is_empty() {
                        self.issues.push(
                            issue(
                                ValidationCode::DokodemoUnixSocketRequired(excerpt(&tag)),
                                None,
                            )
                            .at(target.clone()),
                        );
                    } else {
                        let normalized = normalize_windows_socket_path(path);
                        match self.unix_listeners.get(&normalized) {
                            Some(other) => self.issues.push(
                                issue(
                                    ValidationCode::DokodemoUnixSocketConflict(
                                        excerpt(&tag),
                                        excerpt(other),
                                        excerpt(path),
                                    ),
                                    None,
                                )
                                .at(target.clone()),
                            ),
                            None => {
                                self.unix_listeners.insert(normalized, tag.clone());
                            }
                        }
                    }
                }
                Ok(DokodemoNetwork::Tcp | DokodemoNetwork::Udp | DokodemoNetwork::TcpUdp) => {
                    if inbound.listen_port == 0 {
                        self.issues.push(
                            warning(ValidationCode::DokodemoPortZero(excerpt(&tag)), None)
                                .at(target.clone()),
                        );
                    }
                    let listen_valid = validate_listen_address(&inbound.listen).is_ok();
                    if !listen_valid {
                        self.issues.push(
                            issue(
                                ValidationCode::ListenAddressInvalid,
                                Some(format!("dokodemo inbound {:?}", excerpt(&tag))),
                            )
                            .at(target.clone()),
                        );
                    }
                    if listen_valid && inbound.listen_port != 0 {
                        let protocols =
                            dokodemo_ip_protocols(mode.expect("matched IP mode")).expect("IP mask");
                        self.ip_listeners.push((
                            format!("dokodemo inbound {:?}", excerpt(&tag)),
                            inbound.listen.clone(),
                            inbound.listen_port,
                            protocols,
                        ));
                    }
                }
                Err(_) => {
                    // The emitter answers an unparseable mode with the IP
                    // envelope, so the tokens the core could still read bind and
                    // must join the conflict walk: `tcp,` serves TCP on the
                    // emitted `listen`+port, while an unknown-only token binds
                    // nothing.
                    let protocols = inbound.implied_ip_protocols();
                    let listen_valid = validate_listen_address(&inbound.listen).is_ok();
                    if protocols != 0 && listen_valid && inbound.listen_port != 0 {
                        self.ip_listeners.push((
                            format!("dokodemo inbound {:?}", excerpt(&tag)),
                            inbound.listen.clone(),
                            inbound.listen_port,
                            protocols,
                        ));
                    }
                }
            }
            if !self.inbound_tags.insert(tag.clone()) {
                self.issues.push(
                    issue(ValidationCode::InboundTagDuplicated(excerpt(&tag)), None).at(target),
                );
            }
        }
    }

    /// The TUN gateway rule and the core's leak block. The TUN gateway entries
    /// become the adapter's addresses, and the in-tun DNS listener anchors on
    /// the gateway's IPv4 (the core's DNS leak block permits port-53 only inside
    /// the TUN subnet). The IPv4 gateway is a virtual address that needs no IPv4
    /// from the network — an IPv6-only uplink still works with it — so an
    /// IPv6-only gateway list is refused by design, not for want of an address.
    /// An empty list is refused with it: nothing would own the address the
    /// adapter DNS pins.
    fn tun(&mut self) {
        if let Some(code) = tun_gateway_verdict(self.settings) {
            self.issues.push(issue(code, None).at(FindingTarget::Tun));
        }
        // Every gateway entry becomes an adapter address, and the core parses
        // each one with `netip.MustParsePrefix` while it builds the adapter
        // (proxy/tun/tun_windows.go) — a malformed entry panics the whole
        // process at config load. The app derives the DNS takeover address
        // from the same string, so the model requires a CIDR prefix here.
        if emit::tun_inbound_emitted(self.settings) {
            settings_extra_shadow(
                "tun",
                &self.settings.tun.extra,
                &TUN_WIRE_KEYS,
                &mut self.issues,
            );
            settings_extra_shadow(
                "tun.sniffing",
                &self.settings.tun.sniffing.extra,
                &SNIFFING_WIRE_KEYS,
                &mut self.issues,
            );
            for (index, entry) in self.settings.tun.gateway.iter().enumerate() {
                if entry.trim().is_empty() {
                    continue;
                }
                if !gateway_entry_go_compatible(entry) {
                    self.issues.push(
                        issue(
                            ValidationCode::TunGatewayInvalid(excerpt(entry)),
                            Some(format!("tun.gateway[{index}]")),
                        )
                        .at(FindingTarget::Tun),
                    );
                }
            }
        }
        // The generator writes the leak key exactly while the TUN inbound and
        // the DNS module are both present (`emit::dns_inbound_emitted`, the model
        // side of the `config_runs_tun_dns` predicate the runtime reads back),
        // so these rules judge the same document the core will load. The
        // routing-table and value rules mirror refusals the app's wire can really
        // hit; the dns half needs no check here — the generator overwrites the
        // TUN inbound's resolver list with the in-tun gateway on the same gate
        // (`gen::inbounds`), so the core's `len(v.DNS) == 0` refusal is satisfied
        // structurally. The block is also the only mechanism that now keeps DNS
        // and the unrouted family inside the tunnel, so a half switched off warns
        // with what reopens.
        if emit::dns_inbound_emitted(self.settings) {
            let leak = &self.settings.tun.auto_system_wfp_block_leak;
            if !leak.is_empty() && self.settings.tun.auto_system_routing_table.is_empty() {
                self.issues.push(
                    issue(ValidationCode::TunLeakRoutingTableRequired, None).at(FindingTarget::Tun),
                );
            }
            for (index, value) in leak.iter().enumerate() {
                if !vocabulary_holds(&[TUN_LEAK_DNS, TUN_LEAK_MISCONFIG_TUN], value) {
                    self.issues.push(
                        issue(
                            ValidationCode::TunLeakValueUnknown(excerpt(value)),
                            Some(format!("tun.autoSystemWfpBlockLeak[{index}]")),
                        )
                        .at(FindingTarget::Tun),
                    );
                }
            }
            if tun_leak_misconfig_tun_off(self.settings) {
                self.issues.push(
                    warning(
                        ValidationCode::TunLeakMisconfigTunOff,
                        Some("tun.autoSystemWfpBlockLeak".into()),
                    )
                    .at(FindingTarget::Tun),
                );
            }
        }
    }

    /// Reject `settings.env` keys that would re-point core path resolution.
    /// Xray applies the whole map with `os.Setenv` before it resolves assets
    /// (infra/conf/xray.go), and `xray.location.asset` outranks the
    /// `XRAY_LOCATION_ASSET` the app pins (common/platform/platform.go), so a
    /// configured key can send the core to another asset folder. Windows
    /// environment names ignore case, and Go's own variable lookup reads a
    /// dot as an underscore, so the key is folded to that spelling first.
    fn env(&mut self) {
        for (index, (key, _)) in self.settings.env.iter().enumerate() {
            if env_key_overrides_core_path(key) {
                self.issues.push(issue(
                    ValidationCode::EnvCorePathOverride(excerpt(key)),
                    Some(format!("env[{index}]")),
                ));
            }
        }
    }

    /// Reserve the tags the emitter appends behind the configured entries, in
    /// the emitter's own order, then add the in-tun DNS listeners the runtime
    /// mounts while a DNS module exists.
    fn emitter_reserved_inbounds(&mut self) {
        // The insert that fails reports the collision for the arm walked second,
        // so a configured entry reusing one of these tags is reported on the
        // reserved arm exactly as the document carries it.
        for tag in emit::appended_inbound_tags(self.settings) {
            if !self.inbound_tags.insert(tag.to_string()) {
                self.issues.push(issue(
                    ValidationCode::InboundTagDuplicated(tag.into()),
                    None,
                ));
            }
        }
        // The in-tun DNS listeners (one per gateway address family, port 53,
        // TCP+UDP) are added to the running TUN core while a DNS module exists; a
        // user listener on either endpoint must be rejected like any other
        // collision.
        if emit::dns_inbound_emitted(self.settings) {
            if let Some(address) = self.tun_gateway {
                self.ip_listeners
                    .push(("DNS-in".into(), address.to_string(), 53, 3));
            }
            if let Some(address) = tun_ipv6_gateway(&self.settings.tun) {
                self.ip_listeners
                    .push(("DNS-in6".into(), address.to_string(), 53, 3));
            }
        }
    }

    /// Pair every IP listener against the earlier ones. The conjunction itself
    /// is one definition (`crate::model::inbound::listen_endpoints_conflict`);
    /// this walk keeps the model-level concerns — each entry's label, the
    /// pairing against earlier listeners, and the `ListenerConflict` code.
    /// Disabled entries, invalid listen addresses, and zero ports never reach
    /// `ip_listeners`.
    fn listener_conflicts(&mut self) {
        for current in 0..self.ip_listeners.len() {
            let (label, address, port, protocols) = &self.ip_listeners[current];
            let endpoint = (*port, *protocols, address.as_str());
            if let Some(other) = self.ip_listeners[..current].iter().find(|other| {
                let (_, other_address, other_port, other_protocols) = other;
                listen_endpoints_conflict(
                    endpoint,
                    (*other_port, *other_protocols, other_address.as_str()),
                )
            }) {
                self.issues.push(issue(
                    ValidationCode::ListenerConflict(
                        label.clone(),
                        other.0.clone(),
                        address.clone(),
                        *port,
                    ),
                    None,
                ));
            }
        }
    }

    /// Routing rules: a configured script first (the core refuses it beside
    /// any rule or a non-default strategy, and the app never drops the rules),
    /// then an unresolved target short-circuits (the reference checks below
    /// would name it), then the outbound, balancer and inbound references each
    /// resolve against the set their emitter produced.
    fn routing_rules(&mut self) {
        for code in routing_script_issues(
            self.settings.routing.script.as_deref(),
            self.settings.routing.rules.len(),
            &self.settings.routing.domain_strategy,
        ) {
            self.issues.push(issue(code, Some("routing.script".into())));
        }
        for (index, rule) in self.settings.routing.rules.iter().enumerate() {
            if let Some(error) = rule.target_error() {
                self.issues.push(issue(
                    ValidationCode::RoutingRuleTarget(index + 1, error.to_string()),
                    None,
                ));
                // The reference checks below would name an unresolved target.
                continue;
            }
            if !rule.outbound_tag.is_empty() && !self.outbound_tags.contains(&rule.outbound_tag) {
                self.issues.push(issue(
                    ValidationCode::RoutingRuleOutboundMissing(
                        index + 1,
                        excerpt(&rule.outbound_tag),
                    ),
                    None,
                ));
            }
            if !rule.balancer_tag.is_empty() && !self.balancer_tags.contains(&rule.balancer_tag) {
                self.issues.push(issue(
                    ValidationCode::RoutingRuleBalancerMissing(
                        index + 1,
                        excerpt(&rule.balancer_tag),
                    ),
                    None,
                ));
            }
            if let Some(tag) = rule
                .inbound_tag
                .iter()
                .find(|tag| !self.inbound_tags.contains(*tag))
            {
                self.issues.push(issue(
                    ValidationCode::RoutingRuleInboundMissing(index + 1, excerpt(tag)),
                    None,
                ));
            }
        }
    }

    /// The DNS module: the configured script, the GUI bootstrap override, the
    /// server list, and the fakeDNS pools. A script's structural path rule and
    /// its conflicts with the fallback flags and the per-server matchers are
    /// the core's own load refusals (infra/conf/dns.go). The bootstrap
    /// override replaces the auto-derived first
    /// server as the resolver for proxy-server domains, so it must be an
    /// endpoint the generator can emit as the scoped `+local` entry: an
    /// IP-literal host (behind `https://`, `h2c://`, `quic://`, `tcp://` or
    /// bare) or the literal `localhost`. A domain host would need that very
    /// resolution, so the generator emits nothing and the override silently has
    /// no effect. The auto-derived path is not judged here: its input is the
    /// server list. The pools must be CIDRs Xray's fakeip holder can build: a
    /// bad range, a non-positive size, or an LRU size not smaller than the
    /// subnet fails the core at start (app/dns/fakedns/fake.go:82-90) — such a
    /// config must never be applied.
    fn dns(&mut self) {
        settings_extra_shadow(
            "dns",
            &self.settings.dns.extra,
            &DNS_WIRE_KEYS,
            &mut self.issues,
        );
        for code in dns_script_issues(
            self.settings.dns.script.as_deref(),
            &self.settings.dns.servers,
            self.settings.dns.disable_fallback,
            self.settings.dns.disable_fallback_if_match,
        ) {
            self.issues.push(issue(code, Some("dns.script".into())));
        }
        let bootstrap = self.settings.dns.bootstrap.trim();
        if !bootstrap.is_empty()
            && bootstrap != "localhost"
            && crate::model::dns::scoped_bootstrap_endpoint(bootstrap, None).is_none()
        {
            self.issues.push(warning(
                ValidationCode::DnsBootstrapNotResolvable,
                Some("dns.bootstrap".into()),
            ));
        }
        for (index, server) in self.settings.dns.servers.iter().enumerate() {
            if server.address.trim().is_empty() {
                self.issues.push(issue(
                    ValidationCode::DnsServerAddressMissing(index + 1),
                    None,
                ));
            }
        }
        for (index, pool) in self.settings.dns.fakedns.pools.iter().enumerate() {
            let parsed = parse_pool_cidr(&pool.ip_pool);
            if parsed.is_none() {
                self.issues.push(issue(
                    ValidationCode::FakeDnsPoolCidrInvalid(index + 1),
                    None,
                ));
            }
            if pool.pool_size < 1 {
                self.issues.push(issue(
                    ValidationCode::FakeDnsPoolSizeInvalid(index + 1),
                    None,
                ));
            }
            if let Some((_, host_bits)) = parsed
                && pool.pool_size >= 1
                && host_bits < 63
                && (pool.pool_size as u64) >= (1u64 << host_bits)
            {
                self.issues.push(issue(
                    ValidationCode::FakeDnsPoolCapacityExceeded(
                        index + 1,
                        pool.pool_size,
                        excerpt(&pool.ip_pool),
                    ),
                    None,
                ));
            }
        }
    }

    /// The geo data block: when configured, every URL must be HTTPS-with-host
    /// and the cron (when set) must be the 5-field shape. Empty = unconfigured.
    fn geodata(&mut self) {
        if self.settings.geodata.is_configured() {
            for (url, file) in [
                (self.settings.geodata.geoip_url.as_deref(), "geoip.dat"),
                (self.settings.geodata.geosite_url.as_deref(), "geosite.dat"),
            ] {
                if let Some(url) = url
                    && !crate::model::settings::geodata_url_valid(url)
                {
                    self.issues.push(issue(
                        ValidationCode::GeodataUrlInvalid(file.to_string()),
                        None,
                    ));
                }
            }
            if let Some(cron) = self.settings.geodata.cron.as_deref()
                && !crate::model::settings::geodata_cron_valid(cron)
            {
                self.issues
                    .push(issue(ValidationCode::GeodataCronInvalid, None));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::inbound::Account;
    use crate::model::outbound::{OutboundModel, Protocol, ProtocolSettings};
    use crate::model::settings::Mode;
    use crate::model::validation::Severity;
    use crate::model::validation::tests::{codes, finding};
    use serde_json::{Map, json};

    /// The verdict one local endpoint's authentication editor renders, and
    /// with it the walk's rule: "require authentication" ticked on an emitted
    /// row whose wire form authenticates nobody. HTTP's accounts are its only
    /// authentication, so an empty list serves everyone at any bind; a
    /// disabled row never reaches the wire, and SOCKS password mode with an
    /// empty list denies every connection (never the trap).
    #[test]
    fn local_endpoint_auth_verdict_follows_the_wire_form() {
        let http = |enabled: bool, auth: &str, accounts: usize| LocalInboundCfg {
            protocol: LocalInboundProtocol::Http,
            tag: "in-http".into(),
            enabled,
            listen: "0.0.0.0".into(),
            auth: auth.into(),
            accounts: vec![Account::default(); accounts],
            ..Default::default()
        };
        for listen in ["127.0.0.1", "0.0.0.0"] {
            let entry = LocalInboundCfg {
                listen: listen.into(),
                ..http(true, "password", 0)
            };
            assert_eq!(
                local_inbound_auth_verdict(&entry),
                Some(ValidationCode::LocalInboundAuthRequiresAccounts),
                "password mode with no account authenticates nobody (bind {listen})"
            );
        }
        assert_eq!(
            local_inbound_auth_verdict(&http(false, "password", 0)),
            None
        );
        for (auth, accounts) in [("password", 1), ("noauth", 0)] {
            assert_eq!(
                local_inbound_auth_verdict(&http(true, auth, accounts)),
                None,
                "{auth:?} with {accounts} account(s) authenticates"
            );
        }
        let socks = LocalInboundCfg {
            protocol: LocalInboundProtocol::Socks,
            tag: "in-socks".into(),
            enabled: true,
            auth: "password".into(),
            ..Default::default()
        };
        assert_eq!(local_inbound_auth_verdict(&socks), None);
    }

    /// The verdict the TUN gateway editor renders, and with it the walk's
    /// rule: a TUN-mode document whose gateway list carries no IPv4 address
    /// has no adapter address and no in-subnet address for the in-tun DNS
    /// listeners. Every other mode, and a tunnel with an IPv4 gateway, is
    /// clean.
    #[test]
    fn tun_gateway_verdict_requires_an_ipv4_gateway_in_tun_mode() {
        let tun = |mode: Mode, gateway: &[&str]| Settings {
            mode,
            tun: TunCfg {
                gateway: gateway.iter().map(|entry| (*entry).to_string()).collect(),
                ..Default::default()
            },
            ..Default::default()
        };
        for gateway in [&[][..], &["fd00::1/64"][..]] {
            assert_eq!(
                tun_gateway_verdict(&tun(Mode::Tun, gateway)),
                Some(ValidationCode::TunIpv4GatewayRequired),
                "{gateway:?} carries no IPv4 address"
            );
        }
        assert_eq!(
            tun_gateway_verdict(&tun(Mode::Tun, &["10.255.0.1/30"])),
            None
        );
        assert_eq!(tun_gateway_verdict(&tun(Mode::Off, &[])), None);
    }

    #[test]
    fn listen_address_rejects_non_ip_literals() {
        for ok in ["127.0.0.1", "0.0.0.0", "::", "::1", "192.168.1.5"] {
            assert!(validate_listen_address(ok).is_ok(), "{ok:?}");
        }
        for bad in ["", "localhost", "not-an-ip", "127.0.0.1:8080"] {
            assert_eq!(
                validate_listen_address(bad),
                Err(ValidationCode::ListenAddressInvalid),
                "{bad:?}"
            );
        }
    }

    // ---------- Lua script surfaces ----------

    #[test]
    fn lua_script_paths_must_be_non_empty_and_lua() {
        // The two structural refusals of the core's file resolver
        // (common/platform/platform.go): the blank path and every extension
        // other than `.lua`, compared case-sensitively.
        assert_eq!(lua_script_path_issue("/tmp/dns.lua"), None);
        assert_eq!(
            lua_script_path_issue("dns.lua"),
            None,
            "a relative path is resolved by the core, so it passes the structural rule"
        );
        for blank in ["", "   ", "\t"] {
            assert_eq!(
                lua_script_path_issue(blank),
                Some(ValidationCode::LuaScriptPathRequired),
                "{blank:?}"
            );
        }
        for other in [
            "/tmp/dns.txt",
            "/tmp/dns.lua.bak",
            "/tmp/dns.LUA",
            "/tmp/dns",
        ] {
            assert_eq!(
                lua_script_path_issue(other),
                Some(ValidationCode::LuaScriptPathNotLua),
                "{other:?}"
            );
        }
    }

    #[test]
    fn lua_script_paths_must_stay_local() {
        // The core opens the path while it loads the config, so a UNC or
        // device path makes the Windows client authenticate to the named
        // server before anything else runs. The same predicate guards the TLS
        // certificate rows.
        for remote in [
            r"\\attacker\share\dns.lua",
            "//attacker/share/dns.lua",
            r"/\attacker\share\dns.lua",
            r"\/attacker/share/dns.lua",
            r"\\.\C:\dns.lua",
            r"\\?\C:\dns.lua",
            "//./pipe/dns.lua",
            "//?/C:/dns.lua",
            r"C:relative\dns.lua",
            "file:///C:/dns.lua",
            r"C:\scripts\..\dns.lua",
            r"..\dns.lua",
        ] {
            match lua_script_path_issue(remote) {
                Some(ValidationCode::FilePathRemote(path)) => {
                    assert_eq!(path, remote, "the finding names the offending path")
                }
                other => panic!("{remote:?} must be refused as remote: {other:?}"),
            }
        }
        for local in [
            "dns.lua",
            r"C:\scripts\dns.lua",
            r"C:/scripts/dns.lua",
            r"\scripts\dns.lua",
            "./dns.lua",
        ] {
            assert_eq!(lua_script_path_issue(local), None, "{local:?}");
        }
    }

    /// `settings.env` is emitted verbatim and Xray applies the whole map with
    /// `os.Setenv` before it resolves assets, so a core location variable
    /// redirects the geodata and certificate lookup past the paths the app
    /// pins. Windows names ignore case and Go reads a dot as an underscore, so
    /// every variant of the four names gates.
    #[test]
    fn env_keys_that_repoint_core_paths_are_refused() {
        let settings = |env: &[(&str, &str)]| Settings {
            env: env
                .iter()
                .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
                .collect(),
            ..Default::default()
        };
        let verdict = validate_settings(
            &settings(&[
                ("PATH", r"C:\bin"),
                ("xray.location.asset", r"C:\assets"),
                (" Xray_Location_Cert ", r"C:\certs"),
            ]),
            &ServersFile::default(),
            19999,
        );
        let overrides: Vec<&ValidationIssue> = verdict
            .iter()
            .filter(|issue| matches!(issue.code, ValidationCode::EnvCorePathOverride(_)))
            .collect();
        assert_eq!(overrides.len(), 2, "{verdict:#?}");
        assert_eq!(overrides[0].path.as_deref(), Some("env[1]"));
        assert_eq!(
            overrides[0].code,
            ValidationCode::EnvCorePathOverride("xray.location.asset".into())
        );
        assert_eq!(overrides[1].path.as_deref(), Some("env[2]"));
        assert_eq!(overrides[1].severity, Severity::Error);
        for key in [
            "XRAY_LOCATION_ASSET",
            "XRAY_LOCATION_CONFDIR",
            "XRAY_LOCATION_CONFIG",
            "XRAY_LOCATION_CERT",
        ] {
            let verdict = validate_settings(
                &settings(&[(key, r"C:\elsewhere")]),
                &ServersFile::default(),
                19999,
            );
            assert!(
                verdict
                    .iter()
                    .any(|issue| issue.code == ValidationCode::EnvCorePathOverride(key.into())),
                "{key} must gate: {verdict:#?}"
            );
        }
    }

    /// A flattened settings key that folds onto a modeled field is read by
    /// the core and not by the model: a DNS `Script` path would bypass the
    /// locality rule, and a TUN `Gateway`/`DestOverride` would change the
    /// emitted inbound. All three gate as Errors.
    #[test]
    fn settings_extra_keys_that_fold_onto_modeled_fields_gate() {
        let mut settings = Settings::default();
        settings
            .dns
            .extra
            .insert("Script".into(), json!(r"\\attacker\share\d.lua"));
        let verdict = validate_settings(&settings, &ServersFile::default(), 19999);
        let finding = verdict
            .iter()
            .find(|issue| {
                matches!(
                    &issue.code,
                    ValidationCode::SettingsExtraShadow(key) if key == "Script"
                ) && issue.path.as_deref() == Some("dns.Script")
            })
            .unwrap_or_else(|| panic!("the DNS script shadow must gate: {verdict:#?}"));
        assert_eq!(finding.severity, Severity::Error);

        let mut settings = Settings {
            mode: Mode::Tun,
            ..Default::default()
        };
        settings
            .tun
            .extra
            .insert("Gateway".into(), json!(["10.0.0.1/24"]));
        settings
            .tun
            .sniffing
            .extra
            .insert("DestOverride".into(), json!(["http"]));
        let verdict = validate_settings(&settings, &ServersFile::default(), 19999);
        for (key, path) in [
            ("Gateway", "tun.Gateway"),
            ("DestOverride", "tun.sniffing.DestOverride"),
        ] {
            let finding = verdict
                .iter()
                .find(|issue| {
                    matches!(
                        &issue.code,
                        ValidationCode::SettingsExtraShadow(carried) if carried == key
                    ) && issue.path.as_deref() == Some(path)
                })
                .unwrap_or_else(|| panic!("{key} must gate at {path}: {verdict:#?}"));
            assert_eq!(finding.severity, Severity::Error);
        }
    }

    /// Every `tun.gateway` entry becomes an adapter address, and the core
    /// parses each with `netip.MustParsePrefix` — a malformed entry panics the
    /// process at load. The model requires a CIDR prefix on every non-empty
    /// entry the TUN document emits, and stays silent for the rest.
    #[test]
    fn tun_gateway_entries_must_parse_as_prefixes() {
        let tun = |mode: Mode, gateway: &[&str]| Settings {
            mode,
            tun: TunCfg {
                gateway: gateway.iter().map(|entry| (*entry).to_string()).collect(),
                ..Default::default()
            },
            ..Default::default()
        };
        for entry in [
            "10.255.0.1",
            "not-a-prefix",
            "10.0.0.0/33",
            "fd00::1/129",
            // `ipnet` reads numbers and accepts these; Go's
            // `netip.ParsePrefix` rejects them and the core panics.
            "010.255.0.1/30",
            "10.255.0.1/030",
            "fd00::1/064",
            "::ffff:010.1.2.3/120",
            "::010.1.2.3/120",
        ] {
            let settings = tun(Mode::Tun, &["10.255.0.1/30", entry]);
            let verdict = validate_settings(&settings, &ServersFile::default(), 19999);
            let path = "tun.gateway[1]";
            let finding = verdict
                .iter()
                .find(|issue| {
                    matches!(issue.code, ValidationCode::TunGatewayInvalid(_))
                        && issue.path.as_deref() == Some(path)
                })
                .unwrap_or_else(|| panic!("{entry:?} must gate at {path}: {verdict:#?}"));
            assert_eq!(finding.severity, Severity::Error);
            assert_eq!(finding.target, FindingTarget::Tun);
        }
        assert!(
            !validate_settings(
                &tun(Mode::Tun, &["10.255.0.1/30", "fd00::1/126"]),
                &ServersFile::default(),
                19999,
            )
            .iter()
            .any(|issue| matches!(issue.code, ValidationCode::TunGatewayInvalid(_))),
            "CIDR prefixes stay legal"
        );
        assert!(
            !validate_settings(
                &tun(Mode::Off, &["10.255.0.1"]),
                &ServersFile::default(),
                19999,
            )
            .iter()
            .any(|issue| matches!(issue.code, ValidationCode::TunGatewayInvalid(_))),
            "a config that emits no TUN inbound carries no gateway list"
        );
    }

    #[test]
    fn dns_script_conflicts_with_fallback_flags_and_server_matchers() {
        use crate::model::DnsServer;
        let servers = vec![
            DnsServer {
                address: "1.1.1.1".into(),
                ..Default::default()
            },
            DnsServer {
                address: "2.2.2.2".into(),
                domains: vec!["geosite:cn".into()],
                skip_fallback: Some(true),
                final_query: Some(true),
                ..Default::default()
            },
        ];
        assert_eq!(
            dns_script_issues(Some("dns.lua"), &servers, true, true),
            vec![
                ValidationCode::DnsScriptFallbackConflict,
                ValidationCode::DnsScriptServerConflict(2, "domains".into()),
                ValidationCode::DnsScriptServerConflict(2, "skipFallback".into()),
                ValidationCode::DnsScriptServerConflict(2, "finalQuery".into()),
            ],
            "the core names the flags first, then each server's matcher in wire order"
        );

        // `false` is the core's zero value: those servers carry no matcher.
        let quiet = vec![DnsServer {
            address: "1.1.1.1".into(),
            skip_fallback: Some(false),
            final_query: Some(false),
            ..Default::default()
        }];
        assert!(dns_script_issues(Some("dns.lua"), &quiet, false, false).is_empty());
        assert!(
            dns_script_issues(None, &servers, true, true).is_empty(),
            "no script means no conflict"
        );
    }

    #[test]
    fn dns_script_conflicts_gate_generation_with_the_same_codes() {
        let mut settings = Settings::default();
        settings.dns.script = Some("dns.lua".into());
        settings.dns.disable_fallback_if_match = true;
        settings.dns.servers[0].domains = vec!["geosite:cn".into()];

        let issues = validate_settings(&settings, &ServersFile::default(), 10853);
        for code in [
            ValidationCode::DnsScriptFallbackConflict,
            ValidationCode::DnsScriptServerConflict(1, "domains".into()),
        ] {
            let issue = finding(&issues, &code)
                .unwrap_or_else(|| panic!("{code:?} must reach the apply gate: {issues:#?}"));
            assert_eq!(issue.path.as_deref(), Some("dns.script"));
            assert_eq!(issue.severity, Severity::Error);
        }

        // An enabled script with no path is the core's empty-path refusal.
        let mut blank = Settings::default();
        blank.dns.script = Some(String::new());
        let issues = validate_settings(&blank, &ServersFile::default(), 10853);
        assert_eq!(
            finding(&issues, &ValidationCode::LuaScriptPathRequired)
                .expect("the empty path must gate")
                .path
                .as_deref(),
            Some("dns.script")
        );
    }

    #[test]
    fn routing_script_conflicts_with_rules_and_a_domain_strategy() {
        let mut settings = Settings::default();
        settings.routing.script = Some("routing.lua".into());
        settings.routing.rules.push(crate::model::routing::Rule {
            outbound_tag: "direct".into(),
            ..Default::default()
        });
        settings.routing.domain_strategy = "IpIfNonMatch".into();

        let issues = validate_settings(&settings, &ServersFile::default(), 10853);
        for code in [
            ValidationCode::RoutingScriptRulesConflict,
            ValidationCode::RoutingScriptStrategyConflict,
        ] {
            let issue = finding(&issues, &code)
                .unwrap_or_else(|| panic!("{code:?} must reach the apply gate: {issues:#?}"));
            assert_eq!(issue.path.as_deref(), Some("routing.script"));
            assert_eq!(issue.severity, Severity::Error);
        }
        assert_eq!(
            settings.routing.rules.len(),
            1,
            "validation judges the rules, it never drops them"
        );

        // A script with no rules on the default strategy is appliable.
        let mut clean = Settings::default();
        clean.routing.script = Some("routing.lua".into());
        let issues = validate_settings(&clean, &ServersFile::default(), 10853);
        assert!(
            !issues.iter().any(|issue| matches!(
                issue.code,
                ValidationCode::RoutingScriptRulesConflict
                    | ValidationCode::RoutingScriptStrategyConflict
                    | ValidationCode::LuaScriptPathNotLua
                    | ValidationCode::LuaScriptPathRequired
            )),
            "a well-formed script on the default strategy must not gate: {issues:#?}"
        );
    }

    // ---------- settings-level verdict (validate_settings) ----------

    fn named_profile(id: &str, name: &str, outbound: OutboundModel) -> ServerProfile {
        ServerProfile {
            id: id.into(),
            name: name.into(),
            outbound,
            latency_ms: None,
            extra: Map::new(),
        }
    }

    #[test]
    fn settings_verdict_surfaces_the_moved_editor_rules() {
        // `sendThrough`, freedom final-rule actions, and DNS-rule actions
        // used to be editor-only errors; the settings verdict must carry all
        // three as blocking codes now.
        let mut freedom = OutboundModel::new(Protocol::Freedom);
        let ProtocolSettings::Freedom(settings) = &mut freedom.settings else {
            unreachable!()
        };
        settings
            .final_rules
            .push(crate::model::outbound::FreedomFinalRule {
                action: "proxy".into(),
                ..Default::default()
            });
        freedom.send_through = Some("10.0.0.0/33".into());

        let mut dns = OutboundModel::new(Protocol::Dns);
        let ProtocolSettings::Dns(settings) = &mut dns.settings else {
            unreachable!()
        };
        settings.rules.push(crate::model::outbound::DnsOutRule {
            action: String::new(),
            ..Default::default()
        });

        let servers = ServersFile {
            profiles: vec![
                named_profile("aaaaaaaa11111111", "edge", freedom),
                named_profile("bbbbbbbb22222222", "resolver", dns),
            ],
            ..Default::default()
        };
        let issues = validate_settings(&Settings::default(), &servers, 10853);
        for code in [
            ValidationCode::SendThroughInvalid,
            ValidationCode::FreedomFinalRuleInvalid,
            ValidationCode::DnsRuleActionInvalid,
        ] {
            let issue = finding(&issues, &code).unwrap_or_else(|| {
                panic!("{code:?} must fire through the settings verdict: {issues:#?}")
            });
            assert_eq!(issue.severity, Severity::Error, "{issue:?}");
        }
    }

    #[test]
    fn a_user_listener_on_a_tunnel_gateway_port_53_conflicts_with_the_dns_listeners() {
        // The runtime adds one in-tun DNS listener per gateway address family
        // to the running TUN core, all on port 53: a user endpoint on either
        // gateway address would take a socket the tunnel's own DNS answers
        // on, so the settings verdict must refuse it before any start.
        for gateway in ["10.255.0.1", "fd00::1"] {
            let mut settings = Settings::default();
            settings.set_mode(crate::model::settings::Mode::Tun);
            settings.dokodemo.push(crate::model::inbound::DokodemoCfg {
                tag: "in-dns-clash".into(),
                enabled: true,
                listen: gateway.into(),
                listen_port: 53,
                ..Default::default()
            });
            let issues = validate_settings(&settings, &ServersFile::default(), 10853);
            assert!(
                issues.iter().any(|issue| matches!(
                    &issue.code,
                    ValidationCode::ListenerConflict(_, _, address, port)
                        if address == gateway && *port == 53
                )),
                "a listener on {gateway}:53 must conflict with the in-tun DNS listener: {issues:#?}"
            );
        }
    }

    #[test]
    fn a_user_listener_on_a_tunnel_gateway_port_53_is_fine_without_tun() {
        // The reservation follows the listeners: with no TUN inbound there is
        // no in-tun DNS listener, so the same endpoint is the user's.
        let mut settings = Settings::default();
        settings.dokodemo.push(crate::model::inbound::DokodemoCfg {
            tag: "in-dns-clash".into(),
            enabled: true,
            listen: "10.255.0.1".into(),
            listen_port: 53,
            ..Default::default()
        });
        let issues = validate_settings(&settings, &ServersFile::default(), 10853);
        assert!(
            !issues
                .iter()
                .any(|issue| matches!(issue.code, ValidationCode::ListenerConflict(..))),
            "no tunnel, no in-tun DNS listener to conflict with: {issues:#?}"
        );
    }

    #[test]
    fn settings_verdict_walks_the_generator_rules_in_order() {
        use crate::i18n::{Key, t};
        use crate::model::settings::Language;

        let mut settings = Settings::default();
        settings
            .routing
            .balancers
            .push(crate::model::routing::Balancer::default());
        settings
            .routing
            .rules
            .push(crate::model::routing::Rule::default());
        settings.dns.servers.clear();
        settings.dns.servers.push(Default::default());
        settings.dns.fakedns.pools.clear();
        settings
            .dns
            .fakedns
            .pools
            .push(crate::model::dns::FakeDnsPool {
                ip_pool: "not-a-cidr".into(),
                pool_size: 0,
                extra: Map::new(),
            });

        let found = codes(&validate_settings(
            &settings,
            &ServersFile::default(),
            10853,
        ));
        let position = |code: &ValidationCode| {
            found
                .iter()
                .position(|candidate| candidate == code)
                .unwrap_or_else(|| panic!("{code:?} must fire in one pass: {found:#?}"))
        };
        let balancer = position(&ValidationCode::BalancerTagMissing(1));
        // The rule's own rejection rides its keyed integrity sentence.
        let rule_target = t(Language::En, Key::IntegrityRuleTargetRequired).to_string();
        let rule = position(&ValidationCode::RoutingRuleTarget(1, rule_target));
        let server = position(&ValidationCode::DnsServerAddressMissing(1));
        let pool_cidr = position(&ValidationCode::FakeDnsPoolCidrInvalid(1));
        let pool_size = position(&ValidationCode::FakeDnsPoolSizeInvalid(1));
        assert!(
            balancer < rule && rule < server && server < pool_cidr && pool_cidr < pool_size,
            "rules must stay in the generator's order: {found:#?}"
        );
    }

    #[test]
    fn every_walk_finding_carries_the_target_of_the_row_it_judges() {
        use crate::model::routing::{Balancer, Rule};

        // One finding in every row family the walk names.
        let mut freedom = OutboundModel::new(Protocol::Freedom);
        freedom.send_through = Some("10.0.0.0/33".into());
        let mut settings = Settings {
            mode: Mode::Tun,
            ..Default::default()
        };
        settings.local_inbounds[1].listen = "not-an-address".into();
        settings.dokodemo.push(crate::model::inbound::DokodemoCfg {
            tag: "in-doko-a".into(),
            enabled: true,
            network: "tcp".into(),
            listen: "also-not-an-address".into(),
            listen_port: 10810,
            ..Default::default()
        });
        settings.tun.gateway.clear();
        settings.routing.rules = vec![
            Rule {
                outbound_tag: DIRECT_OUTBOUND_TAG.into(),
                ..Default::default()
            },
            Rule {
                outbound_tag: "missing-outbound".into(),
                ..Default::default()
            },
        ];
        settings.routing.balancers = vec![Balancer::default()];
        let servers = ServersFile {
            profiles: vec![named_profile("aaaaaaaa11111111", "edge", freedom)],
            ..Default::default()
        };
        let verdict = validate_settings(&settings, &servers, 10853);

        // The row's own target answers with the row's finding, and a row
        // without one answers nothing.
        let codes_at = |target: FindingTarget| -> Vec<ValidationCode> {
            verdict
                .for_target(target)
                .map(|issue| issue.code.clone())
                .collect()
        };
        assert!(
            codes_at(FindingTarget::LocalInbound(1))
                .contains(&ValidationCode::ListenAddressInvalid)
        );
        assert!(
            codes_at(FindingTarget::LocalInbound(0)).is_empty(),
            "the valid endpoint owns nothing"
        );
        assert!(
            codes_at(FindingTarget::Dokodemo(0)).contains(&ValidationCode::ListenAddressInvalid)
        );
        assert!(codes_at(FindingTarget::Tun).contains(&ValidationCode::TunIpv4GatewayRequired));
        // Profiles, rules and balancers judge no screen-editable settings row:
        // their findings stay document-scoped, with the location in `path`.
        let document = codes_at(FindingTarget::Document);
        assert!(
            document
                .iter()
                .any(|code| matches!(code, ValidationCode::RoutingRuleOutboundMissing(2, _))),
            "a rule finding names its reference in the code, not as a row target"
        );
        assert!(
            document.contains(&ValidationCode::SendThroughInvalid),
            "a profile finding is judged in isolation and owns no settings row"
        );
        assert!(document.contains(&ValidationCode::BalancerTagMissing(1)));
    }

    #[test]
    fn settings_verdict_reports_profile_chains_and_the_profile_location() {
        let mut first = named_profile(
            "aaaaaaaa11111111",
            "",
            OutboundModel::new(Protocol::Freedom),
        );
        first.outbound.chain_via("srv-bbbbbbbb");
        first.outbound.send_through = Some("bogus".into());
        let mut second = named_profile(
            "bbbbbbbb22222222",
            "second",
            OutboundModel::new(Protocol::Freedom),
        );
        second.outbound.chain_via("srv-aaaaaaaa");
        let servers = ServersFile {
            profiles: vec![first, second],
            ..Default::default()
        };

        let issues = validate_settings(&Settings::default(), &servers, 10853);
        let scoped = finding(&issues, &ValidationCode::SendThroughInvalid)
            .expect("the profile's own rule must fire");
        assert_eq!(
            scoped.path.as_deref(),
            Some("srv-aaaaaaaa"),
            "a profile-scoped finding carries the profile's display name"
        );
        finding(
            &issues,
            &ValidationCode::OutboundChainCycle(
                "srv-aaaaaaaa -> srv-bbbbbbbb -> srv-aaaaaaaa".into(),
            ),
        )
        .unwrap_or_else(|| panic!("the chain cycle must be reported: {issues:#?}"));
    }

    #[test]
    fn retired_proxy_settings_key_gates_every_shape_with_the_profile_location() {
        use crate::i18n::validation_issue_message;
        use crate::model::settings::Language;

        // Every non-null JSON shape loads — a wrong-typed or malformed value
        // must not fail the load (Xray models the key as a raw message) — and
        // each one leaves the profile gated under its own location until the
        // user resolves it. The fix-it text names the replacement.
        for value in [
            json!({"tag": "srv-bbbbbbbb"}),
            json!("srv-bbbbbbbb"),
            json!({"tag": 7}),
            json!(7),
            json!(true),
            json!(["srv-bbbbbbbb"]),
        ] {
            let profile: ServerProfile = serde_json::from_value(json!({
                "id": "aaaaaaaa11111111",
                "name": "first",
                "outbound": {"protocol": "freedom", "proxySettings": value},
            }))
            .unwrap_or_else(|error| panic!("{value} must load: {error}"));

            let issues = validate_profiles(std::slice::from_ref(&profile), None, false);
            let found = finding(&issues, &ValidationCode::OutboundProxySettingsRemoved)
                .unwrap_or_else(|| panic!("{value} must gate: {issues:#?}"));
            assert_eq!(found.severity, Severity::Error, "{value}");
            assert_eq!(found.path.as_deref(), Some("first"), "{value}");
            let rendered = validation_issue_message(found, Language::En);
            assert!(
                rendered.contains("streamSettings.sockopt.dialerProxy"),
                "{value}: {rendered}"
            );
            assert!(rendered.contains("proxySettings"), "{value}: {rendered}");

            // An edit clears the mark, and the profile validates clean: the
            // key is not part of the model, so nothing remains to report.
            let mut edited = profile;
            edited.outbound.retired_proxy_settings = None;
            let issues = validate_profiles(std::slice::from_ref(&edited), None, false);
            assert!(issues.is_empty(), "{value}: {issues:#?}");
        }

        // JSON `null` is the Go zero shape — the pinned core accepts it — so
        // the profile drives no finding and the key is gone from the model
        // (and therefore from the next save).
        let nulled: ServerProfile = serde_json::from_value(json!({
            "id": "aaaaaaaa11111111",
            "name": "first",
            "outbound": {"protocol": "freedom", "proxySettings": null},
        }))
        .expect("a null value must load");
        assert!(nulled.outbound.retired_proxy_settings.is_none());
        let issues = validate_profiles(std::slice::from_ref(&nulled), None, false);
        assert!(issues.is_empty(), "{issues:#?}");
        let persisted = serde_json::to_value(&nulled).expect("the profile serializes");
        assert!(
            persisted["outbound"].get("proxySettings").is_none(),
            "{persisted}"
        );
    }

    #[test]
    fn oversized_profile_identity_fields_render_bounded_findings() {
        // A hand-edited state file can carry multi-KB ids and names; every
        // parameterized payload and the per-profile finding path are bounded
        // with `crate::excerpt::excerpt` at construction (the enum's own
        // contract), so no render site can be inflated by them.
        use crate::i18n::validation_issue_message;
        use crate::model::settings::Language;

        let huge = "p".repeat(4096);
        let mut first = named_profile(&huge, &huge, OutboundModel::new(Protocol::Freedom));
        first.outbound.send_through = Some(huge.clone());
        let second = named_profile(&huge, "", OutboundModel::new(Protocol::Freedom));
        let servers = ServersFile {
            active: Some(huge.clone()),
            profiles: vec![first, second],
            ..Default::default()
        };

        let issues = validate_settings(&Settings::default(), &servers, 10853);
        assert!(
            issues.iter().any(|issue| matches!(
                issue.code,
                ValidationCode::ActiveProfileAmbiguous(..)
                    | ValidationCode::ProfileIdDuplicated(..)
            )),
            "the fixture must produce parameterized findings: {issues:#?}"
        );
        let scoped = finding(&issues, &ValidationCode::SendThroughInvalid)
            .expect("the profile's own rule must fire");
        let path = scoped.path.as_deref().expect("profile findings are scoped");
        assert!(
            path.chars().count() <= crate::excerpt::MAX_ERROR_EXCERPT_CHARS + 1,
            "the profile location must be excerpted: {path:?}"
        );
        for issue in &issues {
            let message = validation_issue_message(issue, Language::En);
            assert!(
                !message.contains(&huge),
                "finding must not embed the raw value: {message}"
            );
            assert!(
                message.len() < 1024,
                "finding must stay bounded, got {} chars: {message}",
                message.len()
            );
        }
    }

    #[test]
    fn dns_bootstrap_override_must_be_an_ip_literal_or_localhost() {
        let verdict = |bootstrap: &str| {
            let mut settings = Settings::default();
            settings.dns.bootstrap = bootstrap.into();
            validate_settings(&settings, &ServersFile::default(), 10853)
                .into_iter()
                .filter(|issue| issue.code == ValidationCode::DnsBootstrapNotResolvable)
                .collect::<Vec<_>>()
        };
        // Honored overrides stay silent: an IP-literal host behind any of the
        // generator's schemes, a bare host[:port] (IPv6 included), and the OS
        // resolver. The empty string is the auto-derive from the first
        // server, whose grammar the server list owns.
        for accepted in [
            "localhost",
            "1.1.1.1",
            "1.1.1.1:5353",
            "https://223.5.5.5/dns-query",
            "h2c://1.1.1.1",
            "quic://[2606:4700:4700::1111]",
            "2606:4700:4700::1111",
            "",
        ] {
            assert!(
                verdict(accepted).is_empty(),
                "{accepted:?} must stay silent: {:#?}",
                verdict(accepted)
            );
        }
        // A domain host needs the very resolution the entry provides, and an
        // unknown scheme has no `+local` form: the generator emits nothing,
        // so the typed override silently does nothing at all. `localhost` is
        // matched as spelled (the generator compares the trimmed text
        // verbatim), so another case of it is refused too.
        for refused in [
            "https://dns.google/dns-query",
            "dns.google",
            "dns.google:53",
            "udp://1.1.1.1",
            "http://223.5.5.5/dns-query",
            "fakedns",
            "LOCALHOST",
        ] {
            let issues = verdict(refused);
            assert_eq!(
                issues.len(),
                1,
                "{refused:?} must warn exactly once: {issues:#?}"
            );
            assert_eq!(issues[0].severity, Severity::Warning, "{refused:?}");
            assert_eq!(issues[0].path.as_deref(), Some("dns.bootstrap"));
        }
    }

    #[test]
    fn default_settings_verdict_is_error_free() {
        // Golden generation starts from the defaults; a spurious Error here
        // would block every one of them.
        let issues = validate_settings(&Settings::default(), &ServersFile::default(), 10853);
        assert!(
            !issues.iter().any(|issue| issue.severity == Severity::Error),
            "{issues:#?}"
        );
    }

    /// The collision walk judges exactly the entries the emitter carries: a tag
    /// shared with an entry `emit` leaves off the wire is no collision, and
    /// turning that entry on is one. The expectations are read from the
    /// emitter's own enablement predicates, so a walk that keeps its own copy
    /// of the policy fails here; `emit`'s emitted-document agreement test pins
    /// the other reader against the same predicates.
    #[test]
    fn inbound_collisions_follow_the_emitted_entries() {
        use crate::model::DokodemoCfg;

        let duplicates = |settings: &Settings| {
            validate_settings(settings, &ServersFile::default(), 10853)
                .into_iter()
                .filter(|issue| matches!(issue.code, ValidationCode::InboundTagDuplicated(_)))
                .collect::<Vec<_>>()
        };

        // The dokodemo arm: the disabled listener reuses an emitted endpoint's
        // tag, but it is off the wire, so nothing collides.
        let mut settings = Settings::default();
        let seeded_tag = settings.local_inbounds[0].tag.clone();
        assert!(
            emit::local_inbound_emitted(&settings.local_inbounds[0]),
            "the seeded endpoint is on the wire"
        );
        settings.dokodemo = vec![DokodemoCfg {
            tag: seeded_tag.clone(),
            ..Default::default()
        }];
        assert!(!emit::dokodemo_emitted(&settings.dokodemo[0]));
        assert!(
            duplicates(&settings).is_empty(),
            "a listener the emitter drops cannot collide"
        );

        settings.dokodemo[0].enabled = true;
        assert!(emit::dokodemo_emitted(&settings.dokodemo[0]));
        let found = duplicates(&settings);
        assert_eq!(
            found.len(),
            1,
            "the emitted listener collides on the shared tag: {found:#?}"
        );
        assert_eq!(
            found[0].code,
            ValidationCode::InboundTagDuplicated(seeded_tag)
        );
        assert_eq!(found[0].path, None, "a tag collision carries no path");

        // The local-endpoint arm: a disabled duplicate of an emitted tag is
        // off the wire too.
        let mut settings = Settings::default();
        let mut copy = settings.local_inbounds[0].clone();
        copy.enabled = false;
        settings.local_inbounds.push(copy);
        let copy_index = settings.local_inbounds.len() - 1;
        assert!(!emit::local_inbound_emitted(
            &settings.local_inbounds[copy_index]
        ));
        assert!(
            duplicates(&settings).is_empty(),
            "an endpoint the emitter drops cannot collide"
        );

        settings.local_inbounds[copy_index].enabled = true;
        assert!(emit::local_inbound_emitted(
            &settings.local_inbounds[copy_index]
        ));
        assert_eq!(
            duplicates(&settings).len(),
            1,
            "the emitted endpoint collides on the shared tag"
        );
    }
}
