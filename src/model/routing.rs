//! Routing, balancers, observatory/burstObservatory.
//! Observatory config is stored here (GUI grouping) but generated as
//! top-level keys by the generator.

use super::inbound::DIRECT_OUTBOUND_TAG;
use super::{
    DurationMs, skip_duration_zero, skip_empty_map, skip_empty_str, skip_empty_vec, skip_false,
};
use crate::diag::Diag;
use crate::i18n::{Key, t, t_fmt};
use crate::model::settings::Language;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

/// One routing rule (router.go:121-151). Every field gets a GUI editor row.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Rule {
    /// id for runtime AddRule/RemoveRule — auto-uuid on creation
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub rule_tag: String,
    /// exactly one of outbound_tag / balancer_tag
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub outbound_tag: String,
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub balancer_tag: String,
    #[serde(skip_serializing_if = "skip_empty_vec")]
    pub domain: Vec<String>,
    #[serde(skip_serializing_if = "skip_empty_vec")]
    pub ip: Vec<String>,
    /// PortList string
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub port: String,
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub source_port: String,
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub local_port: String,
    /// tcp | udp | unix
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub network: String,
    #[serde(skip_serializing_if = "skip_empty_vec")]
    pub source: Vec<String>,
    #[serde(skip_serializing_if = "skip_empty_vec", rename = "localIP")]
    pub local_ip: Vec<String>,
    #[serde(skip_serializing_if = "skip_empty_vec")]
    pub user: Vec<String>,
    #[serde(skip_serializing_if = "skip_empty_vec")]
    pub inbound_tag: Vec<String>,
    /// sniffer names: http, tls, quic, bittorrent, fakedns
    #[serde(skip_serializing_if = "skip_empty_vec")]
    pub protocol: Vec<String>,
    /// map key → regexp matched against HTTP sniff headers
    #[serde(skip_serializing_if = "skip_empty_map")]
    pub attrs: Map<String, Value>,
    /// PortList vs VLESS routing marker
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub vless_route: String,
    /// per-app routing: process name/path; xray/ = self path, self/ = self PID
    #[serde(skip_serializing_if = "skip_empty_vec")]
    pub process: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webhook: Option<Webhook>,
    /// OS names matched case-insensitively against the OS the core itself
    /// runs on (`infra/conf/router.go` `localOS`, `app/router/condition.go`
    /// `NewLocalOSMatcher`), so one imported rule set can select a platform.
    #[serde(skip_serializing_if = "skip_empty_vec", rename = "localOS")]
    pub local_os: Vec<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl Default for Rule {
    fn default() -> Self {
        Self {
            rule_tag: uuid::Uuid::new_v4().to_string(),
            outbound_tag: String::new(),
            balancer_tag: String::new(),
            domain: Vec::new(),
            ip: Vec::new(),
            port: String::new(),
            source_port: String::new(),
            local_port: String::new(),
            network: String::new(),
            source: Vec::new(),
            local_ip: Vec::new(),
            user: Vec::new(),
            inbound_tag: Vec::new(),
            protocol: Vec::new(),
            attrs: Map::new(),
            vless_route: String::new(),
            process: Vec::new(),
            webhook: None,
            local_os: Vec::new(),
            extra: Map::new(),
        }
    }
}

impl Rule {
    /// New GUI rules always have a valid built-in target.
    pub fn new() -> Self {
        Self {
            outbound_tag: DIRECT_OUTBOUND_TAG.into(),
            ..Self::default()
        }
    }

    /// The target verdict for the rule editor, or `None` when the rule is
    /// well formed. The message renders in the active language at the display
    /// boundary.
    pub fn target_error(&self) -> Option<Diag> {
        match (self.outbound_tag.is_empty(), self.balancer_tag.is_empty()) {
            (true, true) => Some(Diag::new(Key::IntegrityRuleTargetRequired)),
            (false, false) => Some(Diag::new(Key::IntegrityRuleTargetExclusive)),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Webhook {
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deduplication: Option<u32>,
    #[serde(skip_serializing_if = "skip_empty_map")]
    pub headers: Map<String, Value>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Balancing rule (router.go:22-25 + router_strategy.go).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Balancer {
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub tag: String,
    #[serde(skip_serializing_if = "skip_empty_vec")]
    pub selector: Vec<String>,
    pub strategy: StrategyCfg,
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub fallback_tag: String,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl Balancer {
    pub fn new(tag: String, selector: String) -> Self {
        Self {
            tag,
            selector: vec![selector],
            strategy: StrategyCfg {
                r#type: "random".into(),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    /// True when this balancer reads live outbound health: a `leastping` /
    /// `leastload` strategy, or a `fallbackTag` (roundrobin consults the
    /// observatory before it falls back).
    pub fn needs_live_health(&self) -> bool {
        matches!(self.strategy.r#type.as_str(), "leastping" | "leastload")
            || !self.fallback_tag.is_empty()
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct StrategyCfg {
    /// random | roundrobin | leastping | leastload
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub r#type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub settings: Option<LeastLoadSettings>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// leastload settings (router_strategy.go:33-44).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct LeastLoadSettings {
    #[serde(skip_serializing_if = "skip_empty_vec")]
    pub costs: Vec<StrategyCost>,
    #[serde(skip_serializing_if = "skip_empty_vec")]
    pub baselines: Vec<DurationMs>,
    /// node count; ≤0 = speed-priority
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "maxRTT")]
    pub max_rtt: Option<DurationMs>,
    /// 0..=1
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tolerance: Option<f64>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// router.StrategyWeight proto: {regexp bool, match string, value float}.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct StrategyCost {
    #[serde(skip_serializing_if = "skip_false")]
    pub regexp: bool,
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub r#match: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<f64>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Observatory (observatory.go), including the exact subject selector sent to
/// Xray. An empty selector means no outbounds are observed.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ObservatoryCfg {
    #[serde(skip_serializing_if = "skip_false")]
    pub enabled: bool,
    pub subject_selector: Vec<String>,
    #[serde(skip_serializing_if = "skip_empty_str", rename = "probeURL")]
    pub probe_url: String,
    #[serde(skip_serializing_if = "skip_duration_zero")]
    pub probe_interval: DurationMs,
    #[serde(skip_serializing_if = "skip_false")]
    pub enable_concurrency: bool,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl Default for ObservatoryCfg {
    fn default() -> Self {
        Self {
            enabled: false,
            subject_selector: vec!["srv-".into()],
            probe_url: "https://www.google.com/generate_204".into(),
            probe_interval: DurationMs::secs(10),
            enable_concurrency: false,
            extra: Map::new(),
        }
    }
}

impl ObservatoryCfg {
    /// Wire form of the top-level `observatory` object. `enabled` is
    /// GUI-only; `forced_subjects` (dependency-forced observatory only)
    /// replaces subjectSelector with the given outbound tags.
    pub fn to_wire(&self, forced_subjects: Option<&[String]>) -> Value {
        let mut v = serde_json::to_value(self).expect(
            "model serialization is infallible: ObservatoryCfg fields are u64/bool/string \
             values and string-keyed Value maps only",
        );
        let o = v.as_object_mut().unwrap();
        o.remove("enabled"); // GUI-only toggle, not an Xray key
        if let Some(subjects) = forced_subjects {
            o.insert(
                "subjectSelector".into(),
                Value::Array(
                    subjects
                        .iter()
                        .map(|tag| Value::String(tag.clone()))
                        .collect(),
                ),
            );
        }
        v
    }
}

/// burstObservatory — pingConfig is required when enabled.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct BurstObservatoryCfg {
    #[serde(skip_serializing_if = "skip_false")]
    pub enabled: bool,
    pub subject_selector: Vec<String>,
    pub ping_config: PingConfig,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl Default for BurstObservatoryCfg {
    fn default() -> Self {
        Self {
            enabled: false,
            subject_selector: vec!["srv-".into()],
            ping_config: PingConfig::default(),
            extra: Map::new(),
        }
    }
}

impl BurstObservatoryCfg {
    /// Wire form of the top-level `burstObservatory` object. `enabled` is
    /// GUI-only; pingConfig is always emitted by serde (it is required when
    /// burstObservatory is enabled).
    pub fn to_wire(&self) -> Value {
        let mut v = serde_json::to_value(self).expect(
            "model serialization is infallible: BurstObservatoryCfg/PingConfig fields are \
             u64/bool/string/i32 values and string-keyed Value maps only",
        );
        if let Some(o) = v.as_object_mut() {
            o.remove("enabled"); // GUI-only toggle, not an Xray key
        }
        v
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct PingConfig {
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub destination: String,
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub connectivity: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interval: Option<DurationMs>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sampling: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<DurationMs>,
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub http_method: String,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl Default for PingConfig {
    fn default() -> Self {
        Self {
            destination: "https://connectivitycheck.gstatic.com/generate_204".into(),
            connectivity: String::new(),
            interval: None,
            sampling: None,
            timeout: None,
            http_method: "HEAD".into(),
            extra: Map::new(),
        }
    }
}

/// Complete GUI-side contract for Xray's official `RoutingContext` fields
/// that correspond to predicates editable in Broccoli routing rules.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteTestRequest {
    pub target_domain: String,
    pub target_ips: Vec<String>,
    pub target_port: u32,
    pub source_ips: Vec<String>,
    pub source_port: u32,
    pub local_ips: Vec<String>,
    pub local_port: u32,
    pub inbound_tag: String,
    pub user: String,
    pub protocol: String,
    pub network: String,
    pub vless_route: u32,
    pub attributes: BTreeMap<String, String>,
}

impl Default for RouteTestRequest {
    fn default() -> Self {
        Self {
            target_domain: String::new(),
            target_ips: Vec::new(),
            target_port: 443,
            source_ips: Vec::new(),
            source_port: 0,
            local_ips: Vec::new(),
            local_port: 0,
            inbound_tag: "in-socks".into(),
            user: String::new(),
            protocol: String::new(),
            network: "tcp".into(),
            vless_route: 0,
            attributes: BTreeMap::new(),
        }
    }
}

impl RouteTestRequest {
    /// Check the GUI-side test request and report the first problem as a
    /// keyed message, so the display boundary renders it in the active
    /// language.
    pub fn validate(&self) -> Result<(), Diag> {
        if self.target_domain.trim().is_empty() && self.target_ips.is_empty() {
            return Err(Diag::new(Key::IntegrityRouteTargetRequired));
        }
        if !(1..=u16::MAX as u32).contains(&self.target_port) {
            return Err(Diag::new(Key::IntegrityRouteTargetPort));
        }
        for (label, port) in [
            ("source port", self.source_port),
            ("local port", self.local_port),
            ("VLESS route", self.vless_route),
        ] {
            if port > u16::MAX as u32 {
                return Err(Diag::new(Key::IntegrityRoutePort).arg(label));
            }
        }
        for (kind, ips) in [
            ("target", self.target_ips.as_slice()),
            ("source", self.source_ips.as_slice()),
            ("local", self.local_ips.as_slice()),
        ] {
            for ip in ips {
                let candidate = ip.trim();
                candidate.parse::<std::net::IpAddr>().map_err(|_| {
                    Diag::new(Key::IntegrityRouteIp)
                        .arg(kind)
                        .arg(format!("{candidate:?}"))
                })?;
            }
        }
        if !matches!(self.network.as_str(), "" | "tcp" | "udp" | "unix") {
            return Err(Diag::new(Key::IntegrityRouteNetwork).arg(format!("{:?}", self.network)));
        }
        if let Some(key) = self.attributes.keys().find(|key| key.trim().is_empty()) {
            return Err(Diag::new(Key::IntegrityRouteAttributeKey).arg(format!("{key:?}")));
        }
        Ok(())
    }
}

/// A balancer edit the routing model refuses. `Display` renders English for
/// logs and tests; the display boundary renders the active language with
/// [`RoutingIntegrityError::text`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RoutingIntegrityError {
    /// The balancer list holds no such index.
    MissingBalancer(usize),
    /// The requested tag is blank.
    EmptyBalancerTag,
    /// Another balancer already carries the tag.
    DuplicateBalancerTag(String),
    /// Routing rules still reference the tag, so the balancer cannot go.
    BalancerReferenced { tag: String, rules: usize },
}

impl RoutingIntegrityError {
    /// Render the failure in `language`.
    pub fn text(&self, language: Language) -> String {
        match self {
            Self::MissingBalancer(index) => {
                t_fmt(language, Key::IntegrityBalancerMissing, &[index])
            }
            Self::EmptyBalancerTag => t(language, Key::IntegrityBalancerTagEmpty).to_string(),
            Self::DuplicateBalancerTag(tag) => t_fmt(
                language,
                Key::IntegrityBalancerTagDuplicate,
                &[&format!("{tag:?}")],
            ),
            Self::BalancerReferenced { tag, rules } => t_fmt(
                language,
                Key::IntegrityBalancerReferenced,
                &[&format!("{tag:?}"), rules],
            ),
        }
    }
}

impl fmt::Display for RoutingIntegrityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text(Language::En))
    }
}

impl Error for RoutingIntegrityError {}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct RoutingCfg {
    #[serde(skip_serializing_if = "skip_empty_vec")]
    pub rules: Vec<Rule>,
    #[serde(skip_serializing_if = "skip_empty_vec")]
    pub balancers: Vec<Balancer>,
    /// AsIs | IpIfNonMatch | IpOnDemand
    #[serde(skip_serializing_if = "RoutingCfg::skip_default_strategy")]
    pub domain_strategy: String,
    pub observatory: ObservatoryCfg,
    pub burst_observatory: BurstObservatoryCfg,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl RoutingCfg {
    fn skip_default_strategy(s: &str) -> bool {
        s == "AsIs"
    }

    /// True when the configuration carries a balancer that reads live
    /// outbound health.
    pub fn needs_live_health(&self) -> bool {
        self.balancers.iter().any(Balancer::needs_live_health)
    }

    /// True when the generated configuration emits the ordinary observatory:
    /// the user enabled it, or a balancer reads live health data and therefore
    /// needs an engine that observes every profile (`leastping` and
    /// `leastload` return no target at all when no observed outbound is
    /// alive). The UI keeps the burst toggle out of that case.
    pub fn observatory_emitted(&self) -> bool {
        self.observatory.enabled || self.needs_live_health()
    }

    /// True when the generated configuration emits the burst observatory.
    pub fn burst_observatory_emitted(&self) -> bool {
        self.burst_observatory.enabled
    }

    /// True when the generated configuration carries an outbound-health
    /// extension. A core serves one `extension.Observatory` — the first app
    /// registered wins, and `infra/conf/xray.go` appends `observatory` before
    /// `burstObservatory` — so the two emissions above are also the predicate
    /// for the GUI's status read.
    pub fn emits_health_extension(&self) -> bool {
        self.observatory_emitted() || self.burst_observatory_emitted()
    }

    /// Enable or disable the ordinary observatory. Enabling it clears the
    /// burst observatory: the core serves one health engine, and the ordinary
    /// one is registered first.
    pub fn set_observatory_enabled(&mut self, enabled: bool) {
        self.observatory.enabled = enabled;
        if enabled {
            self.burst_observatory.enabled = false;
        }
    }

    /// Enable or disable the burst observatory. Enabling it clears the
    /// ordinary observatory — see [`Self::set_observatory_enabled`].
    pub fn set_burst_observatory_enabled(&mut self, enabled: bool) {
        self.burst_observatory.enabled = enabled;
        if enabled {
            self.observatory.enabled = false;
        }
    }

    pub fn balancer_reference_count(&self, tag: &str) -> usize {
        self.rules
            .iter()
            .filter(|rule| rule.balancer_tag == tag)
            .count()
    }

    pub fn inbound_reference_count(&self, tag: &str) -> usize {
        self.rules
            .iter()
            .filter(|rule| rule.inbound_tag.iter().any(|candidate| candidate == tag))
            .count()
    }

    /// Rename a balancer and every rule reference as one validated mutation.
    pub fn rename_balancer(
        &mut self,
        index: usize,
        requested_tag: &str,
    ) -> Result<usize, RoutingIntegrityError> {
        let new_tag = requested_tag.trim();
        if new_tag.is_empty() {
            return Err(RoutingIntegrityError::EmptyBalancerTag);
        }
        let Some(old_tag) = self
            .balancers
            .get(index)
            .map(|balancer| balancer.tag.clone())
        else {
            return Err(RoutingIntegrityError::MissingBalancer(index));
        };
        if self
            .balancers
            .iter()
            .enumerate()
            .any(|(other, balancer)| other != index && balancer.tag == new_tag)
        {
            return Err(RoutingIntegrityError::DuplicateBalancerTag(
                new_tag.to_string(),
            ));
        }
        if old_tag == new_tag {
            return Ok(0);
        }

        let mut rewritten = 0;
        for rule in &mut self.rules {
            if rule.balancer_tag == old_tag {
                rule.balancer_tag = new_tag.to_string();
                rewritten += 1;
            }
        }
        self.balancers[index].tag = new_tag.to_string();
        Ok(rewritten)
    }

    /// Delete only an unreferenced balancer; callers must never orphan rules.
    pub fn remove_balancer(&mut self, index: usize) -> Result<Balancer, RoutingIntegrityError> {
        let Some(tag) = self
            .balancers
            .get(index)
            .map(|balancer| balancer.tag.clone())
        else {
            return Err(RoutingIntegrityError::MissingBalancer(index));
        };
        let rules = self.balancer_reference_count(&tag);
        if rules != 0 {
            return Err(RoutingIntegrityError::BalancerReferenced { tag, rules });
        }
        Ok(self.balancers.remove(index))
    }
}

impl Default for RoutingCfg {
    fn default() -> Self {
        Self {
            rules: Vec::new(),
            balancers: Vec::new(),
            domain_strategy: "AsIs".into(),
            observatory: ObservatoryCfg::default(),
            burst_observatory: BurstObservatoryCfg::default(),
            extra: Map::new(),
        }
    }
}

#[cfg(test)]
mod integrity_tests {
    use super::{Balancer, RouteTestRequest, RoutingCfg, RoutingIntegrityError, Rule, StrategyCfg};

    #[test]
    fn balancer_rename_rewrites_all_rule_references_atomically() {
        let mut cfg = RoutingCfg::default();
        cfg.balancers.push(Balancer {
            tag: "old".into(),
            ..Default::default()
        });
        cfg.rules.push(Rule {
            balancer_tag: "old".into(),
            ..Default::default()
        });

        assert_eq!(cfg.rename_balancer(0, "new"), Ok(1));
        assert_eq!(cfg.balancers[0].tag, "new");
        assert_eq!(cfg.rules[0].balancer_tag, "new");
    }

    #[test]
    fn referenced_balancer_delete_is_blocked() {
        let mut cfg = RoutingCfg::default();
        cfg.balancers.push(Balancer {
            tag: "used".into(),
            ..Default::default()
        });
        cfg.rules.push(Rule {
            balancer_tag: "used".into(),
            ..Default::default()
        });

        assert!(matches!(
            cfg.remove_balancer(0),
            Err(RoutingIntegrityError::BalancerReferenced { rules: 1, .. })
        ));
        assert_eq!(cfg.balancers.len(), 1);
        assert_eq!(cfg.rules[0].balancer_tag, "used");
    }

    #[test]
    fn complete_route_context_validates_every_ip_dimension() {
        let mut request = RouteTestRequest {
            target_domain: "example.com".into(),
            target_ips: vec!["203.0.113.10".into(), "2001:db8::10".into()],
            source_ips: vec!["192.0.2.1".into()],
            source_port: 12345,
            local_ips: vec!["127.0.0.1".into(), "::1".into()],
            local_port: 1080,
            inbound_tag: "in-doko-stable".into(),
            user: "broccoli@example.com".into(),
            protocol: "tls".into(),
            network: "tcp".into(),
            vless_route: 65535,
            ..Default::default()
        };
        request
            .attributes
            .insert("host".into(), "example.com".into());
        assert!(request.validate().is_ok());

        request.local_ips.push("not-an-ip".into());
        assert!(request.validate().is_err());
    }

    #[test]
    fn route_context_rejects_every_port_overflow_and_zero_target() {
        let valid = RouteTestRequest {
            target_domain: "example.com".into(),
            ..Default::default()
        };
        for request in [
            RouteTestRequest {
                target_port: 0,
                ..valid.clone()
            },
            RouteTestRequest {
                source_port: u16::MAX as u32 + 1,
                ..valid.clone()
            },
            RouteTestRequest {
                local_port: u16::MAX as u32 + 1,
                ..valid.clone()
            },
            RouteTestRequest {
                vless_route: u16::MAX as u32 + 1,
                ..valid.clone()
            },
        ] {
            assert!(request.validate().is_err());
        }
    }
    /// The health-engine predicates: the user toggle emits the ordinary
    /// observatory, a balancer that reads live data emits it only while the
    /// burst observatory does not supply an engine, and a plain balancer or
    /// the untouched seed emits nothing.
    #[test]
    fn health_engine_predicates_cover_toggle_dependency_and_burst() {
        let mut cfg = RoutingCfg::default();
        assert!(!cfg.needs_live_health());
        assert!(!cfg.emits_health_extension(), "the seed emits no engine");

        cfg.observatory.enabled = true;
        assert!(cfg.observatory_emitted(), "the user toggle must emit it");
        assert!(cfg.emits_health_extension());
        cfg.observatory.enabled = false;

        cfg.burst_observatory.enabled = true;
        assert!(cfg.burst_observatory_emitted());
        assert!(cfg.emits_health_extension(), "burst must emit it");
        assert!(
            !cfg.observatory_emitted(),
            "burst alone leaves the ordinary observatory out"
        );
        cfg.burst_observatory.enabled = false;

        for (strategy, fallback) in [
            ("leastping", ""),
            ("leastload", ""),
            ("roundrobin", "direct"),
            ("random", "direct"),
        ] {
            cfg.balancers = vec![Balancer {
                tag: "health".into(),
                selector: vec!["srv-".into()],
                strategy: StrategyCfg {
                    r#type: strategy.into(),
                    ..Default::default()
                },
                fallback_tag: fallback.into(),
                ..Default::default()
            }];
            assert!(
                cfg.needs_live_health(),
                "{strategy} with fallback {fallback:?} reads live health data"
            );
            assert!(
                cfg.observatory_emitted(),
                "{strategy} forces the ordinary observatory on its own"
            );
            assert!(cfg.emits_health_extension());
        }

        // A balancer that reads live health data forces the ordinary
        // observatory, which observes every profile; the burst observatory
        // cannot replace it (the burst toggle is gated while such a balancer
        // exists), and a hand-edited file that enables both gets the
        // observatory, registered first.
        cfg.burst_observatory.enabled = true;
        assert!(cfg.needs_live_health());
        assert!(cfg.observatory_emitted());
        assert!(cfg.emits_health_extension());
        cfg.burst_observatory.enabled = false;

        cfg.balancers = vec![Balancer::new("plain".into(), "srv-".into())];
        assert!(!cfg.needs_live_health());
        assert!(!cfg.emits_health_extension());
    }

    /// Enabling one engine clears the other: a core serves one
    /// `extension.Observatory`.
    #[test]
    fn enabling_one_health_engine_clears_the_other() {
        let mut cfg = RoutingCfg::default();
        cfg.set_burst_observatory_enabled(true);
        assert!(cfg.burst_observatory.enabled);

        cfg.set_observatory_enabled(true);
        assert!(cfg.observatory.enabled);
        assert!(!cfg.burst_observatory.enabled);

        cfg.set_burst_observatory_enabled(true);
        assert!(cfg.burst_observatory.enabled);
        assert!(!cfg.observatory.enabled);

        // Disabling one leaves the other untouched.
        cfg.set_burst_observatory_enabled(false);
        assert!(!cfg.burst_observatory.enabled);
        assert!(!cfg.observatory.enabled);
    }

    #[test]
    fn gui_constructors_create_valid_targets_and_balancers() {
        let rule = Rule::new();
        assert_eq!(rule.outbound_tag, "direct");
        assert!(rule.target_error().is_none());

        let balancer = Balancer::new("balancer".into(), "srv-".into());
        assert_eq!(balancer.tag, "balancer");
        assert_eq!(balancer.selector, ["srv-"]);
        assert_eq!(balancer.strategy.r#type, "random");
    }
}
#[cfg(test)]
mod error_text_tests {
    use super::{Key, Language, RouteTestRequest, RoutingIntegrityError, Rule, t_fmt};

    #[test]
    fn routing_integrity_error_text_renders_through_the_locale_table() {
        let error = RoutingIntegrityError::BalancerReferenced {
            tag: "used".into(),
            rules: 2,
        };
        assert_eq!(
            error.text(Language::En),
            t_fmt(
                Language::En,
                Key::IntegrityBalancerReferenced,
                &[&"\"used\"", &2]
            )
        );
        assert_eq!(error.to_string(), error.text(Language::En));
        assert_eq!(
            RoutingIntegrityError::EmptyBalancerTag.text(Language::En),
            t_fmt(Language::En, Key::IntegrityBalancerTagEmpty, &[])
        );
    }

    #[test]
    fn rule_target_verdict_and_route_test_problems_are_keyed() {
        let rule = Rule::default();
        assert_eq!(
            rule.target_error().map(|message| message.key()),
            Some(Key::IntegrityRuleTargetRequired)
        );
        let rule = Rule {
            outbound_tag: "direct".into(),
            balancer_tag: "health".into(),
            ..Default::default()
        };
        assert_eq!(
            rule.target_error().map(|message| message.key()),
            Some(Key::IntegrityRuleTargetExclusive)
        );
        assert!(Rule::new().target_error().is_none());

        let empty = RouteTestRequest {
            target_domain: String::new(),
            ..Default::default()
        };
        let problem = empty.validate().expect_err("an empty target is refused");
        assert_eq!(problem.key(), Key::IntegrityRouteTargetRequired);

        let bad_ip = RouteTestRequest {
            target_ips: vec!["nope".into()],
            ..Default::default()
        };
        let problem = bad_ip.validate().expect_err("a bad IP is refused");
        assert_eq!(problem.key(), Key::IntegrityRouteIp);
        assert_eq!(
            problem.text(Language::En),
            t_fmt(
                Language::En,
                Key::IntegrityRouteIp,
                &[&"target", &"\"nope\""]
            )
        );
    }
}

/// The `localOS` matcher list: modelled under its exact upstream spelling
/// (`infra/conf/router.go` `json:"localOS"`), so an imported cross-platform
/// rule set loads, emits, and re-loads unchanged instead of leaning on the
/// unknown-key passthrough.
#[cfg(test)]
mod local_os_tests {
    use super::Rule;
    use serde_json::json;

    #[test]
    fn local_os_loads_emits_and_reloads_under_its_upstream_spelling() {
        let raw = json!({
            "ruleTag": "cross-platform",
            "outboundTag": "direct",
            "localOS": ["windows", "Darwin"],
            "futureRuleKey": {"kept": true},
        });
        let rule: Rule =
            serde_json::from_value(raw.clone()).expect("a rule carrying localOS loads");
        assert_eq!(rule.local_os, ["windows", "Darwin"]);

        let emitted = serde_json::to_value(&rule).expect("a rule carrying localOS serializes");
        assert_eq!(emitted, raw, "the field and future keys must round-trip");

        let reloaded: Rule = serde_json::from_value(emitted).expect("the emitted rule loads again");
        assert_eq!(reloaded.local_os, rule.local_os);
    }

    #[test]
    fn an_empty_local_os_list_stays_out_of_the_emitted_rule() {
        let rule = Rule {
            outbound_tag: "direct".into(),
            ..Rule::default()
        };
        let emitted = serde_json::to_value(&rule).expect("serialize");
        assert!(emitted.get("localOS").is_none(), "{emitted}");
    }
}
