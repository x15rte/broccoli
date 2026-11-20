//! The condition grammar of one routing rule: every stored value the pinned
//! core refuses when it loads the rule.
//!
//! A rule's conditions reach the core as `infra/conf.RawFieldRule`
//! (`infra/conf/router.go:139-162`). Two value families have a grammar whose
//! failures refuse the whole document, and they are the families this module
//! owns:
//!
//! - `port`, `sourcePort`, `localPort` and `vlessRoute` are one `PortList`
//!   type (`infra/conf/router.go:145-156`, `:207-249`), parsed by
//!   `PortList.UnmarshalJSON` (`infra/conf/common.go:247-283`): comma-separated
//!   entries, each either a bare port read as a JSON `uint32` or a `from-to`
//!   pair whose endpoints `strconv.ParseUint` reads (`common/net/port.go:20-38`,
//!   so a range endpoint may keep leading zeros while a bare port may not).
//!   Every endpoint stays at most 65535. A blank entry is skipped, so `"80,"`
//!   loads; the empty string is the absent condition. The order of a range is
//!   deliberately not checked: `PortRange.UnmarshalJSON` (`common.go:194-217`)
//!   is the only reader that refuses `from > to`, and the rule path never uses
//!   it — the pinned core (26.11.9) loads `"1-0"` and `"5-3, 80"` unchanged,
//!   verified with `xray run -test`.
//! - `ip`, `source` (the `sourceIP` alias, `router.go:222-227`) and `localIP`
//!   are read by `geodata.ParseIPRules` (`common/geodata/rule_parser.go:15-40`),
//!   whose refused entry fails the document with "illegal ip rule".
//!   [`ip_rule_valid`] is that grammar, shared with the `filter` mask gate, so
//!   this module only adds the per-field finding on top of it.
//!
//! Every other condition accepts whatever the model stores, which is why this
//! module has no arm for them:
//!
//! - `network` is a `NetworkList` (`infra/conf/common.go:92-120`) split on
//!   commas, and `Network.Build` (`common.go:74-90`) maps every other spelling
//!   to `Network_Unknown`; the matcher then matches nothing and the document
//!   still loads. The pinned core accepts `network: "foo"` and
//!   `network: "tcp, udp"` under `run -test`.
//! - `user` is a plain string list (`infra/conf/router.go:252-256`):
//!   `NewUserMatcher` (`app/router/condition.go:163-181`) drops blank entries
//!   and every `regexp:` entry that does not compile, so a malformed list
//!   loads and only narrows the match.
//!
//! A refused value is a blocking finding: the core cannot build the rule, so
//! the configuration never loads (see [`ValidationCode`]'s Error tier).

use super::Rule;
use crate::diag::Diag;
use crate::excerpt::excerpt;
use crate::i18n::Key;
use crate::model::validation::{ValidationCode, ip_rule_valid};

/// One routing-rule condition field whose value has a wire grammar.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ConditionField {
    Ip,
    Source,
    LocalIp,
    Port,
    SourcePort,
    LocalPort,
    VlessRoute,
}

impl ConditionField {
    /// The field's editor-row label, which the blocking finding names beside
    /// the refused value.
    pub fn label(self) -> Key {
        match self {
            Self::Ip => Key::Ips,
            Self::Source => Key::SourceIps,
            Self::LocalIp => Key::LocalIps,
            Self::Port => Key::Port,
            Self::SourcePort => Key::SourcePort,
            Self::LocalPort => Key::LocalPort,
            Self::VlessRoute => Key::VlessRoute,
        }
    }
}

/// One condition value the pinned core refuses: the field that holds it, the
/// sentence the rule editor renders under that field, and the blocking model
/// rule the apply/generation gate reports.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConditionFinding {
    pub field: ConditionField,
    pub diag: Diag,
    pub code: ValidationCode,
}

/// Every condition value of `rule` the pinned core refuses, in editor-row
/// order (the three IP lists, then the four PortList fields). `number` is the
/// rule's 1-based position in the routing list, which every settings-scope
/// finding about a rule names; a field with several refused entries reports
/// its first one, and the sentence states the grammar once per field.
pub fn rule_condition_findings(rule: &Rule, number: usize) -> Vec<ConditionFinding> {
    let mut findings = Vec::new();
    for (field, entries) in [
        (ConditionField::Ip, &rule.ip),
        (ConditionField::Source, &rule.source),
        (ConditionField::LocalIp, &rule.local_ip),
    ] {
        if let Some(entry) = first_refused_ip_entry(entries) {
            findings.push(ConditionFinding {
                field,
                diag: Diag::new(Key::RoutingIpListInvalid),
                code: ValidationCode::RoutingRuleIpRuleInvalid(number, field, excerpt(entry)),
            });
        }
    }
    for (field, value) in [
        (ConditionField::Port, &rule.port),
        (ConditionField::SourcePort, &rule.source_port),
        (ConditionField::LocalPort, &rule.local_port),
        (ConditionField::VlessRoute, &rule.vless_route),
    ] {
        if let Some(entry) = first_refused_port_entry(value) {
            findings.push(ConditionFinding {
                field,
                diag: Diag::new(Key::RoutingPortListInvalid),
                code: ValidationCode::RoutingRulePortListInvalid(number, field, excerpt(entry)),
            });
        }
    }
    findings
}

/// The inline sentence for a PortList the core refuses, or `None` when it
/// loads. The rule editor's commit gate for a draft buffer and the model's
/// finding both read this one predicate, so a half-typed list never reaches
/// the model and the red text cannot name a different grammar.
pub fn port_list_error(value: &str) -> Option<Diag> {
    first_refused_port_entry(value).map(|_| Diag::new(Key::RoutingPortListInvalid))
}

/// The first PortList entry `PortList.UnmarshalJSON` refuses, or `None`.
fn first_refused_port_entry(value: &str) -> Option<&str> {
    value
        .split(',')
        .map(str::trim)
        .find(|entry| !entry.is_empty() && !port_entry_valid(entry))
}

/// One PortList entry as `PortList.UnmarshalJSON` reads it. A `env:` entry
/// resolves from the core's environment at load, so its value is not part of
/// the document and this grammar does not guess it. Every other entry is a
/// range when it holds a dash, and a bare port otherwise.
fn port_entry_valid(entry: &str) -> bool {
    if entry.starts_with("env:") {
        return true;
    }
    match entry.split_once('-') {
        Some((from, to)) => port_range_endpoint_valid(from) && port_range_endpoint_valid(to),
        None => bare_port_valid(entry),
    }
}

/// A range endpoint as `strconv.ParseUint(s, 10, 32)` plus `PortFromInt` read
/// it (`common/net/port.go:20-38`): decimal digits only (no sign, no
/// underscore in base 10), then at most 65535. Leading zeros stay legal here,
/// unlike in the bare-port form.
fn port_range_endpoint_valid(endpoint: &str) -> bool {
    !endpoint.is_empty()
        && endpoint.bytes().all(|byte| byte.is_ascii_digit())
        && endpoint
            .parse::<u64>()
            .is_ok_and(|port| port <= u16::MAX.into())
}

/// A bare entry as `json.Unmarshal` into `uint32` plus `PortFromInt` read it:
/// a JSON integer literal (no sign, fraction, exponent, or leading zero) of at
/// most 65535. That is why `"0053"` fails while `"0053-0060"` loads.
fn bare_port_valid(entry: &str) -> bool {
    if entry == "0" {
        return true;
    }
    !entry.is_empty()
        && !entry.starts_with('0')
        && entry.bytes().all(|byte| byte.is_ascii_digit())
        && entry
            .parse::<u64>()
            .is_ok_and(|port| port <= u16::MAX.into())
}

/// The first entry `geodata.ParseIPRules` refuses, or `None`.
fn first_refused_ip_entry(entries: &[String]) -> Option<&str> {
    entries
        .iter()
        .map(String::as_str)
        .find(|entry| !ip_rule_valid(entry))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The PortList table, pinned to the pinned core's own parser
    /// (`infra/conf/common.go:247-283`) and confirmed with `xray run -test`
    /// on 26.11.9. The accepted column includes the shapes a stricter reading
    /// would refuse — a reversed range, blank entries, a leading-zero range
    /// endpoint, a trailing comma — because the core loads them.
    #[test]
    fn port_list_grammar_matches_the_wire_parser() {
        for accepted in [
            "",
            "80",
            "0",
            "65535",
            "0-65535",
            "53,443-448",
            "80,443,1000-2000",
            "80, 443",
            "1000-2000,53",
            "80-80",
            "1-0",
            "5-3, 80",
            "80,",
            ",80",
            "53,,443",
            "0053-0060",
            "env:XRAY_ROUTING_PORT",
        ] {
            assert!(
                port_list_error(accepted).is_none(),
                "{accepted:?} must load on the pinned core"
            );
        }
        for refused in [
            "abc",
            "70,abc",
            "99999",
            "65536",
            "70000",
            "0053",
            "000",
            "1-",
            "-1",
            "80--90",
            "1.5",
            "0x50",
            "80,1-",
            "80--",
            "53-443-448",
            "+80",
            "1-env:XRAY_ROUTING_PORT",
        ] {
            assert!(
                port_list_error(refused).is_some(),
                "{refused:?} must be refused"
            );
        }
    }

    /// The IP-rule table: `geodata.ParseIPRules`' grammar, the same one the
    /// `filter` mask gate reads.
    #[test]
    fn ip_rule_grammar_matches_the_wire_parser() {
        for accepted in [
            "1.2.3.4",
            " 1.2.3.4 ",
            "[::1]",
            "::1",
            "2001:db8::68",
            "10.0.0.0/8",
            "2001:db8::/32",
            "1.2.3.0/24",
            "0.0.0.0/0",
            "::/0",
            "1.2.3.4/32",
            "1.2.3.4/",
            "::1/128",
            "geoip:cn",
            "geoip:private",
            "geoip:!private",
            "ext:geoip.dat:cn",
            "ext-ip:geoip.dat:cn",
            "!1.2.3.4",
            "!!geoip:cn",
        ] {
            assert!(ip_rule_valid(accepted), "{accepted:?} must be accepted");
        }
        for refused in [
            "abc",
            "example.com",
            "1.2.3.4/33",
            "::1/129",
            "1.2.3.4/abc",
            "1.2.3.4/ 24",
            "1.2.3.4/24/8",
            "/24",
            "geoip:",
            "ext:",
            "ext:geoip.dat",
            "ext::cn",
            "ext:geoip.dat:",
            "999.1.2.3",
            "10.0.0.0/-1",
            "10.0.0.0/8 ",
        ] {
            assert!(!ip_rule_valid(refused), "{refused:?} must be refused");
        }
    }

    /// The fields report in editor-row order, each carrying the first refused
    /// entry, and the rules name the rule's position.
    #[test]
    fn findings_are_keyed_by_field_and_name_the_rule() {
        let rule = Rule {
            ip: vec!["1.2.3.4".into(), "example.com".into()],
            source: vec!["not-an-ip".into()],
            port: "80".into(),
            source_port: "70000".into(),
            vless_route: "1-".into(),
            ..Rule::default()
        };
        let findings = rule_condition_findings(&rule, 3);
        let keyed: Vec<(ConditionField, ValidationCode)> = findings
            .iter()
            .map(|finding| (finding.field, finding.code.clone()))
            .collect();
        assert_eq!(
            keyed,
            vec![
                (
                    ConditionField::Ip,
                    ValidationCode::RoutingRuleIpRuleInvalid(
                        3,
                        ConditionField::Ip,
                        "example.com".into()
                    ),
                ),
                (
                    ConditionField::Source,
                    ValidationCode::RoutingRuleIpRuleInvalid(
                        3,
                        ConditionField::Source,
                        "not-an-ip".into()
                    ),
                ),
                (
                    ConditionField::SourcePort,
                    ValidationCode::RoutingRulePortListInvalid(
                        3,
                        ConditionField::SourcePort,
                        "70000".into()
                    ),
                ),
                (
                    ConditionField::VlessRoute,
                    ValidationCode::RoutingRulePortListInvalid(
                        3,
                        ConditionField::VlessRoute,
                        "1-".into()
                    ),
                ),
            ],
            "the valid port and the valid IP entry report nothing"
        );
        assert!(
            findings
                .iter()
                .all(|finding| finding.diag.key() == Key::RoutingIpListInvalid
                    || finding.diag.key() == Key::RoutingPortListInvalid),
            "each finding renders the sentence of its own grammar"
        );
    }

    /// `network` and `user` carry no refusal on the pinned core: an unknown
    /// network becomes `Network_Unknown` and matches nothing, and an invalid
    /// `regexp:` user entry is dropped from the matcher. The document loads,
    /// so the model must not block it.
    #[test]
    fn network_and_user_values_are_accepted_by_the_core() {
        let rule = Rule {
            network: "foo, udp".into(),
            user: vec![String::new(), "regexp:[".into(), "alice@example.com".into()],
            ..Rule::default()
        };
        assert!(
            rule_condition_findings(&rule, 1).is_empty(),
            "the core loads both lists; only the matchers narrow"
        );
    }
}
