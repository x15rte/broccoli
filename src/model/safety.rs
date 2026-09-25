//! Model-layer safety assessment — the seam every unsafe-configuration
//! warning surface consumes: a pure computation over the settings model that
//! returns per-field findings, classified into the hazard taxonomy.
//!
//! Pure model checks: no i18n here. Every finding carries a [`SafetyCode`]
//! (the message key rendered through `crate::i18n`) whose
//! variants carry the payload values the message interpolates, a
//! [`HazardClass`], and a wire-style path. One
//! pass per model, no short-circuit — a single `assess` call surfaces every
//! hazard. Exposure rules cover listeners bound beyond loopback whose wire
//! form authenticates nobody; privacy rules cover TUN mode without a DNS
//! configuration; breakage rules cover balancers whose selectors match no
//! outbound tag.

use super::inbound::{
    BLOCK_OUTBOUND_TAG, DIRECT_OUTBOUND_TAG, DNS_OUTBOUND_TAG, DokodemoNetwork,
    LocalInboundProtocol, socket_address,
};
use super::servers::ServerProfile;
use super::servers::ServersFile;
use super::settings::{Mode, Settings};

/// Hazard classes: exposure (a listener open
/// beyond loopback), privacy (proxying without DNS protection), breakage
/// (a balancer that cannot carry traffic).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HazardClass {
    Exposure,
    Privacy,
    Breakage,
}

/// Every safety hazard the model layer knows, keyed by rule rather than by
/// rendered message. Order-independent; parameterized rules carry the value
/// that the message interpolates (the exposed listen address).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SafetyCode {
    /// SOCKS listener enabled, unauthenticated, and bound beyond loopback.
    SocksListenerExposed(String),
    /// HTTP listener enabled and bound beyond loopback with nobody
    /// authenticating on the wire — noauth, or password mode whose empty
    /// account list the projection drops (accounts are HTTP's only auth).
    HttpListenerExposed(String),
    /// dokodemo-door inbound enabled and bound beyond loopback — it has no
    /// authentication at all.
    DokodemoListenerExposed(String),
    /// TUN mode without a DNS configuration: the adapter falls back to the
    /// hardcoded plaintext 1.1.1.1/8.8.8.8 and DNS is not intercepted.
    TunDnsUnprotected,
    /// A balancer whose selectors match no emitted outbound tag — it cannot
    /// carry traffic. Payload is the balancer tag.
    BalancerSelectorNoMatch(String),
}

/// One safety finding: the hazard class, the message-key code, and the wire
/// path of the offending field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SafetyFinding {
    pub path: String,
    pub class: HazardClass,
    pub code: SafetyCode,
}

fn finding(path: String, class: HazardClass, code: SafetyCode) -> SafetyFinding {
    SafetyFinding { path, class, code }
}

/// A listen address bound beyond loopback: any parseable IP that is not a
/// loopback address; the wildcards 0.0.0.0/::, LAN IPs, and anything else
/// non-loopback count as exposed — the wildcards bind every interface and
/// are exactly the exposure this rule flags. The address is classified in
/// its socket form ([`inbound::socket_address`]), so an IPv4-mapped loopback
/// literal is loopback here too. Unparseable values are skipped: the
/// validation layer owns invalidity, and this must never panic.
fn is_exposed_listen(s: &str) -> bool {
    s.parse::<std::net::IpAddr>()
        .is_ok_and(|address| !socket_address(address).is_loopback())
}

/// Assess one settings + servers model for safety hazards: one pass, no
/// short-circuit; only enabled inbounds are examined. Exposure rules: a
/// SOCKS or HTTP entry in `settings.local_inbounds` bound beyond loopback
/// whose wire form authenticates nobody, and any enabled dokodemo inbound
/// (which has no authentication at all) bound beyond loopback in an
/// IP-listener mode. Wire truth, never the auth label alone: password mode
/// protects only when the wire authenticates — HTTP's accounts are its only
/// authentication, so password mode with an empty account list serves
/// everyone (the projection drops the empty list), while SOCKS password
/// mode always authenticates and denies every uncredentialed connection.
/// Privacy rules: TUN mode with no DNS configuration. Breakage rules: a
/// balancer whose selectors match no emitted outbound tag.
pub fn assess(servers: &ServersFile, settings: &Settings) -> Vec<SafetyFinding> {
    let mut findings = Vec::new();

    for (index, entry) in settings.local_inbounds.iter().enumerate() {
        // Effective wire authentication, not the auth label: password mode
        // protects only when the wire authenticates (see
        // `LocalInboundCfg::authenticates`). HTTP carries no auth key —
        // accounts are its only authentication, so password mode with an
        // empty account list serves everyone and must expose like noauth.
        if !entry.enabled || entry.authenticates() || !is_exposed_listen(&entry.listen) {
            continue;
        }
        let code = match entry.protocol {
            LocalInboundProtocol::Socks => SafetyCode::SocksListenerExposed(entry.listen.clone()),
            LocalInboundProtocol::Http => SafetyCode::HttpListenerExposed(entry.listen.clone()),
        };
        findings.push(finding(
            format!("localInbounds[{index}].listen"),
            HazardClass::Exposure,
            code,
        ));
    }

    for (index, entry) in settings.dokodemo.iter().enumerate() {
        if !entry.enabled {
            continue;
        }
        // IP-listener mode: NOT the unix-socket mode (a non-empty
        // `unix_socket_path` with a "unix" network listens on the socket
        // path, not an IP address). Mirrors the generator's `network_mode`
        // token test, which is case-insensitive (Xray accepts token
        // casing) — a "UNIX" listener must never be flagged as exposed.
        let ip_mode = !matches!(entry.network_mode(), Ok(DokodemoNetwork::Unix));
        if ip_mode && is_exposed_listen(&entry.listen) {
            findings.push(finding(
                format!("dokodemo[{index}].listen"),
                HazardClass::Exposure,
                SafetyCode::DokodemoListenerExposed(entry.listen.clone()),
            ));
        }
    }

    // Privacy: TUN mode without a DNS configuration. The emptiness
    // predicate mirrors the generator's emission decision exactly.
    let dns_empty = settings.dns.is_effectively_empty();
    if settings.mode == Mode::Tun && dns_empty {
        findings.push(finding(
            "tun".into(),
            HazardClass::Privacy,
            SafetyCode::TunDnsUnprotected,
        ));
    }

    // Breakage: a balancer whose selectors match no emitted outbound tag
    // (mirrors the generator's outbound contract: profile tags, the
    // built-ins, and dns-out only when DNS interception is active).
    let mut outbound_tags: Vec<String> = servers.profiles.iter().map(ServerProfile::tag).collect();
    outbound_tags.push(DIRECT_OUTBOUND_TAG.into());
    outbound_tags.push(BLOCK_OUTBOUND_TAG.into());
    let tun_on = settings.mode == Mode::Tun;
    let socks_on = settings
        .local_inbounds
        .iter()
        .any(|entry| entry.enabled && entry.protocol == LocalInboundProtocol::Socks);
    if !dns_empty && (tun_on || socks_on) {
        outbound_tags.push(DNS_OUTBOUND_TAG.into());
    }
    for (index, balancer) in settings.routing.balancers.iter().enumerate() {
        let matched = balancer
            .selector
            .iter()
            .any(|pattern| outbound_tags.iter().any(|tag| tag.starts_with(pattern)));
        if !matched {
            findings.push(finding(
                format!("routing.balancers[{index}]"),
                HazardClass::Breakage,
                SafetyCode::BalancerSelectorNoMatch(balancer.tag.clone()),
            ));
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::dns::{DnsCfg, DnsServer};
    use crate::model::inbound::{
        Account, DokodemoCfg, LocalInboundCfg, LocalInboundProtocol, TunCfg,
    };
    use crate::model::routing::{Balancer, RoutingCfg};
    use crate::model::servers::{ServerProfile, ServersFile};
    use crate::model::settings::{Mode, Settings};

    fn with_socks(listen: &str) -> Settings {
        Settings {
            local_inbounds: vec![LocalInboundCfg {
                listen: listen.into(),
                ..Default::default()
            }],
            ..Default::default()
        }
    }

    fn with_http(listen: &str) -> Settings {
        Settings {
            local_inbounds: vec![LocalInboundCfg {
                protocol: LocalInboundProtocol::Http,
                listen: listen.into(),
                ..Default::default()
            }],
            ..Default::default()
        }
    }

    fn with_dokodemo(entries: Vec<DokodemoCfg>) -> Settings {
        Settings {
            dokodemo: entries,
            ..Default::default()
        }
    }

    #[test]
    fn default_settings_have_no_findings() {
        assert!(assess(&ServersFile::default(), &Settings::default()).is_empty());
    }

    #[test]
    fn noauth_socks_and_http_on_wildcard_expose() {
        let settings = Settings {
            local_inbounds: vec![
                LocalInboundCfg {
                    listen: "0.0.0.0".into(),
                    ..Default::default()
                },
                LocalInboundCfg {
                    protocol: LocalInboundProtocol::Http,
                    listen: "0.0.0.0".into(),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let findings = assess(&ServersFile::default(), &settings);
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].path, "localInbounds[0].listen");
        assert_eq!(findings[0].class, HazardClass::Exposure);
        assert_eq!(
            findings[0].code,
            SafetyCode::SocksListenerExposed("0.0.0.0".into())
        );
        assert_eq!(findings[1].path, "localInbounds[1].listen");
        assert_eq!(findings[1].class, HazardClass::Exposure);
        assert_eq!(
            findings[1].code,
            SafetyCode::HttpListenerExposed("0.0.0.0".into())
        );
    }

    #[test]
    fn noauth_socks_beyond_loopback_exposes() {
        for listen in ["192.168.1.5", "::", "::ffff:192.168.1.5"] {
            let findings = assess(&ServersFile::default(), &with_socks(listen));
            assert_eq!(findings.len(), 1, "listen {listen:?} must expose");
            assert_eq!(findings[0].path, "localInbounds[0].listen");
            assert_eq!(findings[0].class, HazardClass::Exposure);
            assert_eq!(
                findings[0].code,
                SafetyCode::SocksListenerExposed(listen.into())
            );
        }
    }

    #[test]
    fn loopback_listeners_are_safe() {
        // The IPv4-mapped spellings bind the same loopback sockets as their
        // plain forms, so neither may be reported as exposed.
        for listen in ["127.0.0.1", "::1", "::ffff:127.0.0.1"] {
            assert!(
                assess(&ServersFile::default(), &with_socks(listen)).is_empty(),
                "socks {listen:?} must be safe"
            );
            assert!(
                assess(&ServersFile::default(), &with_http(listen)).is_empty(),
                "http {listen:?} must be safe"
            );
        }
    }

    #[test]
    fn password_mode_socks_with_empty_accounts_on_wildcard_is_safe() {
        // SOCKS password mode authenticates even with an empty account list:
        // the wire carries `auth: password` and Xray denies every connection.
        let settings = Settings {
            local_inbounds: vec![LocalInboundCfg {
                auth: "password".into(),
                listen: "0.0.0.0".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        assert!(assess(&ServersFile::default(), &settings).is_empty());
    }

    #[test]
    fn password_mode_http_with_empty_accounts_on_wildcard_exposes() {
        // HTTP carries no auth key — accounts are its only authentication,
        // so password mode with an empty account list authenticates nobody
        // and exposes exactly like noauth. The safe SOCKS entry before it
        // must not shift the finding's path.
        let settings = Settings {
            local_inbounds: vec![
                LocalInboundCfg {
                    auth: "password".into(),
                    listen: "0.0.0.0".into(),
                    ..Default::default()
                },
                LocalInboundCfg {
                    protocol: LocalInboundProtocol::Http,
                    auth: "password".into(),
                    listen: "0.0.0.0".into(),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let findings = assess(&ServersFile::default(), &settings);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].path, "localInbounds[1].listen");
        assert_eq!(findings[0].class, HazardClass::Exposure);
        assert_eq!(
            findings[0].code,
            SafetyCode::HttpListenerExposed("0.0.0.0".into())
        );
    }

    #[test]
    fn password_mode_http_with_accounts_on_wildcard_is_safe() {
        // HTTP password mode with at least one account authenticates on the
        // wire: the projection emits the account list and Xray serves only
        // valid credentials.
        let settings = Settings {
            local_inbounds: vec![LocalInboundCfg {
                protocol: LocalInboundProtocol::Http,
                auth: "password".into(),
                accounts: vec![Account {
                    user: "u".into(),
                    pass: "p".into(),
                    ..Default::default()
                }],
                listen: "0.0.0.0".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        assert!(assess(&ServersFile::default(), &settings).is_empty());
    }

    #[test]
    fn password_mode_http_with_empty_accounts_on_loopback_is_safe() {
        // Loopback binds never expose, whatever the wire authentication.
        for listen in ["127.0.0.1", "::1"] {
            let settings = Settings {
                local_inbounds: vec![LocalInboundCfg {
                    protocol: LocalInboundProtocol::Http,
                    auth: "password".into(),
                    listen: listen.into(),
                    ..Default::default()
                }],
                ..Default::default()
            };
            assert!(
                assess(&ServersFile::default(), &settings).is_empty(),
                "http {listen:?} must be safe"
            );
        }
    }

    #[test]
    fn password_mode_socks_with_empty_accounts_beyond_loopback_is_safe() {
        // SOCKS password mode denies every connection when the account list
        // is empty, so even a non-loopback bind authenticates — no exposure.
        for listen in ["192.168.1.5", "::"] {
            let settings = Settings {
                local_inbounds: vec![LocalInboundCfg {
                    auth: "password".into(),
                    listen: listen.into(),
                    ..Default::default()
                }],
                ..Default::default()
            };
            assert!(
                assess(&ServersFile::default(), &settings).is_empty(),
                "socks {listen:?} must be safe"
            );
        }
    }

    #[test]
    fn two_exposed_entries_produce_two_findings_with_distinct_indexes() {
        let settings = Settings {
            local_inbounds: vec![
                LocalInboundCfg {
                    listen: "0.0.0.0".into(),
                    ..Default::default()
                },
                LocalInboundCfg {
                    protocol: LocalInboundProtocol::Http,
                    listen: "::".into(),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let findings = assess(&ServersFile::default(), &settings);
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].path, "localInbounds[0].listen");
        assert_eq!(findings[0].class, HazardClass::Exposure);
        assert_eq!(
            findings[0].code,
            SafetyCode::SocksListenerExposed("0.0.0.0".into())
        );
        assert_eq!(findings[1].path, "localInbounds[1].listen");
        assert_eq!(findings[1].class, HazardClass::Exposure);
        assert_eq!(
            findings[1].code,
            SafetyCode::HttpListenerExposed("::".into())
        );
    }

    #[test]
    fn password_mode_http_with_empty_accounts_is_flagged_among_exposed_entries() {
        // Password label aside, the empty-account HTTP entry authenticates
        // nobody on the wire and must surface exactly like the noauth entry
        // beside it — both flagged, each at its own index.
        let settings = Settings {
            local_inbounds: vec![
                LocalInboundCfg {
                    listen: "0.0.0.0".into(),
                    ..Default::default()
                },
                LocalInboundCfg {
                    protocol: LocalInboundProtocol::Http,
                    auth: "password".into(),
                    listen: "0.0.0.0".into(),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let findings = assess(&ServersFile::default(), &settings);
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].path, "localInbounds[0].listen");
        assert_eq!(
            findings[0].code,
            SafetyCode::SocksListenerExposed("0.0.0.0".into())
        );
        assert_eq!(findings[1].path, "localInbounds[1].listen");
        assert_eq!(
            findings[1].code,
            SafetyCode::HttpListenerExposed("0.0.0.0".into())
        );
    }

    #[test]
    fn disabled_exposed_entry_is_not_flagged() {
        let settings = Settings {
            local_inbounds: vec![LocalInboundCfg {
                enabled: false,
                listen: "0.0.0.0".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        assert!(assess(&ServersFile::default(), &settings).is_empty());
    }

    #[test]
    fn finding_index_matches_the_list_position() {
        let settings = Settings {
            local_inbounds: vec![
                LocalInboundCfg {
                    listen: "127.0.0.1".into(),
                    ..Default::default()
                },
                LocalInboundCfg {
                    protocol: LocalInboundProtocol::Http,
                    listen: "0.0.0.0".into(),
                    ..Default::default()
                },
                LocalInboundCfg {
                    listen: "127.0.0.1".into(),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let findings = assess(&ServersFile::default(), &settings);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].path, "localInbounds[1].listen");
        assert_eq!(findings[0].class, HazardClass::Exposure);
        assert_eq!(
            findings[0].code,
            SafetyCode::HttpListenerExposed("0.0.0.0".into())
        );
    }

    #[test]
    fn mixed_protocol_entries_each_get_their_own_code() {
        let settings = Settings {
            local_inbounds: vec![
                LocalInboundCfg {
                    protocol: LocalInboundProtocol::Http,
                    listen: "::".into(),
                    ..Default::default()
                },
                LocalInboundCfg {
                    listen: "192.168.1.5".into(),
                    ..Default::default()
                },
                LocalInboundCfg {
                    protocol: LocalInboundProtocol::Http,
                    listen: "0.0.0.0".into(),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let findings = assess(&ServersFile::default(), &settings);
        assert_eq!(findings.len(), 3);
        for (index, finding) in findings.iter().enumerate() {
            assert_eq!(finding.path, format!("localInbounds[{index}].listen"));
            assert_eq!(finding.class, HazardClass::Exposure);
        }
        assert_eq!(
            findings[0].code,
            SafetyCode::HttpListenerExposed("::".into())
        );
        assert_eq!(
            findings[1].code,
            SafetyCode::SocksListenerExposed("192.168.1.5".into())
        );
        assert_eq!(
            findings[2].code,
            SafetyCode::HttpListenerExposed("0.0.0.0".into())
        );
    }

    #[test]
    fn disabled_dokodemo_is_safe() {
        let settings = with_dokodemo(vec![DokodemoCfg {
            listen: "0.0.0.0".into(),
            ..Default::default()
        }]);
        assert!(assess(&ServersFile::default(), &settings).is_empty());
    }

    #[test]
    fn enabled_dokodemo_on_wildcard_exposes() {
        let settings = with_dokodemo(vec![DokodemoCfg {
            enabled: true,
            listen: "0.0.0.0".into(),
            ..Default::default()
        }]);
        let findings = assess(&ServersFile::default(), &settings);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].path, "dokodemo[0].listen");
        assert_eq!(findings[0].class, HazardClass::Exposure);
        assert_eq!(
            findings[0].code,
            SafetyCode::DokodemoListenerExposed("0.0.0.0".into())
        );
    }

    #[test]
    fn dokodemo_index_paths_are_per_entry() {
        let settings = with_dokodemo(vec![
            DokodemoCfg {
                enabled: true,
                listen: "0.0.0.0".into(),
                ..Default::default()
            },
            DokodemoCfg {
                enabled: true,
                listen: "127.0.0.1".into(),
                ..Default::default()
            },
        ]);
        let findings = assess(&ServersFile::default(), &settings);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].path, "dokodemo[0].listen");
    }

    #[test]
    fn unix_mode_dokodemo_is_safe() {
        for network in ["unix", "UNIX"] {
            let settings = with_dokodemo(vec![DokodemoCfg {
                enabled: true,
                unix_socket_path: "C:\\run\\xray.sock".into(),
                network: network.into(),
                listen: "0.0.0.0".into(),
                ..Default::default()
            }]);
            assert!(
                assess(&ServersFile::default(), &settings).is_empty(),
                "network {network:?} must stay unexposed (the generator's token test is case-insensitive)"
            );
        }
    }

    #[test]
    fn loopback_dokodemo_is_safe() {
        let settings = with_dokodemo(vec![DokodemoCfg {
            enabled: true,
            listen: "127.0.0.1".into(),
            ..Default::default()
        }]);
        assert!(assess(&ServersFile::default(), &settings).is_empty());
    }

    #[test]
    fn unparseable_listen_is_skipped() {
        let settings = with_socks("localhost");
        assert!(assess(&ServersFile::default(), &settings).is_empty());
    }

    fn with_balancers(servers: ServersFile, balancers: Vec<Balancer>) -> (ServersFile, Settings) {
        (
            servers,
            Settings {
                routing: RoutingCfg {
                    balancers,
                    ..Default::default()
                },
                ..Default::default()
            },
        )
    }

    fn profile_servers() -> ServersFile {
        ServersFile {
            profiles: vec![ServerProfile {
                id: "0123456789abcdef".into(),
                ..Default::default()
            }],
            ..Default::default()
        }
    }

    /// A DNS configuration with nothing on the wire. `DnsCfg::default()`
    /// now seeds 1.1.1.1 and parallel queries, so the genuinely
    /// DNS-less state must be spelled out: no servers and parallel queries
    /// off (both would otherwise make `is_effectively_empty` false).
    fn dns_less() -> DnsCfg {
        DnsCfg {
            servers: Vec::new(),
            enable_parallel_query: false,
            ..Default::default()
        }
    }

    #[test]
    fn tun_mode_without_dns_warns_privacy() {
        let settings = Settings {
            mode: Mode::Tun,
            tun: TunCfg::default(),
            // DnsCfg::default() now seeds 1.1.1.1 — this test
            // targets the genuinely DNS-less configuration.
            dns: dns_less(),
            ..Default::default()
        };
        let findings = assess(&ServersFile::default(), &settings);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].path, "tun");
        assert_eq!(findings[0].class, HazardClass::Privacy);
        assert_eq!(findings[0].code, SafetyCode::TunDnsUnprotected);
    }

    #[test]
    fn tun_with_dns_is_safe() {
        let settings = Settings {
            mode: Mode::Tun,
            tun: TunCfg::default(),
            dns: DnsCfg {
                servers: vec![DnsServer {
                    address: "1.1.1.1".into(),
                    ..Default::default()
                }],
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(assess(&ServersFile::default(), &settings).is_empty());
    }

    #[test]
    fn off_mode_reports_exposure_but_not_privacy() {
        let settings = with_socks("0.0.0.0");
        let findings = assess(&ServersFile::default(), &settings);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].path, "localInbounds[0].listen");
    }

    #[test]
    fn balancer_selector_matching_no_profile_warns_breakage() {
        let (servers, settings) = with_balancers(
            ServersFile::default(),
            vec![Balancer {
                tag: "bal".into(),
                selector: vec!["srv-".into()],
                ..Default::default()
            }],
        );
        let findings = assess(&servers, &settings);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].path, "routing.balancers[0]");
        assert_eq!(findings[0].class, HazardClass::Breakage);
        assert_eq!(
            findings[0].code,
            SafetyCode::BalancerSelectorNoMatch("bal".into())
        );
    }

    #[test]
    fn balancer_selector_matching_profile_is_safe() {
        let (servers, settings) = with_balancers(
            profile_servers(),
            vec![Balancer {
                tag: "bal".into(),
                selector: vec!["srv-".into()],
                ..Default::default()
            }],
        );
        assert!(assess(&servers, &settings).is_empty());
    }

    #[test]
    fn balancer_selector_matching_builtin_outbound_is_safe() {
        let (servers, settings) = with_balancers(
            ServersFile::default(),
            vec![Balancer {
                tag: "bal".into(),
                selector: vec!["direct".into()],
                ..Default::default()
            }],
        );
        assert!(assess(&servers, &settings).is_empty());
    }

    #[test]
    fn balancer_with_empty_selector_warns_breakage() {
        let (servers, settings) = with_balancers(
            ServersFile::default(),
            vec![Balancer {
                tag: "bal".into(),
                ..Default::default()
            }],
        );
        let findings = assess(&servers, &settings);
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].code,
            SafetyCode::BalancerSelectorNoMatch("bal".into())
        );
    }

    #[test]
    fn balancer_index_paths_are_per_entry() {
        let (servers, settings) = with_balancers(
            ServersFile::default(),
            vec![
                Balancer {
                    tag: "ok".into(),
                    selector: vec!["direct".into()],
                    ..Default::default()
                },
                Balancer {
                    tag: "broken".into(),
                    selector: vec!["srv-".into()],
                    ..Default::default()
                },
            ],
        );
        let findings = assess(&servers, &settings);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].path, "routing.balancers[1]");
    }

    #[test]
    fn balancer_selector_matching_dns_out_is_safe_when_dns_configured() {
        let servers = ServersFile::default();
        let settings = Settings {
            dns: DnsCfg {
                servers: vec![DnsServer {
                    address: "1.1.1.1".into(),
                    ..Default::default()
                }],
                ..Default::default()
            },
            routing: RoutingCfg {
                balancers: vec![Balancer {
                    tag: "bal".into(),
                    selector: vec!["dns-out".into()],
                    ..Default::default()
                }],
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(assess(&servers, &settings).is_empty());
    }

    #[test]
    fn dns_out_selector_warns_when_dns_not_configured() {
        let servers = ServersFile::default();
        let settings = Settings {
            // DnsCfg::default() now seeds 1.1.1.1 — this test
            // targets the genuinely DNS-less configuration.
            dns: dns_less(),
            routing: RoutingCfg {
                balancers: vec![Balancer {
                    tag: "bal".into(),
                    selector: vec!["dns-out".into()],
                    ..Default::default()
                }],
                ..Default::default()
            },
            ..Default::default()
        };
        let findings = assess(&servers, &settings);
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].code,
            SafetyCode::BalancerSelectorNoMatch("bal".into())
        );
    }

    #[test]
    fn tun_privacy_and_exposure_findings_coexist() {
        let settings = Settings {
            mode: Mode::Tun,
            tun: TunCfg::default(),
            local_inbounds: vec![LocalInboundCfg {
                listen: "0.0.0.0".into(),
                ..Default::default()
            }],
            // DnsCfg::default() now seeds 1.1.1.1 — this test
            // targets the genuinely DNS-less configuration.
            dns: dns_less(),
            ..Default::default()
        };
        let findings = assess(&ServersFile::default(), &settings);
        let paths: Vec<&str> = findings
            .iter()
            .map(|finding| finding.path.as_str())
            .collect();
        assert!(paths.contains(&"tun"));
        assert!(paths.contains(&"localInbounds[0].listen"));
    }
}
