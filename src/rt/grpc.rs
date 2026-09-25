//! gRPC client for the Xray API inbound.
//!
//! The generated config adds an API inbound on `127.0.0.1:<api_port>` with the
//! stats / observatory / router / logger / handler services. This module wraps
//! a lazily-connected tonic channel to that inbound.
//!
//! Prost path note: prost-build emits cross-package references as `super::`
//! chains with one `super` per unmatched package segment, so the module tree
//! in [`pb`] MUST mirror the protobuf package segments exactly
//! (`xray.core.app.observatory.command` → `pb::xray::core::app::observatory::command`).

use std::collections::BTreeMap;
use std::future::Future;
use std::time::Duration;

use tonic::Request;
use tonic::transport::{Channel, Endpoint};
/// Generated code from the vendored Xray protos (`broccoli/proto/`).
#[allow(dead_code, clippy::all)]
pub mod pb {
    pub mod xray {
        pub mod core {
            tonic::include_proto!("xray.core");
            pub mod app {
                pub mod observatory {
                    tonic::include_proto!("xray.core.app.observatory");
                    pub mod command {
                        tonic::include_proto!("xray.core.app.observatory.command");
                    }
                }
            }
        }
        pub mod common {
            pub mod net {
                tonic::include_proto!("xray.common.net");
            }
            pub mod geodata {
                tonic::include_proto!("xray.common.geodata");
            }
            pub mod protocol {
                tonic::include_proto!("xray.common.protocol");
            }
            pub mod serial {
                tonic::include_proto!("xray.common.serial");
            }
        }
        pub mod app {
            pub mod log {
                pub mod command {
                    tonic::include_proto!("xray.app.log.command");
                }
            }
            pub mod proxyman {
                tonic::include_proto!("xray.app.proxyman");
                pub mod command {
                    tonic::include_proto!("xray.app.proxyman.command");
                }
            }
            pub mod router {
                tonic::include_proto!("xray.app.router");
                pub mod command {
                    tonic::include_proto!("xray.app.router.command");
                }
            }
            pub mod stats {
                pub mod command {
                    tonic::include_proto!("xray.app.stats.command");
                }
            }
        }
        pub mod proxy {
            pub mod dokodemo {
                tonic::include_proto!("xray.proxy.dokodemo");
            }
        }
        pub mod transport {
            pub mod internet {
                tonic::include_proto!("xray.transport.internet");
            }
        }
    }
}

use pb::xray::app::log::command as log_cmd;
use pb::xray::app::proxyman::command as handler_cmd;
use pb::xray::app::router as router_cfg;
use pb::xray::app::router::command as router_cmd;
use pb::xray::app::stats::command as stats_cmd;
use pb::xray::common::geodata as geodata_pb;
use pb::xray::common::net::Network;

use super::TrialRuleAddOutcome;
use super::dns_in;
use crate::diag::{Diag, DiagError};
use crate::i18n::Key;
use crate::model::routing::{RouteTestRequest, Rule};
use pb::xray::core::app::observatory::command as obs_cmd;

const CONNECT_TIMEOUT: Duration = Duration::from_millis(750);
const RPC_TIMEOUT: Duration = Duration::from_millis(500);
/// The local Tokio deadline is authoritative. Give the gRPC metadata and
/// tower layer a small later deadline so they cannot race it into `Cancelled`.
const TRANSPORT_DEADLINE_SLACK: Duration = Duration::from_millis(50);

/// One 1 Hz stats sample for the GUI. Rates are per-second byte deltas
/// computed by the runtime (the core only exposes cumulative counters); the
/// `total_*` fields carry those cumulative counters as-is (never accumulated
/// client-side), so a dropped tick cannot skew them.
///
/// Equality is field-wise (`PartialEq`) so a cache keyed on the sample can
/// state its own freshness instead of re-listing the fields it covers.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct StatsTick {
    /// Total uplink bytes/s across all inbounds (listener traffic).
    pub up: u64,
    /// Total downlink bytes/s across all inbounds (listener traffic).
    pub down: u64,
    /// `(tag, up bytes/s, down bytes/s)` per outbound, sorted by tag.
    pub per_outbound: Vec<(String, u64, u64)>,
    /// `(tag, up bytes/s, down bytes/s)` per inbound (listener traffic),
    /// sorted by tag. Dynamic: the set is whatever `inbound>>>` counters the
    /// core reports — no coupling to the generated config.
    pub per_inbound: Vec<(String, u64, u64)>,
    /// Cumulative uplink bytes across all inbounds (listener traffic) since
    /// core start — the aggregate of [`Self::per_inbound_totals`], from the
    /// same raw response, so the dashboard totals line can never diverge
    /// from the table it sits next to.
    pub total_up: u64,
    /// Cumulative downlink bytes across all inbounds (listener traffic) since
    /// core start — the aggregate of [`Self::per_inbound_totals`].
    pub total_down: u64,
    /// `(tag, cumulative up bytes, cumulative down bytes)` per inbound
    /// (listener traffic) since core start, sorted by tag; same tag set as
    /// [`Self::per_inbound`].
    pub per_inbound_totals: Vec<(String, u64, u64)>,
    /// Core uptime in seconds (`SysStatsResponse.Uptime`).
    pub uptime_secs: u64,
    /// Goroutine count (`SysStatsResponse.NumGoroutine`).
    pub goroutines: u64,
    /// Go runtime heap allocation in bytes (`SysStatsResponse.Alloc`).
    pub alloc_bytes: u64,
    /// Go runtime total memory reserved in bytes (`SysStatsResponse.Sys`).
    pub sys_bytes: u64,
    /// Live heap object count (`SysStatsResponse.LiveObjects`).
    pub live_objects: u64,
    /// Total completed GC cycles (`SysStatsResponse.NumGC`).
    pub num_gc: u64,
}

/// GUI-facing view of one live inbound/outbound handler of the running core
/// (`ListInbounds`/`ListOutbounds`). Only tags and the protocol message type
/// are surfaced; the settings payloads stay opaque.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeEntryView {
    pub tag: String,
    /// Protocol message type name, e.g. `xray.proxy.socks.Config`; empty when
    /// the core returned no settings for the entry.
    pub kind: String,
}

/// GUI-facing view of one observatory `HealthPingMeasurementResult`. The
/// burst engine fills it; the ordinary observatory leaves it empty. Xray
/// copies Go `time.Duration` values straight into the protobuf, so every
/// value arrives in nanoseconds — converted to milliseconds here, the unit
/// the rest of the view uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HealthPingView {
    /// Pings in the sliding window.
    pub all: i64,
    /// Pings that failed inside that window.
    pub fail: i64,
    pub average_ms: i64,
    pub deviation_ms: i64,
    pub max_ms: i64,
    pub min_ms: i64,
}

impl HealthPingView {
    /// Xray copies Go `time.Duration` values straight into the protobuf, so
    /// every measurement field arrives in nanoseconds.
    fn from_wire(health: pb::xray::core::app::observatory::HealthPingMeasurementResult) -> Self {
        const NS_PER_MS: i64 = 1_000_000;
        Self {
            all: health.all,
            fail: health.fail,
            average_ms: health.average / NS_PER_MS,
            deviation_ms: health.deviation / NS_PER_MS,
            max_ms: health.max / NS_PER_MS,
            min_ms: health.min / NS_PER_MS,
        }
    }
}

/// GUI-facing view of one observatory `OutboundStatus`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundStatusView {
    pub tag: String,
    pub alive: bool,
    pub delay_ms: i64,
    /// The Observatory's last error reason for this outbound. `None` means
    /// the Observatory reported no error text: an alive row, a row without a
    /// recorded reason, or no observation data for the tag at all.
    pub last_error: Option<String>,
    /// Windowed ping statistics of the burst health engine; `None` for the
    /// ordinary observatory, which reports no history.
    pub health_ping: Option<HealthPingView>,
    /// The run-level captured core-diagnostics tail of the latency-probe
    /// child that produced this row (80 x 512-char capped,
    /// `[stdout]`/`[stderr]`-prefixed lines, without the "Xray
    /// diagnostics:" wall header), attached only to dead rows of a probe
    /// run whose child produced output. Rows from the live observatory —
    /// and rows of probe runs without child output — carry `None`; their
    /// verdict text degrades to today's headline-only shape.
    pub diagnostics: Option<String>,
}

/// GUI-facing snapshot of Xray's ephemeral state for one configured balancer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BalancerInfoView {
    /// `None` means the balancer is following its configured strategy.
    pub override_target: Option<String>,
    /// `None` means the strategy does not expose principle targets.
    pub principle_targets: Option<Vec<String>>,
}

/// Lazily-connected gRPC client to the core's API inbound.
///
/// Cheap to clone (shares the channel); every RPC opens its own HTTP/2 stream,
/// so calls against a dead core fail fast instead of blocking forever.
#[derive(Clone)]
pub struct GrpcClient {
    channel: Channel,
    rpc_timeout: Duration,
    tun_timeout: Duration,
}

impl GrpcClient {
    /// `http://127.0.0.1:{api_port}`, `connect_lazy` — no connection attempt is
    /// made until the first RPC.
    pub fn new(api_port: u16) -> Self {
        Self::with_timeouts(
            api_port,
            CONNECT_TIMEOUT,
            RPC_TIMEOUT,
            super::TUN_RPC_TIMEOUT,
        )
    }

    fn with_timeouts(
        api_port: u16,
        connect_timeout: Duration,
        rpc_timeout: Duration,
        tun_timeout: Duration,
    ) -> Self {
        let endpoint = Endpoint::from_shared(format!("http://127.0.0.1:{api_port}"))
            .expect("loopback endpoint URI is always valid")
            .connect_timeout(connect_timeout)
            // Keep tower's default bounded too, but after the local deadline.
            .timeout(
                tun_timeout
                    .max(rpc_timeout)
                    .saturating_add(TRANSPORT_DEADLINE_SLACK),
            );
        Self {
            channel: endpoint.connect_lazy(),
            rpc_timeout,
            tun_timeout,
        }
    }

    fn request<T>(&self, message: T, local_timeout: Duration) -> Request<T> {
        let mut request = Request::new(message);
        // The outer `bounded` deadline below is the stable GUI-facing result.
        request.set_timeout(local_timeout.saturating_add(TRANSPORT_DEADLINE_SLACK));
        request
    }

    async fn bounded<T>(
        &self,
        timeout: Duration,
        future: impl Future<Output = Result<T, tonic::Status>>,
    ) -> Result<T, tonic::Status> {
        tokio::time::timeout(timeout, future)
            .await
            .map_err(|_| tonic::Status::deadline_exceeded("local Xray API deadline elapsed"))?
    }

    /// Raw `SysStatsResponse` (uptime, goroutines, GC/alloc counters).
    pub async fn get_sys_stats(&self) -> Result<stats_cmd::SysStatsResponse, tonic::Status> {
        let mut client =
            stats_cmd::stats_service_client::StatsServiceClient::new(self.channel.clone());
        let request = self.request(stats_cmd::SysStatsRequest {}, self.rpc_timeout);
        let response = self
            .bounded(self.rpc_timeout, client.get_sys_stats(request))
            .await?;
        Ok(response.into_inner())
    }

    /// Cumulative per-outbound traffic counters as `(tag, uplink, downlink)`.
    ///
    /// The Go implementation matches `pattern` with `strings.Contains`
    /// (app/stats/command/command.go `QueryStats`), so a single call with
    /// `outbound>>>` returns every `outbound>>><tag>>>traffic>>>uplink|downlink`
    /// counter.
    pub async fn query_traffic(&self) -> Result<Vec<(String, u64, u64)>, tonic::Status> {
        self.query_traffic_with("outbound>>>", "outbound>>>").await
    }

    /// Cumulative per-inbound (listener traffic) counters as
    /// `(tag, uplink, downlink)`, mirroring [`Self::query_traffic`] against
    /// the `inbound>>>` sweep. The returned tag set is dynamic — whatever
    /// listeners the running config actually carries.
    pub async fn query_inbound_traffic(&self) -> Result<Vec<(String, u64, u64)>, tonic::Status> {
        self.query_traffic_with("inbound>>>", "inbound>>>").await
    }

    async fn query_traffic_with(
        &self,
        pattern: &str,
        prefix: &str,
    ) -> Result<Vec<(String, u64, u64)>, tonic::Status> {
        let mut client =
            stats_cmd::stats_service_client::StatsServiceClient::new(self.channel.clone());
        let request = self.request(
            stats_cmd::QueryStatsRequest {
                pattern: pattern.to_string(),
                reset: false,
            },
            self.rpc_timeout,
        );
        let response = self
            .bounded(self.rpc_timeout, client.query_stats(request))
            .await?;
        let mut per_tag: BTreeMap<String, (u64, u64)> = BTreeMap::new();
        for stat in response.into_inner().stat {
            let Some(rest) = stat.name.strip_prefix(prefix) else {
                continue;
            };
            let mut parts = rest.split(">>>");
            let (Some(tag), Some(kind), Some(direction)) =
                (parts.next(), parts.next(), parts.next())
            else {
                continue;
            };
            if kind != "traffic" {
                continue;
            }
            let value = stat.value.max(0) as u64;
            let entry = per_tag.entry(tag.to_string()).or_default();
            match direction {
                "uplink" => entry.0 = value,
                "downlink" => entry.1 = value,
                _ => {}
            }
        }
        Ok(per_tag
            .into_iter()
            .map(|(tag, (up, down))| (tag, up, down))
            .collect())
    }

    /// All outbound statuses currently known to the observatory.
    ///
    /// `GetOutboundStatus` takes no selector — the observed set is fixed by the
    /// observatory config's `subject_selector`; filter client-side.
    pub async fn outbound_statuses(&self) -> Result<Vec<OutboundStatusView>, tonic::Status> {
        let mut client = obs_cmd::observatory_service_client::ObservatoryServiceClient::new(
            self.channel.clone(),
        );
        let request = self.request(obs_cmd::GetOutboundStatusRequest {}, self.rpc_timeout);
        let response = self
            .bounded(self.rpc_timeout, client.get_outbound_status(request))
            .await?;
        let result = response.into_inner().status.unwrap_or_default();
        Ok(result
            .status
            .into_iter()
            .map(|status| OutboundStatusView {
                tag: status.outbound_tag,
                alive: status.alive,
                delay_ms: status.delay,
                last_error: Some(status.last_error_reason).filter(|reason| !reason.is_empty()),
                health_ping: status.health_ping.map(HealthPingView::from_wire),
                // Live observatory rows carry no probe-child diagnostics.
                diagnostics: None,
            })
            .collect())
    }

    /// Status of a single outbound tag. When the observatory has no data for
    /// the tag yet, returns a synthetic dead view instead of an error.
    pub async fn outbound_status(&self, tag: &str) -> Result<OutboundStatusView, tonic::Status> {
        let all = self.outbound_statuses().await?;
        Ok(all
            .into_iter()
            .find(|s| s.tag == tag)
            .unwrap_or_else(|| OutboundStatusView {
                tag: tag.to_string(),
                alive: false,
                delay_ms: 0,
                last_error: None,
                health_ping: None,
                diagnostics: None,
            }))
    }

    /// Live inbound handlers of the running core (`HandlerService.ListInbounds`).
    ///
    /// Full settings are requested (not `is_only_tags`) so each entry carries
    /// the protocol message type name; the settings payloads themselves stay
    /// opaque — only `tag` + `kind` are surfaced.
    pub async fn list_inbounds(&self) -> Result<Vec<RuntimeEntryView>, tonic::Status> {
        let mut client =
            handler_cmd::handler_service_client::HandlerServiceClient::new(self.channel.clone());
        let request = self.request(
            handler_cmd::ListInboundsRequest {
                is_only_tags: false,
            },
            self.rpc_timeout,
        );
        let response = self
            .bounded(self.rpc_timeout, client.list_inbounds(request))
            .await?;
        Ok(response
            .into_inner()
            .inbounds
            .into_iter()
            .map(|config| runtime_entry_view(config.tag, config.proxy_settings))
            .collect())
    }

    /// Live outbound handlers of the running core (`HandlerService.ListOutbounds`).
    pub async fn list_outbounds(&self) -> Result<Vec<RuntimeEntryView>, tonic::Status> {
        let mut client =
            handler_cmd::handler_service_client::HandlerServiceClient::new(self.channel.clone());
        let request = self.request(handler_cmd::ListOutboundsRequest {}, self.rpc_timeout);
        let response = self
            .bounded(self.rpc_timeout, client.list_outbounds(request))
            .await?;
        Ok(response
            .into_inner()
            .outbounds
            .into_iter()
            .map(|config| runtime_entry_view(config.tag, config.proxy_settings))
            .collect())
    }

    /// `RoutingService.TestRoute` rendered as a human-readable line, e.g.
    /// `tcp example.com:443 -> outbound 'direct'`.
    pub async fn test_route(
        &self,
        ctx: router_cmd::RoutingContext,
    ) -> Result<String, tonic::Status> {
        let mut client =
            router_cmd::routing_service_client::RoutingServiceClient::new(self.channel.clone());
        let request = self.request(
            router_cmd::TestRouteRequest {
                routing_context: Some(ctx),
                field_selectors: Vec::new(),
                publish_result: false,
            },
            self.rpc_timeout,
        );
        let response = self
            .bounded(self.rpc_timeout, client.test_route(request))
            .await?;
        Ok(format_route(&response.into_inner()))
    }

    /// Current ephemeral override and principle targets for one balancer.
    ///
    /// The error is keyed: the missing-balancer branch is an app-authored
    /// sentence, and an RPC failure travels below the same keyed layer, so
    /// the screen renders the whole message in the active language.
    pub async fn get_balancer_info(&self, tag: &str) -> Result<BalancerInfoView, DiagError> {
        let mut client =
            router_cmd::routing_service_client::RoutingServiceClient::new(self.channel.clone());
        let request = self.request(
            router_cmd::GetBalancerInfoRequest {
                tag: tag.to_string(),
            },
            self.rpc_timeout,
        );
        let response = self
            .bounded(self.rpc_timeout, client.get_balancer_info(request))
            .await
            .map_err(|error| balancer_status_diag(Key::GrpcBalancerInfoFailed, tag, error))?
            .into_inner();
        let balancer = response.balancer.ok_or_else(|| {
            DiagError::new(Diag::new(Key::GrpcBalancerInfoFailed))
                .caused_by(DiagError::from(Diag::new(Key::GrpcBalancerInfoMissing)))
        })?;
        Ok(balancer_info_view(balancer))
    }

    /// Set an exact balancer target. Xray defines an empty target as clearing
    /// the override; the UI exposes that behavior through a separate control.
    pub async fn override_balancer_target(
        &self,
        balancer_tag: &str,
        target: &str,
    ) -> Result<(), tonic::Status> {
        let mut client =
            router_cmd::routing_service_client::RoutingServiceClient::new(self.channel.clone());
        let request = self.request(
            router_cmd::OverrideBalancerTargetRequest {
                balancer_tag: balancer_tag.to_string(),
                target: target.to_string(),
            },
            self.rpc_timeout,
        );
        self.bounded(self.rpc_timeout, client.override_balancer_target(request))
            .await?;
        Ok(())
    }

    /// Inject one routing rule into the running core (`RoutingService.AddRule`).
    ///
    /// `should_append = true` keeps every existing rule; the payload must be
    /// rules-only (no balancers — the core rejects duplicate balancer tags in
    /// append mode and ignores the payload's domain strategy). The injected
    /// rules are ephemeral: lost on core restart or config commit.
    pub async fn add_rule(
        &self,
        config: router_cfg::Config,
        should_append: bool,
    ) -> Result<(), tonic::Status> {
        let mut client =
            router_cmd::routing_service_client::RoutingServiceClient::new(self.channel.clone());
        let request = self.request(
            router_cmd::AddRuleRequest {
                config: Some(router_typed_config(config)),
                should_append,
            },
            self.rpc_timeout,
        );
        self.bounded(self.rpc_timeout, client.add_rule(request))
            .await?;
        Ok(())
    }

    /// Remove every live rule carrying `rule_tag` (`RoutingService.RemoveRule`).
    /// The core rejects an empty tag, so callers must validate before sending.
    pub async fn remove_rule(&self, rule_tag: &str) -> Result<(), tonic::Status> {
        let mut client =
            router_cmd::routing_service_client::RoutingServiceClient::new(self.channel.clone());
        let request = self.request(
            router_cmd::RemoveRuleRequest {
                rule_tag: rule_tag.to_string(),
            },
            self.rpc_timeout,
        );
        self.bounded(self.rpc_timeout, client.remove_rule(request))
            .await?;
        Ok(())
    }

    /// Live rule inventory (`RoutingService.ListRule`) as `(target tag,
    /// rule tag)`. Untagged rules report an empty rule tag; the target tag is
    /// the rule's outbound/balancer target.
    pub async fn list_rules(&self) -> Result<Vec<(String, String)>, tonic::Status> {
        let mut client =
            router_cmd::routing_service_client::RoutingServiceClient::new(self.channel.clone());
        let request = self.request(router_cmd::ListRuleRequest {}, self.rpc_timeout);
        let response = self
            .bounded(self.rpc_timeout, client.list_rule(request))
            .await?;
        Ok(response
            .into_inner()
            .rules
            .into_iter()
            .map(|item| (item.tag, item.rule_tag))
            .collect())
    }

    /// `LoggerService.RestartLogger` — reopens the core's log outputs.
    pub async fn restart_logger(&self) -> Result<(), tonic::Status> {
        let mut client =
            log_cmd::logger_service_client::LoggerServiceClient::new(self.channel.clone());
        let request = self.request(log_cmd::RestartLoggerRequest {}, self.rpc_timeout);
        self.bounded(self.rpc_timeout, client.restart_logger(request))
            .await?;
        Ok(())
    }

    /// Remove an inbound handler. Xray's manager synchronously calls
    /// `handler.Close()` before returning; removing `in-tun` therefore lets
    /// Wintun restore routes/DNS and close the adapter before process teardown.
    pub async fn remove_inbound(&self, tag: &str) -> Result<(), tonic::Status> {
        let mut client =
            handler_cmd::handler_service_client::HandlerServiceClient::new(self.channel.clone());
        let request = self.request(
            handler_cmd::RemoveInboundRequest {
                tag: tag.to_string(),
            },
            self.tun_timeout,
        );
        self.bounded(self.tun_timeout, client.remove_inbound(request))
            .await?;
        Ok(())
    }

    /// Add an inbound handler to the running core. The core registers the
    /// tag before it starts the handler, so a failed start keeps the tag
    /// registered — a caller retrying the same tag must remove it first, as
    /// [`Self::add_dns_in_listener`] does.
    pub async fn add_inbound(
        &self,
        inbound: pb::xray::core::InboundHandlerConfig,
    ) -> Result<(), tonic::Status> {
        let mut client =
            handler_cmd::handler_service_client::HandlerServiceClient::new(self.channel.clone());
        let request = self.request(
            handler_cmd::AddInboundRequest {
                inbound: Some(inbound),
            },
            self.rpc_timeout,
        );
        self.bounded(self.rpc_timeout, client.add_inbound(request))
            .await?;
        Ok(())
    }

    /// Add the in-tun DNS listener to the running core. The listener binds
    /// the TUN gateway, an address the core owns only once its tun inbound
    /// has assigned it, so callers retry this call while the adapter is
    /// still coming up. The add clears the tag first: a previous failed
    /// attempt left it registered in the core's manager, and removing a tag
    /// that was never added is a `NO_CLUE` error that stays ignored.
    pub async fn add_dns_in_listener(
        &self,
        listener: &dns_in::Listener,
    ) -> Result<(), tonic::Status> {
        let _ = self.remove_inbound(listener.tag()).await;
        self.add_inbound(listener.inbound_config()).await
    }
}

/// The verdict of one trial-rule add: the live inventory read back after the
/// attempt decides, never the add reply alone.
///
/// Xray's `AddRule` handler completes the mutation server-side and never
/// reads the request context (`app/router/command/command.go`; the rules are
/// rebuilt in `app/router/router.go` `ReloadRules`), so a local deadline
/// expiry cancels only this client's wait: the rule is live while the reply
/// says otherwise, and a retry would die as a duplicate. A failed reply is
/// therefore fatal only when the read-back cannot show the rule either —
/// `Err` means the core does not hold the rule, `Ok` means it does.
pub fn add_rule_outcome(
    rule_tag: &str,
    add: Result<(), tonic::Status>,
    list: Result<Vec<(String, String)>, tonic::Status>,
) -> Result<TrialRuleAddOutcome, DiagError> {
    let tag = rule_tag.trim();
    let live_rules = list.ok();
    let holds_rule = live_rules
        .as_ref()
        .is_some_and(|rules| rules.iter().any(|(_, live_tag)| live_tag.trim() == tag));
    match add {
        // The core accepted the rule; the read-back is what the caller shows.
        Ok(()) => Ok(TrialRuleAddOutcome { rules: live_rules }),
        // The reply failed, but the read-back lists the tag: the mutation
        // landed and only this client's wait was lost.
        Err(_) if holds_rule => Ok(TrialRuleAddOutcome { rules: live_rules }),
        // Nothing shows the core holds the rule, so the add's own failure is
        // the verdict.
        Err(error) => Err(DiagError::new(Diag::new(Key::GrpcAddRuleFailed)).caused_by(error)),
    }
}

/// Map one core status onto its keyed failure sentence.
///
/// The pinned core answers `cannot find tag` when the tag is absent from the
/// router it loaded (`app/router/balancing.go` `GetOverrideTarget` /
/// `SetOverrideTarget`), which the app renders as the missing-balancer
/// sentence naming the tag. The matched text is exactly what that core says:
/// a core that reworded it degrades to `wrapper` with the status as the
/// cause, instead of reporting a raw core string.
pub(crate) fn balancer_status_diag(wrapper: Key, tag: &str, error: tonic::Status) -> DiagError {
    if error.message() == "cannot find tag" {
        DiagError::new(Diag::new(Key::GrpcBalancerNotFound).arg(tag))
    } else {
        DiagError::new(Diag::new(wrapper)).caused_by(error)
    }
}

fn balancer_info_view(balancer: router_cmd::BalancerMsg) -> BalancerInfoView {
    BalancerInfoView {
        override_target: balancer
            .r#override
            .map(|info| info.target)
            .filter(|target| !target.is_empty()),
        principle_targets: balancer.principle_target.map(|info| info.tag),
    }
}

/// Map one live handler config to the GUI view: tag plus the protocol message
/// type name (the settings payload stays opaque).
fn runtime_entry_view(
    tag: String,
    proxy_settings: Option<pb::xray::common::serial::TypedMessage>,
) -> RuntimeEntryView {
    RuntimeEntryView {
        tag,
        kind: proxy_settings
            .map(|settings| settings.r#type)
            .unwrap_or_default(),
    }
}

/// Wrap a router `Config` in the TypedMessage `AddRule` requires. The `type`
/// string must be the exact protobuf full name (`xray.app.router.Config`);
/// the server resolves it via the global registry and unmarshals `value` as
/// protobuf — there is no JSON path (common/serial/typed_message.go).
fn router_typed_config(config: router_cfg::Config) -> pb::xray::common::serial::TypedMessage {
    use prost::Message;
    pb::xray::common::serial::TypedMessage {
        r#type: "xray.app.router.Config".to_string(),
        value: config.encode_to_vec(),
    }
}

/// One routing rule ready for `RoutingService.AddRule` (trial rules).
///
/// Only the trial-rule surface is convertible: target (outbound xor balancer),
/// rule tag, domains, IPs, and source processes. Every other model field is
/// rejected rather than silently dropped, so a trial rule can never diverge
/// from what the dialog promised. Domain/IP strings use exactly the prefix
/// grammar the core's own parser accepts (common/geodata/rule_parser.go).
pub fn trial_rule_to_pb(rule: &Rule) -> Result<router_cfg::RoutingRule, DiagError> {
    if rule.rule_tag.is_empty() {
        return Err(DiagError::from(Diag::new(Key::GrpcTrialRuleTagRequired)));
    }
    let unsupported = [
        ("port", !rule.port.is_empty()),
        ("sourcePort", !rule.source_port.is_empty()),
        ("localPort", !rule.local_port.is_empty()),
        ("network", !rule.network.is_empty()),
        ("source", !rule.source.is_empty()),
        ("localIP", !rule.local_ip.is_empty()),
        ("user", !rule.user.is_empty()),
        ("inboundTag", !rule.inbound_tag.is_empty()),
        ("protocol", !rule.protocol.is_empty()),
        ("attrs", !rule.attrs.is_empty()),
        ("vlessRoute", !rule.vless_route.is_empty()),
        ("localOS", !rule.local_os.is_empty()),
        ("webhook", rule.webhook.is_some()),
        ("extra", !rule.extra.is_empty()),
    ];
    if let Some((field, _)) = unsupported.iter().find(|(_, set)| *set) {
        return Err(DiagError::from(
            Diag::new(Key::GrpcTrialRuleFieldUnsupported).arg(field),
        ));
    }
    let target_tag = match (rule.outbound_tag.is_empty(), rule.balancer_tag.is_empty()) {
        (true, true) => {
            return Err(DiagError::from(Diag::new(Key::GrpcTrialRuleTargetRequired)));
        }
        (false, false) => {
            return Err(DiagError::from(Diag::new(Key::GrpcTrialRuleTargetConflict)));
        }
        (false, _) => Some(router_cfg::routing_rule::TargetTag::Tag(
            rule.outbound_tag.clone(),
        )),
        (_, false) => Some(router_cfg::routing_rule::TargetTag::BalancingTag(
            rule.balancer_tag.clone(),
        )),
    };
    let domain = rule
        .domain
        .iter()
        .map(|entry| parse_domain_rule(entry))
        .collect::<Result<Vec<_>, _>>()?;
    let ip = rule
        .ip
        .iter()
        .map(|entry| parse_ip_rule(entry))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(router_cfg::RoutingRule {
        rule_tag: rule.rule_tag.clone(),
        target_tag,
        domain,
        ip,
        process: rule.process.clone(),
        ..Default::default()
    })
}

/// Parse one `domain` list entry into a `DomainRule`, mirroring
/// `ParseDomainRules` (common/geodata/rule_parser.go): `geosite:` is sugar
/// for `ext:geosite.dat:`, `ext:*` entries become geosite rules, the
/// `regexp:`/`domain:`/`full:`/`keyword:`/`dotless:` prefixes become typed
/// custom domains, and bare strings are substring matches. The geosite code
/// is not checked against the dat file here, but the core resolves it while
/// it builds the rule condition (`app/router/config.go` `BuildCondition` →
/// `common/geodata` `loadFile`/`find`), so a code the dat file does not
/// carry fails the whole add instead of matching nothing.
fn parse_domain_rule(entry: &str) -> Result<geodata_pb::DomainRule, DiagError> {
    let mut rule = entry.to_string();
    if let Some(rest) = rule.strip_prefix("geosite:") {
        rule = format!("ext:geosite.dat:{rest}");
    }
    let prefix_len = ["ext:", "ext-domain:", "ext-site:"]
        .iter()
        .find_map(|prefix| rule.strip_prefix(prefix).map(|_| prefix.len()));
    let value = if let Some(prefix_len) = prefix_len {
        let rest = &rule[prefix_len..];
        let Some((file, code_with_attrs)) = rest.split_once(':') else {
            return Err(DiagError::from(Diag::new(Key::GrpcGeodataSyntaxError)));
        };
        if file.is_empty() {
            return Err(DiagError::from(Diag::new(Key::GrpcGeodataEmptyFile)));
        }
        if code_with_attrs.ends_with('@') || code_with_attrs.contains("@@") {
            return Err(DiagError::from(Diag::new(Key::GrpcGeodataEmptyAttr)));
        }
        let (code, attrs) = code_with_attrs
            .split_once('@')
            .unwrap_or((code_with_attrs, ""));
        if code.is_empty() {
            return Err(DiagError::from(Diag::new(Key::GrpcGeodataEmptyCode)));
        }
        geodata_pb::domain_rule::Value::Geosite(geodata_pb::GeoSiteRule {
            file: file.to_string(),
            code: code.to_uppercase(),
            attrs: attrs.to_lowercase(),
        })
    } else {
        let (kind, value) = if let Some(rest) = rule.strip_prefix("regexp:") {
            (geodata_pb::domain::Type::Regex, rest.to_string())
        } else if let Some(rest) = rule.strip_prefix("domain:") {
            (geodata_pb::domain::Type::Domain, rest.to_string())
        } else if let Some(rest) = rule.strip_prefix("full:") {
            (geodata_pb::domain::Type::Full, rest.to_string())
        } else if let Some(rest) = rule.strip_prefix("keyword:") {
            (geodata_pb::domain::Type::Substr, rest.to_string())
        } else if let Some(rest) = rule.strip_prefix("dotless:") {
            let value = if rest.is_empty() {
                "^[^.]*$".to_string()
            } else if !rest.contains('.') {
                format!("^[^.]*{rest}[^.]*$")
            } else {
                return Err(DiagError::from(Diag::new(Key::GrpcDotlessRuleContainsDot)));
            };
            (geodata_pb::domain::Type::Regex, value)
        } else {
            (geodata_pb::domain::Type::Substr, rule)
        };
        geodata_pb::domain_rule::Value::Custom(geodata_pb::Domain {
            r#type: kind as i32,
            value,
            attribute: Vec::new(),
        })
    };
    Ok(geodata_pb::DomainRule { value: Some(value) })
}

/// Parse one `ip` list entry into an `IPRule`, mirroring `ParseIPRules`
/// (common/geodata/rule_parser.go): leading `!` toggles reverse matching,
/// `geoip:` is sugar for `ext:geoip.dat:`, `ext:*` entries become geoip
/// rules, and anything else must be an IP literal or CIDR range (v4 prefix
/// ≤ 32, v6 ≤ 128).
fn parse_ip_rule(entry: &str) -> Result<geodata_pb::IpRule, DiagError> {
    let (rule, mut reverse) = cut_reverse_prefix(entry);
    let rule = if let Some(rest) = rule.strip_prefix("geoip:") {
        format!("ext:geoip.dat:{rest}")
    } else {
        rule.to_string()
    };
    let prefix_len = ["ext:", "ext-ip:"]
        .iter()
        .find_map(|prefix| rule.strip_prefix(prefix).map(|_| prefix.len()));
    let value = if let Some(prefix_len) = prefix_len {
        let rest = &rule[prefix_len..];
        let Some((file, code)) = rest.split_once(':') else {
            return Err(DiagError::from(Diag::new(Key::GrpcGeodataSyntaxError)));
        };
        if file.is_empty() {
            return Err(DiagError::from(Diag::new(Key::GrpcGeodataEmptyFile)));
        }
        let (code, code_reverse) = cut_reverse_prefix(code);
        reverse = reverse != code_reverse;
        if code.is_empty() {
            return Err(DiagError::from(Diag::new(Key::GrpcGeodataEmptyCode)));
        }
        geodata_pb::ip_rule::Value::Geoip(geodata_pb::GeoIpRule {
            file: file.to_string(),
            code: code.to_uppercase(),
            reverse_match: reverse,
        })
    } else {
        geodata_pb::ip_rule::Value::Custom(geodata_pb::CidrRule {
            cidr: Some(parse_cidr(&rule)?),
            reverse_match: reverse,
        })
    };
    Ok(geodata_pb::IpRule { value: Some(value) })
}

/// Strip leading `!` negations, toggling `reverse` per occurrence.
fn cut_reverse_prefix(mut rule: &str) -> (&str, bool) {
    let mut reverse = false;
    while let Some(rest) = rule.strip_prefix('!') {
        rule = rest;
        reverse = !reverse;
    }
    (rule, reverse)
}

/// Parse an IP literal or CIDR into 4/16-byte address bytes plus a prefix.
/// A missing prefix means the full width (32/128), mirroring `parseCIDR`.
fn parse_cidr(rule: &str) -> Result<geodata_pb::Cidr, DiagError> {
    let (ip_text, prefix_text) = rule
        .split_once('/')
        .map_or((rule, None), |(ip, prefix)| (ip, Some(prefix)));
    let address: std::net::IpAddr = ip_text
        .parse()
        .map_err(|_| DiagError::from(Diag::new(Key::GrpcUnsupportedAddressFamily)))?;
    let (bytes, max_prefix) = match address {
        std::net::IpAddr::V4(v4) => (v4.octets().to_vec(), 32),
        std::net::IpAddr::V6(v6) => (v6.octets().to_vec(), 128),
    };
    let prefix = match prefix_text {
        Some(text) => {
            let parsed: u32 = text
                .parse()
                .map_err(|_| DiagError::from(Diag::new(Key::GrpcInvalidCidrPrefix).arg(text)))?;
            if parsed > max_prefix {
                return Err(DiagError::from(
                    Diag::new(Key::GrpcCidrPrefixTooLong)
                        .arg(parsed)
                        .arg(max_prefix),
                ));
            }
            parsed
        }
        None => max_prefix,
    };
    Ok(geodata_pb::Cidr { ip: bytes, prefix })
}

/// Build a complete official `RoutingContext` for [`GrpcClient::test_route`].
/// Validation happens before any IP text is converted, so malformed or
/// out-of-range GUI input is reported instead of silently normalized.
pub fn routing_context(
    request: &RouteTestRequest,
) -> Result<router_cmd::RoutingContext, DiagError> {
    request.validate()?;
    let encode_ips = |kind: &str, values: &[String]| {
        values
            .iter()
            .map(|value| {
                value
                    .trim()
                    .parse::<std::net::IpAddr>()
                    .map(|address| match address {
                        std::net::IpAddr::V4(value) => value.octets().to_vec(),
                        std::net::IpAddr::V6(value) => value.octets().to_vec(),
                    })
                    .map_err(|_| {
                        DiagError::from(Diag::new(Key::GrpcInvalidRouteIp).arg(kind).arg(value))
                    })
            })
            .collect::<Result<Vec<_>, _>>()
    };
    let network = match request.network.as_str() {
        "" => Network::Unknown,
        "tcp" => Network::Tcp,
        "udp" => Network::Udp,
        "unix" => Network::Unix,
        value => {
            return Err(DiagError::from(
                Diag::new(Key::GrpcUnsupportedNetwork).arg(value),
            ));
        }
    };
    Ok(router_cmd::RoutingContext {
        inbound_tag: request.inbound_tag.clone(),
        network: network as i32,
        source_i_ps: encode_ips("source", &request.source_ips)?,
        target_i_ps: encode_ips("target", &request.target_ips)?,
        source_port: request.source_port,
        target_port: request.target_port,
        target_domain: request.target_domain.trim().to_string(),
        protocol: request.protocol.clone(),
        user: request.user.clone(),
        attributes: request
            .attributes
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect(),
        local_i_ps: encode_ips("local", &request.local_ips)?,
        local_port: request.local_port,
        vless_route: request.vless_route,
        ..Default::default()
    })
}

fn format_route(ctx: &router_cmd::RoutingContext) -> String {
    let network = match Network::try_from(ctx.network) {
        Ok(Network::Tcp) => "tcp",
        Ok(Network::Udp) => "udp",
        Ok(Network::Unix) => "unix",
        _ => "unknown",
    };
    let target = if !ctx.target_domain.is_empty() {
        format!("{}:{}", ctx.target_domain, ctx.target_port)
    } else if let Some(first) = ctx.target_i_ps.first() {
        let b = first.as_slice();
        match b.len() {
            4 => format!("{}.{}.{}.{}:{}", b[0], b[1], b[2], b[3], ctx.target_port),
            16 => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(b);
                format!("{}:{}", std::net::Ipv6Addr::from(octets), ctx.target_port)
            }
            _ => format!("<ip>:{}", ctx.target_port),
        }
    } else {
        format!("<any>:{}", ctx.target_port)
    };
    let via = if !ctx.outbound_tag.is_empty() {
        format!("'{}'", ctx.outbound_tag)
    } else if !ctx.outbound_group_tags.is_empty() {
        format!("group [{}]", ctx.outbound_group_tags.join(", "))
    } else {
        "<no route>".to_string()
    };
    format!("{network} {target} -> outbound {via}")
}

#[cfg(test)]
mod tests {
    use crate::model::inbound::TUN_INBOUND_TAG;
    use std::net::TcpListener;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::{Duration, Instant};

    use super::{
        CONNECT_TIMEOUT, GrpcClient, HealthPingView, Network, TrialRuleAddOutcome,
        add_rule_outcome, balancer_info_view, balancer_status_diag, format_route,
        pb::xray::app::router::command as router_cmd, router_cfg, routing_context,
        trial_rule_to_pb,
    };
    use crate::i18n::Key;
    use crate::model::routing::RouteTestRequest;
    use crate::model::settings::Language;

    /// Xray copies Go `time.Duration` values into the protobuf, so the burst
    /// window statistics arrive in nanoseconds while the row delay arrives in
    /// milliseconds.
    #[test]
    fn health_ping_view_converts_nanoseconds_to_milliseconds() {
        let view = HealthPingView::from_wire(
            super::pb::xray::core::app::observatory::HealthPingMeasurementResult {
                all: 10,
                fail: 1,
                deviation: 40_000_000,
                average: 123_000_000,
                max: 210_000_000,
                min: 90_000_000,
            },
        );
        assert_eq!((view.all, view.fail), (10, 1));
        assert_eq!(view.average_ms, 123);
        assert_eq!(view.deviation_ms, 40);
        assert_eq!(view.max_ms, 210);
        assert_eq!(view.min_ms, 90);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn stalled_tcp_peer_is_cancelled_by_local_rpc_deadline() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind stalling API");
        listener
            .set_nonblocking(true)
            .expect("nonblocking listener");
        let port = listener.local_addr().expect("listener address").port();
        let stop = Arc::new(AtomicBool::new(false));
        let server_stop = Arc::clone(&stop);
        let server = std::thread::spawn(move || {
            let mut accepted = None;
            while !server_stop.load(Ordering::Acquire) {
                if accepted.is_none() {
                    match listener.accept() {
                        Ok((stream, _)) => accepted = Some(stream),
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                        Err(error) => panic!("stall listener accept failed: {error}"),
                    }
                }
                std::thread::sleep(Duration::from_millis(2));
            }
            drop(accepted);
        });

        // The connect timeout must stay above the local deadline under test —
        // the production ordering, `CONNECT_TIMEOUT` against `RPC_TIMEOUT`. A
        // shorter one lets a loaded runner return the transport error before
        // the deadline fires, which made this test load-dependent.
        let client = GrpcClient::with_timeouts(
            port,
            CONNECT_TIMEOUT,
            Duration::from_millis(100),
            Duration::from_millis(100),
        );
        let started = Instant::now();
        let error = client
            .get_sys_stats()
            .await
            .expect_err("stalling API must time out");
        let elapsed = started.elapsed();
        stop.store(true, Ordering::Release);
        server.join().expect("stall server thread");

        assert_eq!(error.code(), tonic::Code::DeadlineExceeded);
        // A sanity bound, not a latency assertion: the deadline is 100 ms, and
        // a loaded runner overshoots it. The bound only has to catch a deadline
        // that never fires.
        assert!(
            elapsed < Duration::from_secs(2),
            "local deadline was not enforced: {elapsed:?}"
        );
    }

    #[test]
    fn route_context_preserves_every_editable_dimension() {
        let request = RouteTestRequest {
            target_domain: "example.com".to_string(),
            target_ips: vec!["2001:db8::1".to_string()],
            target_port: 8443,
            source_ips: vec!["192.0.2.8".to_string()],
            source_port: 53000,
            local_ips: vec!["127.0.0.1".to_string(), "::1".to_string()],
            local_port: 1080,
            inbound_tag: TUN_INBOUND_TAG.to_string(),
            user: "broccoli@example.com".to_string(),
            protocol: "tls".to_string(),
            network: "udp".to_string(),
            vless_route: 65535,
            attributes: [("tenant".to_string(), "blue".to_string())]
                .into_iter()
                .collect(),
        };

        let context = routing_context(&request).expect("valid full route context");
        assert_eq!(context.target_domain, "example.com");
        assert_eq!(context.target_port, 8443);
        assert_eq!(
            context.target_i_ps,
            vec![
                "2001:db8::1"
                    .parse::<std::net::Ipv6Addr>()
                    .unwrap()
                    .octets()
                    .to_vec()
            ]
        );
        assert_eq!(context.source_i_ps, vec![vec![192, 0, 2, 8]]);
        assert_eq!(context.source_port, 53000);
        assert_eq!(
            context.local_i_ps,
            vec![
                vec![127, 0, 0, 1],
                vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
            ]
        );
        assert_eq!(context.local_port, 1080);
        assert_eq!(context.inbound_tag, TUN_INBOUND_TAG);
        assert_eq!(context.user, "broccoli@example.com");
        assert_eq!(context.protocol, "tls");
        assert_eq!(context.network, Network::Udp as i32);
        assert_eq!(context.vless_route, 65535);
        assert_eq!(
            context.attributes.get("tenant").map(String::as_str),
            Some("blue")
        );
    }

    #[test]
    fn route_target_renders_canonical_ipv6_literal() {
        // 0x2001:0x0db8::1 — expected string derived from the compiled
        // standard-library conversion (canonical "2001:db8::1"), not a
        // hand-typed guess.
        let bytes = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let canonical = std::net::Ipv6Addr::from(bytes).to_string();
        let context = router_cmd::RoutingContext {
            network: Network::Tcp as i32,
            target_i_ps: vec![bytes.to_vec()],
            target_port: 443,
            ..Default::default()
        };

        assert_eq!(
            format_route(&context),
            format!("tcp {canonical}:443 -> outbound <no route>")
        );
    }

    #[test]
    fn balancer_info_maps_empty_override_to_following_strategy() {
        let view = balancer_info_view(router_cmd::BalancerMsg {
            r#override: Some(router_cmd::OverrideInfo {
                target: String::new(),
            }),
            principle_target: Some(router_cmd::PrincipleTargetInfo {
                tag: vec!["srv-a".into(), "srv-b".into()],
            }),
        });

        assert_eq!(view.override_target, None);
        assert_eq!(
            view.principle_targets,
            Some(vec!["srv-a".into(), "srv-b".into()])
        );
    }

    use super::pb::xray::common::geodata::{domain, domain_rule, ip_rule};
    use crate::model::routing::Rule;

    #[test]
    fn trial_rule_maps_domains_ips_processes_and_target() {
        let rule = Rule {
            rule_tag: "trial-1".into(),
            outbound_tag: "direct".into(),
            domain: vec![
                "geosite:cn".into(),
                "example.com".into(),
                "domain:maps.google.com".into(),
                "full:exact.example".into(),
                "regexp:^ads\\.example$".into(),
                "keyword:tracker".into(),
            ],
            ip: vec![
                "geoip:private".into(),
                "192.0.2.0/24".into(),
                "2001:db8::1".into(),
                "!10.0.0.0/8".into(),
            ],
            process: vec!["firefox.exe".into(), "xray/".into()],
            ..Default::default()
        };

        let pb = trial_rule_to_pb(&rule).expect("valid trial rule");
        assert_eq!(pb.rule_tag, "trial-1");
        assert!(matches!(
            pb.target_tag,
            Some(router_cfg::routing_rule::TargetTag::Tag(tag)) if tag == "direct"
        ));
        assert_eq!(pb.domain.len(), 6);
        assert_eq!(pb.ip.len(), 4);
        assert_eq!(pb.process, vec!["firefox.exe", "xray/"]);

        // geosite:cn → geosite rule against the default dat, code uppercased.
        match pb.domain[0].value.as_ref().expect("domain value") {
            domain_rule::Value::Geosite(rule) => {
                assert_eq!(rule.file, "geosite.dat");
                assert_eq!(rule.code, "CN");
                assert!(rule.attrs.is_empty());
            }
            _ => panic!("geosite:cn must map to a geosite rule"),
        }
        // Bare string → substring custom domain.
        match pb.domain[1].value.as_ref().expect("domain value") {
            domain_rule::Value::Custom(domain) => {
                assert_eq!(domain.r#type, domain::Type::Substr as i32);
                assert_eq!(domain.value, "example.com");
            }
            _ => panic!("bare domain must map to a custom domain"),
        }
        // Prefixes map to their types.
        match pb.domain[2].value.as_ref().expect("domain value") {
            domain_rule::Value::Custom(domain) => {
                assert_eq!(domain.r#type, domain::Type::Domain as i32);
                assert_eq!(domain.value, "maps.google.com");
            }
            _ => panic!("domain: prefix must map to a typed custom domain"),
        }
        match pb.domain[3].value.as_ref().expect("domain value") {
            domain_rule::Value::Custom(domain) => {
                assert_eq!(domain.r#type, domain::Type::Full as i32);
                assert_eq!(domain.value, "exact.example");
            }
            _ => panic!("full: prefix must map to a typed custom domain"),
        }
        match pb.domain[4].value.as_ref().expect("domain value") {
            domain_rule::Value::Custom(domain) => {
                assert_eq!(domain.r#type, domain::Type::Regex as i32);
                assert_eq!(domain.value, "^ads\\.example$");
            }
            _ => panic!("regexp: prefix must map to a typed custom domain"),
        }
        match pb.domain[5].value.as_ref().expect("domain value") {
            domain_rule::Value::Custom(domain) => {
                assert_eq!(domain.r#type, domain::Type::Substr as i32);
                assert_eq!(domain.value, "tracker");
            }
            _ => panic!("keyword: prefix must map to a typed custom domain"),
        }

        // geoip:private → geoip rule, code uppercased, no reverse.
        match pb.ip[0].value.as_ref().expect("ip value") {
            ip_rule::Value::Geoip(rule) => {
                assert_eq!(rule.file, "geoip.dat");
                assert_eq!(rule.code, "PRIVATE");
                assert!(!rule.reverse_match);
            }
            _ => panic!("geoip:private must map to a geoip rule"),
        }
        // CIDR keeps 4-byte address + prefix.
        match pb.ip[1].value.as_ref().expect("ip value") {
            ip_rule::Value::Custom(rule) => {
                let cidr = rule.cidr.as_ref().expect("cidr");
                assert_eq!(cidr.ip, vec![192, 0, 2, 0]);
                assert_eq!(cidr.prefix, 24);
                assert!(!rule.reverse_match);
            }
            _ => panic!("CIDR must map to a custom ip rule"),
        }
        // Bare v6 literal → full-width prefix, 16-byte address.
        match pb.ip[2].value.as_ref().expect("ip value") {
            ip_rule::Value::Custom(rule) => {
                let cidr = rule.cidr.as_ref().expect("cidr");
                assert_eq!(cidr.ip.len(), 16);
                assert_eq!(cidr.prefix, 128);
            }
            _ => panic!("bare IP must map to a custom ip rule"),
        }
        // Leading ! toggles reverse matching.
        match pb.ip[3].value.as_ref().expect("ip value") {
            ip_rule::Value::Custom(rule) => {
                assert!(rule.reverse_match);
                assert_eq!(rule.cidr.as_ref().expect("cidr").prefix, 8);
            }
            _ => panic!("negated CIDR must map to a custom ip rule"),
        }
    }

    #[test]
    fn trial_rule_balancer_target_uses_balancing_tag_oneof() {
        let rule = Rule {
            rule_tag: "trial-2".into(),
            balancer_tag: "accel".into(),
            ..Default::default()
        };
        let pb = trial_rule_to_pb(&rule).expect("valid balancer target");
        assert!(matches!(
            pb.target_tag,
            Some(router_cfg::routing_rule::TargetTag::BalancingTag(tag)) if tag == "accel"
        ));

        let mut both = rule;
        both.outbound_tag = "direct".into();
        let error = trial_rule_to_pb(&both).expect_err("both targets must be rejected");
        assert_eq!(error.diag().key(), Key::GrpcTrialRuleTargetConflict);
    }

    #[test]
    fn trial_rule_rejects_unsupported_fields_and_bad_grammar() {
        let base = || Rule {
            rule_tag: "trial-3".into(),
            outbound_tag: "direct".into(),
            ..Default::default()
        };

        let mut rule = base();
        rule.port = "443".into();
        let error = trial_rule_to_pb(&rule).expect_err("port is unsupported");
        assert_eq!(error.diag().key(), Key::GrpcTrialRuleFieldUnsupported);
        assert!(
            error.text(Language::En).contains("port"),
            "the field name must survive, got: {error}"
        );

        let mut rule = base();
        rule.network = "tcp".into();
        let error = trial_rule_to_pb(&rule).expect_err("network is unsupported");
        assert_eq!(error.diag().key(), Key::GrpcTrialRuleFieldUnsupported);
        assert!(
            error.text(Language::En).contains("network"),
            "the field name must survive, got: {error}"
        );

        let mut rule = base();
        rule.webhook = Some(crate::model::routing::Webhook::default());
        let error = trial_rule_to_pb(&rule).expect_err("webhook is unsupported");
        assert_eq!(error.diag().key(), Key::GrpcTrialRuleFieldUnsupported);
        assert!(
            error.text(Language::En).contains("webhook"),
            "the field name must survive, got: {error}"
        );

        let mut rule = base();
        rule.local_os = vec!["windows".into()];
        let error = trial_rule_to_pb(&rule).expect_err("localOS is unsupported");
        assert_eq!(error.diag().key(), Key::GrpcTrialRuleFieldUnsupported);
        assert!(
            error.text(Language::En).contains("localOS"),
            "the field name must survive, got: {error}"
        );

        let mut rule = base();
        rule.ip = vec!["999.1.2.3".into()];
        let error = trial_rule_to_pb(&rule).expect_err("bad IP");
        assert_eq!(error.diag().key(), Key::GrpcUnsupportedAddressFamily);

        let mut rule = base();
        rule.ip = vec!["10.0.0.0/40".into()];
        let error = trial_rule_to_pb(&rule).expect_err("prefix too long");
        assert_eq!(error.diag().key(), Key::GrpcCidrPrefixTooLong);

        let mut rule = base();
        rule.domain = vec!["geosite:".into()];
        let error = trial_rule_to_pb(&rule).expect_err("empty geosite code");
        assert_eq!(error.diag().key(), Key::GrpcGeodataEmptyCode);

        let mut rule = base();
        rule.rule_tag.clear();
        let error = trial_rule_to_pb(&rule).expect_err("missing tag");
        assert_eq!(error.diag().key(), Key::GrpcTrialRuleTagRequired);

        let mut rule = base();
        rule.outbound_tag.clear();
        rule.balancer_tag.clear();
        let error = trial_rule_to_pb(&rule).expect_err("missing target");
        assert_eq!(error.diag().key(), Key::GrpcTrialRuleTargetRequired);
    }

    #[test]
    fn add_rule_outcome_reports_the_readback_after_a_confirmed_add() {
        let live = vec![("direct".to_string(), "trial-6".to_string())];
        let outcome = add_rule_outcome("trial-6", Ok(()), Ok(live.clone()))
            .expect("a confirmed add is a success");
        assert_eq!(outcome, TrialRuleAddOutcome { rules: Some(live) });
    }

    #[test]
    fn add_rule_outcome_survives_a_failed_readback_after_a_confirmed_add() {
        let outcome = add_rule_outcome(
            "trial-7",
            Ok(()),
            Err(tonic::Status::unavailable("core went away")),
        )
        .expect("the core accepted the rule, so the add must not be reported as failed");
        assert_eq!(outcome.rules, None);
    }

    #[test]
    fn add_rule_outcome_accepts_a_reply_failure_the_readback_contradicts() {
        // Xray's AddRule handler completes the mutation server-side and never
        // reads the request context (app/router/command/command.go), so a
        // local deadline expiry cancels the client's wait while the rule is
        // live; the read-back is the only authority.
        let live = vec![
            ("direct".to_string(), "trial-8".to_string()),
            ("direct".to_string(), String::new()),
        ];
        let outcome = add_rule_outcome(
            "trial-8",
            Err(tonic::Status::deadline_exceeded("local deadline")),
            Ok(live.clone()),
        )
        .expect("the read-back lists the tag, so the add landed");
        assert_eq!(outcome, TrialRuleAddOutcome { rules: Some(live) });
    }

    #[test]
    fn add_rule_outcome_fails_when_the_readback_lacks_the_tag() {
        let error = add_rule_outcome(
            "trial-9",
            Err(tonic::Status::unknown("duplicate ruleTag trial-9")),
            Ok(vec![("direct".to_string(), "other".to_string())]),
        )
        .expect_err("neither the reply nor the read-back shows the rule");
        assert_eq!(error.diag().key(), Key::GrpcAddRuleFailed);
        let cause =
            std::error::Error::source(&error).expect("the add's own status stays the cause");
        assert!(
            cause.to_string().contains("duplicate ruleTag trial-9"),
            "the add's own failure must survive as the cause, got: {cause}"
        );
    }

    #[test]
    fn add_rule_outcome_fails_when_the_add_and_the_readback_both_fail() {
        let error = add_rule_outcome(
            "trial-10",
            Err(tonic::Status::unavailable("core down")),
            Err(tonic::Status::unavailable("core down")),
        )
        .expect_err("nothing proves the core holds the rule");
        assert_eq!(error.diag().key(), Key::GrpcAddRuleFailed);
        let cause =
            std::error::Error::source(&error).expect("the add's own status stays the cause");
        assert!(
            cause.to_string().contains("core down"),
            "the add's own failure must survive as the cause, got: {cause}"
        );
    }

    #[test]
    fn add_rule_outcome_matches_the_trimmed_rule_tag() {
        let live = vec![("direct".to_string(), "trial-11".to_string())];
        let outcome = add_rule_outcome(
            "  trial-11  ",
            Err(tonic::Status::unknown("duplicate ruleTag trial-11")),
            Ok(live.clone()),
        )
        .expect("the padded tag must match the trimmed read-back tag");
        assert_eq!(outcome, TrialRuleAddOutcome { rules: Some(live) });
    }

    #[test]
    fn balancer_status_diag_names_a_balancer_the_core_does_not_know() {
        let error = balancer_status_diag(
            Key::GrpcBalancerInfoFailed,
            "lb-a",
            tonic::Status::unknown("cannot find tag"),
        );
        assert_eq!(error.diag().key(), Key::GrpcBalancerNotFound);
        assert_eq!(
            error.text(Language::En),
            "The running core has no balancer named lb-a. Apply the configuration, \
             then refresh the runtime state."
        );
    }

    #[test]
    fn balancer_status_diag_keeps_the_wrapper_for_any_other_status() {
        let error = balancer_status_diag(
            Key::GrpcBalancerOverrideFailed,
            "lb-a",
            tonic::Status::unknown("failed to dial the dispatcher"),
        );
        assert_eq!(error.diag().key(), Key::GrpcBalancerOverrideFailed);
        let cause =
            std::error::Error::source(&error).expect("the core status stays under the wrapper");
        assert!(
            cause.to_string().contains("failed to dial the dispatcher"),
            "an unrelated core failure must keep the wrapper plus its cause, got: {cause}"
        );
    }

    #[test]
    fn trial_rule_dotless_builds_anchored_regex() {
        let rule = Rule {
            rule_tag: "trial-4".into(),
            outbound_tag: "direct".into(),
            domain: vec!["dotless:".into(), "dotless:music".into()],
            ..Default::default()
        };
        let pb = trial_rule_to_pb(&rule).expect("valid dotless rules");
        match pb.domain[0].value.as_ref().expect("domain value") {
            domain_rule::Value::Custom(domain) => {
                assert_eq!(domain.r#type, domain::Type::Regex as i32);
                assert_eq!(domain.value, "^[^.]*$");
            }
            _ => panic!("empty dotless must map to the anchored regex"),
        }
        match pb.domain[1].value.as_ref().expect("domain value") {
            domain_rule::Value::Custom(domain) => {
                assert_eq!(domain.r#type, domain::Type::Regex as i32);
                assert_eq!(domain.value, "^[^.]*music[^.]*$");
            }
            _ => panic!("dotless must map to the anchored regex"),
        }

        let rule = Rule {
            rule_tag: "trial-5".into(),
            outbound_tag: "direct".into(),
            domain: vec!["dotless:mu.sic".into()],
            ..Default::default()
        };
        let error = trial_rule_to_pb(&rule).expect_err("dotted dotless");
        assert_eq!(error.diag().key(), Key::GrpcDotlessRuleContainsDot);
    }
}
