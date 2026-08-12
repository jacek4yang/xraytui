//! The high-level API client the controller uses.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use tokio_stream::{Stream, StreamExt};
use tonic::transport::Channel;

use crate::proto::log::RestartLoggerRequest;
use crate::proto::proxyman::{ListInboundsRequest, ListOutboundsRequest, RemoveOutboundRequest};
use crate::proto::router::{
    GetBalancerInfoRequest, ListRuleRequest, OverrideBalancerTargetRequest, RemoveRuleRequest,
    RoutingContext, SubscribeRoutingStatsRequest, TestRouteRequest,
};
use crate::proto::stats::{GetStatsRequest, QueryStatsRequest, SysStatsRequest};
use crate::{ApiEndpoint, ApiError, Services, connect_tcp, connect_uds};

/// Default per-call deadline. Every RPC xraytui makes is a local loopback call,
/// so anything slower than this indicates a wedged core rather than a slow link.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

/// A connected Xray commander.
#[derive(Clone)]
pub struct ApiClient {
    services: Services,
    endpoint: ApiEndpoint,
}

impl std::fmt::Debug for ApiClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiClient").field("endpoint", &self.endpoint).finish_non_exhaustive()
    }
}

impl ApiClient {
    /// Connect to a commander.
    ///
    /// # Errors
    /// Returns [`ApiError::Connect`] when the transport cannot be established.
    pub async fn connect(endpoint: &ApiEndpoint, timeout: Duration) -> Result<Self, ApiError> {
        let channel: Channel = match endpoint {
            ApiEndpoint::Tcp { authority } => connect_tcp(authority, timeout).await?,
            ApiEndpoint::Unix { path } => connect_uds(path, timeout).await?,
        };
        Ok(Self { services: Services::new(channel), endpoint: endpoint.clone() })
    }

    /// Connect, retrying until the deadline expires.
    ///
    /// Xray binds its listeners a moment after the process starts, so the first
    /// few attempts after a spawn are expected to fail with `Connection refused`.
    ///
    /// # Errors
    /// Returns [`ApiError::NotReady`] if the deadline passes without a
    /// successful `ListOutbounds` call.
    pub async fn connect_ready(
        endpoint: &ApiEndpoint,
        deadline: Duration,
        poll_interval: Duration,
    ) -> Result<Self, ApiError> {
        let started = Instant::now();
        let mut last: Option<ApiError> = None;
        while started.elapsed() < deadline {
            match Self::connect(endpoint, DEFAULT_TIMEOUT).await {
                Ok(mut client) => match client.list_outbound_tags().await {
                    Ok(_) => return Ok(client),
                    Err(error) => last = Some(error),
                },
                Err(error) => last = Some(error),
            }
            tokio::time::sleep(poll_interval).await;
        }
        Err(match last {
            Some(error) if !error.is_transient() => error,
            _ => ApiError::NotReady(deadline),
        })
    }

    /// The endpoint this client is bound to.
    #[must_use]
    pub fn endpoint(&self) -> &ApiEndpoint {
        &self.endpoint
    }

    // ------------------------------------------------------------- handler

    /// Tags of every outbound the core currently has.
    ///
    /// # Errors
    /// Propagates the gRPC status.
    pub async fn list_outbound_tags(&mut self) -> Result<Vec<String>, ApiError> {
        let response = self
            .services
            .handler
            .list_outbounds(ListOutboundsRequest {})
            .await
            .map_err(|s| ApiError::call("ListOutbounds", s))?;
        Ok(response.into_inner().outbounds.into_iter().map(|o| o.tag).collect())
    }

    /// Tags of every inbound the core currently has.
    ///
    /// # Errors
    /// Propagates the gRPC status.
    pub async fn list_inbound_tags(&mut self) -> Result<Vec<String>, ApiError> {
        let response = self
            .services
            .handler
            .list_inbounds(ListInboundsRequest { is_only_tags: true })
            .await
            .map_err(|s| ApiError::call("ListInbounds", s))?;
        Ok(response.into_inner().inbounds.into_iter().map(|i| i.tag).collect())
    }

    /// Remove an outbound by tag.
    ///
    /// # Errors
    /// Propagates the gRPC status.
    pub async fn remove_outbound(&mut self, tag: &str) -> Result<(), ApiError> {
        self.services
            .handler
            .remove_outbound(RemoveOutboundRequest { tag: tag.to_owned() })
            .await
            .map_err(|s| ApiError::call("RemoveOutbound", s))?;
        Ok(())
    }

    // ------------------------------------------------------------- routing

    /// Point a balancer at a concrete outbound tag.
    ///
    /// This is the profile hot-switch. Upstream applies the override ahead of the
    /// balancer's strategy and does **not** validate it against the selector, so
    /// any existing outbound tag is a legal target. The override is process
    /// state: it does not survive a core restart, which is why the controller
    /// re-applies every override as part of its start sequence.
    ///
    /// # Errors
    /// Propagates the gRPC status; a missing balancer tag surfaces as
    /// `Unknown`/`Internal` with "cannot find tag".
    pub async fn override_balancer(&mut self, balancer: &str, target: &str) -> Result<(), ApiError> {
        self.services
            .routing
            .override_balancer_target(OverrideBalancerTargetRequest {
                balancer_tag: balancer.to_owned(),
                target: target.to_owned(),
            })
            .await
            .map_err(|s| ApiError::call("OverrideBalancerTarget", s))?;
        Ok(())
    }

    /// Read back a balancer's current override and principle targets.
    ///
    /// # Errors
    /// Propagates the gRPC status.
    pub async fn balancer_info(&mut self, tag: &str) -> Result<BalancerInfo, ApiError> {
        let response = self
            .services
            .routing
            .get_balancer_info(GetBalancerInfoRequest { tag: tag.to_owned() })
            .await
            .map_err(|s| ApiError::call("GetBalancerInfo", s))?;
        let balancer = response.into_inner().balancer.unwrap_or_default();
        Ok(BalancerInfo {
            override_target: balancer.r#override.map(|o| o.target).filter(|t| !t.is_empty()),
            principle_targets: balancer.principle_target.map(|p| p.tag).unwrap_or_default(),
        })
    }

    /// Every routing rule the core has, as `(tag, ruleTag)` pairs.
    ///
    /// # Errors
    /// Propagates the gRPC status.
    pub async fn list_rules(&mut self) -> Result<Vec<(String, String)>, ApiError> {
        let response = self
            .services
            .routing
            .list_rule(ListRuleRequest {})
            .await
            .map_err(|s| ApiError::call("ListRule", s))?;
        Ok(response.into_inner().rules.into_iter().map(|r| (r.tag, r.rule_tag)).collect())
    }

    /// Remove a routing rule by its `ruleTag`.
    ///
    /// # Errors
    /// Propagates the gRPC status.
    pub async fn remove_rule(&mut self, rule_tag: &str) -> Result<(), ApiError> {
        self.services
            .routing
            .remove_rule(RemoveRuleRequest { rule_tag: rule_tag.to_owned() })
            .await
            .map_err(|s| ApiError::call("RemoveRule", s))?;
        Ok(())
    }

    /// Ask the core which outbound a hypothetical connection would take.
    ///
    /// Nothing is dialled; `publish_result` is left false so the simulation does
    /// not appear in the routing event stream.
    ///
    /// # Errors
    /// Propagates the gRPC status.
    pub async fn test_route(&mut self, query: RouteQuery) -> Result<RouteDecision, ApiError> {
        let context = RoutingContext {
            inbound_tag: query.inbound_tag.unwrap_or_default(),
            network: match query.network.as_deref() {
                Some("udp") => 2,
                _ => 1,
            },
            target_domain: query.domain.unwrap_or_default(),
            target_i_ps: query
                .ip
                .as_deref()
                .and_then(|ip| ip.parse::<std::net::IpAddr>().ok())
                .map(|ip| match ip {
                    std::net::IpAddr::V4(v4) => vec![v4.octets().to_vec()],
                    std::net::IpAddr::V6(v6) => vec![v6.octets().to_vec()],
                })
                .unwrap_or_default(),
            target_port: u32::from(query.port),
            protocol: query.protocol.unwrap_or_default(),
            attributes: query.attributes,
            ..Default::default()
        };
        let response = self
            .services
            .routing
            .test_route(TestRouteRequest {
                routing_context: Some(context),
                field_selectors: Vec::new(),
                publish_result: false,
            })
            .await
            .map_err(|s| ApiError::call("TestRoute", s))?;
        let result = response.into_inner();
        Ok(RouteDecision {
            outbound_tag: result.outbound_tag,
            outbound_group_tags: result.outbound_group_tags,
        })
    }

    /// Subscribe to routing decisions as they happen.
    ///
    /// Only metadata is delivered — inbound/outbound tags, network, addresses,
    /// ports and the matched rule. No payload is ever read; see `<non_goals>` in
    /// the project specification and `docs/NETWORKING.md`.
    ///
    /// # Errors
    /// Propagates the gRPC status.
    pub async fn subscribe_routing(
        &mut self,
    ) -> Result<impl Stream<Item = Result<RoutingContext, tonic::Status>>, ApiError> {
        let response = self
            .services
            .routing
            .subscribe_routing_stats(SubscribeRoutingStatsRequest {
                field_selectors: vec![
                    "inbound".into(),
                    "network".into(),
                    "ip".into(),
                    "port".into(),
                    "domain".into(),
                    "protocol".into(),
                    "outbound".into(),
                ],
            })
            .await
            .map_err(|s| ApiError::call("SubscribeRoutingStats", s))?;
        Ok(response.into_inner().map(|item| item))
    }

    // --------------------------------------------------------------- stats

    /// Read one counter.
    ///
    /// # Errors
    /// Propagates the gRPC status.
    pub async fn stat(&mut self, name: &str, reset: bool) -> Result<i64, ApiError> {
        let response = self
            .services
            .stats
            .get_stats(GetStatsRequest { name: name.to_owned(), reset })
            .await
            .map_err(|s| ApiError::call("GetStats", s))?;
        Ok(response.into_inner().stat.map(|s| s.value).unwrap_or_default())
    }

    /// Read every counter matching a substring pattern.
    ///
    /// # Errors
    /// Propagates the gRPC status.
    pub async fn query_stats(
        &mut self,
        pattern: &str,
        reset: bool,
    ) -> Result<BTreeMap<String, i64>, ApiError> {
        let response = self
            .services
            .stats
            .query_stats(QueryStatsRequest { pattern: pattern.to_owned(), reset })
            .await
            .map_err(|s| ApiError::call("QueryStats", s))?;
        Ok(response.into_inner().stat.into_iter().map(|s| (s.name, s.value)).collect())
    }

    /// Process-level statistics: goroutines, memory, uptime.
    ///
    /// # Errors
    /// Propagates the gRPC status.
    pub async fn sys_stats(&mut self) -> Result<SysStats, ApiError> {
        let response = self
            .services
            .stats
            .get_sys_stats(SysStatsRequest {})
            .await
            .map_err(|s| ApiError::call("GetSysStats", s))?;
        let stats = response.into_inner();
        Ok(SysStats {
            goroutines: stats.num_goroutine,
            alloc_bytes: stats.alloc,
            sys_bytes: stats.sys,
            uptime_secs: stats.uptime,
        })
    }

    // -------------------------------------------------------------- logger

    /// Ask the core to reopen its log files, for log rotation.
    ///
    /// # Errors
    /// Propagates the gRPC status.
    pub async fn restart_logger(&mut self) -> Result<(), ApiError> {
        self.services
            .logger
            .restart_logger(RestartLoggerRequest {})
            .await
            .map_err(|s| ApiError::call("RestartLogger", s))?;
        Ok(())
    }
}

/// What a balancer currently points at.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BalancerInfo {
    /// The override in force, if any.
    pub override_target: Option<String>,
    /// The candidates the strategy would choose between.
    pub principle_targets: Vec<String>,
}

/// A hypothetical connection to test.
#[derive(Debug, Clone, Default)]
pub struct RouteQuery {
    /// Inbound tag to simulate arrival on.
    pub inbound_tag: Option<String>,
    /// `tcp` or `udp`.
    pub network: Option<String>,
    /// Destination domain.
    pub domain: Option<String>,
    /// Destination IP.
    pub ip: Option<String>,
    /// Destination port.
    pub port: u16,
    /// Sniffed protocol.
    pub protocol: Option<String>,
    /// Extra attributes.
    pub attributes: std::collections::HashMap<String, String>,
}

/// The answer to a [`RouteQuery`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteDecision {
    /// Outbound the connection would take.
    pub outbound_tag: String,
    /// Balancer groups consulted on the way.
    pub outbound_group_tags: Vec<String>,
}

/// Process statistics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SysStats {
    /// Live goroutines.
    pub goroutines: u32,
    /// Bytes currently allocated.
    pub alloc_bytes: u64,
    /// Bytes obtained from the OS.
    pub sys_bytes: u64,
    /// Seconds since the core started.
    pub uptime_secs: u32,
}

/// Which commander services a particular core actually serves.
///
/// Xray's commander does not implement gRPC reflection, so each service is
/// probed with a cheap read-only call and `Unimplemented` is recorded as absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capabilities {
    /// `HandlerService` responds.
    pub handler: bool,
    /// `RoutingService` responds.
    pub routing: bool,
    /// `RoutingService.OverrideBalancerTarget` is usable.
    pub balancer_override: bool,
    /// `RoutingService.ListRule` is usable, implying `ruleTag`/`RemoveRule`.
    pub rule_management: bool,
    /// `RoutingService.TestRoute` is usable.
    pub test_route: bool,
    /// `StatsService` responds.
    pub stats: bool,
    /// `LoggerService` responds.
    pub logger: bool,
}

impl Capabilities {
    /// The minimum xraytui needs in order to run at all.
    #[must_use]
    pub fn is_sufficient(&self) -> bool {
        self.handler && self.routing && self.balancer_override
    }

    /// Human-readable list of missing capabilities, for `xraytui doctor`.
    #[must_use]
    pub fn missing(&self) -> Vec<&'static str> {
        let mut out = Vec::new();
        if !self.handler {
            out.push("HandlerService");
        }
        if !self.routing {
            out.push("RoutingService");
        }
        if !self.balancer_override {
            out.push("RoutingService.OverrideBalancerTarget (profile switching)");
        }
        if !self.rule_management {
            out.push("RoutingService.ListRule/RemoveRule (runtime rule edits)");
        }
        if !self.test_route {
            out.push("RoutingService.TestRoute (rule explanation)");
        }
        if !self.stats {
            out.push("StatsService (traffic counters)");
        }
        if !self.logger {
            out.push("LoggerService (log rotation)");
        }
        out
    }

    /// Probe a live core.
    ///
    /// `probe_balancer` should be a balancer tag the caller knows exists;
    /// override support is confirmed by reading it back rather than by writing.
    pub async fn probe(client: &mut ApiClient, probe_balancer: Option<&str>) -> Self {
        async fn ok<T>(result: Result<T, ApiError>) -> bool {
            match result {
                Ok(_) => true,
                Err(error) => !error.is_unimplemented(),
            }
        }

        let handler = ok(client.list_outbound_tags().await).await;
        let routing = ok(client.list_rules().await).await;
        let rule_management = client.list_rules().await.is_ok();
        let balancer_override = match probe_balancer {
            Some(tag) => match client.balancer_info(tag).await {
                Ok(_) => true,
                Err(error) => !error.is_unimplemented(),
            },
            None => routing,
        };
        let test_route = match client.test_route(RouteQuery {
            domain: Some("example.invalid".into()),
            port: 443,
            network: Some("tcp".into()),
            ..Default::default()
        })
        .await
        {
            Ok(_) => true,
            Err(error) => !error.is_unimplemented(),
        };
        let stats = ok(client.sys_stats().await).await;
        let logger = ok(client.restart_logger().await).await;

        Self { handler, routing, balancer_override, rule_management, test_route, stats, logger }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_sufficiency_requires_switching() {
        let full = Capabilities {
            handler: true,
            routing: true,
            balancer_override: true,
            rule_management: true,
            test_route: true,
            stats: true,
            logger: true,
        };
        assert!(full.is_sufficient());
        assert!(full.missing().is_empty());

        let no_override = Capabilities { balancer_override: false, ..full };
        assert!(!no_override.is_sufficient());
        assert_eq!(no_override.missing().len(), 1);
    }

    #[tokio::test]
    async fn connecting_to_a_dead_endpoint_fails_transiently() {
        // Port 1 on loopback has nothing listening in any sane environment.
        let error = ApiClient::connect(&ApiEndpoint::loopback(1), Duration::from_millis(200))
            .await
            .expect_err("must fail");
        assert!(error.is_transient(), "{error}");
    }

    #[tokio::test]
    async fn connect_ready_gives_up_at_the_deadline() {
        let error = ApiClient::connect_ready(
            &ApiEndpoint::loopback(1),
            Duration::from_millis(300),
            Duration::from_millis(50),
        )
        .await
        .expect_err("must fail");
        assert!(error.is_transient(), "{error}");
    }

    #[test]
    fn missing_socket_path_is_reported_as_a_connect_failure() {
        let endpoint = ApiEndpoint::unix("/nonexistent/xraytui-test.sock");
        assert!(endpoint.to_string().starts_with("unix://"));
    }
}
