//! Upstream DNS server configuration and latency probing handlers.

use axum::Json;
use axum::extract::State;
use sito_core::config::{UpstreamConfig, UpstreamStrategy};
use sito_proto::{Message, MessageType, Name, OpCode, Query, RecordType};
use sito_upstream::{BootstrapResolver, DotUpstream, PlainUpstream, Upstream};
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::auth::rbac::RequireOperator;
use crate::config_writer::save_config_atomic;
use crate::error::ProblemDetails;
use crate::models::{
    UpstreamConfigDto, UpstreamTestItem, UpstreamTestRequest, UpstreamTestResponse,
};
use crate::state::ServerContext;

/// Get current upstream DNS configuration.
#[utoipa::path(
    get,
    path = "/api/v1/upstream",
    responses(
        (status = 200, description = "Current upstream DNS configuration", body = UpstreamConfigDto),
        (status = 401, description = "Unauthorized", body = ProblemDetails),
        (status = 403, description = "Forbidden", body = ProblemDetails)
    ),
    security(("bearer_auth" = []), ("cookie_auth" = []))
)]
pub async fn get_upstream_config(
    _operator: RequireOperator,
    State(ctx): State<ServerContext>,
) -> Json<UpstreamConfigDto> {
    let cfg = ctx.config.load();
    let up = &cfg.upstream;

    let strategy_str = match up.strategy {
        UpstreamStrategy::Failover => "failover",
        UpstreamStrategy::Parallel => "parallel",
        UpstreamStrategy::LoadBalance => "load_balance",
    };

    let bootstrap_strs = up
        .bootstrap
        .iter()
        .map(std::string::ToString::to_string)
        .collect();

    Json(UpstreamConfigDto {
        servers: up.servers.clone(),
        bootstrap: bootstrap_strs,
        strategy: strategy_str.to_string(),
        timeout_ms: up.timeout_ms,
        probe_domain: up.probe_domain.clone(),
        pool_size: up.pool_size,
    })
}

/// Update upstream DNS configuration.
#[utoipa::path(
    put,
    path = "/api/v1/upstream",
    request_body = UpstreamConfigDto,
    responses(
        (status = 200, description = "Updated upstream DNS configuration", body = UpstreamConfigDto),
        (status = 400, description = "Invalid configuration", body = ProblemDetails),
        (status = 401, description = "Unauthorized", body = ProblemDetails),
        (status = 403, description = "Forbidden", body = ProblemDetails)
    ),
    security(("bearer_auth" = []), ("cookie_auth" = []))
)]
pub async fn update_upstream_config(
    _operator: RequireOperator,
    State(ctx): State<ServerContext>,
    Json(dto): Json<UpstreamConfigDto>,
) -> Result<Json<UpstreamConfigDto>, ProblemDetails> {
    let strategy = match dto.strategy.as_str() {
        "failover" => UpstreamStrategy::Failover,
        "parallel" | "fastest" => UpstreamStrategy::Parallel,
        "load_balance" | "round_robin" => UpstreamStrategy::LoadBalance,
        other => {
            return Err(ProblemDetails::bad_request(format!(
                "Invalid upstream strategy '{other}'. Valid options: failover, parallel, load_balance"
            )));
        }
    };

    let mut bootstrap_ips = Vec::new();
    for b in &dto.bootstrap {
        let ip = b
            .parse()
            .map_err(|e| ProblemDetails::bad_request(format!("Invalid bootstrap IP '{b}': {e}")))?;
        bootstrap_ips.push(ip);
    }

    let mut new_config = (**ctx.config.load()).clone();
    new_config.upstream = UpstreamConfig {
        servers: dto.servers.clone(),
        bootstrap: bootstrap_ips,
        strategy,
        timeout_ms: dto.timeout_ms,
        probe_domain: dto.probe_domain.clone(),
        pool_size: dto.pool_size,
        per_domain: new_config.upstream.per_domain,
    };

    // Pre-commit validation and atomic write
    save_config_atomic(&ctx.config_path, &new_config).await?;
    ctx.config.store(Arc::new(new_config));
    crate::publish_bundle(&ctx);

    Ok(Json(dto))
}

/// Test upstream server latency and availability.
#[utoipa::path(
    post,
    path = "/api/v1/upstream/test",
    request_body = UpstreamTestRequest,
    responses(
        (status = 200, description = "Latency test results", body = UpstreamTestResponse),
        (status = 401, description = "Unauthorized", body = ProblemDetails),
        (status = 403, description = "Forbidden", body = ProblemDetails)
    ),
    security(("bearer_auth" = []), ("cookie_auth" = []))
)]
pub async fn test_upstream_servers(
    _operator: RequireOperator,
    State(ctx): State<ServerContext>,
    Json(req): Json<UpstreamTestRequest>,
) -> Json<UpstreamTestResponse> {
    let bootstrap = BootstrapResolver::new(
        ctx.config.load().upstream.bootstrap.clone(),
        Duration::from_millis(2000),
    );

    let test_qname = Name::from_str("example.com.").unwrap();
    let mut results = Vec::new();

    for server in req.servers {
        let start = Instant::now();
        let timeout = Duration::from_millis(3000);

        let upstream_res: Result<Arc<dyn Upstream>, String> =
            if let Some(tls_target) = server.strip_prefix("tls://") {
                let parts: Vec<&str> = tls_target.split(':').collect();
                let host = parts[0];
                let port: u16 = if parts.len() > 1 {
                    parts[1].parse().unwrap_or(853)
                } else {
                    853
                };

                match bootstrap.resolve_hostname(host).await {
                    Ok(ips) if !ips.is_empty() => {
                        let addr = SocketAddr::new(ips[0], port);
                        match DotUpstream::new(addr, host.to_string(), timeout, 2) {
                            Ok(dot) => Ok(Arc::new(dot)),
                            Err(e) => Err(format!("DoT setup failed: {e}")),
                        }
                    }
                    Ok(_) => Err("No IPs resolved for upstream host".to_string()),
                    Err(e) => Err(format!("Bootstrap resolution failed: {e}")),
                }
            } else {
                let target = server.strip_prefix("udp://").unwrap_or(&server);
                let addr_res = if let Ok(addr) = SocketAddr::from_str(target) {
                    Ok(addr)
                } else {
                    let parts: Vec<&str> = target.split(':').collect();
                    let host = parts[0];
                    let port: u16 = if parts.len() > 1 {
                        parts[1].parse().unwrap_or(53)
                    } else {
                        53
                    };

                    match bootstrap.resolve_hostname(host).await {
                        Ok(ips) if !ips.is_empty() => Ok(SocketAddr::new(ips[0], port)),
                        Ok(_) => Err("No IPs resolved for host".to_string()),
                        Err(e) => Err(format!("Failed to resolve {host}: {e}")),
                    }
                };

                match addr_res {
                    Ok(addr) => Ok(Arc::new(PlainUpstream::new(addr, timeout))),
                    Err(e) => Err(e),
                }
            };

        match upstream_res {
            Ok(up) => {
                let mut query = Message::new(1, MessageType::Query, OpCode::Query);
                query
                    .queries
                    .push(Query::query(test_qname.clone(), RecordType::A));

                match up.resolve(&query).await {
                    Ok(_) => {
                        let rtt = start.elapsed().as_millis() as u64;
                        results.push(UpstreamTestItem {
                            server,
                            rtt_ms: Some(rtt),
                            healthy: true,
                            error: None,
                        });
                    }
                    Err(e) => {
                        results.push(UpstreamTestItem {
                            server,
                            rtt_ms: None,
                            healthy: false,
                            error: Some(e.to_string()),
                        });
                    }
                }
            }
            Err(e) => {
                results.push(UpstreamTestItem {
                    server,
                    rtt_ms: None,
                    healthy: false,
                    error: Some(e),
                });
            }
        }
    }

    Json(UpstreamTestResponse { results })
}
