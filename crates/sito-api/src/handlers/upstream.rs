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

    let bootstrap = BootstrapResolver::new(
        new_config.upstream.bootstrap.clone(),
        Duration::from_millis(new_config.upstream.timeout_ms),
    );

    // Reload upstream manager with new configuration (also validates upstreams)
    ctx.upstream
        .reload(&new_config.upstream, &bootstrap)
        .await
        .map_err(|e| ProblemDetails::bad_request(format!("Invalid upstream configuration: {e}")))?;

    // Pre-commit validation and atomic write
    if let Err(e) = save_config_atomic(&ctx.config_path, &new_config).await {
        let prev_cfg = ctx.config.load();
        let prev_bootstrap = BootstrapResolver::new(
            prev_cfg.upstream.bootstrap.clone(),
            Duration::from_millis(prev_cfg.upstream.timeout_ms),
        );
        let _ = ctx
            .upstream
            .reload(&prev_cfg.upstream, &prev_bootstrap)
            .await;
        return Err(e);
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::rbac::AuthUser;
    use crate::auth::token::Role;
    use arc_swap::ArcSwap;
    use sito_core::config::Config;
    use std::sync::Mutex;

    async fn mock_context(temp_dir: &std::path::Path) -> ServerContext {
        let db_path = temp_dir.join("test.db");
        let stats_db = sito_stats::StatsDb::open(&db_path).await.unwrap();
        let querylog_writer = sito_stats::QueryLogWriter::spawn(stats_db.clone(), 100);
        let querylog_sender = querylog_writer.sender();
        let metrics = sito_stats::MetricsRegistry::new("1.2.1", "test");
        let auth_mgr = Arc::new(crate::auth::AuthManager::new());
        let config = Config::default();
        let config_arc = Arc::new(ArcSwap::new(Arc::new(config)));
        let filter = Arc::new(
            sito_filter::HostsFilterEngine::init(Default::default(), temp_dir.to_path_buf()).await,
        );
        let cache = Arc::new(sito_cache::DnsCache::new(Default::default()));
        let bootstrap = sito_upstream::BootstrapResolver::new(
            vec!["127.0.0.1".parse().unwrap()],
            std::time::Duration::from_secs(1),
        );
        let upstream = Arc::new(
            sito_upstream::UpstreamManager::from_config(&Default::default(), &bootstrap)
                .await
                .unwrap(),
        );
        let clients = Arc::new(ArcSwap::new(Arc::new(sito_clients::ClientRegistry::new(
            Default::default(),
        ))));
        let rewrites = Arc::new(ArcSwap::new(Arc::new(sito_rewrites::RewriteTable::new(
            Default::default(),
        ))));

        ServerContext {
            config: config_arc,
            config_path: temp_dir.join("config.toml"),
            auth_mgr,
            stats_db,
            querylog_sender,
            metrics,
            filter,
            cache,
            upstream,
            clients,
            rewrites,
            start_time: Instant::now(),
            restore_tokens: Arc::new(Mutex::new(std::collections::HashMap::new())),
            master_coordinator: None,
            slave_tracker: None,
            resync_sender: None,
            setup_pending: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            dns_starter: None,
        }
    }

    #[tokio::test]
    async fn test_update_upstream_config_hot_reloads() {
        let temp_dir =
            std::env::temp_dir().join(format!("sito_upstream_test_{}", rand::random::<u64>()));
        let _ = std::fs::create_dir_all(&temp_dir);
        let ctx = mock_context(&temp_dir).await;

        let operator = RequireOperator(AuthUser {
            username: "operator".to_string(),
            role: Role::Operator,
            token_id: None,
        });

        let dto = UpstreamConfigDto {
            servers: vec!["1.1.1.1:53".to_string()],
            bootstrap: vec!["1.0.0.1".to_string()],
            strategy: "load_balance".to_string(),
            timeout_ms: 3000,
            probe_domain: "cloudflare.com".to_string(),
            pool_size: 4,
        };

        let res = update_upstream_config(operator.clone(), State(ctx.clone()), Json(dto)).await;
        assert!(res.is_ok());

        assert_eq!(ctx.upstream.strategy(), UpstreamStrategy::LoadBalance);
        assert_eq!(ctx.upstream.timeout(), Duration::from_millis(3000));
        let statuses = ctx.upstream.statuses().await;
        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0].0, "1.1.1.1:53");

        // Test invalid upstream server fails and does not change config
        let bad_dto = UpstreamConfigDto {
            servers: vec!["invalid-ip-without-port".to_string()],
            bootstrap: vec!["1.0.0.1".to_string()],
            strategy: "failover".to_string(),
            timeout_ms: 1000,
            probe_domain: "example.com".to_string(),
            pool_size: 2,
        };

        let bad_res = update_upstream_config(operator, State(ctx.clone()), Json(bad_dto)).await;
        assert!(bad_res.is_err());
        // Strategy remains LoadBalance
        assert_eq!(ctx.upstream.strategy(), UpstreamStrategy::LoadBalance);
    }
}
