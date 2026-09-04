//! Upstream manager coordinating failover, health checking, and server pooling.

use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::time::sleep;
use tracing::{debug, info, trace, warn};

use sito_core::config::{UpstreamConfig, UpstreamStrategy};
use sito_core::error::UpstreamError;
use sito_proto::{Message, MessageType, Name, OpCode, Query, RecordType};

use crate::bootstrap::BootstrapResolver;
use crate::dot::DotUpstream;
use crate::health::{HealthStatus, UpstreamHealth};
use crate::plain::PlainUpstream;
use crate::upstream::Upstream;

struct ManagedEntry {
    name: String,
    upstream: Arc<dyn Upstream>,
    health: Arc<RwLock<UpstreamHealth>>,
}

/// Central manager for upstream DNS servers, handling failover and health tracking.
pub struct UpstreamManager {
    entries: Vec<ManagedEntry>,
    strategy: UpstreamStrategy,
    timeout_duration: Duration,
    probe_domain: String,
}

impl UpstreamManager {
    /// Create an UpstreamManager from configuration and bootstrap resolver.
    pub async fn from_config(
        config: &UpstreamConfig,
        bootstrap: &BootstrapResolver,
    ) -> Result<Self, UpstreamError> {
        let timeout_duration = Duration::from_millis(config.timeout_ms);
        let mut entries = Vec::new();

        for server_str in &config.servers {
            let (name, upstream): (String, Arc<dyn Upstream>) =
                if let Some(tls_target) = server_str.strip_prefix("tls://") {
                    let parts: Vec<&str> = tls_target.split(':').collect();
                    let host = parts[0];
                    let port: u16 = if parts.len() > 1 {
                        parts[1].parse().unwrap_or(853)
                    } else {
                        853
                    };

                    // Resolve hostname via bootstrap
                    let resolved_ips = bootstrap.resolve_hostname(host).await?;
                    let target_ip = resolved_ips[0];
                    let socket_addr = SocketAddr::new(target_ip, port);

                    let dot = DotUpstream::new(
                        socket_addr,
                        host.to_string(),
                        timeout_duration,
                        config.pool_size,
                    )?;
                    (server_str.clone(), Arc::new(dot))
                } else {
                    let target_str = server_str.strip_prefix("udp://").unwrap_or(server_str);
                    let socket_addr = if let Ok(addr) = SocketAddr::from_str(target_str) {
                        addr
                    } else {
                        let parts: Vec<&str> = target_str.split(':').collect();
                        let host = parts[0];
                        let port: u16 = if parts.len() > 1 {
                            parts[1].parse().unwrap_or(53)
                        } else {
                            53
                        };

                        let resolved_ips = bootstrap.resolve_hostname(host).await?;
                        SocketAddr::new(resolved_ips[0], port)
                    };

                    let plain = PlainUpstream::new(socket_addr, timeout_duration);
                    (server_str.clone(), Arc::new(plain))
                };

            entries.push(ManagedEntry {
                name,
                upstream,
                health: Arc::new(RwLock::new(UpstreamHealth::new())),
            });
        }

        Ok(Self {
            entries,
            strategy: config.strategy,
            timeout_duration,
            probe_domain: config.probe_domain.clone(),
        })
    }

    /// Create an UpstreamManager with explicitly provided Upstream implementations (for testing).
    pub fn with_upstreams(
        upstreams: Vec<(String, Arc<dyn Upstream>)>,
        strategy: UpstreamStrategy,
        timeout_duration: Duration,
    ) -> Self {
        let entries = upstreams
            .into_iter()
            .map(|(name, upstream)| ManagedEntry {
                name,
                upstream,
                health: Arc::new(RwLock::new(UpstreamHealth::new())),
            })
            .collect();

        Self {
            entries,
            strategy,
            timeout_duration,
            probe_domain: "example.com".to_string(),
        }
    }

    pub fn strategy(&self) -> UpstreamStrategy {
        self.strategy
    }

    pub fn timeout(&self) -> Duration {
        self.timeout_duration
    }

    /// Resolve a DNS query according to the configured strategy (e.g. failover).
    pub async fn resolve(&self, msg: &Message) -> Result<Message, UpstreamError> {
        if self.entries.is_empty() {
            return Err(UpstreamError::AllDown);
        }

        // Collect available upstreams
        let mut candidates = Vec::new();
        for entry in &self.entries {
            let health = entry.health.read().await;
            if health.is_available() {
                candidates.push(entry);
            }
        }

        // If all are marked down, fall back to trying all candidates
        if candidates.is_empty() {
            warn!("All upstreams marked down, attempting emergency query to all upstreams");
            candidates.extend(self.entries.iter());
        }

        // Failover execution: try first healthy, fallback to next on error
        let mut last_error = None;
        for entry in candidates {
            trace!("Querying upstream {}", entry.name);
            match entry.upstream.resolve(msg).await {
                Ok(response) => {
                    entry.health.write().await.record_success();
                    return Ok(response);
                }
                Err(e) => {
                    warn!("Upstream {} failed query: {}", entry.name, e);
                    entry.health.write().await.record_error(&e);
                    last_error = Some(e);
                }
            }
        }

        Err(last_error.unwrap_or(UpstreamError::AllDown))
    }

    /// Spawn background health probing loop (probes every 10 seconds).
    pub fn start_health_prober(
        self: &Arc<Self>,
        mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
    ) -> tokio::task::JoinHandle<()> {
        let this = Arc::clone(self);
        tokio::spawn(async move {
            let probe_qname =
                match Name::from_str(&format!("{}.", this.probe_domain.trim_end_matches('.'))) {
                    Ok(n) => n,
                    Err(_) => Name::from_str("example.com.").unwrap(),
                };

            loop {
                tokio::select! {
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() {
                            break;
                        }
                    }
                    () = sleep(Duration::from_secs(10)) => {
                        for entry in &this.entries {
                            let status = entry.health.read().await.status();
                            // Only probe if Suspect or Down
                            if status != HealthStatus::Healthy {
                                debug!("Active probing upstream {} (current status: {:?})", entry.name, status);
                                let mut query = Message::new(rand::random(), MessageType::Query, OpCode::Query);
                                query.queries.push(Query::query(probe_qname.clone(), RecordType::A));

                                match entry.upstream.resolve(&query).await {
                                    Ok(_) => {
                                        info!("Active probe succeeded for upstream {}", entry.name);
                                        entry.health.write().await.record_probe_success();
                                    }
                                    Err(e) => {
                                        debug!("Active probe failed for upstream {}: {}", entry.name, e);
                                        entry.health.write().await.record_error(&e);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        })
    }
}
