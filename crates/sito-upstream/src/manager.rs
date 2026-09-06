//! Upstream manager coordinating failover, load balancing, parallel racing, health checking, and server pooling.

use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
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

pub type NamedUpstream = (String, Arc<dyn Upstream>);
pub type PerDomainRule = (Vec<String>, Vec<NamedUpstream>);

#[derive(Clone)]
struct ManagedEntry {
    name: String,
    upstream: Arc<dyn Upstream>,
    health: Arc<RwLock<UpstreamHealth>>,
}

#[derive(Clone)]
struct UpstreamInner {
    entries: Vec<ManagedEntry>,
    per_domain_rules: Vec<(Vec<String>, Vec<ManagedEntry>)>,
    strategy: UpstreamStrategy,
    timeout_duration: Duration,
    probe_domain: String,
}

impl UpstreamInner {
    async fn from_config(
        config: &UpstreamConfig,
        bootstrap: &BootstrapResolver,
    ) -> Result<Self, UpstreamError> {
        let timeout_duration = Duration::from_millis(config.timeout_ms);
        let mut entries = Vec::new();

        for server_str in &config.servers {
            entries.push(
                create_managed_entry(server_str, bootstrap, timeout_duration, config.pool_size)
                    .await?,
            );
        }

        let mut per_domain_rules = Vec::new();
        for pd in &config.per_domain {
            let mut pd_entries = Vec::new();
            for server_str in &pd.servers {
                pd_entries.push(
                    create_managed_entry(server_str, bootstrap, timeout_duration, config.pool_size)
                        .await?,
                );
            }
            let cleaned_domains = pd
                .domains
                .iter()
                .map(|d| clean_rule_domain(d))
                .filter(|d| !d.is_empty())
                .collect();
            per_domain_rules.push((cleaned_domains, pd_entries));
        }

        Ok(Self {
            entries,
            per_domain_rules,
            strategy: config.strategy,
            timeout_duration,
            probe_domain: config.probe_domain.clone(),
        })
    }
}

/// Central manager for upstream DNS servers, handling failover, load balancing,
/// parallel queries, per-domain routing, and health tracking.
pub struct UpstreamManager {
    inner: arc_swap::ArcSwap<UpstreamInner>,
    rr_counter: AtomicUsize,
}

async fn create_managed_entry(
    server_str: &str,
    bootstrap: &BootstrapResolver,
    timeout_duration: Duration,
    pool_size: usize,
) -> Result<ManagedEntry, UpstreamError> {
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
            let target_ip = resolved_ips.first().copied().ok_or_else(|| {
                UpstreamError::BadResponse(format!("no IP addresses resolved for '{host}'"))
            })?;
            let socket_addr = SocketAddr::new(target_ip, port);

            let dot = DotUpstream::new(socket_addr, host.to_string(), timeout_duration, pool_size)?;
            (server_str.to_string(), Arc::new(dot))
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
                let target_ip = resolved_ips.first().copied().ok_or_else(|| {
                    UpstreamError::BadResponse(format!("no IP addresses resolved for '{host}'"))
                })?;
                SocketAddr::new(target_ip, port)
            };

            let plain = PlainUpstream::new(socket_addr, timeout_duration);
            (server_str.to_string(), Arc::new(plain))
        };

    Ok(ManagedEntry {
        name,
        upstream,
        health: Arc::new(RwLock::new(UpstreamHealth::new())),
    })
}

fn clean_rule_domain(d: &str) -> String {
    let s = d.trim().to_lowercase();
    let s = s.trim_start_matches('*').trim_start_matches('.');
    s.trim_end_matches('.').to_string()
}

impl UpstreamManager {
    /// Create an UpstreamManager from configuration and bootstrap resolver.
    pub async fn from_config(
        config: &UpstreamConfig,
        bootstrap: &BootstrapResolver,
    ) -> Result<Self, UpstreamError> {
        let inner = UpstreamInner::from_config(config, bootstrap).await?;
        Ok(Self {
            inner: arc_swap::ArcSwap::new(Arc::new(inner)),
            rr_counter: AtomicUsize::new(0),
        })
    }

    /// Hot-reloads upstream manager dynamically with updated servers, strategy, and domain rules.
    pub async fn reload(
        &self,
        config: &UpstreamConfig,
        bootstrap: &BootstrapResolver,
    ) -> Result<(), UpstreamError> {
        let new_inner = UpstreamInner::from_config(config, bootstrap).await?;
        self.inner.store(Arc::new(new_inner));
        info!(
            servers = ?config.servers,
            strategy = ?config.strategy,
            "UpstreamManager successfully hot-reloaded"
        );
        Ok(())
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

        let inner = UpstreamInner {
            entries,
            per_domain_rules: Vec::new(),
            strategy,
            timeout_duration,
            probe_domain: "example.com".to_string(),
        };

        Self {
            inner: arc_swap::ArcSwap::new(Arc::new(inner)),
            rr_counter: AtomicUsize::new(0),
        }
    }

    /// Create an UpstreamManager with per-domain rules (for testing).
    #[must_use]
    pub fn with_per_domain_upstreams(self, rules: Vec<PerDomainRule>) -> Self {
        let per_domain_rules = rules
            .into_iter()
            .map(|(domains, upstreams)| {
                let cleaned_domains = domains
                    .iter()
                    .map(|d| clean_rule_domain(d))
                    .filter(|d| !d.is_empty())
                    .collect();
                let entries = upstreams
                    .into_iter()
                    .map(|(name, upstream)| ManagedEntry {
                        name,
                        upstream,
                        health: Arc::new(RwLock::new(UpstreamHealth::new())),
                    })
                    .collect();
                (cleaned_domains, entries)
            })
            .collect();

        let current = self.inner.load();
        let new_inner = UpstreamInner {
            entries: current.entries.clone(),
            per_domain_rules,
            strategy: current.strategy,
            timeout_duration: current.timeout_duration,
            probe_domain: current.probe_domain.clone(),
        };
        self.inner.store(Arc::new(new_inner));
        self
    }

    pub fn strategy(&self) -> UpstreamStrategy {
        self.inner.load().strategy
    }

    pub fn timeout(&self) -> Duration {
        self.inner.load().timeout_duration
    }

    /// Retrieve the current health status of all configured upstreams.
    pub async fn statuses(&self) -> Vec<(String, HealthStatus)> {
        let inner = self.inner.load();
        let mut res = Vec::with_capacity(inner.entries.len());
        for entry in &inner.entries {
            let status = entry.health.read().await.status();
            res.push((entry.name.clone(), status));
        }
        for (_, group) in &inner.per_domain_rules {
            for entry in group {
                let status = entry.health.read().await.status();
                res.push((entry.name.clone(), status));
            }
        }
        res
    }

    /// Resolve a DNS query according to domain rules and configured strategy (parallel, load balance, failover).
    pub async fn resolve(&self, msg: &Message) -> Result<Message, UpstreamError> {
        self.resolve_with_upstream(msg).await.map(|(resp, _)| resp)
    }

    /// Resolve a DNS query according to domain rules and return the response along with the upstream identifier.
    pub async fn resolve_with_upstream(
        &self,
        msg: &Message,
    ) -> Result<(Message, String), UpstreamError> {
        let inner = self.inner.load();
        if let Some(query) = msg.queries.first() {
            let qname_str = query.name.to_utf8().to_lowercase();
            let qname_clean = qname_str.trim_end_matches('.');
            for (domains, group) in &inner.per_domain_rules {
                for d in domains {
                    if let Some(prefix) = qname_clean.strip_suffix(d.as_str())
                        && (prefix.is_empty() || prefix.ends_with('.'))
                    {
                        debug!(
                            "Routing query for {} to per-domain upstreams {:?}",
                            qname_str, domains
                        );
                        return self.resolve_entries(group, msg, inner.strategy).await;
                    }
                }
            }
        }

        self.resolve_entries(&inner.entries, msg, inner.strategy)
            .await
    }

    async fn resolve_entries(
        &self,
        entries: &[ManagedEntry],
        msg: &Message,
        strategy: UpstreamStrategy,
    ) -> Result<(Message, String), UpstreamError> {
        if entries.is_empty() {
            return Err(UpstreamError::AllDown);
        }

        // Collect available upstreams
        let mut candidates = Vec::new();
        for entry in entries {
            let health = entry.health.read().await;
            if health.is_available() {
                candidates.push(entry);
            }
        }

        // If all are marked down, fall back to trying all candidates
        if candidates.is_empty() {
            warn!("All upstreams marked down, attempting emergency query to all upstreams");
            candidates.extend(entries.iter());
        }

        match strategy {
            UpstreamStrategy::Parallel => {
                let mut futs = Vec::with_capacity(candidates.len());
                for entry in candidates {
                    let u = Arc::clone(&entry.upstream);
                    let h = Arc::clone(&entry.health);
                    let m = msg.clone();
                    let name = entry.name.clone();
                    futs.push(Box::pin(async move {
                        match u.resolve(&m).await {
                            Ok(resp) => {
                                h.write().await.record_success();
                                Ok((resp, name))
                            }
                            Err(e) => {
                                warn!("Upstream {} failed parallel query: {}", name, e);
                                h.write().await.record_error(&e);
                                Err(e)
                            }
                        }
                    }));
                }
                match futures_util::future::select_ok(futs).await {
                    Ok((resp, _)) => Ok(resp),
                    Err(e) => Err(e),
                }
            }
            UpstreamStrategy::LoadBalance => {
                let start_idx = self.rr_counter.fetch_add(1, Ordering::Relaxed) % candidates.len();
                let mut last_error = None;
                for i in 0..candidates.len() {
                    let entry = candidates[(start_idx + i) % candidates.len()];
                    trace!("Querying upstream (load_balance) {}", entry.name);
                    match entry.upstream.resolve(msg).await {
                        Ok(response) => {
                            entry.health.write().await.record_success();
                            return Ok((response, entry.name.clone()));
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
            UpstreamStrategy::Failover => {
                let mut last_error = None;
                for entry in candidates {
                    trace!("Querying upstream (failover) {}", entry.name);
                    match entry.upstream.resolve(msg).await {
                        Ok(response) => {
                            entry.health.write().await.record_success();
                            return Ok((response, entry.name.clone()));
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
        }
    }

    /// Spawn background health probing loop (probes every 10 seconds).
    pub fn start_health_prober(
        self: &Arc<Self>,
        mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
    ) -> tokio::task::JoinHandle<()> {
        let this = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() {
                            break;
                        }
                    }
                    () = sleep(Duration::from_secs(10)) => {
                        let inner = this.inner.load();
                        let probe_qname =
                            match Name::from_str(&format!("{}.", inner.probe_domain.trim_end_matches('.'))) {
                                Ok(n) => n,
                                Err(_) => Name::from_str("example.com.").unwrap(),
                            };

                        let mut all_entries = Vec::new();
                        for entry in &inner.entries {
                            all_entries.push(entry.clone());
                        }
                        for (_, group) in &inner.per_domain_rules {
                            for entry in group {
                                all_entries.push(entry.clone());
                            }
                        }

                        for entry in all_entries {
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

#[cfg(test)]
mod tests {
    use super::*;
    use sito_proto::rdata::A;
    use sito_proto::{RData, Record, ResponseCode};
    use std::sync::atomic::AtomicU32;

    struct ConfigurableMockUpstream {
        succeed: bool,
        delay: Duration,
        result_ip: std::net::Ipv4Addr,
        call_count: Arc<AtomicU32>,
    }

    #[async_trait::async_trait]
    impl Upstream for ConfigurableMockUpstream {
        async fn resolve(&self, msg: &Message) -> Result<Message, UpstreamError> {
            self.call_count.fetch_add(1, Ordering::SeqCst);
            if self.delay > Duration::ZERO {
                tokio::time::sleep(self.delay).await;
            }
            if self.succeed {
                let mut resp = Message::response(msg.metadata.id, msg.metadata.op_code);
                resp.queries = msg.queries.clone();
                resp.metadata.response_code = ResponseCode::NoError;
                resp.answers.push(Record::from_rdata(
                    msg.queries[0].name().clone(),
                    300,
                    RData::A(A(self.result_ip)),
                ));
                Ok(resp)
            } else {
                Err(UpstreamError::Timeout)
            }
        }
    }

    #[tokio::test]
    async fn test_parallel_strategy_fastest_wins() {
        let calls_fast = Arc::new(AtomicU32::new(0));
        let calls_slow = Arc::new(AtomicU32::new(0));

        let fast_upstream = Arc::new(ConfigurableMockUpstream {
            succeed: true,
            delay: Duration::from_millis(10),
            result_ip: std::net::Ipv4Addr::new(1, 1, 1, 1),
            call_count: Arc::clone(&calls_fast),
        });

        let slow_upstream = Arc::new(ConfigurableMockUpstream {
            succeed: true,
            delay: Duration::from_millis(200),
            result_ip: std::net::Ipv4Addr::new(2, 2, 2, 2),
            call_count: Arc::clone(&calls_slow),
        });

        let manager = UpstreamManager::with_upstreams(
            vec![
                ("slow".to_string(), slow_upstream),
                ("fast".to_string(), fast_upstream),
            ],
            UpstreamStrategy::Parallel,
            Duration::from_secs(1),
        );

        let mut query = Message::new(1, MessageType::Query, OpCode::Query);
        query.queries.push(Query::query(
            Name::from_str("test.com.").unwrap(),
            RecordType::A,
        ));

        let resp = manager.resolve(&query).await.unwrap();
        assert_eq!(resp.answers.len(), 1);
        assert_eq!(
            resp.answers[0].data,
            RData::A(A(std::net::Ipv4Addr::new(1, 1, 1, 1)))
        );
    }

    #[tokio::test]
    async fn test_load_balance_strategy_round_robin() {
        let calls_a = Arc::new(AtomicU32::new(0));
        let calls_b = Arc::new(AtomicU32::new(0));

        let upstream_a = Arc::new(ConfigurableMockUpstream {
            succeed: true,
            delay: Duration::ZERO,
            result_ip: std::net::Ipv4Addr::new(1, 1, 1, 1),
            call_count: Arc::clone(&calls_a),
        });

        let upstream_b = Arc::new(ConfigurableMockUpstream {
            succeed: true,
            delay: Duration::ZERO,
            result_ip: std::net::Ipv4Addr::new(2, 2, 2, 2),
            call_count: Arc::clone(&calls_b),
        });

        let manager = UpstreamManager::with_upstreams(
            vec![("a".to_string(), upstream_a), ("b".to_string(), upstream_b)],
            UpstreamStrategy::LoadBalance,
            Duration::from_secs(1),
        );

        let mut query = Message::new(1, MessageType::Query, OpCode::Query);
        query.queries.push(Query::query(
            Name::from_str("test.com.").unwrap(),
            RecordType::A,
        ));

        let resp1 = manager.resolve(&query).await.unwrap();
        let resp2 = manager.resolve(&query).await.unwrap();

        // Round robin should give answers from both servers
        assert_ne!(resp1.answers[0].data, resp2.answers[0].data);
        assert_eq!(calls_a.load(Ordering::SeqCst), 1);
        assert_eq!(calls_b.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_per_domain_routing() {
        let calls_default = Arc::new(AtomicU32::new(0));
        let calls_corp = Arc::new(AtomicU32::new(0));

        let default_upstream = Arc::new(ConfigurableMockUpstream {
            succeed: true,
            delay: Duration::ZERO,
            result_ip: std::net::Ipv4Addr::new(8, 8, 8, 8),
            call_count: Arc::clone(&calls_default),
        });

        let corp_upstream = Arc::new(ConfigurableMockUpstream {
            succeed: true,
            delay: Duration::ZERO,
            result_ip: std::net::Ipv4Addr::new(10, 0, 0, 1),
            call_count: Arc::clone(&calls_corp),
        });

        let manager = UpstreamManager::with_upstreams(
            vec![("default".to_string(), default_upstream)],
            UpstreamStrategy::Failover,
            Duration::from_secs(1),
        )
        .with_per_domain_upstreams(vec![(
            vec!["corp".to_string(), "internal.lan".to_string()],
            vec![("corp".to_string(), corp_upstream)],
        )]);

        // 1. Query for corp domain
        let mut query_corp = Message::new(1, MessageType::Query, OpCode::Query);
        query_corp.queries.push(Query::query(
            Name::from_str("server.corp.").unwrap(),
            RecordType::A,
        ));

        let resp_corp = manager.resolve(&query_corp).await.unwrap();
        assert_eq!(
            resp_corp.answers[0].data,
            RData::A(A(std::net::Ipv4Addr::new(10, 0, 0, 1)))
        );
        assert_eq!(calls_corp.load(Ordering::SeqCst), 1);
        assert_eq!(calls_default.load(Ordering::SeqCst), 0);

        // 2. Query for public domain
        let mut query_pub = Message::new(2, MessageType::Query, OpCode::Query);
        query_pub.queries.push(Query::query(
            Name::from_str("google.com.").unwrap(),
            RecordType::A,
        ));

        let resp_pub = manager.resolve(&query_pub).await.unwrap();
        assert_eq!(
            resp_pub.answers[0].data,
            RData::A(A(std::net::Ipv4Addr::new(8, 8, 8, 8)))
        );
        assert_eq!(calls_corp.load(Ordering::SeqCst), 1);
        assert_eq!(calls_default.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_upstream_manager_reload() {
        let calls_default = Arc::new(AtomicU32::new(0));
        let default_upstream = Arc::new(ConfigurableMockUpstream {
            succeed: true,
            delay: Duration::ZERO,
            result_ip: std::net::Ipv4Addr::new(8, 8, 8, 8),
            call_count: calls_default,
        });

        let manager = UpstreamManager::with_upstreams(
            vec![("default".to_string(), default_upstream)],
            UpstreamStrategy::Failover,
            Duration::from_secs(1),
        );

        assert_eq!(manager.strategy(), UpstreamStrategy::Failover);
        assert_eq!(manager.timeout(), Duration::from_secs(1));

        let bootstrap = BootstrapResolver::new(
            vec!["127.0.0.1".parse().unwrap()],
            Duration::from_millis(500),
        );

        let new_config = UpstreamConfig {
            servers: vec!["1.1.1.1:53".to_string()],
            bootstrap: vec![],
            strategy: UpstreamStrategy::LoadBalance,
            timeout_ms: 2500,
            probe_domain: "cloudflare.com".to_string(),
            pool_size: 2,
            per_domain: vec![],
        };

        manager.reload(&new_config, &bootstrap).await.unwrap();

        assert_eq!(manager.strategy(), UpstreamStrategy::LoadBalance);
        assert_eq!(manager.timeout(), Duration::from_millis(2500));
        let statuses = manager.statuses().await;
        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0].0, "1.1.1.1:53");
    }
}
