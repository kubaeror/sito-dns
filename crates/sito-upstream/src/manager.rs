//! Upstream manager coordinating failover, load balancing, parallel racing, health checking, and server pooling.

use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, RwLock};
use tokio::time::sleep;
use tracing::{debug, info, trace, warn};

use sito_core::config::{UpstreamConfig, UpstreamStrategy};
use sito_core::error::UpstreamError;
use sito_proto::{Message, MessageType, Name, OpCode, Query, RecordType};

use crate::bootstrap::BootstrapResolver;
use crate::doh::HttpsUpstream;
use crate::doq::QuicUpstream;
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

/// How often a multi-address upstream re-resolves its hostname.
const UPSTREAM_RE_RESOLVE_INTERVAL: Duration = Duration::from_secs(300);

/// Transport used for every address a hostname resolves to.
enum CandidateKind {
    Plain,
    Dot {
        server_name: String,
        pool_size: usize,
    },
    Quic {
        server_name: String,
    },
    Https {
        url: String,
    },
}

/// An upstream that resolves a hostname to *all* of its addresses and fails
/// over between them, re-resolving periodically (bounded) when candidates
/// fail so DNS changes are eventually picked up.
struct FailoverUpstream {
    bootstrap: BootstrapResolver,
    host: String,
    port: u16,
    timeout: Duration,
    kind: CandidateKind,
    candidates: RwLock<Vec<Arc<dyn Upstream>>>,
    last_resolve: Mutex<Instant>,
    re_resolve_interval: Duration,
}

impl FailoverUpstream {
    async fn new(
        bootstrap: BootstrapResolver,
        host: String,
        port: u16,
        timeout: Duration,
        kind: CandidateKind,
    ) -> Result<Self, UpstreamError> {
        Self::with_interval(
            bootstrap,
            host,
            port,
            timeout,
            kind,
            UPSTREAM_RE_RESOLVE_INTERVAL,
        )
        .await
    }

    async fn with_interval(
        bootstrap: BootstrapResolver,
        host: String,
        port: u16,
        timeout: Duration,
        kind: CandidateKind,
        re_resolve_interval: Duration,
    ) -> Result<Self, UpstreamError> {
        let upstream = Self {
            bootstrap,
            host,
            port,
            timeout,
            kind,
            candidates: RwLock::new(Vec::new()),
            last_resolve: Mutex::new(Instant::now()),
            re_resolve_interval,
        };
        let candidates = upstream.build_candidates().await?;
        *upstream.candidates.write().await = candidates;
        Ok(upstream)
    }

    async fn build_candidates(&self) -> Result<Vec<Arc<dyn Upstream>>, UpstreamError> {
        let ips = self.bootstrap.resolve_hostname(&self.host).await?;
        if ips.is_empty() {
            return Err(UpstreamError::BadResponse(format!(
                "no IP addresses resolved for '{}'",
                self.host
            )));
        }

        // DoH keeps a single client that carries all resolved addresses.
        if let CandidateKind::Https { url } = &self.kind {
            let doh = HttpsUpstream::new(url, &ips, self.timeout)?;
            return Ok(vec![Arc::new(doh)]);
        }

        let mut candidates: Vec<Arc<dyn Upstream>> = Vec::with_capacity(ips.len());
        for ip in ips {
            let addr = SocketAddr::new(ip, self.port);
            let upstream: Arc<dyn Upstream> = match &self.kind {
                CandidateKind::Plain => Arc::new(PlainUpstream::new(addr, self.timeout)),
                CandidateKind::Dot {
                    server_name,
                    pool_size,
                } => Arc::new(DotUpstream::new(
                    addr,
                    server_name.clone(),
                    self.timeout,
                    *pool_size,
                )?),
                CandidateKind::Quic { server_name } => {
                    Arc::new(QuicUpstream::new(server_name, addr, self.timeout)?)
                }
                CandidateKind::Https { .. } => unreachable!("handled above"),
            };
            candidates.push(upstream);
        }
        Ok(candidates)
    }

    /// Re-resolve if the interval elapsed and no other task holds the refresh
    /// lock. Returns `true` when the candidate set was replaced.
    async fn try_re_resolve(&self) -> bool {
        let Ok(mut last) = self.last_resolve.try_lock() else {
            return false;
        };
        if last.elapsed() < self.re_resolve_interval {
            return false;
        }
        *last = Instant::now();
        match self.build_candidates().await {
            Ok(candidates) => {
                *self.candidates.write().await = candidates;
                debug!("Re-resolved upstream '{}' candidate addresses", self.host);
                true
            }
            Err(e) => {
                debug!("Failed to re-resolve upstream '{}': {}", self.host, e);
                false
            }
        }
    }

    async fn resolve_candidates(&self, msg: &Message) -> Result<Message, UpstreamError> {
        let candidates = self.candidates.read().await.clone();
        let mut last_error = None;
        for candidate in &candidates {
            match candidate.resolve(msg).await {
                Ok(response) => return Ok(response),
                Err(e) => {
                    debug!("Upstream candidate for '{}' failed: {}", self.host, e);
                    last_error = Some(e);
                }
            }
        }

        // Every known address failed: refresh (bounded) and retry once so
        // rotated DNS records can be picked up without a restart.
        if self.try_re_resolve().await {
            let candidates = self.candidates.read().await.clone();
            for candidate in &candidates {
                match candidate.resolve(msg).await {
                    Ok(response) => return Ok(response),
                    Err(e) => last_error = Some(e),
                }
            }
        }

        Err(last_error.unwrap_or(UpstreamError::AllDown))
    }
}

#[async_trait::async_trait]
impl Upstream for FailoverUpstream {
    async fn resolve(&self, msg: &Message) -> Result<Message, UpstreamError> {
        self.resolve_candidates(msg).await
    }

    async fn refresh(&self) -> Result<(), UpstreamError> {
        let _ = self.try_re_resolve().await;
        Ok(())
    }
}

async fn create_managed_entry(
    server_str: &str,
    bootstrap: &BootstrapResolver,
    timeout_duration: Duration,
    pool_size: usize,
) -> Result<ManagedEntry, UpstreamError> {
    let name = server_str.to_string();
    let bootstrap = bootstrap.clone();

    let upstream: Arc<dyn Upstream> = if let Some(tls_target) = server_str.strip_prefix("tls://") {
        let (host, port) = split_host_port(tls_target, 853);
        Arc::new(
            FailoverUpstream::new(
                bootstrap,
                host.clone(),
                port,
                timeout_duration,
                CandidateKind::Dot {
                    server_name: host,
                    pool_size,
                },
            )
            .await?,
        )
    } else if server_str.starts_with("https://") {
        let (host, port, _path) = parse_scheme_target(server_str, "https", 443)?;
        Arc::new(
            FailoverUpstream::new(
                bootstrap,
                host,
                port,
                timeout_duration,
                CandidateKind::Https {
                    url: server_str.to_string(),
                },
            )
            .await?,
        )
    } else if server_str.starts_with("quic://") {
        let (host, port, _path) = parse_scheme_target(server_str, "quic", 853)?;
        Arc::new(
            FailoverUpstream::new(
                bootstrap,
                host.clone(),
                port,
                timeout_duration,
                CandidateKind::Quic { server_name: host },
            )
            .await?,
        )
    } else {
        let target_str = server_str.strip_prefix("udp://").unwrap_or(server_str);
        if let Some(scheme) = unsupported_scheme(target_str) {
            return Err(UpstreamError::BadResponse(format!(
                "unsupported upstream scheme '{scheme}://' in '{server_str}'; supported schemes are tls://, https://, udp:// and plain host/IP"
            )));
        }
        let (host, port) = split_host_port(target_str, 53);
        Arc::new(
            FailoverUpstream::new(
                bootstrap,
                host,
                port,
                timeout_duration,
                CandidateKind::Plain,
            )
            .await?,
        )
    };

    Ok(ManagedEntry {
        name,
        upstream,
        health: Arc::new(RwLock::new(UpstreamHealth::new())),
    })
}

/// Parses a `scheme://host[:port][/path]` upstream target.
fn parse_scheme_target(
    url: &str,
    scheme: &str,
    default_port: u16,
) -> Result<(String, u16, String), UpstreamError> {
    let prefix = format!("{scheme}://");
    let rest = url.strip_prefix(prefix.as_str()).unwrap_or(url);
    let (authority, path) = match rest.split_once('/') {
        Some((authority, path)) => (authority, format!("/{path}")),
        None => (rest, "/dns-query".to_string()),
    };
    let (host, port) = split_host_port(authority, default_port);
    if host.is_empty() {
        return Err(UpstreamError::BadResponse(format!(
            "invalid upstream URL '{url}': missing host"
        )));
    }
    Ok((host, port, path))
}

/// Returns the scheme of an upstream string if it uses an unsupported `xxx://` prefix.
fn unsupported_scheme(target: &str) -> Option<String> {
    let (scheme, _) = target.split_once("://")?;
    if scheme.is_empty()
        || scheme.eq_ignore_ascii_case("tls")
        || scheme.eq_ignore_ascii_case("https")
        || scheme.eq_ignore_ascii_case("quic")
        || scheme.eq_ignore_ascii_case("udp")
    {
        None
    } else {
        Some(scheme.to_string())
    }
}

/// Splits an upstream target into `(host, port)`, supporting IPv6 literals in
/// brackets (`[::1]:853`), bare IPv6 literals (`2001:db8::1`) and hostnames.
fn split_host_port(target: &str, default_port: u16) -> (String, u16) {
    let target = target.trim();

    // [IPv6]:port or [IPv6]
    if let Some(rest) = target.strip_prefix('[')
        && let Some((host, tail)) = rest.split_once(']')
    {
        let port = tail
            .strip_prefix(':')
            .and_then(|p| p.parse::<u16>().ok())
            .unwrap_or(default_port);
        return (host.to_string(), port);
    }

    // Bare IPv6 literal without brackets/port
    if target.matches(':').count() >= 2 && target.parse::<std::net::Ipv6Addr>().is_ok() {
        return (target.to_string(), default_port);
    }

    // host:port
    if let Some((host, port)) = target.rsplit_once(':')
        && !host.is_empty()
        && let Ok(port) = port.parse::<u16>()
    {
        return (host.to_string(), port);
    }

    (target.trim_end_matches('.').to_string(), default_port)
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
    ///
    /// Health state is carried over for upstreams that keep the same name so a
    /// reload does not resurrect a known-down server as Healthy.
    pub async fn reload(
        &self,
        config: &UpstreamConfig,
        bootstrap: &BootstrapResolver,
    ) -> Result<(), UpstreamError> {
        let new_inner = UpstreamInner::from_config(config, bootstrap).await?;
        let old = self.inner.load();

        let mut entries = new_inner.entries;
        for entry in &mut entries {
            if let Some(previous) = old.entries.iter().find(|prev| prev.name == entry.name) {
                entry.health = Arc::clone(&previous.health);
            }
        }
        let mut per_domain_rules = new_inner.per_domain_rules;
        for (domains, group) in &mut per_domain_rules {
            let old_group = old
                .per_domain_rules
                .iter()
                .find(|(old_domains, _)| old_domains.as_slice() == domains.as_slice())
                .map(|(_, group)| group);
            if let Some(old_group) = old_group {
                for entry in group.iter_mut() {
                    if let Some(previous) = old_group.iter().find(|prev| prev.name == entry.name) {
                        entry.health = Arc::clone(&previous.health);
                    }
                }
            }
        }

        self.inner.store(Arc::new(UpstreamInner {
            entries,
            per_domain_rules,
            strategy: new_inner.strategy,
            timeout_duration: new_inner.timeout_duration,
            probe_domain: new_inner.probe_domain,
        }));
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

                        // Bounded periodic re-resolution for multi-address
                        // upstreams, run concurrently so one slow bootstrap
                        // lookup cannot delay the probe cycle.
                        let refreshes = all_entries
                            .iter()
                            .map(|entry| entry.upstream.refresh());
                        futures_util::future::join_all(refreshes).await;

                        let probe_timeout = inner.timeout_duration.max(Duration::from_millis(1));
                        let mut to_probe = Vec::new();
                        for entry in all_entries {
                            let status = entry.health.read().await.status();
                            // Only probe if Suspect or Down
                            if status != HealthStatus::Healthy {
                                debug!(
                                    "Active probing upstream {} (current status: {:?})",
                                    entry.name, status
                                );
                                to_probe.push(entry);
                            }
                        }

                        // Probe in parallel so a single stalled upstream cannot
                        // delay every other probe; each probe is bounded.
                        probe_all(to_probe, probe_qname.clone(), probe_timeout).await;
                    }
                }
            }
        })
    }
}

/// Probe a set of upstreams concurrently, bounding each individual probe.
async fn probe_all(entries: Vec<ManagedEntry>, probe_qname: Name, probe_timeout: Duration) {
    let probes = entries.into_iter().map(|entry| {
        let qname = probe_qname.clone();
        async move { probe_one(entry, qname, probe_timeout).await }
    });
    futures_util::future::join_all(probes).await;
}

/// Send a single active health probe and record its result.
async fn probe_one(entry: ManagedEntry, qname: Name, probe_timeout: Duration) {
    let name = entry.name.clone();
    let mut query = Message::new(rand::random(), MessageType::Query, OpCode::Query);
    query.queries.push(Query::query(qname, RecordType::A));

    match tokio::time::timeout(probe_timeout, entry.upstream.resolve(&query)).await {
        Ok(Ok(_)) => {
            info!("Active probe succeeded for upstream {}", name);
            entry.health.write().await.record_probe_success();
        }
        Ok(Err(e)) => {
            debug!("Active probe failed for upstream {}: {}", name, e);
            entry.health.write().await.record_error(&e);
        }
        Err(_) => {
            debug!("Active probe timed out for upstream {}", name);
            entry
                .health
                .write()
                .await
                .record_error(&UpstreamError::Timeout);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sito_proto::rdata::A;
    use sito_proto::{RData, Record, ResponseCode, decode_message, encode_message};
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

    #[test]
    fn test_split_host_port_supports_ipv6_literals() {
        assert_eq!(
            split_host_port("[2606:4700:4700::1111]:853", 853),
            ("2606:4700:4700::1111".to_string(), 853)
        );
        assert_eq!(
            split_host_port("[2606:4700:4700::1111]", 853),
            ("2606:4700:4700::1111".to_string(), 853)
        );
        assert_eq!(
            split_host_port("2606:4700:4700::1111", 853),
            ("2606:4700:4700::1111".to_string(), 853)
        );
        assert_eq!(
            split_host_port("dns.quad9.net:8853", 853),
            ("dns.quad9.net".to_string(), 8853)
        );
        assert_eq!(
            split_host_port("dns.quad9.net", 853),
            ("dns.quad9.net".to_string(), 853)
        );
        assert_eq!(split_host_port("1.1.1.1", 53), ("1.1.1.1".to_string(), 53));
    }

    #[test]
    fn test_parse_https_target() {
        assert_eq!(
            parse_scheme_target("https://dns.quad9.net/dns-query", "https", 443).unwrap(),
            ("dns.quad9.net".to_string(), 443, "/dns-query".to_string())
        );
        assert_eq!(
            parse_scheme_target("https://dns.google:8443/dns-query", "https", 443)
                .unwrap()
                .1,
            8443
        );
        assert_eq!(
            parse_scheme_target("https://[2606:4700:4700::1111]/dns-query", "https", 443)
                .unwrap()
                .0,
            "2606:4700:4700::1111"
        );
        assert_eq!(
            parse_scheme_target("https://cloudflare-dns.com", "https", 443)
                .unwrap()
                .2,
            "/dns-query"
        );
        assert!(parse_scheme_target("https:///dns-query", "https", 443).is_err());
        assert_eq!(
            parse_scheme_target("quic://dns.adguard.com", "quic", 853).unwrap(),
            ("dns.adguard.com".to_string(), 853, "/dns-query".to_string())
        );
    }

    #[test]
    fn test_unsupported_scheme_detection() {
        assert_eq!(
            unsupported_scheme("sdns://AQcAAAAAAAA").as_deref(),
            Some("sdns")
        );
        assert_eq!(unsupported_scheme("quic://dns.quad9.net"), None);
        assert_eq!(unsupported_scheme("tls://dns.quad9.net"), None);
        assert_eq!(unsupported_scheme("https://dns.quad9.net/dns-query"), None);
        assert_eq!(unsupported_scheme("udp://1.1.1.1"), None);
        assert_eq!(unsupported_scheme("1.1.1.1"), None);
    }

    /// Spawns a mock bootstrap server returning the given A records in order.
    async fn spawn_bootstrap_records(records: Vec<std::net::Ipv4Addr>) -> SocketAddr {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            while let Ok((len, peer)) = socket.recv_from(&mut buf).await {
                let Ok(query) = decode_message(&buf[..len]) else {
                    continue;
                };
                if query.queries.first().map(Query::query_type) != Some(RecordType::A) {
                    continue;
                }
                let mut resp = Message::response(query.metadata.id, query.metadata.op_code);
                resp.queries = query.queries.clone();
                let name = query.queries[0].name().clone();
                for ip in &records {
                    resp.answers
                        .push(Record::from_rdata(name.clone(), 300, RData::A(A(*ip))));
                }
                if let Ok(encoded) = encode_message(&resp) {
                    let _ = socket.send_to(&encoded, peer).await;
                }
            }
        });
        addr
    }

    #[tokio::test]
    async fn test_managed_entry_fails_over_across_resolved_addresses() {
        // Live plain DNS server on 127.0.0.2; 127.0.0.1:<same port> is dead.
        let live = tokio::net::UdpSocket::bind("127.0.0.2:0").await.unwrap();
        let live_port = live.local_addr().unwrap().port();
        let live_calls = Arc::new(AtomicU32::new(0));
        let calls = Arc::clone(&live_calls);
        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            while let Ok((len, peer)) = live.recv_from(&mut buf).await {
                calls.fetch_add(1, Ordering::SeqCst);
                let Ok(query) = decode_message(&buf[..len]) else {
                    continue;
                };
                let mut resp = Message::response(query.metadata.id, query.metadata.op_code);
                resp.queries = query.queries.clone();
                resp.answers.push(Record::from_rdata(
                    query.queries[0].name().clone(),
                    300,
                    RData::A(A(std::net::Ipv4Addr::new(5, 5, 5, 5))),
                ));
                if let Ok(encoded) = encode_message(&resp) {
                    let _ = live.send_to(&encoded, peer).await;
                }
            }
        });

        let bootstrap_addr = spawn_bootstrap_records(vec![
            std::net::Ipv4Addr::LOCALHOST,
            std::net::Ipv4Addr::new(127, 0, 0, 2),
        ])
        .await;
        let bootstrap = BootstrapResolver::new(vec![bootstrap_addr.ip()], Duration::from_secs(1))
            .with_port(bootstrap_addr.port());

        let entry = create_managed_entry(
            &format!("multi-address.test:{live_port}"),
            &bootstrap,
            Duration::from_millis(500),
            1,
        )
        .await
        .expect("managed entry");

        let mut query = Message::new(1, MessageType::Query, OpCode::Query);
        query.queries.push(Query::query(
            Name::from_str("example.com.").unwrap(),
            RecordType::A,
        ));

        let resp = entry
            .upstream
            .resolve(&query)
            .await
            .expect("failover to the second resolved address must succeed");
        assert_eq!(
            resp.answers[0].data,
            RData::A(A(std::net::Ipv4Addr::new(5, 5, 5, 5)))
        );
        assert_eq!(live_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_reload_preserves_upstream_health() {
        let manager = UpstreamManager::with_upstreams(
            vec![(
                "1.1.1.1:53".to_string(),
                Arc::new(ConfigurableMockUpstream {
                    succeed: false,
                    delay: Duration::ZERO,
                    result_ip: std::net::Ipv4Addr::new(1, 1, 1, 1),
                    call_count: Arc::new(AtomicU32::new(0)),
                }),
            )],
            UpstreamStrategy::Failover,
            Duration::from_secs(1),
        );

        for _ in 0..6 {
            manager.inner.load_full().entries[0]
                .health
                .write()
                .await
                .record_error(&UpstreamError::Timeout);
        }
        assert_eq!(
            manager.inner.load_full().entries[0]
                .health
                .read()
                .await
                .status(),
            HealthStatus::Down
        );

        let bootstrap = BootstrapResolver::new(
            vec!["127.0.0.1".parse().unwrap()],
            Duration::from_millis(200),
        );
        let config = UpstreamConfig {
            servers: vec!["1.1.1.1:53".to_string()],
            bootstrap: vec![],
            strategy: UpstreamStrategy::Failover,
            timeout_ms: 1000,
            probe_domain: "example.com".to_string(),
            pool_size: 1,
            per_domain: vec![],
        };
        manager.reload(&config, &bootstrap).await.unwrap();

        assert_eq!(
            manager.inner.load_full().entries[0]
                .health
                .read()
                .await
                .status(),
            HealthStatus::Down,
            "reload must not resurrect a known-down upstream as Healthy"
        );
    }

    struct HangingUpstream;

    #[async_trait::async_trait]
    impl Upstream for HangingUpstream {
        async fn resolve(&self, _msg: &Message) -> Result<Message, UpstreamError> {
            std::future::pending::<()>().await;
            unreachable!("pending never resolves")
        }
    }

    struct NotifyingUpstream {
        notify: Arc<tokio::sync::Notify>,
    }

    #[async_trait::async_trait]
    impl Upstream for NotifyingUpstream {
        async fn resolve(&self, msg: &Message) -> Result<Message, UpstreamError> {
            self.notify.notify_one();
            let mut resp = Message::response(msg.metadata.id, msg.metadata.op_code);
            resp.queries = msg.queries.clone();
            Ok(resp)
        }
    }

    #[tokio::test]
    async fn test_health_probes_run_in_parallel() {
        let notify = Arc::new(tokio::sync::Notify::new());
        let manager = UpstreamManager::with_upstreams(
            vec![
                ("hanging".to_string(), Arc::new(HangingUpstream)),
                (
                    "healthy".to_string(),
                    Arc::new(NotifyingUpstream {
                        notify: Arc::clone(&notify),
                    }),
                ),
            ],
            UpstreamStrategy::Failover,
            Duration::from_secs(30),
        );

        let entries = manager.inner.load_full().entries.clone();
        let probe_task = tokio::spawn(probe_all(
            entries,
            Name::from_str("example.com.").unwrap(),
            Duration::from_secs(30),
        ));

        // With sequential probing the hanging upstream would block the healthy
        // one; parallel probes must reach it immediately.
        tokio::time::timeout(Duration::from_secs(2), notify.notified())
            .await
            .expect("healthy upstream must be probed without waiting for the stalled one");
        probe_task.abort();
    }
}
