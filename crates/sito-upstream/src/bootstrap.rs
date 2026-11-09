//! Bootstrap DNS resolver for resolving encrypted upstream hostnames.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, RwLock};
use tracing::{debug, warn};

use crate::plain::PlainUpstream;
use crate::upstream::Upstream;
use sito_core::error::UpstreamError;
use sito_core::ssrf::is_denied_target_ip;
use sito_proto::rdata::{A, AAAA};
use sito_proto::{Message, MessageType, Name, OpCode, Query, RData, RecordType};

struct CachedEntry {
    ips: Vec<IpAddr>,
    expires_at: Instant,
}

/// Resolves hostnames for DoT/DoH using a set of static bootstrap IP addresses.
///
/// Lookups request both A and AAAA records so IPv6-only upstream hosts can be
/// reached, and concurrent lookups for the same hostname are single-flighted.
#[derive(Clone)]
pub struct BootstrapResolver {
    bootstrap_ips: Vec<IpAddr>,
    bootstrap_port: u16,
    query_timeout: Duration,
    allow_private_targets: bool,
    cache: Arc<RwLock<HashMap<String, CachedEntry>>>,
    inflight: Arc<Mutex<HashMap<String, Arc<Mutex<()>>>>>,
}

impl BootstrapResolver {
    /// Create a new BootstrapResolver from a list of IP addresses.
    pub fn new(bootstrap_ips: Vec<IpAddr>, query_timeout: Duration) -> Self {
        Self {
            bootstrap_ips,
            bootstrap_port: 53,
            query_timeout,
            allow_private_targets: false,
            cache: Arc::new(RwLock::new(HashMap::new())),
            inflight: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Create a resolver from the `[upstream]` configuration section.
    ///
    /// Uses the configured bootstrap IPs, query timeout and
    /// `allow_private_targets` policy.
    #[must_use]
    pub fn from_config(config: &sito_core::config::UpstreamConfig) -> Self {
        Self::new(
            config.bootstrap.clone(),
            Duration::from_millis(config.timeout_ms),
        )
        .with_allow_private_targets(config.allow_private_targets)
    }

    /// Set a custom port for bootstrap DNS queries (useful in testing).
    #[must_use]
    pub fn with_port(mut self, port: u16) -> Self {
        self.bootstrap_port = port;
        self
    }

    /// Allow bootstrap-resolved hostnames to point at private, loopback,
    /// link-local or otherwise reserved addresses.
    ///
    /// Disabled by default: a compromised or spoofed bootstrap answer must not
    /// be able to redirect a hostname-configured upstream into the local
    /// network. IP literals in the upstream configuration remain an explicit
    /// operator choice and bypass this check.
    #[must_use]
    pub fn with_allow_private_targets(mut self, allow: bool) -> Self {
        self.allow_private_targets = allow;
        self
    }

    /// Resolve a hostname or return the IP directly if it's already an IP literal.
    pub async fn resolve_hostname(&self, hostname: &str) -> Result<Vec<IpAddr>, UpstreamError> {
        self.resolve_hostname_inner(hostname, false).await
    }

    /// Resolve a hostname while bypassing the bootstrap cache.
    ///
    /// Used when every known address for an upstream has failed: the cached
    /// entry may still be unexpired (bootstrap TTLs are clamped to 60s..86400s)
    /// even though the records have rotated. The fresh answer is cached again on
    /// success.
    pub async fn resolve_hostname_forced(
        &self,
        hostname: &str,
    ) -> Result<Vec<IpAddr>, UpstreamError> {
        self.resolve_hostname_inner(hostname, true).await
    }

    async fn resolve_hostname_inner(
        &self,
        hostname: &str,
        force_refresh: bool,
    ) -> Result<Vec<IpAddr>, UpstreamError> {
        let trimmed = hostname.trim();

        // Check if hostname is already an IP address. A literal is an explicit
        // operator choice, so it is not subject to the SSRF denylist.
        if let Ok(ip) = IpAddr::from_str(trimmed) {
            return Ok(vec![ip]);
        }

        if !force_refresh && let Some(ips) = self.cached(trimmed).await {
            debug!("Bootstrap cache hit for '{}': {:?}", trimmed, ips);
            return Ok(ips);
        }

        // Single-flight: concurrent lookups for the same hostname share one
        // resolution attempt instead of stampeding the bootstrap servers.
        let host_lock = {
            let mut inflight = self.inflight.lock().await;
            Arc::clone(
                inflight
                    .entry(trimmed.to_string())
                    .or_insert_with(|| Arc::new(Mutex::new(()))),
            )
        };
        let guard = host_lock.lock().await;

        // Another task may have completed the resolution while we waited. A
        // forced refresh must not accept this cache hit, otherwise a failed
        // candidate set cannot pick up rotated records.
        if !force_refresh && let Some(ips) = self.cached(trimmed).await {
            drop(guard);
            self.finish_inflight(trimmed, &host_lock).await;
            return Ok(ips);
        }

        let result = self.resolve_uncached(trimmed).await;
        drop(guard);
        self.finish_inflight(trimmed, &host_lock).await;
        result
    }

    /// Look up a fresh cache entry, if one is present and unexpired.
    async fn cached(&self, hostname: &str) -> Option<Vec<IpAddr>> {
        let cache = self.cache.read().await;
        cache
            .get(hostname)
            .filter(|entry| Instant::now() < entry.expires_at)
            .map(|entry| entry.ips.clone())
    }

    /// Drop the single-flight entry once no other task is waiting on it.
    async fn finish_inflight(&self, hostname: &str, host_lock: &Arc<Mutex<()>>) {
        let mut inflight = self.inflight.lock().await;
        // References: this local + the map entry. More means a waiter holds a clone.
        if let Some(existing) = inflight.get(hostname)
            && Arc::ptr_eq(existing, host_lock)
            && Arc::strong_count(host_lock) <= 2
        {
            inflight.remove(hostname);
        }
    }

    async fn resolve_uncached(&self, trimmed: &str) -> Result<Vec<IpAddr>, UpstreamError> {
        let fqdn = if trimmed.ends_with('.') {
            trimmed.to_string()
        } else {
            format!("{trimmed}.")
        };

        let qname = Name::from_str(&fqdn).map_err(|e| {
            UpstreamError::BadResponse(format!("invalid hostname '{trimmed}': {e}"))
        })?;

        let mut errors = Vec::new();
        let mut denied_any = false;

        // Query bootstrap resolvers
        for &ip in &self.bootstrap_ips {
            let server_addr = SocketAddr::new(ip, self.bootstrap_port);
            let upstream = PlainUpstream::new(server_addr, self.query_timeout);

            // An IPv6-only upstream host has no A record, so ask for both
            // families concurrently and accept either.
            let mut query_a = Message::new(rand::random(), MessageType::Query, OpCode::Query);
            query_a.metadata.recursion_desired = true;
            query_a
                .queries
                .push(Query::query(qname.clone(), RecordType::A));
            let mut query_aaaa = Message::new(rand::random(), MessageType::Query, OpCode::Query);
            query_aaaa.metadata.recursion_desired = true;
            query_aaaa
                .queries
                .push(Query::query(qname.clone(), RecordType::AAAA));

            let (a_res, aaaa_res) =
                tokio::join!(upstream.resolve(&query_a), upstream.resolve(&query_aaaa));

            let mut resolved_ips = Vec::new();
            let mut min_ttl = 300u32;
            for res in [a_res, aaaa_res] {
                match res {
                    Ok(resp) => {
                        for ans in &resp.answers {
                            // Only accept addresses the bootstrap server is
                            // authoritative for: a response may otherwise point
                            // the resolver at an unrelated (attacker-chosen)
                            // address for a different owner name.
                            if ans.name != qname {
                                continue;
                            }
                            match &ans.data {
                                RData::A(A(v4)) => {
                                    resolved_ips.push(IpAddr::V4(*v4));
                                    min_ttl = min_ttl.min(ans.ttl);
                                }
                                RData::AAAA(AAAA(v6)) => {
                                    resolved_ips.push(IpAddr::V6(*v6));
                                    min_ttl = min_ttl.min(ans.ttl);
                                }
                                _ => {}
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Bootstrap resolver {} failed for '{}': {}", ip, trimmed, e);
                        errors.push(e);
                    }
                }
            }

            // P1-25: a hostname-resolved upstream must not be redirected into
            // loopback/private/link-local/metadata space by a compromised or
            // spoofed bootstrap answer. IP literals remain an explicit
            // operator choice (handled before resolution).
            if !self.allow_private_targets {
                let before = resolved_ips.len();
                resolved_ips.retain(|candidate| !is_denied_target_ip(*candidate));
                if resolved_ips.len() != before {
                    denied_any = true;
                    warn!(
                        "Bootstrap answer for '{}' via {} included denied private/reserved addresses; ignoring them",
                        trimmed, ip
                    );
                }
            }

            if !resolved_ips.is_empty() {
                resolved_ips.sort();
                resolved_ips.dedup();
                debug!(
                    "Bootstrap resolved '{}' via {} to {:?}",
                    trimmed, ip, resolved_ips
                );
                let ttl_duration = Duration::from_secs(u64::from(min_ttl.clamp(60, 86400)));
                let mut cache = self.cache.write().await;
                cache.insert(
                    trimmed.to_string(),
                    CachedEntry {
                        ips: resolved_ips.clone(),
                        expires_at: Instant::now() + ttl_duration,
                    },
                );
                return Ok(resolved_ips);
            }
        }

        if denied_any {
            return Err(UpstreamError::BadResponse(format!(
                "Bootstrap resolution for '{trimmed}' returned only private/reserved addresses; \
                 refusing to use them (set upstream.allow_private_targets = true to opt in)"
            )));
        }

        Err(UpstreamError::BadResponse(format!(
            "Bootstrap resolution failed for '{trimmed}': {errors:?}"
        )))
    }
}
