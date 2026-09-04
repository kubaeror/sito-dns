//! Bootstrap DNS resolver for resolving encrypted upstream hostnames.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, warn};

use crate::plain::PlainUpstream;
use crate::upstream::Upstream;
use sito_core::error::UpstreamError;
use sito_proto::rdata::{A, AAAA};
use sito_proto::{Message, MessageType, Name, OpCode, Query, RData, RecordType};

struct CachedEntry {
    ips: Vec<IpAddr>,
    expires_at: Instant,
}

/// Resolves hostnames for DoT/DoH using a set of static bootstrap IP addresses.
#[derive(Clone)]
pub struct BootstrapResolver {
    bootstrap_ips: Vec<IpAddr>,
    bootstrap_port: u16,
    query_timeout: Duration,
    cache: Arc<RwLock<HashMap<String, CachedEntry>>>,
}

impl BootstrapResolver {
    /// Create a new BootstrapResolver from a list of IP addresses.
    pub fn new(bootstrap_ips: Vec<IpAddr>, query_timeout: Duration) -> Self {
        Self {
            bootstrap_ips,
            bootstrap_port: 53,
            query_timeout,
            cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Set a custom port for bootstrap DNS queries (useful in testing).
    #[must_use]
    pub fn with_port(mut self, port: u16) -> Self {
        self.bootstrap_port = port;
        self
    }

    /// Resolve a hostname or return the IP directly if it's already an IP literal.
    pub async fn resolve_hostname(&self, hostname: &str) -> Result<Vec<IpAddr>, UpstreamError> {
        let trimmed = hostname.trim();

        // Check if hostname is already an IP address
        if let Ok(ip) = IpAddr::from_str(trimmed) {
            return Ok(vec![ip]);
        }

        // Check in-memory cache
        {
            let cache = self.cache.read().await;
            if let Some(entry) = cache.get(trimmed) {
                if Instant::now() < entry.expires_at {
                    debug!("Bootstrap cache hit for '{}': {:?}", trimmed, entry.ips);
                    return Ok(entry.ips.clone());
                }
            }
        }

        let fqdn = if trimmed.ends_with('.') {
            trimmed.to_string()
        } else {
            format!("{trimmed}.")
        };

        let qname = Name::from_str(&fqdn).map_err(|e| {
            UpstreamError::BadResponse(format!("invalid hostname '{trimmed}': {e}"))
        })?;

        let mut errors = Vec::new();

        // Query bootstrap resolvers
        for &ip in &self.bootstrap_ips {
            let server_addr = SocketAddr::new(ip, self.bootstrap_port);
            let upstream = PlainUpstream::new(server_addr, self.query_timeout);

            // Query A records
            let mut query = Message::new(rand::random(), MessageType::Query, OpCode::Query);
            query
                .queries
                .push(Query::query(qname.clone(), RecordType::A));

            match upstream.resolve(&query).await {
                Ok(resp) => {
                    let mut resolved_ips = Vec::new();
                    let mut min_ttl = 300u32;

                    for ans in &resp.answers {
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

                    if !resolved_ips.is_empty() {
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
                Err(e) => {
                    warn!("Bootstrap resolver {} failed for '{}': {}", ip, trimmed, e);
                    errors.push(e);
                }
            }
        }

        Err(UpstreamError::BadResponse(format!(
            "Bootstrap resolution failed for '{trimmed}': {errors:?}"
        )))
    }
}
