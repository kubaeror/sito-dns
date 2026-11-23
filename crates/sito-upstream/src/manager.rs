//! Upstream manager coordinating failover, load balancing, parallel racing, health checking, and server pooling.

use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, RwLock};
use tokio::time::{sleep, timeout};
use tracing::{debug, info, trace, warn};

use sito_core::config::{UpstreamConfig, UpstreamStrategy};
use sito_core::error::UpstreamError;
use sito_proto::{Message, MessageType, Name, OpCode, Query, RecordType, ResponseCode};

use crate::bootstrap::BootstrapResolver;
use crate::doh::{DEFAULT_DOH_PATH, HttpsUpstream};
use crate::doq::QuicUpstream;
use crate::dot::DotUpstream;
use crate::health::{HealthStatus, UpstreamHealth};
use crate::plain::PlainUpstream;
use crate::upstream::{Upstream, is_edns_failure_code, is_retryable_response};

pub type NamedUpstream = (String, Arc<dyn Upstream>);
pub type PerDomainRule = (Vec<String>, Vec<NamedUpstream>);

/// One candidate attempt made while resolving a query.
///
/// The manager records each attempt separately so the pipeline can emit
/// per-attempt RTT/error metrics. The successful attempt's `rtt` measures only
/// that attempt, not the time already spent on failed candidates.
///
/// A parallel race also reports candidates that were still in flight when
/// another candidate won or the overall deadline fired. Those attempts are
/// marked `cancelled`: they did not produce a response, they did not fail, so
/// [`Self::is_success`] is `false` and [`Self::error_kind`] is `None`, and
/// their `rtt` is the time they ran before cancellation, not a usable
/// round-trip sample.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamAttempt {
    /// Configured upstream name (the label used by metrics and health).
    pub name: String,
    /// Time spent on this attempt alone.
    pub rtt: Duration,
    /// `None` on success and on cancellation; the candidate's error otherwise.
    pub error: Option<UpstreamError>,
    /// `true` when the candidate was dropped before it could answer because
    /// another parallel candidate won or the overall deadline fired.
    ///
    /// Cancellation is not a health failure and produces no RTT sample.
    pub cancelled: bool,
}

impl UpstreamAttempt {
    fn success(name: String, rtt: Duration) -> Self {
        Self {
            name,
            rtt,
            error: None,
            cancelled: false,
        }
    }

    fn failure(name: String, rtt: Duration, error: UpstreamError) -> Self {
        Self {
            name,
            rtt,
            error: Some(error),
            cancelled: false,
        }
    }

    /// An attempt that was still in flight when the race ended without it.
    fn cancelled(name: String, rtt: Duration) -> Self {
        Self {
            name,
            rtt,
            error: None,
            cancelled: true,
        }
    }

    /// Whether the candidate produced a usable response.
    ///
    /// A cancelled candidate never did, so this is `false` for it.
    #[must_use]
    pub fn is_success(&self) -> bool {
        !self.cancelled && self.error.is_none()
    }

    /// Stable, low-cardinality error kind for metrics labels.
    ///
    /// A cancellation is not a failure, so this is `None` for it.
    #[must_use]
    pub fn error_kind(&self) -> Option<&'static str> {
        if self.cancelled {
            return None;
        }
        self.error.as_ref().map(UpstreamError::kind)
    }
}

/// Drop guard that records a cancelled attempt for one parallel candidate.
///
/// The future owning the guard disarms it after it has recorded its real
/// success/failure attempt. If the future is dropped first (another candidate
/// won, or the overall deadline fired) the guard appends a cancelled attempt.
/// It only takes the existing `std::sync::Mutex`, never a Tokio lock, so it is
/// safe to run from `Drop`.
struct CancelledAttemptGuard {
    log: Arc<std::sync::Mutex<Vec<UpstreamAttempt>>>,
    name: String,
    started: Instant,
    armed: bool,
}

impl CancelledAttemptGuard {
    fn new(log: Arc<std::sync::Mutex<Vec<UpstreamAttempt>>>, name: String) -> Self {
        Self {
            log,
            name,
            started: Instant::now(),
            armed: true,
        }
    }

    /// Time elapsed since the candidate was launched.
    fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }

    /// The candidate recorded its own outcome; do not report a cancellation.
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for CancelledAttemptGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        if let Ok(mut log) = self.log.lock() {
            log.push(UpstreamAttempt::cancelled(
                self.name.clone(),
                self.started.elapsed(),
            ));
        }
    }
}

/// Failure returned by [`UpstreamManager::resolve_with_upstream`].
///
/// Carries the name of the upstream that produced the final error so callers
/// can attribute metrics and logs per server instead of labelling every
/// failure `"all"`. [`Self::kind`] and the `Display` implementation delegate to
/// the underlying [`UpstreamError`], so existing pipelines keep working.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamQueryError {
    /// The underlying upstream failure.
    pub error: UpstreamError,
    /// Name of the upstream entry that produced `error`, when one was tried.
    pub upstream: Option<String>,
    /// Every candidate attempt made before the failure.
    pub attempts: Vec<UpstreamAttempt>,
}

impl UpstreamQueryError {
    /// Failure attributed to a concrete managed upstream.
    fn from_entry(entry: &ManagedEntry, error: UpstreamError) -> Self {
        Self {
            error,
            upstream: Some(entry.name.clone()),
            attempts: Vec::new(),
        }
    }

    /// Failure that cannot be attributed to a single server (e.g. no
    /// candidates were available at all).
    fn unattributed(error: UpstreamError) -> Self {
        Self {
            error,
            upstream: None,
            attempts: Vec::new(),
        }
    }

    /// Stable, low-cardinality kind label (delegates to [`UpstreamError::kind`]).
    #[must_use]
    pub fn kind(&self) -> &'static str {
        self.error.kind()
    }

    /// Consume the failure, discarding upstream attribution.
    #[must_use]
    pub fn into_error(self) -> UpstreamError {
        self.error
    }
}

impl std::fmt::Display for UpstreamQueryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.upstream {
            Some(name) => write!(f, "upstream '{name}': {}", self.error),
            None => write!(f, "{}", self.error),
        }
    }
}

impl std::error::Error for UpstreamQueryError {}

impl From<UpstreamQueryError> for UpstreamError {
    fn from(error: UpstreamQueryError) -> Self {
        error.error
    }
}

/// Error recorded for a structurally valid reply whose response code marks a
/// transient upstream failure (see [`is_retryable_response`]).
fn retryable_status_error(code: ResponseCode) -> UpstreamError {
    UpstreamError::BadResponse(format!("upstream returned {code}, treated as retryable"))
}

/// Whether a reply indicates the upstream could not process the query's EDNS
/// OPT record (FORMERR/BADVERS). These are retried once without EDNS before the
/// candidate is considered failed.
fn is_edns_failure(response: &Message) -> bool {
    is_edns_failure_code(response.metadata.response_code)
}

/// Send one query to a candidate, retrying once without EDNS when the reply is
/// FORMERR/BADVERS.
///
/// Some recursive resolvers refuse the OPT record entirely (especially older or
/// middlebox-fronted servers). Dropping EDNS for the retry keeps the upstream
/// usable while still allowing us to fail over if it rejects the bare query
/// too.
async fn resolve_with_edns_fallback(
    upstream: &dyn Upstream,
    msg: &Message,
) -> Result<Message, UpstreamError> {
    let response = upstream.resolve(msg).await?;
    if msg.edns.is_some() && is_edns_failure(&response) {
        debug!(
            "Upstream returned {} for an EDNS query; retrying without EDNS",
            response.metadata.response_code
        );
        let mut fallback = msg.clone();
        fallback.edns = None;
        return upstream.resolve(&fallback).await;
    }
    Ok(response)
}

/// Overall deadline for one logical resolve. Retries share this budget so a
/// failover chain cannot take `timeout_duration × candidates`.
fn resolve_deadline(timeout_duration: Duration) -> Instant {
    Instant::now() + timeout_duration
}

/// Per-attempt budget: an equal share of what is left before `deadline` across
/// the candidates still to try, so every candidate gets a chance while the
/// total stays inside the deadline. `None` when the budget is exhausted.
fn attempt_budget(deadline: Instant, candidates_left: usize) -> Option<Duration> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    let left = u32::try_from(candidates_left.max(1)).unwrap_or(u32::MAX);
    let share = remaining / left;
    (!share.is_zero()).then_some(share)
}

#[derive(Clone)]
struct ManagedEntry {
    name: String,
    upstream: Arc<dyn Upstream>,
    health: Arc<RwLock<UpstreamHealth>>,
    /// Relative load-balancing weight (1..=100). Managed entries built outside
    /// the configuration path default to 1.
    weight: u32,
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

        for (index, server_str) in config.servers.iter().enumerate() {
            let mut entry =
                create_managed_entry(server_str, bootstrap, timeout_duration, config.pool_size)
                    .await?;
            entry.weight = config.effective_weight(index);
            entries.push(entry);
        }

        let mut per_domain_rules = Vec::new();
        for pd in &config.per_domain {
            let mut pd_entries = Vec::new();
            for (index, server_str) in pd.servers.iter().enumerate() {
                let mut entry =
                    create_managed_entry(server_str, bootstrap, timeout_duration, config.pool_size)
                        .await?;
                entry.weight = pd.effective_weight(index);
                pd_entries.push(entry);
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
    /// Historical round-robin cursor used while every weight is the default.
    rr_counter: AtomicUsize,
    /// Counter feeding the seeded SplitMix64 roll used for weighted
    /// `load_balance` selection. Kept as a counter (not a mutable RNG) so
    /// selection needs no lock on the query path.
    weight_rng: AtomicU64,
}

/// Golden-ratio increment for the SplitMix64 counter. Every query advances
/// the counter by this value and mixes the result, so concurrent callers get
/// independent, uniformly distributed rolls without sharing mutable state.
const WEIGHT_RNG_GAMMA: u64 = 0x9E37_79B9_7F4A_7C15;

/// Mixes one SplitMix64 counter value into a uniformly distributed `u64`.
fn splitmix64(mut value: u64) -> u64 {
    value = (value ^ (value >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    value ^ (value >> 31)
}

/// Returns a nondeterministic starting point for [`UpstreamManager::weight_rng`].
fn random_weight_seed() -> u64 {
    rand::random::<u64>() | 1
}

/// Picks one candidate index with probability proportional to its weight.
///
/// A single weighted choice is enough for the load-balance path: after the
/// first pick the remaining candidates are tried in configuration order, so a
/// failure still falls through to every other candidate. This is O(n) and
/// allocates nothing, and all candidates remain reachable.
fn weighted_start(weights: &[u32], mut roll: impl FnMut() -> u64) -> usize {
    if weights.is_empty() {
        return 0;
    }
    // Out-of-range or zero weights only come from internal/test callers;
    // treating them as unit weight keeps the selector total and avoids a
    // division by zero without hiding a configuration error (validation
    // rejects 0 before the manager is built).
    let total: u64 = weights
        .iter()
        .map(|weight| u64::from((*weight).max(1)))
        .sum();
    let mut pick = roll() % total;
    for (index, weight) in weights.iter().enumerate() {
        let weight = u64::from((*weight).max(1));
        if pick < weight {
            return index;
        }
        pick -= weight;
    }
    weights.len().saturating_sub(1)
}

/// A validated replacement upstream set that is not live yet.
pub struct PreparedUpstream {
    inner: UpstreamInner,
}

impl std::fmt::Debug for PreparedUpstream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedUpstream")
            .field("entries", &self.inner.entries.len())
            .finish_non_exhaustive()
    }
}

/// How often a multi-address upstream re-resolves its hostname.
const UPSTREAM_RE_RESOLVE_INTERVAL: Duration = Duration::from_secs(300);

/// Minimum spacing between cache-bypassing forced refreshes for one hostname.
/// Prevents a flapping upstream (or a query burst) from stampeding the
/// bootstrap servers.
const FORCED_REFRESH_BACKOFF: Duration = Duration::from_secs(5);

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
    #[cfg(test)]
    candidate_ips: RwLock<Vec<std::net::IpAddr>>,
    last_resolve: Mutex<Instant>,
    last_forced_refresh: Mutex<Option<Instant>>,
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
            #[cfg(test)]
            candidate_ips: RwLock::new(Vec::new()),
            last_resolve: Mutex::new(Instant::now()),
            last_forced_refresh: Mutex::new(None),
            re_resolve_interval,
        };
        let candidates = upstream.build_candidates(false).await?;
        *upstream.candidates.write().await = candidates;
        Ok(upstream)
    }

    async fn build_candidates(
        &self,
        force_refresh: bool,
    ) -> Result<Vec<Arc<dyn Upstream>>, UpstreamError> {
        let ips = if force_refresh {
            self.bootstrap.resolve_hostname_forced(&self.host).await?
        } else {
            self.bootstrap.resolve_hostname(&self.host).await?
        };
        if ips.is_empty() {
            return Err(UpstreamError::BadResponse(format!(
                "no IP addresses resolved for '{}'",
                self.host
            )));
        }

        #[cfg(test)]
        {
            *self.candidate_ips.write().await = ips.clone();
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

    #[cfg(test)]
    async fn candidate_ips(&self) -> Vec<std::net::IpAddr> {
        self.candidate_ips.read().await.clone()
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
        match self.build_candidates(false).await {
            Ok(candidates) => {
                *self.candidates.write().await = candidates;
                // Only advance the timestamp on success. A failed lookup must
                // not delay the next attempt for a full interval.
                *last = Instant::now();
                debug!("Re-resolved upstream '{}' candidate addresses", self.host);
                true
            }
            Err(e) => {
                debug!("Failed to re-resolve upstream '{}': {}", self.host, e);
                false
            }
        }
    }

    /// Force a cache-bypassing bootstrap refresh after every known candidate
    /// failed. Returns `true` when the candidate set was replaced.
    ///
    /// This ignores both the periodic interval and the bootstrap resolver's
    /// positive cache (TTLs are clamped to 60s..86400s), so rotated records can be picked up
    /// as soon as the old addresses stop answering.
    async fn force_re_resolve(&self) -> bool {
        // A literal address cannot rotate; retrying the same candidate after a
        // failure only doubles load and latency.
        if self.host.parse::<std::net::IpAddr>().is_ok() {
            return false;
        }
        let mut last_forced = self.last_forced_refresh.lock().await;
        if last_forced.is_some_and(|last| last.elapsed() < FORCED_REFRESH_BACKOFF) {
            return false;
        }
        // Timestamp the attempt, not just success: a hostname whose bootstrap
        // also fails must not be retried on every query.
        *last_forced = Some(Instant::now());
        drop(last_forced);

        let mut last = self.last_resolve.lock().await;
        match self.build_candidates(true).await {
            Ok(candidates) => {
                *self.candidates.write().await = candidates;
                *last = Instant::now();
                debug!(
                    "Force-refreshed upstream '{}' candidate addresses",
                    self.host
                );
                true
            }
            Err(e) => {
                debug!("Failed to force-refresh upstream '{}': {}", self.host, e);
                false
            }
        }
    }

    /// Tries candidates in order until one returns a usable answer. Returns the
    /// last error (`None` only when there were no candidates at all) so callers
    /// can decide whether to re-resolve.
    async fn try_candidates(
        &self,
        candidates: &[Arc<dyn Upstream>],
        msg: &Message,
        deadline: Instant,
    ) -> Result<Message, Option<UpstreamError>> {
        let mut last_error = None;
        let mut remaining = candidates.len();
        for candidate in candidates {
            // Each attempt gets an equal share of what is left of the overall
            // deadline; a failing candidate must not consume the whole budget.
            let Some(budget) = attempt_budget(deadline, remaining) else {
                break;
            };
            remaining -= 1;

            match timeout(budget, resolve_with_edns_fallback(candidate.as_ref(), msg)).await {
                Ok(Ok(response)) if !is_retryable_response(&response) => return Ok(response),
                Ok(Ok(response)) => {
                    debug!(
                        "Upstream candidate for '{}' returned retryable {}",
                        self.host, response.metadata.response_code
                    );
                    last_error = Some(retryable_status_error(response.metadata.response_code));
                }
                Ok(Err(e)) => {
                    debug!("Upstream candidate for '{}' failed: {}", self.host, e);
                    last_error = Some(e);
                }
                Err(_) => {
                    debug!("Upstream candidate for '{}' timed out", self.host);
                    last_error = Some(UpstreamError::Timeout);
                }
            }
        }
        Err(last_error)
    }

    async fn resolve_candidates(&self, msg: &Message) -> Result<Message, UpstreamError> {
        let deadline = resolve_deadline(self.timeout);
        // Hostname-based upstreams can only rotate by re-resolving, so keep
        // part of the overall budget for the forced refresh + retry after a
        // timeout. Literal addresses have nothing to refresh and keep the full
        // budget for their single attempt.
        let refreshable = self.host.parse::<std::net::IpAddr>().is_err();
        let first_phase_deadline = if refreshable {
            Instant::now() + self.timeout.mul_f64(0.7)
        } else {
            deadline
        };

        let candidates = self.candidates.read().await.clone();
        let mut last_error = match self
            .try_candidates(&candidates, msg, first_phase_deadline)
            .await
        {
            Ok(response) => return Ok(response),
            Err(error) => error,
        };

        // Every known address failed: force a cache-bypassing refresh and retry
        // once so rotated DNS records can be picked up without a restart or
        // waiting for the bootstrap cache TTL to expire. The refresh and the retry
        // stay inside the same overall deadline.
        let remaining = deadline.saturating_duration_since(Instant::now());
        if !remaining.is_zero()
            && let Ok(true) = timeout(remaining, self.force_re_resolve()).await
        {
            let candidates = self.candidates.read().await.clone();
            match self.try_candidates(&candidates, msg, deadline).await {
                Ok(response) => return Ok(response),
                Err(error) => last_error = error.or(last_error),
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
        // Propagate the maintenance hook to the transport candidates so idle
        // pooled connections are health-checked even when the candidate set
        // does not need re-resolution.
        let candidates = self.candidates.read().await.clone();
        futures_util::future::join_all(candidates.iter().map(|candidate| candidate.refresh()))
            .await;
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

    // Match schemes case-insensitively: validation accepts `TLS://` and the
    // runtime must build the same transport instead of treating it as a
    // single-label hostname.
    let (scheme, target) = split_scheme(server_str);

    let upstream: Arc<dyn Upstream> = match scheme.as_deref() {
        Some("tls") => {
            reject_path(server_str, target, "tls://")?;
            let (host, port) = split_host_port(target, 853);
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
        }
        Some("https") => {
            let (host, port, path) = parse_scheme_target(target, 443)?;
            Arc::new(
                FailoverUpstream::new(
                    bootstrap,
                    host.clone(),
                    port,
                    timeout_duration,
                    CandidateKind::Https {
                        url: build_https_url(&host, port, &path),
                    },
                )
                .await?,
            )
        }
        Some("quic") => {
            let (host, port, _path) = parse_scheme_target(target, 853)?;
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
        }
        Some("udp") => {
            reject_path(server_str, target, "udp://")?;
            let (host, port) = split_host_port(target, 53);
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
        }
        Some(other) => {
            return Err(UpstreamError::BadResponse(format!(
                "unsupported upstream scheme '{other}://' in '{server_str}'; supported schemes are tls://, https://, quic://, udp:// and plain host/IP"
            )));
        }
        None => {
            reject_path(server_str, server_str, "a plain host:port target")?;
            let (host, port) = split_host_port(server_str, 53);
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
        }
    };

    Ok(ManagedEntry {
        name,
        upstream,
        health: Arc::new(RwLock::new(UpstreamHealth::new())),
        weight: sito_core::config::DEFAULT_UPSTREAM_WEIGHT,
    })
}

/// Splits `scheme://rest` into a lowercased scheme (when present) and `rest`.
fn split_scheme(target: &str) -> (Option<String>, &str) {
    match target.split_once("://") {
        Some((scheme, rest)) => (Some(scheme.to_ascii_lowercase()), rest),
        None => (None, target),
    }
}

/// Rejects a URL path on schemes that do not carry one. Validation rejects
/// these too; the runtime check keeps direct manager callers in agreement.
fn reject_path(server_str: &str, target: &str, kind: &str) -> Result<(), UpstreamError> {
    if target.contains('/') {
        return Err(UpstreamError::BadResponse(format!(
            "upstream target '{server_str}' uses {kind} and must not include a URL path"
        )));
    }
    Ok(())
}

/// Parses `host[:port][/path]` for a scheme that accepts an optional path.
fn parse_scheme_target(
    target: &str,
    default_port: u16,
) -> Result<(String, u16, String), UpstreamError> {
    let (authority, path) = match target.split_once('/') {
        Some((authority, path)) => (authority, format!("/{path}")),
        None => (target, DEFAULT_DOH_PATH.to_string()),
    };
    let (host, port) = split_host_port(authority, default_port);
    if host.is_empty() {
        return Err(UpstreamError::BadResponse(format!(
            "invalid upstream URL '{target}': missing host"
        )));
    }
    Ok((host, port, path))
}

/// Builds the effective DoH URL from the parsed target pieces, including the
/// default `/dns-query` path when the operator omitted one.
fn build_https_url(host: &str, port: u16, path: &str) -> String {
    let authority = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    let port_suffix = if port == 443 {
        String::new()
    } else {
        format!(":{port}")
    };
    let path = if path.is_empty() {
        DEFAULT_DOH_PATH
    } else {
        path
    };
    format!("https://{authority}{port_suffix}{path}")
}

/// Returns the scheme of an upstream string if it uses an unsupported `xxx://` prefix.
#[cfg(test)]
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
    let s = s.trim_end_matches('.');
    // Accept raw IDN in configuration and store the punycode form so it
    // matches the wire-format query name.
    sito_proto::normalize_domain_or_idna(s).unwrap_or_else(|_| s.to_string())
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
            weight_rng: AtomicU64::new(random_weight_seed()),
        })
    }

    /// Builds a replacement upstream set without publishing it.
    ///
    /// Every configured server (including per-domain scopes) is constructed
    /// and validated here, so a bad candidate is an [`UpstreamError`] before
    /// any live component changes. Health state is carried over from this
    /// manager for entries that keep the same name.
    pub async fn prepare(
        &self,
        config: &UpstreamConfig,
        bootstrap: &BootstrapResolver,
    ) -> Result<PreparedUpstream, UpstreamError> {
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

        Ok(PreparedUpstream {
            inner: UpstreamInner {
                entries,
                per_domain_rules,
                strategy: new_inner.strategy,
                timeout_duration: new_inner.timeout_duration,
                probe_domain: new_inner.probe_domain,
            },
        })
    }

    /// Installs a prepared upstream set. Infallible: all fallible construction
    /// and validation happened in [`Self::prepare`].
    pub fn publish(&self, prepared: PreparedUpstream) {
        self.inner.store(Arc::new(prepared.inner));
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
        let prepared = self.prepare(config, bootstrap).await?;
        self.publish(prepared);
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
        let weighted = upstreams
            .into_iter()
            .map(|(name, upstream)| (name, upstream, sito_core::config::DEFAULT_UPSTREAM_WEIGHT))
            .collect();
        Self::with_weighted_upstreams(weighted, strategy, timeout_duration)
    }

    /// Create a manager with explicit per-entry weights and a randomly seeded
    /// selector (for production callers and tests that do not need a fixed
    /// sequence).
    pub fn with_weighted_upstreams(
        upstreams: Vec<(String, Arc<dyn Upstream>, u32)>,
        strategy: UpstreamStrategy,
        timeout_duration: Duration,
    ) -> Self {
        Self::with_weighted_upstreams_seeded(
            upstreams,
            strategy,
            timeout_duration,
            random_weight_seed(),
        )
    }

    /// Deterministic variant of [`Self::with_weighted_upstreams`].
    ///
    /// The seed drives the weighted first pick only; failover, health,
    /// deadlines, EDNS fallback and parallel racing are unchanged.
    #[must_use]
    pub fn with_weighted_upstreams_seeded(
        upstreams: Vec<(String, Arc<dyn Upstream>, u32)>,
        strategy: UpstreamStrategy,
        timeout_duration: Duration,
        seed: u64,
    ) -> Self {
        let entries = upstreams
            .into_iter()
            .map(|(name, upstream, weight)| ManagedEntry {
                name,
                upstream,
                health: Arc::new(RwLock::new(UpstreamHealth::new())),
                weight,
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
            weight_rng: AtomicU64::new(seed),
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
                        weight: sito_core::config::DEFAULT_UPSTREAM_WEIGHT,
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

    /// Effective weights for the global entry list, in the same order as
    /// [`Self::statuses`]. Per-domain rules keep their own weights.
    #[must_use]
    pub fn weights(&self) -> Vec<u32> {
        self.inner
            .load()
            .entries
            .iter()
            .map(|entry| entry.weight)
            .collect()
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
        self.resolve_with_upstream(msg)
            .await
            .map(|(resp, _)| resp)
            .map_err(UpstreamQueryError::into_error)
    }

    /// Resolve a DNS query according to domain rules and return the response
    /// along with the upstream identifier.
    ///
    /// On failure the returned [`UpstreamQueryError`] names the upstream that
    /// produced the final error (when one was tried), so callers can attribute
    /// metrics per server.
    pub async fn resolve_with_upstream(
        &self,
        msg: &Message,
    ) -> Result<(Message, String), UpstreamQueryError> {
        self.resolve_with_attempts(msg)
            .await
            .map(|(response, upstream, _attempts)| (response, upstream))
    }

    /// Resolve a DNS query and return every candidate attempt alongside the
    /// response (or failure).
    ///
    /// Callers that emit metrics should use this method: each entry in the
    /// returned attempt list is one candidate, including failures that were
    /// followed by a successful failover. `resolve_with_upstream` remains the
    /// compatibility wrapper for callers that only need the winner.
    pub async fn resolve_with_attempts(
        &self,
        msg: &Message,
    ) -> Result<(Message, String, Vec<UpstreamAttempt>), UpstreamQueryError> {
        let inner = self.inner.load();
        let mut attempts = Vec::new();
        let result = if let Some(query) = msg.queries.first() {
            // ASCII/punycode form: per-domain rules are normalized to
            // punycode, so a UTS46-decoded IDN would never match them.
            let qname_str = query.name.to_ascii().to_lowercase();
            let qname_clean = qname_str.trim_end_matches('.');
            let mut routed = None;
            for (domains, group) in &inner.per_domain_rules {
                if domains
                    .iter()
                    .any(|d| sito_core::matches_domain_suffix(qname_clean, d))
                {
                    debug!(
                        "Routing query for {} to per-domain upstreams {:?}",
                        qname_str, domains
                    );
                    routed = Some(
                        self.resolve_entries(
                            group,
                            msg,
                            inner.strategy,
                            inner.timeout_duration,
                            &mut attempts,
                        )
                        .await,
                    );
                    break;
                }
            }
            match routed {
                Some(result) => result,
                None => {
                    self.resolve_entries(
                        &inner.entries,
                        msg,
                        inner.strategy,
                        inner.timeout_duration,
                        &mut attempts,
                    )
                    .await
                }
            }
        } else {
            self.resolve_entries(
                &inner.entries,
                msg,
                inner.strategy,
                inner.timeout_duration,
                &mut attempts,
            )
            .await
        };

        match result {
            Ok((response, upstream)) => Ok((response, upstream, attempts)),
            Err(mut error) => {
                error.attempts = attempts;
                Err(error)
            }
        }
    }

    /// Runs one resolve across `entries` with the configured `strategy`.
    ///
    /// Retryable outcomes are `SERVFAIL`, `REFUSED` and `NOTIMP` replies (see
    /// [`is_retryable_response`]) as well as transport errors: each is recorded
    /// against the entry's health and the next candidate is tried.
    ///
    /// Strategy-specific behavior:
    /// - `Failover`: candidates in configuration order. Weights never reorder
    ///   an explicit failover chain.
    /// - `LoadBalance`: historical round-robin while every weight is the
    ///   default; once an operator opts in, a weighted first pick followed by
    ///   the remaining eligible candidates in configuration order. The first
    ///   pick follows the weight ratio and a failed pick falls through to
    ///   every other candidate, so weights cannot starve one.
    /// - `Parallel`: all candidates are raced; a retryable reply is treated as
    ///   a failure for that candidate so the race continues with the others.
    ///   Weights do not apply because every eligible candidate runs anyway.
    ///
    /// All strategies share one deadline (`timeout_duration` from the start of
    /// this call). Sequential attempts each get an equal share of the remaining
    /// budget, so total latency stays bounded by the configured timeout instead
    /// of growing by a factor of the candidate count.
    async fn resolve_entries(
        &self,
        entries: &[ManagedEntry],
        msg: &Message,
        strategy: UpstreamStrategy,
        timeout_duration: Duration,
        attempts: &mut Vec<UpstreamAttempt>,
    ) -> Result<(Message, String), UpstreamQueryError> {
        if entries.is_empty() {
            return Err(UpstreamQueryError::unattributed(UpstreamError::AllDown));
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

        let deadline = resolve_deadline(timeout_duration);

        match strategy {
            UpstreamStrategy::Parallel => {
                let mut futs = Vec::with_capacity(candidates.len());
                let parallel_attempts = Arc::new(std::sync::Mutex::new(Vec::new()));
                for entry in candidates {
                    let u = Arc::clone(&entry.upstream);
                    let h = Arc::clone(&entry.health);
                    let m = msg.clone();
                    let name = entry.name.clone();
                    let attempt_log = Arc::clone(&parallel_attempts);
                    let mut guard =
                        CancelledAttemptGuard::new(Arc::clone(&parallel_attempts), name.clone());
                    futs.push(Box::pin(async move {
                        let result = match resolve_with_edns_fallback(u.as_ref(), &m).await {
                            Ok(resp) if !is_retryable_response(&resp) => {
                                h.write().await.record_success();
                                Ok((resp, name.clone()))
                            }
                            Ok(resp) => {
                                let error = retryable_status_error(resp.metadata.response_code);
                                warn!("Upstream {} returned retryable response: {}", name, error);
                                h.write().await.record_error(&error);
                                Err(UpstreamQueryError {
                                    error,
                                    upstream: Some(name.clone()),
                                    attempts: Vec::new(),
                                })
                            }
                            Err(error) => {
                                warn!("Upstream {} failed parallel query: {}", name, error);
                                h.write().await.record_error(&error);
                                Err(UpstreamQueryError {
                                    error,
                                    upstream: Some(name.clone()),
                                    attempts: Vec::new(),
                                })
                            }
                        };
                        let rtt = guard.elapsed();
                        let attempt = match &result {
                            Ok(_) => UpstreamAttempt::success(name, rtt),
                            Err(error) => UpstreamAttempt::failure(name, rtt, error.error.clone()),
                        };
                        if let Ok(mut log) = attempt_log.lock() {
                            log.push(attempt);
                        }
                        // The real outcome is logged; if this future is still
                        // dropped afterwards it must not also log a cancellation.
                        guard.disarm();
                        result
                    }));
                }
                // All attempts already run concurrently, so the whole race gets
                // the full timeout; the deadline only bounds implementations
                // that ignore their own timeout.
                let mut race = Box::pin(timeout(
                    timeout_duration,
                    futures_util::future::select_ok(futs),
                ));
                let raced = race.as_mut().await;
                // Drop the race first: on the timeout path this drops every
                // still-pending candidate, which runs its cancellation guard.
                drop(race);
                let result = match raced {
                    Ok(Ok((response, rest))) => {
                        // `select_ok` returns the losing futures. Dropping them
                        // runs their cancellation guards before the attempt log
                        // is collected below.
                        drop(rest);
                        Ok(response)
                    }
                    Ok(Err(error)) => Err(error),
                    Err(_) => Err(UpstreamQueryError::unattributed(UpstreamError::Timeout)),
                };
                if let Ok(mut log) = parallel_attempts.lock() {
                    attempts.append(&mut log);
                }
                result
            }
            UpstreamStrategy::LoadBalance => {
                let weights: Vec<u32> = candidates.iter().map(|entry| entry.weight).collect();
                // Keep the historical round-robin order exactly when every
                // weight is the default. The weighted selector only takes over
                // once an operator opts in, so default configs keep their
                // previous selection behavior.
                if weights
                    .iter()
                    .all(|weight| *weight == sito_core::config::DEFAULT_UPSTREAM_WEIGHT)
                {
                    let start_idx =
                        self.rr_counter.fetch_add(1, Ordering::Relaxed) % candidates.len();
                    let ordered: Vec<&ManagedEntry> = (0..candidates.len())
                        .map(|index| candidates[(start_idx + index) % candidates.len()])
                        .collect();
                    resolve_sequential(&ordered, msg, deadline, attempts).await
                } else {
                    let start = weighted_start(&weights, || {
                        splitmix64(
                            self.weight_rng
                                .fetch_add(WEIGHT_RNG_GAMMA, Ordering::Relaxed),
                        )
                    });
                    let ordered: Vec<&ManagedEntry> = (0..candidates.len())
                        .map(|offset| candidates[(start + offset) % candidates.len()])
                        .collect();
                    resolve_sequential(&ordered, msg, deadline, attempts).await
                }
            }
            UpstreamStrategy::Failover => {
                resolve_sequential(&candidates, msg, deadline, attempts).await
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
                    res = shutdown_rx.changed() => {
                        if res.is_err() || *shutdown_rx.borrow() {
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

                        let probe_timeout = health_probe_timeout(inner.timeout_duration);
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

/// Minimum timeout for an active health probe. Probes must not reuse the query
/// timeout: a healthy but slow upstream (e.g. a cold DoT handshake that takes
/// longer than the query budget) would otherwise be recorded as a failure and
/// mark a working upstream down.
const MIN_HEALTH_PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// Timeout applied to a single active health probe.
fn health_probe_timeout(query_timeout: Duration) -> Duration {
    query_timeout.max(MIN_HEALTH_PROBE_TIMEOUT)
}

/// Runs one candidate attempt inside its share of the overall deadline.
async fn attempt_entry(
    entry: &ManagedEntry,
    msg: &Message,
    budget: Duration,
) -> Result<Message, UpstreamError> {
    match timeout(
        budget,
        resolve_with_edns_fallback(entry.upstream.as_ref(), msg),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => Err(UpstreamError::Timeout),
    }
}

/// Tries `ordered` entries in sequence, each within its share of `deadline`.
///
/// A reply is only accepted when [`is_retryable_response`] is false; other
/// replies are recorded against the entry's health and the next entry is tried.
async fn resolve_sequential(
    ordered: &[&ManagedEntry],
    msg: &Message,
    deadline: Instant,
    attempts: &mut Vec<UpstreamAttempt>,
) -> Result<(Message, String), UpstreamQueryError> {
    let mut last_error = None;
    for (i, entry) in ordered.iter().enumerate() {
        let Some(budget) = attempt_budget(deadline, ordered.len() - i) else {
            break;
        };
        trace!("Querying upstream {}", entry.name);
        let started = Instant::now();
        match attempt_entry(entry, msg, budget).await {
            Ok(response) if !is_retryable_response(&response) => {
                entry.health.write().await.record_success();
                attempts.push(UpstreamAttempt::success(
                    entry.name.clone(),
                    started.elapsed(),
                ));
                return Ok((response, entry.name.clone()));
            }
            Ok(response) => {
                let error = retryable_status_error(response.metadata.response_code);
                warn!(
                    "Upstream {} returned retryable response: {}",
                    entry.name, error
                );
                entry.health.write().await.record_error(&error);
                attempts.push(UpstreamAttempt::failure(
                    entry.name.clone(),
                    started.elapsed(),
                    error.clone(),
                ));
                last_error = Some(UpstreamQueryError::from_entry(entry, error));
            }
            Err(error) => {
                warn!("Upstream {} failed query: {}", entry.name, error);
                entry.health.write().await.record_error(&error);
                attempts.push(UpstreamAttempt::failure(
                    entry.name.clone(),
                    started.elapsed(),
                    error.clone(),
                ));
                last_error = Some(UpstreamQueryError::from_entry(entry, error));
            }
        }
    }
    Err(last_error.unwrap_or_else(|| UpstreamQueryError::unattributed(UpstreamError::AllDown)))
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
    // Many recursive resolvers refuse RD=0 (they are not authoritative for the
    // probe domain), so health probes must explicitly request recursion.
    query.metadata.recursion_desired = true;
    query.queries.push(Query::query(qname, RecordType::A));

    match tokio::time::timeout(probe_timeout, entry.upstream.resolve(&query)).await {
        Ok(Ok(response)) if !is_retryable_response(&response) => {
            info!("Active probe succeeded for upstream {}", name);
            entry.health.write().await.record_probe_success();
        }
        Ok(Ok(response)) => {
            let error = retryable_status_error(response.metadata.response_code);
            debug!("Active probe failed for upstream {}: {}", name, error);
            entry.health.write().await.record_error(&error);
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

    /// Mock upstream returning a fixed response code (plus an A answer for
    /// `NoError`), used to exercise retryability without a socket.
    struct RcodeMockUpstream {
        response_code: ResponseCode,
        delay: Duration,
        result_ip: std::net::Ipv4Addr,
        call_count: Arc<AtomicU32>,
    }

    #[async_trait::async_trait]
    impl Upstream for RcodeMockUpstream {
        async fn resolve(&self, msg: &Message) -> Result<Message, UpstreamError> {
            self.call_count.fetch_add(1, Ordering::SeqCst);
            if self.delay > Duration::ZERO {
                tokio::time::sleep(self.delay).await;
            }
            let mut resp = Message::response(msg.metadata.id, msg.metadata.op_code);
            resp.queries = msg.queries.clone();
            resp.metadata.response_code = self.response_code;
            if self.response_code == ResponseCode::NoError {
                resp.answers.push(Record::from_rdata(
                    msg.queries[0].name().clone(),
                    300,
                    RData::A(A(self.result_ip)),
                ));
            }
            Ok(resp)
        }
    }

    /// Spawns a plain-DNS UDP mock answering every query with `response_code`
    /// (and an A record when `answer` is `Some` and the code is `NoError`).
    async fn spawn_udp_rcode_server(
        response_code: ResponseCode,
        answer: Option<std::net::Ipv4Addr>,
    ) -> (SocketAddr, Arc<AtomicU32>) {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let calls = Arc::new(AtomicU32::new(0));
        let counter = Arc::clone(&calls);
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            while let Ok((len, peer)) = socket.recv_from(&mut buf).await {
                counter.fetch_add(1, Ordering::SeqCst);
                let Ok(query) = decode_message(&buf[..len]) else {
                    continue;
                };
                let mut resp = Message::response(query.metadata.id, query.metadata.op_code);
                resp.queries = query.queries.clone();
                resp.metadata.response_code = response_code;
                if response_code == ResponseCode::NoError
                    && let Some(ip) = answer
                {
                    resp.answers.push(Record::from_rdata(
                        query.queries[0].name().clone(),
                        300,
                        RData::A(A(ip)),
                    ));
                }
                if let Ok(encoded) = encode_message(&resp) {
                    let _ = socket.send_to(&encoded, peer).await;
                }
            }
        });
        (addr, calls)
    }

    fn test_query() -> Message {
        let mut query = Message::new(1, MessageType::Query, OpCode::Query);
        query.queries.push(Query::query(
            Name::from_str("test.com.").unwrap(),
            RecordType::A,
        ));
        query
    }

    /// WP-6.1 item 1: a well-formed SERVFAIL from the first upstream must be
    /// treated as a failure (not a successful resolution) and the next
    /// upstream must be tried.
    #[tokio::test]
    async fn test_failover_retries_on_servfail_udp_response() {
        let (servfail_addr, servfail_calls) =
            spawn_udp_rcode_server(ResponseCode::ServFail, None).await;
        let (healthy_addr, healthy_calls) = spawn_udp_rcode_server(
            ResponseCode::NoError,
            Some(std::net::Ipv4Addr::new(9, 9, 9, 9)),
        )
        .await;

        let manager = UpstreamManager::with_upstreams(
            vec![
                (
                    "servfail.dns".to_string(),
                    Arc::new(PlainUpstream::new(
                        servfail_addr,
                        Duration::from_millis(500),
                    )),
                ),
                (
                    "healthy.dns".to_string(),
                    Arc::new(PlainUpstream::new(healthy_addr, Duration::from_millis(500))),
                ),
            ],
            UpstreamStrategy::Failover,
            Duration::from_millis(500),
        );

        let (resp, upstream) = manager
            .resolve_with_upstream(&test_query())
            .await
            .expect("SERVFAIL must fail over to the healthy upstream");
        assert_eq!(upstream, "healthy.dns");
        assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
        assert_eq!(
            resp.answers[0].data,
            RData::A(A(std::net::Ipv4Addr::new(9, 9, 9, 9)))
        );
        assert_eq!(servfail_calls.load(Ordering::SeqCst), 1);
        assert_eq!(healthy_calls.load(Ordering::SeqCst), 1);

        // The retryable reply must also count against the failing server's
        // health: 3 consecutive failures move it to Suspect.
        for _ in 0..2 {
            manager
                .resolve(&test_query())
                .await
                .expect("failover must keep succeeding");
        }
        let statuses = manager.statuses().await;
        let status_of = |name: &str| {
            statuses
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, s)| *s)
                .unwrap()
        };
        assert_eq!(status_of("servfail.dns"), HealthStatus::Suspect);
        assert_eq!(status_of("healthy.dns"), HealthStatus::Healthy);
    }

    /// WP-6.1 item 1/2: every retryable response code fails over to the next
    /// candidate in the configured order.
    #[tokio::test]
    async fn test_all_retryable_rcodes_fail_over() {
        for code in [
            ResponseCode::ServFail,
            ResponseCode::Refused,
            ResponseCode::NotImp,
        ] {
            let calls_bad = Arc::new(AtomicU32::new(0));
            let calls_good = Arc::new(AtomicU32::new(0));
            let manager = UpstreamManager::with_upstreams(
                vec![
                    (
                        "bad.dns".to_string(),
                        Arc::new(RcodeMockUpstream {
                            response_code: code,
                            delay: Duration::ZERO,
                            result_ip: std::net::Ipv4Addr::new(1, 1, 1, 1),
                            call_count: Arc::clone(&calls_bad),
                        }),
                    ),
                    (
                        "good.dns".to_string(),
                        Arc::new(RcodeMockUpstream {
                            response_code: ResponseCode::NoError,
                            delay: Duration::ZERO,
                            result_ip: std::net::Ipv4Addr::new(2, 2, 2, 2),
                            call_count: Arc::clone(&calls_good),
                        }),
                    ),
                ],
                UpstreamStrategy::Failover,
                Duration::from_millis(500),
            );

            let resp = manager
                .resolve(&test_query())
                .await
                .unwrap_or_else(|e| panic!("{code} must fail over, got {e}"));
            assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
            assert_eq!(calls_bad.load(Ordering::SeqCst), 1, "{code}");
            assert_eq!(calls_good.load(Ordering::SeqCst), 1, "{code}");
        }
    }

    /// WP-6.1 item 2: load_balance retries the same way as failover.
    #[tokio::test]
    async fn test_load_balance_retries_on_retryable_response() {
        let (servfail_addr, servfail_calls) =
            spawn_udp_rcode_server(ResponseCode::ServFail, None).await;
        let (healthy_addr, healthy_calls) = spawn_udp_rcode_server(
            ResponseCode::NoError,
            Some(std::net::Ipv4Addr::new(5, 5, 5, 5)),
        )
        .await;

        // Try several seeds instead of pinning one: whichever candidate the
        // weighted first pick chooses, a retryable reply must end at the
        // healthy candidate.
        let servfail: Arc<dyn Upstream> = Arc::new(PlainUpstream::new(
            servfail_addr,
            Duration::from_millis(500),
        ));
        let healthy: Arc<dyn Upstream> =
            Arc::new(PlainUpstream::new(healthy_addr, Duration::from_millis(500)));
        for seed in 1..=8 {
            let manager = UpstreamManager::with_weighted_upstreams_seeded(
                vec![
                    ("servfail.dns".to_string(), Arc::clone(&servfail), 99),
                    ("healthy.dns".to_string(), Arc::clone(&healthy), 1),
                ],
                UpstreamStrategy::LoadBalance,
                Duration::from_millis(500),
                seed,
            );
            let (resp, upstream) = manager
                .resolve_with_upstream(&test_query())
                .await
                .expect("load_balance must retry on SERVFAIL");
            assert_eq!(upstream, "healthy.dns");
            assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
        }
        assert!(
            servfail_calls.load(Ordering::SeqCst) >= 1,
            "across seeds the weighted failing candidate must be tried at least once"
        );
        assert_eq!(healthy_calls.load(Ordering::SeqCst), 8);
    }

    /// WP-6.1 item 2: parallel racing must not accept a retryable reply while
    /// another candidate can still answer.
    #[tokio::test]
    async fn test_parallel_ignores_retryable_response() {
        let calls_bad = Arc::new(AtomicU32::new(0));
        let calls_good = Arc::new(AtomicU32::new(0));
        let manager = UpstreamManager::with_upstreams(
            vec![
                (
                    "servfail.dns".to_string(),
                    Arc::new(RcodeMockUpstream {
                        response_code: ResponseCode::ServFail,
                        delay: Duration::ZERO,
                        result_ip: std::net::Ipv4Addr::new(1, 1, 1, 1),
                        call_count: Arc::clone(&calls_bad),
                    }),
                ),
                (
                    "healthy.dns".to_string(),
                    Arc::new(RcodeMockUpstream {
                        response_code: ResponseCode::NoError,
                        delay: Duration::from_millis(50),
                        result_ip: std::net::Ipv4Addr::new(3, 3, 3, 3),
                        call_count: Arc::clone(&calls_good),
                    }),
                ),
            ],
            UpstreamStrategy::Parallel,
            Duration::from_millis(500),
        );

        let (resp, upstream) = manager
            .resolve_with_upstream(&test_query())
            .await
            .expect("parallel must wait for the usable reply");
        assert_eq!(upstream, "healthy.dns");
        assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
        assert_eq!(
            resp.answers[0].data,
            RData::A(A(std::net::Ipv4Addr::new(3, 3, 3, 3)))
        );
        assert_eq!(calls_bad.load(Ordering::SeqCst), 1);
    }

    /// WP-6.1 item 3: the failing server is named in the returned error so the
    /// pipeline can attribute metrics per server instead of `"all"`.
    #[tokio::test]
    async fn test_retryable_failure_is_attributed_to_the_server() {
        let (refused_addr, refused_calls) =
            spawn_udp_rcode_server(ResponseCode::Refused, None).await;
        let manager = UpstreamManager::with_upstreams(
            vec![(
                "refused.dns".to_string(),
                Arc::new(PlainUpstream::new(refused_addr, Duration::from_millis(500))),
            )],
            UpstreamStrategy::Failover,
            Duration::from_millis(500),
        );

        let error = manager
            .resolve_with_upstream(&test_query())
            .await
            .expect_err("REFUSED must not be returned as a successful resolution");
        assert_eq!(error.upstream.as_deref(), Some("refused.dns"));
        assert_eq!(error.kind(), "bad_response");
        assert!(
            error.to_string().contains("refused.dns")
                && error.to_string().contains("Query Refused"),
            "error must name the server and the rcode: {error}"
        );
        assert_eq!(refused_calls.load(Ordering::SeqCst), 1);

        // `resolve` keeps its flat `UpstreamError` contract.
        let flat = manager
            .resolve(&test_query())
            .await
            .expect_err("REFUSED must not be returned as success");
        assert_eq!(flat.kind(), "bad_response");
    }

    /// WP-6.1 item 1: retries share one deadline; a hanging first candidate
    /// must not consume the whole budget and starve the healthy one.
    #[tokio::test]
    async fn test_failover_respects_total_deadline() {
        let calls_healthy = Arc::new(AtomicU32::new(0));
        let manager = UpstreamManager::with_upstreams(
            vec![
                ("hanging.dns".to_string(), Arc::new(HangingUpstream)),
                (
                    "healthy.dns".to_string(),
                    Arc::new(RcodeMockUpstream {
                        response_code: ResponseCode::NoError,
                        delay: Duration::ZERO,
                        result_ip: std::net::Ipv4Addr::new(7, 7, 7, 7),
                        call_count: Arc::clone(&calls_healthy),
                    }),
                ),
            ],
            UpstreamStrategy::Failover,
            Duration::from_millis(300),
        );

        let start = Instant::now();
        for _ in 0..3 {
            let resp = timeout(Duration::from_secs(2), manager.resolve(&test_query()))
                .await
                .expect("resolve must not hang: retries share the configured deadline")
                .expect("the healthy upstream must answer within the shared deadline");
            assert_eq!(
                resp.answers[0].data,
                RData::A(A(std::net::Ipv4Addr::new(7, 7, 7, 7)))
            );
        }
        let elapsed = start.elapsed();
        assert!(
            elapsed < Duration::from_millis(1500),
            "three 300ms-budget resolves must stay near 3x300ms (took {elapsed:?})"
        );

        // The hanging candidate's timeouts must be recorded as health failures.
        let statuses = manager.statuses().await;
        let hanging = statuses
            .iter()
            .find(|(name, _)| name == "hanging.dns")
            .map(|(_, status)| *status)
            .unwrap();
        assert_eq!(hanging, HealthStatus::Suspect);
        assert_eq!(calls_healthy.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn test_attempt_budget_shares_the_deadline() {
        // No time left: no attempt at all.
        let expired = Instant::now()
            .checked_sub(Duration::from_secs(1))
            .expect("one second before now is representable");
        assert_eq!(attempt_budget(expired, 1), None);

        // A single candidate gets (almost) the whole remaining budget.
        let budget = attempt_budget(Instant::now() + Duration::from_millis(300), 1).unwrap();
        assert!(budget <= Duration::from_millis(300));
        assert!(budget > Duration::from_millis(250), "{budget:?}");

        // Two candidates share it equally.
        let budget = attempt_budget(Instant::now() + Duration::from_millis(300), 2).unwrap();
        assert!(budget <= Duration::from_millis(150));
        assert!(budget > Duration::from_millis(100), "{budget:?}");
    }

    /// WP-6.1 item 5: the probe timeout is decoupled from the query timeout.
    #[test]
    fn test_health_probe_timeout_is_at_least_five_seconds() {
        assert_eq!(
            health_probe_timeout(Duration::from_millis(100)),
            Duration::from_secs(5)
        );
        assert_eq!(
            health_probe_timeout(Duration::from_secs(8)),
            Duration::from_secs(8),
            "a query timeout longer than the floor must be kept"
        );
    }

    /// WP-6.1 item 5: a healthy-but-slow upstream must not be marked down by
    /// probes whose timeout equals the query timeout.
    #[tokio::test]
    async fn test_slow_but_healthy_probe_is_not_marked_down() {
        let entry = ManagedEntry {
            name: "slow.dns".to_string(),
            upstream: Arc::new(ConfigurableMockUpstream {
                succeed: true,
                delay: Duration::from_millis(200),
                result_ip: std::net::Ipv4Addr::new(4, 4, 4, 4),
                call_count: Arc::new(AtomicU32::new(0)),
            }),
            health: Arc::new(RwLock::new(UpstreamHealth::new())),
            weight: 1,
        };
        let probe_timeout = health_probe_timeout(Duration::from_millis(100));
        let qname = Name::from_str("example.com.").unwrap();

        for _ in 0..6 {
            probe_one(entry.clone(), qname.clone(), probe_timeout).await;
        }

        assert_eq!(
            entry.health.read().await.status(),
            HealthStatus::Healthy,
            "a 200ms probe with a 100ms query timeout must still succeed"
        );
    }

    /// A retryable reply to an active probe is a probe failure: it must not
    /// count as one of the probe successes that revive a Down upstream.
    #[tokio::test]
    async fn test_probe_does_not_count_retryable_response_as_success() {
        let entry = ManagedEntry {
            name: "servfail.dns".to_string(),
            upstream: Arc::new(RcodeMockUpstream {
                response_code: ResponseCode::ServFail,
                delay: Duration::ZERO,
                result_ip: std::net::Ipv4Addr::new(1, 1, 1, 1),
                call_count: Arc::new(AtomicU32::new(0)),
            }),
            health: Arc::new(RwLock::new(UpstreamHealth::new())),
            weight: 1,
        };
        {
            let mut health = entry.health.write().await;
            for _ in 0..6 {
                health.record_error(&UpstreamError::Timeout);
            }
            assert_eq!(health.status(), HealthStatus::Down);
        }

        let qname = Name::from_str("example.com.").unwrap();
        for _ in 0..3 {
            probe_one(entry.clone(), qname.clone(), Duration::from_secs(1)).await;
        }

        assert_eq!(
            entry.health.read().await.status(),
            HealthStatus::Down,
            "SERVFAIL probes must not revive a down upstream"
        );
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

    /// G2: every candidate launched by a parallel race is reported. The fast
    /// winner is a success; the slower candidate is still in flight when the
    /// race ends, so it is reported as cancelled — not as a success and not as
    /// a failure.
    #[tokio::test]
    async fn test_parallel_reports_cancelled_losers() {
        let calls_fast = Arc::new(AtomicU32::new(0));
        let calls_slow = Arc::new(AtomicU32::new(0));

        let manager = UpstreamManager::with_upstreams(
            vec![
                (
                    "slow".to_string(),
                    Arc::new(ConfigurableMockUpstream {
                        succeed: true,
                        delay: Duration::from_secs(2),
                        result_ip: std::net::Ipv4Addr::new(2, 2, 2, 2),
                        call_count: Arc::clone(&calls_slow),
                    }),
                ),
                (
                    "fast".to_string(),
                    Arc::new(ConfigurableMockUpstream {
                        succeed: true,
                        delay: Duration::from_millis(10),
                        result_ip: std::net::Ipv4Addr::new(1, 1, 1, 1),
                        call_count: Arc::clone(&calls_fast),
                    }),
                ),
            ],
            UpstreamStrategy::Parallel,
            Duration::from_secs(5),
        );

        let (response, upstream, attempts) = manager
            .resolve_with_attempts(&test_query())
            .await
            .expect("the fast candidate must win the race");
        assert_eq!(response.metadata.response_code, ResponseCode::NoError);
        assert_eq!(upstream, "fast");
        assert_eq!(calls_fast.load(Ordering::SeqCst), 1);
        assert_eq!(calls_slow.load(Ordering::SeqCst), 1);
        assert_eq!(
            attempts.len(),
            2,
            "both launched candidates must be reported: {attempts:?}"
        );

        let winner = attempts
            .iter()
            .find(|attempt| attempt.name == "fast")
            .expect("winner attempt present");
        assert!(winner.is_success());
        assert!(!winner.cancelled);
        assert_eq!(winner.error_kind(), None);

        let loser = attempts
            .iter()
            .find(|attempt| attempt.name == "slow")
            .expect("cancelled loser attempt present");
        assert!(loser.cancelled, "the slow loser must be cancelled");
        assert!(!loser.is_success(), "a cancelled attempt is not a success");
        assert_eq!(
            loser.error_kind(),
            None,
            "a cancellation must not be reported as a failure kind"
        );
        assert!(
            loser.rtt >= Duration::from_millis(5),
            "the cancelled attempt reports the time it ran: {:?}",
            loser.rtt
        );
        assert!(
            loser.rtt < Duration::from_secs(2),
            "cancellation happens before the slow upstream answers: {:?}",
            loser.rtt
        );
    }

    /// G2: when the overall parallel deadline fires, every in-flight candidate
    /// is reported as cancelled and the final error is an unattributed timeout.
    #[tokio::test]
    async fn test_parallel_timeout_reports_cancelled_attempts_and_final_timeout() {
        let calls_a = Arc::new(AtomicU32::new(0));
        let calls_b = Arc::new(AtomicU32::new(0));

        let manager = UpstreamManager::with_upstreams(
            vec![
                (
                    "slow-a".to_string(),
                    Arc::new(ConfigurableMockUpstream {
                        succeed: true,
                        delay: Duration::from_millis(500),
                        result_ip: std::net::Ipv4Addr::new(1, 1, 1, 1),
                        call_count: Arc::clone(&calls_a),
                    }),
                ),
                (
                    "slow-b".to_string(),
                    Arc::new(ConfigurableMockUpstream {
                        succeed: true,
                        delay: Duration::from_millis(500),
                        result_ip: std::net::Ipv4Addr::new(2, 2, 2, 2),
                        call_count: Arc::clone(&calls_b),
                    }),
                ),
            ],
            UpstreamStrategy::Parallel,
            Duration::from_millis(60),
        );

        let error = manager
            .resolve_with_attempts(&test_query())
            .await
            .expect_err("the overall parallel deadline must fire");
        assert_eq!(error.kind(), "timeout");
        assert_eq!(
            error.upstream, None,
            "an overall timeout cannot be attributed to one candidate"
        );
        assert_eq!(calls_a.load(Ordering::SeqCst), 1);
        assert_eq!(calls_b.load(Ordering::SeqCst), 1);
        assert_eq!(
            error.attempts.len(),
            2,
            "every timed-out candidate must be reported: {:?}",
            error.attempts
        );
        for attempt in &error.attempts {
            assert!(attempt.cancelled, "{} must be cancelled", attempt.name);
            assert!(!attempt.is_success());
            assert_eq!(attempt.error_kind(), None);
        }
    }

    /// G2: a fully failed race is not a cancellation. Each candidate failed on
    /// its own before the deadline, so each attempt carries its error kind.
    #[tokio::test]
    async fn test_parallel_all_failures_are_not_cancelled() {
        let manager = UpstreamManager::with_upstreams(
            vec![
                (
                    "fail-a".to_string(),
                    Arc::new(ConfigurableMockUpstream {
                        succeed: false,
                        delay: Duration::ZERO,
                        result_ip: std::net::Ipv4Addr::new(1, 1, 1, 1),
                        call_count: Arc::new(AtomicU32::new(0)),
                    }),
                ),
                (
                    "fail-b".to_string(),
                    Arc::new(ConfigurableMockUpstream {
                        succeed: false,
                        delay: Duration::ZERO,
                        result_ip: std::net::Ipv4Addr::new(2, 2, 2, 2),
                        call_count: Arc::new(AtomicU32::new(0)),
                    }),
                ),
            ],
            UpstreamStrategy::Parallel,
            Duration::from_secs(1),
        );

        let error = manager
            .resolve_with_attempts(&test_query())
            .await
            .expect_err("both candidates fail");
        assert_eq!(error.kind(), "timeout");
        assert_eq!(
            error.attempts.len(),
            2,
            "both failures must be reported: {:?}",
            error.attempts
        );
        for attempt in &error.attempts {
            assert!(
                !attempt.cancelled,
                "{} failed, it was not cancelled",
                attempt.name
            );
            assert!(!attempt.is_success());
            assert_eq!(attempt.error_kind(), Some("timeout"));
        }
    }

    #[tokio::test]
    async fn test_load_balance_strategy_spreads_across_servers() {
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

        // Equal default weights keep the historical round-robin behavior, so
        // both servers receive an even share.
        let manager = UpstreamManager::with_weighted_upstreams_seeded(
            vec![
                ("a".to_string(), upstream_a, 1),
                ("b".to_string(), upstream_b, 1),
            ],
            UpstreamStrategy::LoadBalance,
            Duration::from_secs(1),
            1,
        );

        let mut query = Message::new(1, MessageType::Query, OpCode::Query);
        query.queries.push(Query::query(
            Name::from_str("test.com.").unwrap(),
            RecordType::A,
        ));

        let mut answers = Vec::new();
        for _ in 0..100 {
            let response = manager.resolve(&query).await.unwrap();
            assert_eq!(response.answers.len(), 1);
            answers.push(response.answers[0].data.clone());
        }
        assert_ne!(
            answers[0], answers[1],
            "default weights must keep the deterministic round-robin alternation"
        );

        let a = calls_a.load(Ordering::SeqCst);
        let b = calls_b.load(Ordering::SeqCst);
        assert_eq!(a + b, 100);
        assert!(
            (30..=70).contains(&a),
            "equal weights must share the load (a={a}, b={b})"
        );
    }

    fn seeded_roll(seed: &mut u64) -> u64 {
        *seed = seed.wrapping_add(WEIGHT_RNG_GAMMA);
        splitmix64(*seed)
    }

    /// F1: the pure selector picks the first candidate proportionally to its
    /// weight and every index stays reachable.
    #[test]
    fn test_weighted_start_is_proportional() {
        let weights = [3u32, 1];
        let mut seed = 42u64;
        let mut first_counts = [0u32; 2];
        for _ in 0..10_000 {
            let start = weighted_start(&weights, || seeded_roll(&mut seed));
            assert!(start < weights.len());
            first_counts[start] += 1;
        }
        let heavy_share = f64::from(first_counts[0]) / 10_000.0;
        assert!(
            (0.72..=0.78).contains(&heavy_share),
            "a 3:1 split must put the heavy upstream first ~75% of the time (got {heavy_share})"
        );
        assert_eq!(
            weighted_start(&[], || 0),
            0,
            "an empty candidate list must not panic"
        );
    }

    /// F1: load_balance picks the first candidate proportionally to its weight
    /// over many seeded samples instead of round-robin fairness.
    #[tokio::test]
    async fn test_weighted_load_balance_distribution_is_proportional() {
        const SAMPLES: u32 = 2_000;
        let heavy_calls = Arc::new(AtomicU32::new(0));
        let light_calls = Arc::new(AtomicU32::new(0));
        let manager = UpstreamManager::with_weighted_upstreams_seeded(
            vec![
                (
                    "heavy.dns".to_string(),
                    Arc::new(ConfigurableMockUpstream {
                        succeed: true,
                        delay: Duration::ZERO,
                        result_ip: std::net::Ipv4Addr::new(1, 1, 1, 1),
                        call_count: Arc::clone(&heavy_calls),
                    }),
                    3,
                ),
                (
                    "light.dns".to_string(),
                    Arc::new(ConfigurableMockUpstream {
                        succeed: true,
                        delay: Duration::ZERO,
                        result_ip: std::net::Ipv4Addr::new(2, 2, 2, 2),
                        call_count: Arc::clone(&light_calls),
                    }),
                    1,
                ),
            ],
            UpstreamStrategy::LoadBalance,
            Duration::from_secs(1),
            7,
        );

        for _ in 0..SAMPLES {
            manager
                .resolve(&test_query())
                .await
                .expect("both weighted candidates answer");
        }
        assert_eq!(
            heavy_calls.load(Ordering::SeqCst) + light_calls.load(Ordering::SeqCst),
            SAMPLES,
            "exactly one candidate answers each query"
        );
        let share = f64::from(heavy_calls.load(Ordering::SeqCst)) / f64::from(SAMPLES);
        assert!(
            (0.70..=0.80).contains(&share),
            "weights 3:1 must select the heavy upstream ~75% of the time (got {share})"
        );
    }

    /// F1: three candidates share the first pick in proportion to
    /// `4:2:1` weights (no two-way-only shortcut).
    #[tokio::test]
    async fn test_weighted_load_balance_three_candidate_distribution() {
        const SAMPLES: u32 = 2_100;
        let calls = [
            Arc::new(AtomicU32::new(0)),
            Arc::new(AtomicU32::new(0)),
            Arc::new(AtomicU32::new(0)),
        ];
        let manager = UpstreamManager::with_weighted_upstreams_seeded(
            vec![
                (
                    "heavy.dns".to_string(),
                    Arc::new(ConfigurableMockUpstream {
                        succeed: true,
                        delay: Duration::ZERO,
                        result_ip: std::net::Ipv4Addr::new(1, 1, 1, 1),
                        call_count: Arc::clone(&calls[0]),
                    }),
                    4,
                ),
                (
                    "medium.dns".to_string(),
                    Arc::new(ConfigurableMockUpstream {
                        succeed: true,
                        delay: Duration::ZERO,
                        result_ip: std::net::Ipv4Addr::new(2, 2, 2, 2),
                        call_count: Arc::clone(&calls[1]),
                    }),
                    2,
                ),
                (
                    "light.dns".to_string(),
                    Arc::new(ConfigurableMockUpstream {
                        succeed: true,
                        delay: Duration::ZERO,
                        result_ip: std::net::Ipv4Addr::new(3, 3, 3, 3),
                        call_count: Arc::clone(&calls[2]),
                    }),
                    1,
                ),
            ],
            UpstreamStrategy::LoadBalance,
            Duration::from_secs(1),
            17,
        );

        for _ in 0..SAMPLES {
            manager
                .resolve(&test_query())
                .await
                .expect("all three weighted candidates answer");
        }
        let shares: Vec<f64> = calls
            .iter()
            .map(|calls| f64::from(calls.load(Ordering::SeqCst)) / f64::from(SAMPLES))
            .collect();
        assert_eq!(
            calls
                .iter()
                .map(|calls| calls.load(Ordering::SeqCst))
                .sum::<u32>(),
            SAMPLES
        );
        assert!(
            (0.52..=0.62).contains(&shares[0]),
            "weight 4/7 must take ~57% (got {shares:?})"
        );
        assert!(
            (0.24..=0.34).contains(&shares[1]),
            "weight 2/7 must take ~29% (got {shares:?})"
        );
        assert!(
            (0.10..=0.19).contains(&shares[2]),
            "weight 1/7 must take ~14% (got {shares:?})"
        );
    }

    /// F1: a failed weighted pick still falls through to the remaining
    /// candidates inside the same deadline.
    #[tokio::test]
    async fn test_weighted_load_balance_falls_back_after_a_failed_pick() {
        // Exercise many seeds instead of pinning one: whichever order the
        // weighted first pick produces, the healthy candidate must answer.
        let mut failing_attempts = 0;
        for seed in 1..=16 {
            let failing_calls = Arc::new(AtomicU32::new(0));
            let healthy_calls = Arc::new(AtomicU32::new(0));
            let manager = UpstreamManager::with_weighted_upstreams_seeded(
                vec![
                    (
                        "failing.dns".to_string(),
                        Arc::new(ConfigurableMockUpstream {
                            succeed: false,
                            delay: Duration::ZERO,
                            result_ip: std::net::Ipv4Addr::new(1, 1, 1, 1),
                            call_count: Arc::clone(&failing_calls),
                        }),
                        100,
                    ),
                    (
                        "healthy.dns".to_string(),
                        Arc::new(ConfigurableMockUpstream {
                            succeed: true,
                            delay: Duration::ZERO,
                            result_ip: std::net::Ipv4Addr::new(9, 9, 9, 9),
                            call_count: Arc::clone(&healthy_calls),
                        }),
                        1,
                    ),
                ],
                UpstreamStrategy::LoadBalance,
                Duration::from_secs(1),
                seed,
            );

            let (response, upstream) = manager
                .resolve_with_upstream(&test_query())
                .await
                .expect("the healthy candidate must answer after the weighted failure");
            assert_eq!(upstream, "healthy.dns");
            assert_eq!(response.metadata.response_code, ResponseCode::NoError);
            assert_eq!(healthy_calls.load(Ordering::SeqCst), 1);
            failing_attempts += failing_calls.load(Ordering::SeqCst);
        }
        assert!(
            failing_attempts > 0,
            "across seeds the weighted candidate must be attempted at least once"
        );
    }

    /// F1: weights never override health. A down upstream with the largest
    /// weight is excluded until the all-down emergency path runs.
    #[tokio::test]
    async fn test_weight_does_not_bypass_health_state() {
        let down_calls = Arc::new(AtomicU32::new(0));
        let light_calls = Arc::new(AtomicU32::new(0));
        let heavy_calls = Arc::new(AtomicU32::new(0));
        let manager = UpstreamManager::with_weighted_upstreams_seeded(
            vec![
                (
                    "down-heaviest.dns".to_string(),
                    Arc::new(ConfigurableMockUpstream {
                        succeed: true,
                        delay: Duration::ZERO,
                        result_ip: std::net::Ipv4Addr::new(1, 1, 1, 1),
                        call_count: Arc::clone(&down_calls),
                    }),
                    100,
                ),
                (
                    "up-light.dns".to_string(),
                    Arc::new(ConfigurableMockUpstream {
                        succeed: true,
                        delay: Duration::ZERO,
                        result_ip: std::net::Ipv4Addr::new(2, 2, 2, 2),
                        call_count: Arc::clone(&light_calls),
                    }),
                    1,
                ),
                (
                    "up-heavy.dns".to_string(),
                    Arc::new(ConfigurableMockUpstream {
                        succeed: true,
                        delay: Duration::ZERO,
                        result_ip: std::net::Ipv4Addr::new(3, 3, 3, 3),
                        call_count: Arc::clone(&heavy_calls),
                    }),
                    4,
                ),
            ],
            UpstreamStrategy::LoadBalance,
            Duration::from_secs(1),
            3,
        );

        let entry = manager
            .inner
            .load_full()
            .entries
            .iter()
            .find(|entry| entry.name == "down-heaviest.dns")
            .expect("entry")
            .clone();
        {
            let mut health = entry.health.write().await;
            for _ in 0..6 {
                health.record_error(&UpstreamError::Timeout);
            }
            assert_eq!(health.status(), HealthStatus::Down);
        }

        // Two healthy candidates remain, so the weighted selector (not a
        // one-candidate fallback) is exercised while the down server is
        // excluded at weight 100.
        for _ in 0..200 {
            let (_, upstream) = manager
                .resolve_with_upstream(&test_query())
                .await
                .expect("a healthy candidate must answer");
            assert!(upstream == "up-light.dns" || upstream == "up-heavy.dns");
        }
        assert_eq!(down_calls.load(Ordering::SeqCst), 0);
        let light = light_calls.load(Ordering::SeqCst);
        let heavy = heavy_calls.load(Ordering::SeqCst);
        assert_eq!(light + heavy, 200);
        assert!(
            heavy > light,
            "the heavier healthy candidate should dominate (light={light}, heavy={heavy})"
        );
    }

    /// F1: when every upstream is marked down, the emergency path still tries
    /// all of them regardless of weight, and a working one answers.
    #[tokio::test]
    async fn test_all_down_emergency_still_tries_weighted_candidates() {
        let broken_calls = Arc::new(AtomicU32::new(0));
        let working_calls = Arc::new(AtomicU32::new(0));
        let manager = UpstreamManager::with_weighted_upstreams_seeded(
            vec![
                (
                    "broken-heavy.dns".to_string(),
                    Arc::new(ConfigurableMockUpstream {
                        succeed: false,
                        delay: Duration::ZERO,
                        result_ip: std::net::Ipv4Addr::new(1, 1, 1, 1),
                        call_count: Arc::clone(&broken_calls),
                    }),
                    100,
                ),
                (
                    "working-light.dns".to_string(),
                    Arc::new(ConfigurableMockUpstream {
                        succeed: true,
                        delay: Duration::ZERO,
                        result_ip: std::net::Ipv4Addr::new(2, 2, 2, 2),
                        call_count: Arc::clone(&working_calls),
                    }),
                    1,
                ),
            ],
            UpstreamStrategy::LoadBalance,
            Duration::from_secs(1),
            5,
        );

        for entry in &manager.inner.load_full().entries {
            let mut health = entry.health.write().await;
            for _ in 0..6 {
                health.record_error(&UpstreamError::Timeout);
            }
            assert_eq!(health.status(), HealthStatus::Down);
        }

        let (response, upstream) = manager
            .resolve_with_upstream(&test_query())
            .await
            .expect("the emergency path must still reach the working upstream");
        assert_eq!(upstream, "working-light.dns");
        assert_eq!(response.metadata.response_code, ResponseCode::NoError);
        assert_eq!(working_calls.load(Ordering::SeqCst), 1);
        assert!(
            broken_calls.load(Ordering::SeqCst) >= 1,
            "the emergency path must try the heavy candidate too"
        );
    }

    /// F1: failover keeps its explicit configuration order even when weights
    /// are present; only load_balance uses them.
    #[tokio::test]
    async fn test_failover_strategy_keeps_configuration_order_with_weights() {
        let first_calls = Arc::new(AtomicU32::new(0));
        let second_calls = Arc::new(AtomicU32::new(0));
        let manager = UpstreamManager::with_weighted_upstreams_seeded(
            vec![
                (
                    "first-light.dns".to_string(),
                    Arc::new(ConfigurableMockUpstream {
                        succeed: true,
                        delay: Duration::ZERO,
                        result_ip: std::net::Ipv4Addr::new(1, 1, 1, 1),
                        call_count: Arc::clone(&first_calls),
                    }),
                    1,
                ),
                (
                    "second-heavy.dns".to_string(),
                    Arc::new(ConfigurableMockUpstream {
                        succeed: true,
                        delay: Duration::ZERO,
                        result_ip: std::net::Ipv4Addr::new(2, 2, 2, 2),
                        call_count: Arc::clone(&second_calls),
                    }),
                    100,
                ),
            ],
            UpstreamStrategy::Failover,
            Duration::from_secs(1),
            9,
        );

        for _ in 0..20 {
            let (_, upstream) = manager
                .resolve_with_upstream(&test_query())
                .await
                .expect("the first configured upstream answers");
            assert_eq!(upstream, "first-light.dns");
        }
        assert_eq!(first_calls.load(Ordering::SeqCst), 20);
        assert_eq!(second_calls.load(Ordering::SeqCst), 0);
    }

    /// P1-25: bootstrap/health probes must set RD=1. A recursive resolver that
    /// refuses RD=0 must not be treated as down.
    struct RdRequiredUpstream {
        calls: Arc<AtomicU32>,
    }

    #[async_trait::async_trait]
    impl Upstream for RdRequiredUpstream {
        async fn resolve(&self, msg: &Message) -> Result<Message, UpstreamError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if !msg.metadata.recursion_desired {
                return Err(UpstreamError::Refused);
            }
            let mut resp = Message::response(msg.metadata.id, msg.metadata.op_code);
            resp.queries = msg.queries.clone();
            resp.metadata.response_code = ResponseCode::NoError;
            resp.answers.push(Record::from_rdata(
                msg.queries[0].name().clone(),
                300,
                RData::A(A(std::net::Ipv4Addr::new(8, 8, 4, 4))),
            ));
            Ok(resp)
        }
    }

    #[tokio::test]
    async fn test_health_probe_sets_recursion_desired() {
        let calls = Arc::new(AtomicU32::new(0));
        let entry = ManagedEntry {
            name: "rd-required.dns".to_string(),
            upstream: Arc::new(RdRequiredUpstream {
                calls: Arc::clone(&calls),
            }),
            health: Arc::new(RwLock::new(UpstreamHealth::new())),
            weight: 1,
        };
        {
            let mut health = entry.health.write().await;
            for _ in 0..3 {
                health.record_error(&UpstreamError::Timeout);
            }
            assert_eq!(health.status(), HealthStatus::Suspect);
        }

        probe_one(
            entry.clone(),
            Name::from_str("example.com.").unwrap(),
            Duration::from_secs(1),
        )
        .await;

        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            entry.health.read().await.status(),
            HealthStatus::Healthy,
            "an RD=1 probe must revive a Suspect resolver that refuses RD=0"
        );
    }

    /// P2-10: a FORMERR/BADVERS reply to an EDNS query must be retried once
    /// against the same candidate without EDNS instead of being returned.
    struct EdnsIntolerantUpstream {
        calls: Arc<AtomicU32>,
    }

    #[async_trait::async_trait]
    impl Upstream for EdnsIntolerantUpstream {
        async fn resolve(&self, msg: &Message) -> Result<Message, UpstreamError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let mut resp = Message::response(msg.metadata.id, msg.metadata.op_code);
            resp.queries = msg.queries.clone();
            if msg.edns.is_some() {
                resp.metadata.response_code = ResponseCode::FormErr;
                return Ok(resp);
            }
            resp.metadata.response_code = ResponseCode::NoError;
            resp.answers.push(Record::from_rdata(
                msg.queries[0].name().clone(),
                300,
                RData::A(A(std::net::Ipv4Addr::new(6, 6, 6, 6))),
            ));
            Ok(resp)
        }
    }

    #[tokio::test]
    async fn test_formerr_triggers_one_no_edns_retry() {
        let calls = Arc::new(AtomicU32::new(0));
        let manager = UpstreamManager::with_upstreams(
            vec![(
                "edns-intolerant.dns".to_string(),
                Arc::new(EdnsIntolerantUpstream {
                    calls: Arc::clone(&calls),
                }),
            )],
            UpstreamStrategy::Failover,
            Duration::from_secs(1),
        );

        let mut query = test_query();
        query.metadata.recursion_desired = true;
        query.set_edns(sito_proto::Edns::new());

        let resp = manager
            .resolve(&query)
            .await
            .expect("FORMERR must be retried without EDNS");
        assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
        assert_eq!(calls.load(Ordering::SeqCst), 2, "exactly one retry");
    }

    #[tokio::test]
    async fn test_forced_refresh_picks_up_rotated_address() {
        // First bootstrap answer is a black-hole address that receives but never
        // answers; the forced refresh must bypass the bootstrap cache and pick up the
        // live rotated address within the remaining budget.
        let blackhole = tokio::net::UdpSocket::bind("127.0.0.3:0").await.unwrap();
        let live_port = blackhole.local_addr().unwrap().port();
        let live = tokio::net::UdpSocket::bind(format!("127.0.0.2:{live_port}"))
            .await
            .unwrap();
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
        // Keep the black-hole socket alive and drain datagrams without replying.
        let _blackhole_task = tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            while blackhole.recv_from(&mut buf).await.is_ok() {}
        });

        let bootstrap_addr = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let bootstrap = bootstrap_addr.local_addr().unwrap();
        let a_queries = Arc::new(AtomicU32::new(0));
        let counter = Arc::clone(&a_queries);
        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            while let Ok((len, peer)) = bootstrap_addr.recv_from(&mut buf).await {
                let Ok(query) = decode_message(&buf[..len]) else {
                    continue;
                };
                if query.queries.first().map(Query::query_type) != Some(RecordType::A) {
                    let mut resp = Message::response(query.metadata.id, query.metadata.op_code);
                    resp.queries = query.queries.clone();
                    if let Ok(encoded) = encode_message(&resp) {
                        let _ = bootstrap_addr.send_to(&encoded, peer).await;
                    }
                    continue;
                }
                let index = counter.fetch_add(1, Ordering::SeqCst);
                let ip = if index == 0 {
                    std::net::Ipv4Addr::new(127, 0, 0, 3)
                } else {
                    std::net::Ipv4Addr::new(127, 0, 0, 2)
                };
                let mut resp = Message::response(query.metadata.id, query.metadata.op_code);
                resp.queries = query.queries.clone();
                resp.answers.push(Record::from_rdata(
                    query.queries[0].name().clone(),
                    300,
                    RData::A(A(ip)),
                ));
                if let Ok(encoded) = encode_message(&resp) {
                    let _ = bootstrap_addr.send_to(&encoded, peer).await;
                }
            }
        });

        let resolver = BootstrapResolver::new(vec![bootstrap.ip()], Duration::from_secs(1))
            .with_port(bootstrap.port())
            .with_allow_private_targets(true);
        let upstream = FailoverUpstream::with_interval(
            resolver,
            "rotate.test".to_string(),
            live_port,
            Duration::from_secs(2),
            CandidateKind::Plain,
            Duration::from_secs(3600),
        )
        .await
        .expect("construct failover upstream");

        let resp = upstream
            .resolve(&test_query())
            .await
            .expect("forced refresh must reach the rotated address");
        assert_eq!(
            resp.answers[0].data,
            RData::A(A(std::net::Ipv4Addr::new(5, 5, 5, 5)))
        );
        assert_eq!(live_calls.load(Ordering::SeqCst), 1);
        assert!(a_queries.load(Ordering::SeqCst) >= 2);
        assert!(
            !upstream.force_re_resolve().await,
            "a second forced refresh within the backoff window must be skipped"
        );
    }

    /// WP-2.7: forced refresh must also rotate DoT candidates, not only the
    /// plain UDP path. The live listener counts the connection attempt made to
    /// the rotated address (the test endpoint cannot complete TLS).
    /// WP-2.7: every candidate attempt is reported with its own RTT and error
    /// kind. The winner's RTT excludes the time spent on the failed candidate.
    #[tokio::test]
    async fn test_failover_reports_per_attempt_rtt_and_error() {
        let failed_calls = Arc::new(AtomicU32::new(0));
        let winner_calls = Arc::new(AtomicU32::new(0));
        let manager = UpstreamManager::with_upstreams(
            vec![
                (
                    "slow-failure".to_string(),
                    Arc::new(ConfigurableMockUpstream {
                        succeed: false,
                        delay: Duration::from_millis(80),
                        result_ip: std::net::Ipv4Addr::new(1, 1, 1, 1),
                        call_count: Arc::clone(&failed_calls),
                    }),
                ),
                (
                    "winner".to_string(),
                    Arc::new(ConfigurableMockUpstream {
                        succeed: true,
                        delay: Duration::ZERO,
                        result_ip: std::net::Ipv4Addr::new(9, 9, 9, 9),
                        call_count: Arc::clone(&winner_calls),
                    }),
                ),
            ],
            UpstreamStrategy::Failover,
            Duration::from_secs(2),
        );

        let started = Instant::now();
        let (response, upstream, attempts) = manager
            .resolve_with_attempts(&test_query())
            .await
            .expect("the second candidate must succeed");
        let total = started.elapsed();

        assert_eq!(response.metadata.response_code, ResponseCode::NoError);
        assert_eq!(upstream, "winner");
        assert_eq!(failed_calls.load(Ordering::SeqCst), 1);
        assert_eq!(winner_calls.load(Ordering::SeqCst), 1);
        assert_eq!(attempts.len(), 2, "one attempt per candidate: {attempts:?}");

        let failed = &attempts[0];
        assert_eq!(failed.name, "slow-failure");
        assert_eq!(failed.error_kind(), Some("timeout"));
        assert!(!failed.is_success());
        assert!(
            failed.rtt >= Duration::from_millis(80),
            "the failed attempt must report its own elapsed time: {:?}",
            failed.rtt
        );

        let winner = &attempts[1];
        assert_eq!(winner.name, "winner");
        assert!(winner.is_success());
        assert_eq!(winner.error_kind(), None);
        assert!(
            winner.rtt < failed.rtt,
            "the winner RTT must exclude the failed attempt: winner={:?} failed={:?}",
            winner.rtt,
            failed.rtt
        );
        assert!(
            winner.rtt < total,
            "the winner RTT must not be the whole failover duration"
        );
    }

    #[tokio::test]
    async fn test_forced_refresh_rotates_dot_candidate() {
        let blackhole = std::net::Ipv4Addr::new(127, 0, 0, 3);
        let (live_addr, accepts) = spawn_tcp_accept_counter("127.0.0.2:0").await;
        let port = live_addr.port();
        let bootstrap =
            spawn_rotating_bootstrap(blackhole, std::net::Ipv4Addr::new(127, 0, 0, 2)).await;
        let resolver = BootstrapResolver::new(vec![bootstrap.ip()], Duration::from_secs(1))
            .with_port(bootstrap.port())
            .with_allow_private_targets(true);
        let upstream = FailoverUpstream::with_interval(
            resolver,
            "rotate-dot.test".to_string(),
            port,
            Duration::from_millis(400),
            CandidateKind::Dot {
                server_name: "rotate-dot.test".to_string(),
                pool_size: 1,
            },
            Duration::from_secs(3600),
        )
        .await
        .expect("construct DoT failover upstream");

        assert_eq!(
            upstream.candidate_ips().await,
            vec![std::net::IpAddr::V4(blackhole)]
        );
        let _ = upstream.resolve(&test_query()).await;
        assert_eq!(
            upstream.candidate_ips().await,
            vec![std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 2))],
            "forced refresh must replace the black-hole DoT candidate"
        );
        assert!(
            accepts.load(Ordering::SeqCst) >= 1,
            "the rotated DoT candidate must be dialled"
        );
    }

    /// WP-2.7: the same forced-refresh rotation for DoH candidates.
    #[tokio::test]
    async fn test_forced_refresh_rotates_doh_candidate() {
        let blackhole = std::net::Ipv4Addr::new(127, 0, 0, 3);
        let (live_addr, accepts) = spawn_tcp_accept_counter("127.0.0.2:0").await;
        let port = live_addr.port();
        let bootstrap =
            spawn_rotating_bootstrap(blackhole, std::net::Ipv4Addr::new(127, 0, 0, 2)).await;
        let resolver = BootstrapResolver::new(vec![bootstrap.ip()], Duration::from_secs(1))
            .with_port(bootstrap.port())
            .with_allow_private_targets(true);
        let upstream = FailoverUpstream::with_interval(
            resolver,
            "rotate-doh.test".to_string(),
            port,
            Duration::from_millis(500),
            CandidateKind::Https {
                url: build_https_url("rotate-doh.test", port, "/dns-query"),
            },
            Duration::from_secs(3600),
        )
        .await
        .expect("construct DoH failover upstream");

        assert_eq!(
            upstream.candidate_ips().await,
            vec![std::net::IpAddr::V4(blackhole)]
        );
        let _ = upstream.resolve(&test_query()).await;
        assert_eq!(
            upstream.candidate_ips().await,
            vec![std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 2))],
            "forced refresh must replace the black-hole DoH candidate"
        );
        assert!(
            accepts.load(Ordering::SeqCst) >= 1,
            "the rotated DoH candidate must be dialled"
        );
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
            allow_private_targets: false,
            per_domain: vec![],
            ecs: Default::default(),
            weights: Vec::new(),
        };

        manager.reload(&new_config, &bootstrap).await.unwrap();

        assert_eq!(manager.strategy(), UpstreamStrategy::LoadBalance);
        assert_eq!(manager.timeout(), Duration::from_millis(2500));
        let statuses = manager.statuses().await;
        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0].0, "1.1.1.1:53");
    }

    /// F1: per-domain rule weights are copied onto the managed entries so the
    /// same weighted load-balance path applies inside a rule.
    #[tokio::test]
    async fn test_from_config_applies_global_and_per_domain_weights() {
        let bootstrap = BootstrapResolver::new(vec![], Duration::from_millis(500));
        let config = UpstreamConfig {
            servers: vec!["1.1.1.1:53".to_string(), "1.0.0.1:53".to_string()],
            bootstrap: vec![],
            strategy: UpstreamStrategy::LoadBalance,
            timeout_ms: 1000,
            probe_domain: "example.com".to_string(),
            pool_size: 1,
            allow_private_targets: false,
            ecs: Default::default(),
            weights: vec![3, 1],
            per_domain: vec![sito_core::config::PerDomainUpstream {
                domains: vec!["lan".to_string()],
                servers: vec!["192.168.1.1:53".to_string(), "192.168.1.2:53".to_string()],
                weights: vec![5, 1],
            }],
        };
        let manager = UpstreamManager::from_config(&config, &bootstrap)
            .await
            .expect("weighted config constructs");
        let inner = manager.inner.load_full();
        let global: Vec<u32> = inner.entries.iter().map(|entry| entry.weight).collect();
        assert_eq!(global, vec![3, 1]);
        let rule: Vec<u32> = inner.per_domain_rules[0]
            .1
            .iter()
            .map(|entry| entry.weight)
            .collect();
        assert_eq!(rule, vec![5, 1]);
    }

    #[tokio::test]
    async fn test_manager_with_tls_upstream_constructs_without_panicking() {
        // Regression for the P0 where DoT construction used the ambiguous
        // rustls builder and aborted the process under `panic = "abort"`.
        let bootstrap = BootstrapResolver::new(vec![], Duration::from_millis(500));
        let config = UpstreamConfig {
            servers: vec!["tls://1.1.1.1".to_string()],
            bootstrap: vec![],
            strategy: UpstreamStrategy::Failover,
            timeout_ms: 1000,
            probe_domain: "cloudflare.com".to_string(),
            pool_size: 2,
            allow_private_targets: false,
            per_domain: vec![],
            ecs: Default::default(),
            weights: Vec::new(),
        };
        let manager = UpstreamManager::from_config(&config, &bootstrap).await;
        assert!(
            manager.is_ok(),
            "tls:// upstream must construct successfully: {:?}",
            manager.err()
        );
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
            parse_scheme_target("dns.quad9.net/dns-query", 443).unwrap(),
            ("dns.quad9.net".to_string(), 443, "/dns-query".to_string())
        );
        assert_eq!(
            parse_scheme_target("dns.google:8443/dns-query", 443)
                .unwrap()
                .1,
            8443
        );
        assert_eq!(
            parse_scheme_target("[2606:4700:4700::1111]/dns-query", 443)
                .unwrap()
                .0,
            "2606:4700:4700::1111"
        );
        assert_eq!(
            parse_scheme_target("cloudflare-dns.com", 443).unwrap().2,
            "/dns-query"
        );
        assert!(parse_scheme_target("/dns-query", 443).is_err());
        assert_eq!(
            parse_scheme_target("dns.adguard.com", 853).unwrap(),
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

    /// WP-2.7: the manager accepts the same uppercase schemes as validation and
    /// rejects the same path-bearing targets instead of failing later at startup.
    #[tokio::test]
    async fn test_managed_entry_schemes_and_paths_match_validation() {
        let bootstrap = BootstrapResolver::new(
            vec![std::net::Ipv4Addr::LOCALHOST.into()],
            Duration::from_secs(1),
        );
        for target in [
            "UDP://1.1.1.1:53",
            "TLS://1.1.1.1:853",
            "HTTPS://1.1.1.1/dns-query",
        ] {
            create_managed_entry(target, &bootstrap, Duration::from_secs(1), 1)
                .await
                .unwrap_or_else(|e| panic!("uppercase target '{target}' must build: {e}"));
        }

        for target in [
            "UDP://1.1.1.1/dns-query",
            "TLS://1.1.1.1/dns-query",
            "1.1.1.1:53/dns-query",
        ] {
            assert!(
                create_managed_entry(target, &bootstrap, Duration::from_secs(1), 1)
                    .await
                    .is_err(),
                "path-bearing target '{target}' must be rejected"
            );
        }
    }

    /// Spawns a mock bootstrap server whose A answer rotates from `first` to
    /// `second` after the first lookup.
    async fn spawn_rotating_bootstrap(
        first: std::net::Ipv4Addr,
        second: std::net::Ipv4Addr,
    ) -> SocketAddr {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        tokio::spawn(async move {
            let mut a_index = 0u32;
            let mut buf = [0u8; 1024];
            while let Ok((len, peer)) = socket.recv_from(&mut buf).await {
                let Ok(query) = decode_message(&buf[..len]) else {
                    continue;
                };
                let mut resp = Message::response(query.metadata.id, query.metadata.op_code);
                resp.queries = query.queries.clone();
                if query.queries.first().map(Query::query_type) == Some(RecordType::A) {
                    let ip = if a_index == 0 { first } else { second };
                    a_index += 1;
                    resp.answers.push(Record::from_rdata(
                        query.queries[0].name().clone(),
                        300,
                        RData::A(A(ip)),
                    ));
                }
                if let Ok(encoded) = encode_message(&resp) {
                    let _ = socket.send_to(&encoded, peer).await;
                }
            }
        });
        addr
    }

    /// Binds a TCP listener and counts accepted connections. Used to prove a
    /// forced refresh actually routes the next attempt at the rotated address
    /// even when the test endpoint cannot complete a real TLS handshake.
    async fn spawn_tcp_accept_counter(bind: &str) -> (SocketAddr, Arc<AtomicU32>) {
        let listener = tokio::net::TcpListener::bind(bind).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accepts = Arc::new(AtomicU32::new(0));
        let counter = Arc::clone(&accepts);
        tokio::spawn(async move {
            loop {
                if listener.accept().await.is_err() {
                    break;
                }
                counter.fetch_add(1, Ordering::SeqCst);
            }
        });
        (addr, accepts)
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

    /// WP-2.7: a bootstrap answer with more addresses than the cap keeps only
    /// the bounded candidate set instead of building one transport per record.
    #[tokio::test]
    async fn test_bootstrap_resolution_caps_candidates() {
        let records: Vec<_> = (1..=20)
            .map(|last| std::net::Ipv4Addr::new(8, 8, 8, last))
            .collect();
        let addr = spawn_bootstrap_records(records).await;
        let resolver =
            BootstrapResolver::new(vec![addr.ip()], Duration::from_secs(1)).with_port(addr.port());

        let ips = resolver
            .resolve_hostname("many-addresses.test")
            .await
            .expect("bootstrap lookup must succeed");
        assert_eq!(ips.len(), crate::bootstrap::MAX_BOOTSTRAP_CANDIDATES);
    }

    #[test]
    fn test_build_https_url_keeps_path_and_defaults_bare_hosts() {
        assert_eq!(
            build_https_url("dns.example", 443, "/dns-query"),
            "https://dns.example/dns-query"
        );
        assert_eq!(
            build_https_url("dns.example", 8443, "/custom"),
            "https://dns.example:8443/custom"
        );
        assert_eq!(
            build_https_url("2606:4700:4700::1111", 443, "/dns-query"),
            "https://[2606:4700:4700::1111]/dns-query"
        );
        assert_eq!(
            build_https_url("dns.example", 443, ""),
            "https://dns.example/dns-query"
        );
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
            .with_port(bootstrap_addr.port())
            .with_allow_private_targets(true);

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
            allow_private_targets: false,
            per_domain: vec![],
            ecs: Default::default(),
            weights: Vec::new(),
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
