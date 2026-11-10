//! Per-prefix rate limiting using a token bucket in DashMap.
//!
//! Buckets are keyed by the network prefix of the client address: IPv4 `/24`
//! and IPv6 `/64`. This mirrors the privacy/caching granularity used elsewhere
//! in the resolver and prevents a single subscriber from multiplying its budget
//! by rotating through addresses inside its own allocation.

use dashmap::DashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::Instant;

#[derive(Debug)]
struct Bucket {
    tokens: f64,
    last_replenished: Instant,
}

/// Default maximum number of source-prefix buckets tracked at once.
pub const DEFAULT_MAX_BUCKETS: usize = 100_000;

/// Number of buckets sampled when the table is full. Sampling keeps eviction
/// O(1) under a spoofed-source flood while still approximating least-recently
/// used rather than picking an arbitrary entry.
const EVICTION_SAMPLE: usize = 32;

/// Returns the rate-limit key for an address: IPv4 `/24`, IPv6 `/64`.
///
/// An IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) is the same host as its IPv4
/// form and must use the IPv4 `/24` bucket. Masking it as IPv6 `/64` would
/// collapse an entire IPv4 LAN into one bucket and throttle every client when
/// the listener accepts dual-stack socket traffic (`IPV6_V6ONLY=false`).
pub(crate) fn rate_key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => {
            let bits = u32::from(v4) & 0xFFFF_FF00;
            IpAddr::V4(Ipv4Addr::from(bits))
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return IpAddr::V4(Ipv4Addr::from(u32::from(v4) & 0xFFFF_FF00));
            }
            let bits = u128::from(v6) & 0xFFFF_FFFF_FFFF_FFFF_0000_0000_0000_0000;
            IpAddr::V6(Ipv6Addr::from(bits))
        }
    }
}

/// Token-bucket based rate limiter keyed by client network prefix.
///
/// The configured rate lives in atomics so `dns.rate_limit_per_ip` can be
/// hot-reloaded without rebinding listeners.
///
/// Semantics are per source prefix: every prefix gets an independent bucket so
/// one client cannot consume another's budget. The bucket table is bounded
/// ([`DEFAULT_MAX_BUCKETS`] by default) so spoofed/sprayed source addresses
/// cannot grow memory without limit; when the table is full the least recently
/// used of a sampled set of entries is evicted.
#[derive(Debug)]
pub struct RateLimiter {
    rate_per_sec: AtomicU32,
    burst: AtomicU32,
    buckets: DashMap<IpAddr, Bucket>,
    max_buckets: usize,
    pruner_started: AtomicBool,
}

impl RateLimiter {
    /// Create a new RateLimiter with the default bucket bound.
    /// A `rate_per_sec` of 0 disables rate limiting (always permits requests).
    pub fn new(rate_per_sec: u32, burst: u32) -> Self {
        Self::with_max_buckets(rate_per_sec, burst, DEFAULT_MAX_BUCKETS)
    }

    /// Create a new RateLimiter with an explicit bound on tracked prefixes.
    pub fn with_max_buckets(rate_per_sec: u32, burst: u32, max_buckets: usize) -> Self {
        Self {
            rate_per_sec: AtomicU32::new(rate_per_sec),
            burst: AtomicU32::new(burst.max(1)),
            buckets: DashMap::new(),
            max_buckets: max_buckets.max(1),
            pruner_started: AtomicBool::new(false),
        }
    }

    /// Burst allowance derived from a configured per-IP rate (twice the rate),
    /// saturating instead of overflowing for extreme configuration values.
    #[must_use]
    pub const fn burst_for_rate(rate_per_sec: u32) -> u32 {
        rate_per_sec.saturating_mul(2)
    }

    /// Applies a new rate limit. `rate_per_sec = 0` disables limiting.
    pub fn set_rate(&self, rate_per_sec: u32) {
        self.rate_per_sec.store(rate_per_sec, Ordering::Relaxed);
        self.burst
            .store(Self::burst_for_rate(rate_per_sec).max(1), Ordering::Relaxed);
    }

    /// Check if a request from the given address is allowed.
    /// Returns `true` if permitted, `false` if rate limit exceeded.
    pub fn check(&self, ip: IpAddr) -> bool {
        let rate_per_sec = self.rate_per_sec.load(Ordering::Relaxed);
        if rate_per_sec == 0 {
            return true;
        }

        let key = rate_key(ip);
        let now = Instant::now();
        let max_tokens = f64::from(self.burst.load(Ordering::Relaxed));
        let refill_rate = f64::from(rate_per_sec);

        if !self.buckets.contains_key(&key) {
            self.evict_for_capacity();
        }

        let mut entry = self.buckets.entry(key).or_insert_with(|| Bucket {
            tokens: max_tokens,
            last_replenished: now,
        });

        let elapsed = now.duration_since(entry.last_replenished).as_secs_f64();
        entry.tokens = (entry.tokens + elapsed * refill_rate).min(max_tokens);
        entry.last_replenished = now;

        if entry.tokens >= 1.0 {
            entry.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Evicts one bucket when the table is at capacity.
    ///
    /// Only a small sample is inspected so a spoofed-source flood cannot turn
    /// every new prefix into a full-table scan. Among the sample, the bucket
    /// with the oldest last-use timestamp (approximate LRU) is removed.
    fn evict_for_capacity(&self) {
        if self.buckets.len() < self.max_buckets {
            return;
        }
        let victim = {
            let mut oldest: Option<(IpAddr, Instant)> = None;
            for entry in self.buckets.iter().take(EVICTION_SAMPLE) {
                let used = entry.value().last_replenished;
                if oldest.is_none_or(|(_, current)| used < current) {
                    oldest = Some((*entry.key(), used));
                }
            }
            oldest.map(|(key, _)| key)
        };
        if let Some(victim) = victim {
            self.buckets.remove(&victim);
        }
    }

    /// Number of currently tracked source-prefix buckets.
    pub fn tracked_buckets(&self) -> usize {
        self.buckets.len()
    }

    #[cfg(test)]
    fn tracks_for_test(&self, ip: IpAddr) -> bool {
        self.buckets.contains_key(&rate_key(ip))
    }

    /// Prune old buckets that have been inactive for more than 60 seconds.
    pub fn prune(&self) {
        let now = Instant::now();
        self.buckets
            .retain(|_, bucket| now.duration_since(bucket.last_replenished).as_secs() < 60);
    }

    /// Spawn a background task to periodically prune inactive rate limit buckets every 60 seconds until shutdown.
    ///
    /// If a pruner is already running for this `RateLimiter`, subsequent calls
    /// return a no-op task so sharing one limiter across multiple listeners does
    /// not spawn duplicate sweep tasks.
    pub fn spawn_pruner(
        self: &std::sync::Arc<Self>,
        mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
    ) -> tokio::task::JoinHandle<()> {
        if self.pruner_started.swap(true, Ordering::AcqRel) {
            return tokio::spawn(async {});
        }
        let limiter = std::sync::Arc::clone(self);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            interval.tick().await;
            loop {
                tokio::select! {
                    res = shutdown_rx.changed() => {
                        if res.is_err() || *shutdown_rx.borrow() {
                            break;
                        }
                    }
                    _ = interval.tick() => {
                        limiter.prune();
                    }
                }
            }
            limiter.pruner_started.store(false, Ordering::Release);
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_rate_limiter_allows_under_limit() {
        let limiter = RateLimiter::new(10, 5);
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));

        // Burst 5 should all succeed
        for _ in 0..5 {
            assert!(limiter.check(ip));
        }

        // 6th should fail because burst is exhausted
        assert!(!limiter.check(ip));
    }

    #[test]
    fn test_rate_limiter_hot_update() {
        let limiter = RateLimiter::new(0, 1);
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        for _ in 0..50 {
            assert!(limiter.check(ip));
        }

        limiter.set_rate(1);
        // A fresh bucket starts at burst (2 x rate) tokens.
        assert!(limiter.check(ip));
        assert!(limiter.check(ip));
        assert!(
            !limiter.check(ip),
            "tokens exhausted after enabling the limit"
        );

        limiter.set_rate(0);
        assert!(limiter.check(ip), "disabling the limit permits again");
    }

    #[test]
    fn test_rate_limiter_zero_rate_disables() {
        let limiter = RateLimiter::new(0, 5);
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        for _ in 0..100 {
            assert!(limiter.check(ip));
        }
    }

    /// Regression: the derived burst must saturate for extreme configured
    /// rates instead of overflowing (which panicked in debug builds).
    #[test]
    fn test_rate_limiter_burst_for_rate_saturates() {
        assert_eq!(RateLimiter::burst_for_rate(0), 0);
        assert_eq!(RateLimiter::burst_for_rate(20), 40);
        assert_eq!(RateLimiter::burst_for_rate(u32::MAX / 2), u32::MAX - 1);
        assert_eq!(RateLimiter::burst_for_rate(u32::MAX), u32::MAX);
    }

    #[test]
    fn test_rate_limiter_bounds_bucket_table() {
        let max = 8;
        let limiter = RateLimiter::with_max_buckets(10, 5, max);

        // More distinct (spoofed) sources than the table can hold. Vary the
        // /24 so each address maps to its own rate-limit bucket.
        for i in 0..255u8 {
            let ip = IpAddr::V4(Ipv4Addr::new(198, 51, i, 1));
            assert!(limiter.check(ip), "first request from a new source allowed");
        }

        assert!(
            limiter.tracked_buckets() <= max,
            "bucket table must stay bounded (got {})",
            limiter.tracked_buckets()
        );
    }

    #[test]
    fn test_rate_limiter_eviction_keeps_serving() {
        let limiter = RateLimiter::with_max_buckets(2, 2, 2);
        let a = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let b = IpAddr::V4(Ipv4Addr::new(192, 0, 3, 1));
        let c = IpAddr::V4(Ipv4Addr::new(192, 0, 4, 1));

        assert!(limiter.check(a));
        assert!(limiter.check(a));
        assert!(!limiter.check(a), "burst exhausted");
        assert!(limiter.check(b));
        // Third source forces an eviction but must still be served.
        assert!(limiter.check(c));
        assert!(limiter.tracked_buckets() <= 2);
    }

    /// P2-19: rate-limit keys are network prefixes, not full addresses, so
    /// rotating inside one allocation does not multiply the budget.
    #[test]
    fn test_rate_limiter_keys_ipv4_24_and_ipv6_64() {
        let limiter = RateLimiter::with_max_buckets(1, 1, 16);
        let a = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let same_prefix = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 250));
        let other_prefix = IpAddr::V4(Ipv4Addr::new(192, 0, 3, 1));

        assert!(limiter.check(a));
        assert!(
            !limiter.check(same_prefix),
            "another address in the same /24 must share the bucket"
        );
        assert!(
            limiter.check(other_prefix),
            "a different /24 has its own bucket"
        );

        let v6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 1));
        let v6_same = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0xffff, 0, 0, 2));
        let v6_other = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 2, 0, 0, 0, 0, 1));
        assert!(limiter.check(v6));
        assert!(
            !limiter.check(v6_same),
            "another address in the same /64 must share the bucket"
        );
        assert!(
            limiter.check(v6_other),
            "a different /64 has its own bucket"
        );
    }

    /// P2-19: when full, evict the least recently used bucket instead of an
    /// arbitrary one.
    #[test]
    fn test_rate_limiter_evicts_least_recently_used() {
        let limiter = RateLimiter::with_max_buckets(1, 1, 2);
        let a = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));
        let b = IpAddr::V4(Ipv4Addr::new(198, 51, 101, 1));
        let c = IpAddr::V4(Ipv4Addr::new(198, 51, 102, 1));

        assert!(limiter.check(a));
        std::thread::sleep(std::time::Duration::from_millis(5));
        assert!(limiter.check(b));
        std::thread::sleep(std::time::Duration::from_millis(5));
        // Adding `c` evicts `a`, the oldest entry.
        assert!(limiter.check(c));

        assert!(
            !limiter.tracks_for_test(a),
            "the least recently used bucket must have been evicted"
        );
        assert!(
            limiter.tracks_for_test(b),
            "a recently used bucket must not have been evicted"
        );
        assert!(
            !limiter.check(b),
            "the recently used bucket must still hold its exhausted budget"
        );
    }

    /// An IPv4-mapped IPv6 peer must share the IPv4 `/24` key, not collapse
    /// the whole IPv4 LAN into the IPv6 `/64` bucket.
    #[test]
    fn test_ipv4_mapped_ipv6_uses_ipv4_24_bucket() {
        let mapped: IpAddr = "::ffff:192.0.2.10".parse().expect("mapped address");
        assert_eq!(
            rate_key(mapped),
            rate_key("192.0.2.10".parse().expect("IPv4 address")),
            "a mapped address must use its IPv4 /24 key"
        );
        assert_eq!(
            rate_key(mapped).to_string(),
            "192.0.2.0",
            "the mapped key must be masked to the IPv4 /24"
        );

        // A genuine IPv6 address still uses /64.
        assert_eq!(
            rate_key("2001:db8:1:2::1".parse().expect("IPv6 address")).to_string(),
            "2001:db8:1:2::"
        );
    }
}
