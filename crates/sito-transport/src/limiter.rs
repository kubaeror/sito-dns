//! Per-IP rate limiting using a token bucket in DashMap.

use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Instant;

#[derive(Debug)]
struct Bucket {
    tokens: f64,
    last_replenished: Instant,
}

/// Default maximum number of source IP buckets tracked at once.
pub const DEFAULT_MAX_BUCKETS: usize = 100_000;

/// Token-bucket based rate limiter keyed by client IP address.
///
/// The configured rate lives in atomics so `dns.rate_limit_per_ip` can be
/// hot-reloaded without rebinding listeners.
///
/// Semantics are per source IP: every source gets an independent bucket so one
/// client cannot consume another's budget. The bucket table is bounded
/// ([`DEFAULT_MAX_BUCKETS`] by default) so spoofed/sprayed source addresses
/// cannot grow memory without limit; when the table is full an arbitrary
/// (typically stale) entry is evicted, and a source whose bucket was evicted
/// simply starts again with a full burst allowance.
#[derive(Debug)]
pub struct RateLimiter {
    rate_per_sec: AtomicU32,
    burst: AtomicU32,
    buckets: DashMap<IpAddr, Bucket>,
    max_buckets: usize,
}

impl RateLimiter {
    /// Create a new RateLimiter with the default bucket bound.
    /// A `rate_per_sec` of 0 disables rate limiting (always permits requests).
    pub fn new(rate_per_sec: u32, burst: u32) -> Self {
        Self::with_max_buckets(rate_per_sec, burst, DEFAULT_MAX_BUCKETS)
    }

    /// Create a new RateLimiter with an explicit bound on tracked source IPs.
    pub fn with_max_buckets(rate_per_sec: u32, burst: u32, max_buckets: usize) -> Self {
        Self {
            rate_per_sec: AtomicU32::new(rate_per_sec),
            burst: AtomicU32::new(burst.max(1)),
            buckets: DashMap::new(),
            max_buckets: max_buckets.max(1),
        }
    }

    /// Applies a new rate limit. `rate_per_sec = 0` disables limiting.
    pub fn set_rate(&self, rate_per_sec: u32) {
        self.rate_per_sec.store(rate_per_sec, Ordering::Relaxed);
        self.burst
            .store(rate_per_sec.saturating_mul(2).max(1), Ordering::Relaxed);
    }

    /// Check if a request from the given IP is allowed.
    /// Returns `true` if permitted, `false` if rate limit exceeded.
    pub fn check(&self, ip: IpAddr) -> bool {
        let rate_per_sec = self.rate_per_sec.load(Ordering::Relaxed);
        if rate_per_sec == 0 {
            return true;
        }

        let now = Instant::now();
        let max_tokens = f64::from(self.burst.load(Ordering::Relaxed));
        let refill_rate = f64::from(rate_per_sec);

        if !self.buckets.contains_key(&ip) {
            self.evict_for_capacity();
        }

        let mut entry = self.buckets.entry(ip).or_insert_with(|| Bucket {
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

    /// Evict a single bucket when the table is at capacity. Uses an arbitrary
    /// entry so the cost stays O(1) under a spoofed-source flood; `prune`
    /// still removes genuinely idle entries on its periodic sweep.
    fn evict_for_capacity(&self) {
        if self.buckets.len() < self.max_buckets {
            return;
        }
        // Collect the key in its own scope so the DashMap iterator (and its
        // shard guard) is dropped before taking a write lock for removal.
        let victim = {
            let mut iter = self.buckets.iter();
            iter.next().map(|entry| *entry.key())
        };
        if let Some(victim) = victim {
            self.buckets.remove(&victim);
        }
    }

    /// Number of currently tracked source IP buckets.
    pub fn tracked_buckets(&self) -> usize {
        self.buckets.len()
    }

    /// Prune old buckets that have been inactive for more than 60 seconds.
    pub fn prune(&self) {
        let now = Instant::now();
        self.buckets
            .retain(|_, bucket| now.duration_since(bucket.last_replenished).as_secs() < 60);
    }

    /// Spawn a background task to periodically prune inactive rate limit buckets every 60 seconds until shutdown.
    pub fn spawn_pruner(
        self: &std::sync::Arc<Self>,
        mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
    ) -> tokio::task::JoinHandle<()> {
        let limiter = std::sync::Arc::clone(self);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            interval.tick().await;
            loop {
                tokio::select! {
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() {
                            break;
                        }
                    }
                    _ = interval.tick() => {
                        limiter.prune();
                    }
                }
            }
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

    #[test]
    fn test_rate_limiter_bounds_bucket_table() {
        let max = 8;
        let limiter = RateLimiter::with_max_buckets(10, 5, max);

        // More distinct (spoofed) sources than the table can hold.
        for i in 0..255u8 {
            let ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, i));
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
        let b = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));
        let c = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 3));

        assert!(limiter.check(a));
        assert!(limiter.check(a));
        assert!(!limiter.check(a), "burst exhausted");
        assert!(limiter.check(b));
        // Third source forces an eviction but must still be served.
        assert!(limiter.check(c));
        assert!(limiter.tracked_buckets() <= 2);
    }
}
