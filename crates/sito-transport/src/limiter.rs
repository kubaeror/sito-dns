//! Per-IP rate limiting using a token bucket in DashMap.

use dashmap::DashMap;
use std::net::IpAddr;
use std::time::Instant;

struct Bucket {
    tokens: f64,
    last_replenished: Instant,
}

/// Token-bucket based rate limiter keyed by client IP address.
pub struct RateLimiter {
    rate_per_sec: u32,
    burst: u32,
    buckets: DashMap<IpAddr, Bucket>,
}

impl RateLimiter {
    /// Create a new RateLimiter.
    /// A `rate_per_sec` of 0 disables rate limiting (always permits requests).
    pub fn new(rate_per_sec: u32, burst: u32) -> Self {
        Self {
            rate_per_sec,
            burst: burst.max(1),
            buckets: DashMap::new(),
        }
    }

    /// Check if a request from the given IP is allowed.
    /// Returns `true` if permitted, `false` if rate limit exceeded.
    pub fn check(&self, ip: IpAddr) -> bool {
        if self.rate_per_sec == 0 {
            return true;
        }

        let now = Instant::now();
        let max_tokens = f64::from(self.burst);
        let refill_rate = f64::from(self.rate_per_sec);

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

    /// Prune old buckets that have been inactive for more than 60 seconds.
    pub fn prune(&self) {
        let now = Instant::now();
        self.buckets
            .retain(|_, bucket| now.duration_since(bucket.last_replenished).as_secs() < 60);
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
    fn test_rate_limiter_zero_rate_disables() {
        let limiter = RateLimiter::new(0, 5);
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        for _ in 0..100 {
            assert!(limiter.check(ip));
        }
    }
}
