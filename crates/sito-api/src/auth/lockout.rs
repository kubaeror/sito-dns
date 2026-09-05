//! Lockout and rate-limiting tracker per section 12.2 and section 15.
//!
//! 15-minute lockout after 5 consecutive failed attempts.
//! Per-IP rate limiting for login endpoints.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const MAX_FAILED_ATTEMPTS: u32 = 5;
const LOCKOUT_DURATION: Duration = Duration::from_mins(15); // 15 minutes

#[derive(Debug, Clone)]
struct AttemptRecord {
    count: u32,
    locked_until: Option<Instant>,
}

#[derive(Debug, Clone)]
struct IpRateRecord {
    timestamps: Vec<Instant>,
}

/// Thread-safe tracker for auth failures, account lockout, and IP rate limiting.
#[derive(Clone, Default)]
pub struct LockoutTracker {
    attempts: Arc<Mutex<HashMap<String, AttemptRecord>>>,
    ip_rates: Arc<Mutex<HashMap<String, IpRateRecord>>>,
}

impl LockoutTracker {
    pub fn new() -> Self {
        Self {
            attempts: Arc::new(Mutex::new(HashMap::new())),
            ip_rates: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Checks if a given key (user or IP) is currently locked out.
    ///
    /// Returns remaining lockout duration in seconds if locked.
    pub fn check_lockout(&self, key: &str) -> Option<u64> {
        let mut map = self.attempts.lock().unwrap();
        if let Some(record) = map.get_mut(key)
            && let Some(until) = record.locked_until
        {
            let now = Instant::now();
            if now < until {
                return Some((until - now).as_secs());
            }
            // Lockout expired, reset
            record.count = 0;
            record.locked_until = None;
        }
        None
    }

    /// Records a failed attempt for the given key.
    ///
    /// Returns `(is_locked, remaining_attempts)`.
    pub fn record_failure(&self, key: &str) -> (bool, u32) {
        let mut map = self.attempts.lock().unwrap();
        let record = map.entry(key.to_string()).or_insert(AttemptRecord {
            count: 0,
            locked_until: None,
        });

        record.count += 1;
        if record.count >= MAX_FAILED_ATTEMPTS {
            record.locked_until = Some(Instant::now() + LOCKOUT_DURATION);
            (true, 0)
        } else {
            (false, MAX_FAILED_ATTEMPTS - record.count)
        }
    }

    /// Clears any recorded failures upon successful authentication.
    pub fn record_success(&self, key: &str) {
        let mut map = self.attempts.lock().unwrap();
        map.remove(key);
    }

    /// Checks and records an IP request against a per-minute rate limit.
    ///
    /// Returns `true` if allowed, `false` if rate limited.
    pub fn check_ip_rate_limit(&self, ip: &str, limit_per_minute: usize) -> bool {
        if limit_per_minute == 0 {
            return true;
        }

        let now = Instant::now();
        let window = Duration::from_secs(60);
        let mut map = self.ip_rates.lock().unwrap();

        let record = map.entry(ip.to_string()).or_insert(IpRateRecord {
            timestamps: Vec::new(),
        });

        // Prune older than 60s
        record
            .timestamps
            .retain(|&t| now.duration_since(t) <= window);

        if record.timestamps.len() >= limit_per_minute {
            false
        } else {
            record.timestamps.push(now);
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lockout_after_five_failed_attempts() {
        let tracker = LockoutTracker::new();
        let user = "admin";

        for _ in 0..4 {
            let (locked, remaining) = tracker.record_failure(user);
            assert!(!locked);
            assert!(remaining > 0);
            assert!(tracker.check_lockout(user).is_none());
        }

        // 5th failure triggers lockout
        let (locked, remaining) = tracker.record_failure(user);
        assert!(locked);
        assert_eq!(remaining, 0);

        let remaining_secs = tracker.check_lockout(user);
        assert!(remaining_secs.is_some());
        assert!(remaining_secs.unwrap() > 0);

        // Success resets lockout
        tracker.record_success(user);
        assert!(tracker.check_lockout(user).is_none());
    }

    #[test]
    fn test_ip_rate_limiting() {
        let tracker = LockoutTracker::new();
        let ip = "192.168.1.50";

        for _ in 0..5 {
            assert!(tracker.check_ip_rate_limit(ip, 5));
        }

        // 6th attempt in the same minute is blocked
        assert!(!tracker.check_ip_rate_limit(ip, 5));
    }
}
