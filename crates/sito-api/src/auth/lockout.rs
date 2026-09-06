//! Lockout and rate-limiting tracker per section 12.2 and section 15.
//!
//! 15-minute lockout after 5 consecutive failed attempts.
//! Per-IP rate limiting for login endpoints.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const MAX_FAILED_ATTEMPTS: u32 = 5;
const LOCKOUT_DURATION: Duration = Duration::from_mins(15); // 15 minutes
pub const MAX_LOCKOUT_ENTRIES: usize = 10_000;
pub const MAX_IP_RATE_ENTRIES: usize = 10_000;

#[derive(Debug, Clone)]
struct AttemptRecord {
    count: u32,
    locked_until: Option<Instant>,
    last_attempt: Instant,
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
        if let Some(record) = map.get_mut(key) {
            let now = Instant::now();
            if let Some(until) = record.locked_until {
                if now < until {
                    return Some((until - now).as_secs());
                }
                // Lockout expired, reset
                record.count = 0;
                record.locked_until = None;
            } else if now.duration_since(record.last_attempt) > LOCKOUT_DURATION {
                // Inactivity expired failed attempts
                record.count = 0;
            }
        }
        None
    }

    /// Records a failed attempt for the given key.
    ///
    /// Returns `(is_locked, remaining_attempts)`.
    pub fn record_failure(&self, key: &str) -> (bool, u32) {
        let mut map = self.attempts.lock().unwrap();
        let now = Instant::now();

        if !map.contains_key(key) && map.len() >= MAX_LOCKOUT_ENTRIES {
            // Prune expired entries
            map.retain(|_, r| {
                if let Some(until) = r.locked_until {
                    now < until
                } else {
                    now.duration_since(r.last_attempt) <= LOCKOUT_DURATION && r.count > 0
                }
            });
            if map.len() >= MAX_LOCKOUT_ENTRIES
                && let Some(oldest_key) = map.keys().next().cloned()
            {
                map.remove(&oldest_key);
            }
        }

        let record = map.entry(key.to_string()).or_insert(AttemptRecord {
            count: 0,
            locked_until: None,
            last_attempt: now,
        });

        record.last_attempt = now;
        record.count += 1;
        if record.count >= MAX_FAILED_ATTEMPTS {
            record.locked_until = Some(now + LOCKOUT_DURATION);
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

        if !map.contains_key(ip) && map.len() >= MAX_IP_RATE_ENTRIES {
            map.retain(|_, record| {
                record
                    .timestamps
                    .retain(|&t| now.duration_since(t) <= window);
                !record.timestamps.is_empty()
            });
            if map.len() >= MAX_IP_RATE_ENTRIES
                && let Some(oldest_key) = map.keys().next().cloned()
            {
                map.remove(&oldest_key);
            }
        }

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

    /// Prunes expired lockout records and inactive IP rate records.
    pub fn prune(&self) {
        let now = Instant::now();
        let window = Duration::from_secs(60);
        {
            let mut ip_map = self.ip_rates.lock().unwrap();
            ip_map.retain(|_, record| {
                record
                    .timestamps
                    .retain(|&t| now.duration_since(t) <= window);
                !record.timestamps.is_empty()
            });
        }
        {
            let mut attempt_map = self.attempts.lock().unwrap();
            attempt_map.retain(|_, record| {
                if let Some(until) = record.locked_until {
                    now < until
                } else {
                    now.duration_since(record.last_attempt) <= LOCKOUT_DURATION && record.count > 0
                }
            });
        }
    }

    #[cfg(test)]
    pub fn attempts_len(&self) -> usize {
        self.attempts.lock().unwrap().len()
    }

    #[cfg(test)]
    pub fn ip_rates_len(&self) -> usize {
        self.ip_rates.lock().unwrap().len()
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

    #[test]
    fn test_prune_expired_lockout_and_ip_rates() {
        let tracker = LockoutTracker::new();
        tracker.record_failure("user1");
        assert_eq!(tracker.attempts_len(), 1);

        tracker.check_ip_rate_limit("1.2.3.4", 10);
        assert_eq!(tracker.ip_rates_len(), 1);

        // Advance timestamps manually in state to simulate expiration
        {
            let mut attempts = tracker.attempts.lock().unwrap();
            if let Some(rec) = attempts.get_mut("user1") {
                rec.last_attempt = Instant::now()
                    .checked_sub(Duration::from_secs(1000))
                    .unwrap(); // > 15 mins
            }
        }
        {
            let mut ip_rates = tracker.ip_rates.lock().unwrap();
            if let Some(rec) = ip_rates.get_mut("1.2.3.4") {
                rec.timestamps = vec![
                    Instant::now()
                        .checked_sub(Duration::from_secs(120))
                        .unwrap(),
                ]; // > 60s
            }
        }

        tracker.prune();
        assert_eq!(tracker.attempts_len(), 0);
        assert_eq!(tracker.ip_rates_len(), 0);
    }
}
