//! Per-account API rate limiting.
//!
//! This is an account-wide ceiling charged once per authenticated administrative
//! request. It does not replace the per-IP login/TOTP limits or the
//! per-endpoint stats/query-log limits; all of them still apply and the
//! stricter one wins.
//!
//! Buckets are keyed by account:
//!
//! * a browser session uses its username;
//! * an API token with an owner uses the owner's username, so every session and
//!   token of that account shares one bucket;
//! * a legacy ownerless token uses its token id in a separate namespace, so it
//!   can never collide with an account name.
//!
//! The bucket table is bounded ([`MAX_API_RATE_BUCKETS`]) and pruned on every
//! check, matching the existing stats/query-log limiters. The happy path only
//! performs one `HashMap` lookup on a borrowed `&str`; the key is allocated only
//! when a new bucket is inserted.

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

/// Fixed window for the per-account limit.
pub(crate) const API_RATE_WINDOW: Duration = Duration::from_secs(60);

/// Maximum tracked accounts/ownerless tokens. Keeps memory bounded when many
/// (possibly short-lived) accounts or tokens exist.
pub(crate) const MAX_API_RATE_BUCKETS: usize = 8_192;

/// Account key for one authenticated request.
#[derive(Debug, Clone, Copy)]
pub(crate) enum ApiAccountKey<'a> {
    /// A session or an API token owned by this account.
    Account(&'a str),
    /// A legacy API token without an owner, keyed by token id.
    Ownerless(&'a str),
}

#[derive(Debug, Clone, Copy)]
struct Bucket {
    window_start: Instant,
    count: u32,
}

#[derive(Debug, Default)]
struct BucketMap {
    accounts: HashMap<String, Bucket>,
    ownerless: HashMap<String, Bucket>,
}

impl BucketMap {
    fn len(&self) -> usize {
        self.accounts.len() + self.ownerless.len()
    }

    fn contains(&self, key: ApiAccountKey<'_>) -> bool {
        match key {
            ApiAccountKey::Account(name) => self.accounts.contains_key(name),
            ApiAccountKey::Ownerless(id) => self.ownerless.contains_key(id),
        }
    }

    /// Drops every bucket whose window ended at or before `now`.
    fn retain_active(&mut self, now: Instant) {
        self.accounts.retain(|_, bucket| {
            now.saturating_duration_since(bucket.window_start) <= API_RATE_WINDOW
        });
        self.ownerless.retain(|_, bucket| {
            now.saturating_duration_since(bucket.window_start) <= API_RATE_WINDOW
        });
    }

    /// Removes the bucket with the oldest window start.
    fn evict_oldest(&mut self) {
        let oldest_account = self
            .accounts
            .iter()
            .min_by_key(|(_, bucket)| bucket.window_start)
            .map(|(name, _)| name.clone());
        let oldest_ownerless = self
            .ownerless
            .iter()
            .min_by_key(|(_, bucket)| bucket.window_start)
            .map(|(id, _)| id.clone());
        match (oldest_account, oldest_ownerless) {
            (Some(name), Some(id)) => {
                let account_start = self.accounts[&name].window_start;
                let ownerless_start = self.ownerless[&id].window_start;
                if account_start <= ownerless_start {
                    self.accounts.remove(&name);
                } else {
                    self.ownerless.remove(&id);
                }
            }
            (Some(name), None) => {
                self.accounts.remove(&name);
            }
            (None, Some(id)) => {
                self.ownerless.remove(&id);
            }
            (None, None) => {}
        }
    }
}

/// Borrows an existing bucket or inserts a fresh one.
///
/// The `get_mut` fast path avoids allocating a `String` on every request; the
/// key is only cloned when a bucket is first created.
fn charge_map<'a>(
    buckets: &'a mut HashMap<String, Bucket>,
    key: &str,
    now: Instant,
) -> &'a mut Bucket {
    if !buckets.contains_key(key) {
        buckets.insert(
            key.to_string(),
            Bucket {
                window_start: now,
                count: 0,
            },
        );
    }
    buckets
        .get_mut(key)
        .expect("bucket was just inserted or already existed")
}

/// Bounded per-account fixed-window limiter.
#[derive(Debug)]
pub(crate) struct ApiRateLimiter {
    /// Current limit in requests per minute. `0` disables the limiter.
    limit: AtomicUsize,
    buckets: Mutex<BucketMap>,
}

impl ApiRateLimiter {
    pub(crate) fn new(limit: u32) -> Self {
        Self {
            limit: AtomicUsize::new(usize::try_from(limit).unwrap_or(usize::MAX)),
            buckets: Mutex::new(BucketMap::default()),
        }
    }

    pub(crate) fn set_limit(&self, limit: u32) {
        self.limit.store(
            usize::try_from(limit).unwrap_or(usize::MAX),
            Ordering::Relaxed,
        );
    }

    pub(crate) fn limit(&self) -> u32 {
        u32::try_from(self.limit.load(Ordering::Relaxed)).unwrap_or(u32::MAX)
    }

    /// Charges one request to `key`.
    ///
    /// Returns `Err(retry_after_secs)` when the account already consumed its
    /// allowance for the current window. `0` disables the limiter and never
    /// allocates a bucket.
    pub(crate) fn check(&self, key: ApiAccountKey<'_>) -> Result<(), u64> {
        self.check_at(key, Instant::now())
    }

    /// Clock-injected variant used by tests for deterministic window resets.
    fn check_at(&self, key: ApiAccountKey<'_>, now: Instant) -> Result<(), u64> {
        let limit = self.limit.load(Ordering::Relaxed);
        if limit == 0 {
            return Ok(());
        }

        let mut buckets = self
            .buckets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        buckets.retain_active(now);

        if buckets.len() >= MAX_API_RATE_BUCKETS && !buckets.contains(key) {
            buckets.evict_oldest();
        }

        let bucket = match key {
            ApiAccountKey::Account(name) => charge_map(&mut buckets.accounts, name, now),
            ApiAccountKey::Ownerless(id) => charge_map(&mut buckets.ownerless, id, now),
        };

        if now.saturating_duration_since(bucket.window_start) > API_RATE_WINDOW {
            *bucket = Bucket {
                window_start: now,
                count: 0,
            };
        }

        bucket.count = bucket.count.saturating_add(1);
        if bucket.count > u32::try_from(limit).unwrap_or(u32::MAX) {
            let elapsed = now.saturating_duration_since(bucket.window_start);
            let remaining = API_RATE_WINDOW.saturating_sub(elapsed);
            // Round up so a client never retries before the window reset.
            let seconds = remaining.as_secs() + u64::from(remaining.subsec_nanos() > 0);
            return Err(seconds.max(1));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limiter(limit: u32) -> ApiRateLimiter {
        ApiRateLimiter::new(limit)
    }

    #[test]
    fn test_accounts_have_independent_buckets() {
        let limiter = limiter(2);
        let start = Instant::now();
        assert!(
            limiter
                .check_at(ApiAccountKey::Account("alice"), start)
                .is_ok()
        );
        assert!(
            limiter
                .check_at(ApiAccountKey::Account("alice"), start)
                .is_ok()
        );
        assert!(
            limiter
                .check_at(ApiAccountKey::Account("alice"), start)
                .is_err(),
            "the third request in the window must be rejected"
        );
        assert!(
            limiter
                .check_at(ApiAccountKey::Account("bob"), start)
                .is_ok(),
            "another account must keep its own allowance"
        );
    }

    #[test]
    fn test_ownerless_tokens_are_separate_from_accounts() {
        let limiter = limiter(1);
        let start = Instant::now();
        assert!(
            limiter
                .check_at(ApiAccountKey::Ownerless("tok_a"), start)
                .is_ok()
        );
        assert!(
            limiter
                .check_at(ApiAccountKey::Account("tok_a"), start)
                .is_ok(),
            "an account with the same name as a token id must not share its bucket"
        );
        assert!(
            limiter
                .check_at(ApiAccountKey::Ownerless("tok_a"), start)
                .is_err()
        );
        assert!(
            limiter
                .check_at(ApiAccountKey::Ownerless("tok_b"), start)
                .is_ok(),
            "ownerless tokens are keyed individually"
        );
    }

    #[test]
    fn test_zero_disables_the_limiter() {
        let limiter = limiter(0);
        let start = Instant::now();
        for _ in 0..1_000 {
            assert!(
                limiter
                    .check_at(ApiAccountKey::Account("alice"), start)
                    .is_ok()
            );
        }
        assert_eq!(
            limiter
                .buckets
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .len(),
            0,
            "a disabled limiter must not allocate buckets"
        );
    }

    #[test]
    fn test_window_resets_after_the_fixed_interval() {
        let limiter = limiter(1);
        let start = Instant::now();
        assert!(
            limiter
                .check_at(ApiAccountKey::Account("alice"), start)
                .is_ok()
        );
        let retry_after = limiter
            .check_at(ApiAccountKey::Account("alice"), start)
            .expect_err("second request must be limited");
        assert_eq!(retry_after, 60, "Retry-After covers the whole window");
        assert!(
            limiter
                .check_at(
                    ApiAccountKey::Account("alice"),
                    start + API_RATE_WINDOW + Duration::from_millis(1)
                )
                .is_ok(),
            "a new window must restore the allowance"
        );
    }

    #[test]
    fn test_bucket_map_is_bounded() {
        let limiter = limiter(1);
        let start = Instant::now();
        for i in 0..(MAX_API_RATE_BUCKETS + 100) {
            let name = format!("account-{i}");
            assert!(
                limiter
                    .check_at(ApiAccountKey::Account(&name), start)
                    .is_ok()
            );
        }
        let len = limiter
            .buckets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len();
        assert!(
            len <= MAX_API_RATE_BUCKETS,
            "bucket table must stay bounded, got {len}"
        );
    }
}
