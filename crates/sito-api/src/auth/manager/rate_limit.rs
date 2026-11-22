//! Per-account API rate-limit configuration surface.

#[allow(clippy::wildcard_imports)]
use super::*;

impl AuthManager {
    /// Updates the live per-account API rate limit (hot config apply).
    pub fn set_api_rate_limit(&self, limit: u32) {
        self.api_rate_limiter.set_limit(limit);
    }

    /// Current per-account API rate limit.
    #[must_use]
    pub fn api_rate_limit_per_minute(&self) -> u32 {
        self.api_rate_limiter.limit()
    }

    /// Charges one authenticated API request to `key`.
    ///
    /// Returns `Retry-After` seconds when the account already consumed its
    /// allowance for the current window. `0` disables the limiter.
    pub(crate) fn check_api_rate_limit(
        &self,
        key: crate::auth::rate_limit::ApiAccountKey<'_>,
    ) -> Result<(), u64> {
        self.api_rate_limiter.check(key)
    }
}
