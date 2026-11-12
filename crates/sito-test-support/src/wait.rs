//! Bounded event-driven wait helpers.
//!
//! Tests should wait for the thing they care about (a listener accepting, a
//! state flipping, a TTL decrementing) instead of sleeping for a guessed
//! duration. [`wait_until`] is the low-level boolean helper retained for
//! compatibility; [`wait_for`] additionally carries the awaited condition and
//! timeout into a descriptive [`WaitTimeout`] error.

use std::fmt;
use std::time::Duration;

use tokio::time::Instant;

/// How often the condition is re-polled.
pub const WAIT_POLL_INTERVAL: Duration = Duration::from_millis(25);

/// A bounded wait that never observed its condition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WaitTimeout {
    label: String,
    timeout: Duration,
}

impl WaitTimeout {
    /// Creates a timeout error for `label` and `timeout`.
    #[must_use]
    pub fn new(label: impl Into<String>, timeout: Duration) -> Self {
        Self {
            label: label.into(),
            timeout,
        }
    }

    /// The condition that was awaited.
    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }

    /// The patience that was exhausted.
    #[must_use]
    pub fn timeout(&self) -> Duration {
        self.timeout
    }
}

impl fmt::Display for WaitTimeout {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "timed out after {:?} waiting for: {}",
            self.timeout, self.label
        )
    }
}

impl std::error::Error for WaitTimeout {}

/// Polls `condition` every [`WAIT_POLL_INTERVAL`] until it is true or `timeout`
/// elapses.
pub async fn wait_until<F, Fut>(timeout: Duration, mut condition: F) -> bool
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = Instant::now() + timeout;
    loop {
        if condition().await {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(WAIT_POLL_INTERVAL).await;
    }
}

/// Like [`wait_until`], but returns a descriptive [`WaitTimeout`] that names
/// the awaited condition and the budget.
///
/// Use it at assertion boundaries:
/// ```ignore
/// wait_for("HA slave to sync", Duration::from_secs(5), || async {
///     tracker.get_state() == SlaveState::Synced
/// })
/// .await
/// .expect("HA slave did not sync");
/// ```
pub async fn wait_for<F, Fut>(
    label: impl Into<String>,
    timeout: Duration,
    condition: F,
) -> Result<(), WaitTimeout>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let label = label.into();
    if wait_until(timeout, condition).await {
        Ok(())
    } else {
        Err(WaitTimeout::new(label, timeout))
    }
}

#[cfg(test)]
mod tests {
    use super::{WAIT_POLL_INTERVAL, wait_for};

    #[test]
    fn poll_interval_is_small_enough_for_timing_assertions() {
        assert!(WAIT_POLL_INTERVAL <= std::time::Duration::from_millis(50));
    }

    #[tokio::test]
    async fn wait_for_checks_immediately_without_sleeping() {
        wait_for("immediate", std::time::Duration::ZERO, || async { true })
            .await
            .expect("an immediately-true condition must not need a poll interval");
    }
}
