//! Exponential backoff with random jitter for resilient reconnection.

use rand::RngExt;
use std::time::Duration;

/// Exponential backoff generator with jitter.
#[derive(Debug, Clone)]
pub struct ExponentialBackoff {
    current: Duration,
    min: Duration,
    max: Duration,
    multiplier: f64,
}

impl Default for ExponentialBackoff {
    fn default() -> Self {
        Self::new(Duration::from_secs(1), Duration::from_secs(60), 2.0)
    }
}

impl ExponentialBackoff {
    /// Creates a new backoff configuration.
    pub fn new(min: Duration, max: Duration, multiplier: f64) -> Self {
        Self {
            current: min,
            min,
            max,
            multiplier,
        }
    }

    /// Resets backoff delay to the initial minimum duration.
    pub fn reset(&mut self) {
        self.current = self.min;
    }

    /// Computes the next delay with random jitter, then increments the backoff interval.
    pub fn next_delay(&mut self) -> Duration {
        let base_ms = self.current.as_millis() as f64;
        let mut rng = rand::rng();
        // Add +/- 20% random jitter
        let jitter_factor = rng.random_range(0.8..=1.2);
        let jittered_ms = (base_ms * jitter_factor).max(self.min.as_millis() as f64);
        let delay = Duration::from_millis(jittered_ms as u64).min(self.max);

        // Advance current for next attempt
        let next_ms = (base_ms * self.multiplier).min(self.max.as_millis() as f64);
        self.current = Duration::from_millis(next_ms as u64);

        delay
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_backoff_advancement_and_reset() {
        let mut backoff =
            ExponentialBackoff::new(Duration::from_millis(100), Duration::from_millis(1000), 2.0);

        let d1 = backoff.next_delay();
        assert!(d1 >= Duration::from_millis(80) && d1 <= Duration::from_millis(130));

        let d2 = backoff.next_delay();
        assert!(d2 >= Duration::from_millis(160) && d2 <= Duration::from_millis(250));

        // Advance until capped at max
        for _ in 0..10 {
            let _ = backoff.next_delay();
        }
        let capped = backoff.next_delay();
        assert!(capped <= Duration::from_millis(1000));

        backoff.reset();
        let reset_d = backoff.next_delay();
        assert!(reset_d <= Duration::from_millis(130));
    }
}
