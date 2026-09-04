//! Upstream health tracking state machine per plan section 6.3.

use sito_core::error::UpstreamError;
use std::time::Instant;

/// Operational health classification for an upstream server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthStatus {
    Healthy,
    Suspect,
    Down,
}

/// State machine tracking passive error counts and active probe results.
#[derive(Debug, Clone)]
pub struct UpstreamHealth {
    status: HealthStatus,
    consecutive_errors: u32,
    probe_successes: u32,
    last_state_change: Instant,
}

impl Default for UpstreamHealth {
    fn default() -> Self {
        Self {
            status: HealthStatus::Healthy,
            consecutive_errors: 0,
            probe_successes: 0,
            last_state_change: Instant::now(),
        }
    }
}

impl UpstreamHealth {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn status(&self) -> HealthStatus {
        self.status
    }

    /// Whether this upstream is eligible to receive incoming queries in normal rotation.
    pub fn is_available(&self) -> bool {
        self.status != HealthStatus::Down
    }

    /// Record a successful query resolution.
    pub fn record_success(&mut self) {
        self.consecutive_errors = 0;
        self.probe_successes = 0;
        if self.status != HealthStatus::Healthy {
            self.status = HealthStatus::Healthy;
            self.last_state_change = Instant::now();
        }
    }

    /// Record an active probe success.
    pub fn record_probe_success(&mut self) {
        match self.status {
            HealthStatus::Down => {
                self.probe_successes += 1;
                // 2 consecutive probe successes return Down -> Healthy
                if self.probe_successes >= 2 {
                    self.status = HealthStatus::Healthy;
                    self.consecutive_errors = 0;
                    self.probe_successes = 0;
                    self.last_state_change = Instant::now();
                }
            }
            HealthStatus::Suspect => {
                self.record_success();
            }
            HealthStatus::Healthy => {
                self.consecutive_errors = 0;
            }
        }
    }

    /// Record a query failure.
    pub fn record_error(&mut self, err: &UpstreamError) {
        // SERVFAIL and DnssecBogus do not lower health per plan section 6.3
        if matches!(err, UpstreamError::DnssecBogus) {
            return;
        }

        self.consecutive_errors += 1;
        self.probe_successes = 0;

        if self.consecutive_errors >= 6 {
            if self.status != HealthStatus::Down {
                self.status = HealthStatus::Down;
                self.last_state_change = Instant::now();
            }
        } else if self.consecutive_errors >= 3 && self.status == HealthStatus::Healthy {
            self.status = HealthStatus::Suspect;
            self.last_state_change = Instant::now();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_state_transitions() {
        let mut health = UpstreamHealth::new();
        assert_eq!(health.status(), HealthStatus::Healthy);
        assert!(health.is_available());

        // 3 consecutive errors -> Suspect
        for _ in 0..3 {
            health.record_error(&UpstreamError::Timeout);
        }
        assert_eq!(health.status(), HealthStatus::Suspect);
        assert!(health.is_available());

        // 1 success returns Suspect -> Healthy
        health.record_success();
        assert_eq!(health.status(), HealthStatus::Healthy);

        // 6 consecutive errors -> Down
        for _ in 0..6 {
            health.record_error(&UpstreamError::Refused);
        }
        assert_eq!(health.status(), HealthStatus::Down);
        assert!(!health.is_available());

        // First probe success -> still Down
        health.record_probe_success();
        assert_eq!(health.status(), HealthStatus::Down);

        // Second probe success -> Healthy
        health.record_probe_success();
        assert_eq!(health.status(), HealthStatus::Healthy);
        assert!(health.is_available());
    }

    #[test]
    fn test_dnssec_bogus_does_not_lower_health() {
        let mut health = UpstreamHealth::new();
        for _ in 0..10 {
            health.record_error(&UpstreamError::DnssecBogus);
        }
        assert_eq!(health.status(), HealthStatus::Healthy);
    }
}
