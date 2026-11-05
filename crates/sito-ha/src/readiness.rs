//! Shared HA readiness signal.
//!
//! HA failures used to be logged and otherwise invisible: the master returned
//! from `spawn_master_server` when its mTLS key was unreadable, yet
//! `/api/v1/ha/status` still said `active` and the DNS healthcheck passed.
//! The state below is updated by the replication listener/worker and read by
//! the admin API and healthcheck so an operator sees a failed role.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

/// Point-in-time readiness of the node's HA role.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HaReadiness {
    /// True when the HA role is operational (or deliberately disabled).
    pub ready: bool,
    /// Why the role is not ready. `None` only when `ready` is true.
    pub reason: Option<String>,
}

impl HaReadiness {
    #[must_use]
    pub fn ready() -> Self {
        Self {
            ready: true,
            reason: None,
        }
    }

    #[must_use]
    pub fn not_ready(reason: impl Into<String>) -> Self {
        Self {
            ready: false,
            reason: Some(reason.into()),
        }
    }
}

/// Cloneable readiness state shared between a replication task and its API.
#[derive(Debug, Clone)]
pub struct HaReadinessState {
    ready: Arc<AtomicBool>,
    reason: Arc<Mutex<Option<String>>>,
}

impl HaReadinessState {
    #[must_use]
    pub fn not_ready(reason: impl Into<String>) -> Self {
        Self {
            ready: Arc::new(AtomicBool::new(false)),
            reason: Arc::new(Mutex::new(Some(reason.into()))),
        }
    }

    #[must_use]
    pub fn ready() -> Self {
        Self {
            ready: Arc::new(AtomicBool::new(true)),
            reason: Arc::new(Mutex::new(None)),
        }
    }

    pub fn mark_ready(&self) {
        *self.reason.lock().unwrap() = None;
        self.ready.store(true, Ordering::SeqCst);
    }

    /// Marks the role ready while keeping an explanatory note (for example an
    /// intentionally disabled replication listener).
    pub fn mark_ready_with_reason(&self, reason: impl Into<String>) {
        *self.reason.lock().unwrap() = Some(reason.into());
        self.ready.store(true, Ordering::SeqCst);
    }

    pub fn mark_failed(&self, reason: impl Into<String>) {
        *self.reason.lock().unwrap() = Some(reason.into());
        // Store the flag last so a reader that observes `ready == false`
        // always finds the reason that belongs to it.
        self.ready.store(false, Ordering::SeqCst);
    }

    #[must_use]
    pub fn snapshot(&self) -> HaReadiness {
        HaReadiness {
            ready: self.ready.load(Ordering::SeqCst),
            reason: self.reason.lock().unwrap().clone(),
        }
    }
}

impl Default for HaReadinessState {
    fn default() -> Self {
        Self::not_ready("HA replication has not started")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_readiness_transitions() {
        let state = HaReadinessState::not_ready("starting");
        let snapshot = state.snapshot();
        assert!(!snapshot.ready);
        assert_eq!(snapshot.reason.as_deref(), Some("starting"));

        state.mark_ready();
        assert_eq!(state.snapshot(), HaReadiness::ready());

        state.mark_failed("mTLS initialization failed");
        let snapshot = state.snapshot();
        assert!(!snapshot.ready);
        assert_eq!(
            snapshot.reason.as_deref(),
            Some("mTLS initialization failed")
        );
    }
}
