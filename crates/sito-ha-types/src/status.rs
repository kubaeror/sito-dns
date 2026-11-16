//! Portable HA status and outcome types.

use serde::{Deserialize, Serialize};

/// Lifecycle states of a replica slave node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlaveState {
    /// Actively attempting to connect to the master WebSocket endpoint.
    Connecting,
    /// Connected and waiting for synchronization response after sending `Hello`.
    HelloSent,
    /// Synchronized with master; operating normally.
    Synced,
    /// Staging and atomically applying a received configuration push.
    Applying,
    /// Operating with previous working configuration after an apply failure.
    Degraded,
}

impl std::fmt::Display for SlaveState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Connecting => write!(f, "connecting"),
            Self::HelloSent => write!(f, "hello_sent"),
            Self::Synced => write!(f, "synced"),
            Self::Applying => write!(f, "applying"),
            Self::Degraded => write!(f, "degraded"),
        }
    }
}

/// Summary of a connected slave exposed via `/api/v1/ha/slaves` REST API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlaveSummary {
    pub instance: String,
    pub remote_addr: String,
    pub synced_version: u64,
    pub lag: u64,
    /// True when this slave reported a version above the master's current one.
    /// A diverged slave silently ignores every push until the sequence is
    /// recovered above its version, so its `lag` is pinned to 0 and must not be
    /// read as "in sync".
    pub diverged: bool,
    pub last_ping_secs_ago: u64,
    pub connected_at: String,
    pub last_stats: Option<SlaveStatsSummary>,
}

/// Aggregated stats snapshot reported by a slave node for its last reporting
/// window.
///
/// `window_s` is the actual length of that window and `queries`/`blocked` are
/// the activity observed in it (deltas, not lifetime totals).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlaveStatsSummary {
    pub window_s: u64,
    pub queries: u64,
    pub blocked: u64,
    pub upstreams_count: usize,
}

/// Outcome of publishing a configuration bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublishOutcome {
    /// The bundle was persisted and queued for at least one connected slave.
    Published { version: u64, term: u64 },
    /// The bundle was persisted but no slave is currently connected.
    NoSlaves,
    /// The signed envelope exceeds the WebSocket message limit and was not
    /// persisted or broadcast.
    TooLarge { bytes: usize, limit: usize },
}

/// Outcome of a manual resynchronization request, surfaced honestly by the
/// `/ha/resync` API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResyncOutcome {
    /// Version of the replicated configuration bundle.
    pub version: u64,
    /// Whether an active bundle exists to re-push. When false the request was
    /// accepted but there is nothing to replicate yet.
    pub active_bundle: bool,
    /// Connected slaves for which a push was queued (or coalesced).
    pub slaves_notified: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slave_state_display_is_stable() {
        assert_eq!(SlaveState::Connecting.to_string(), "connecting");
        assert_eq!(SlaveState::HelloSent.to_string(), "hello_sent");
        assert_eq!(SlaveState::Synced.to_string(), "synced");
        assert_eq!(SlaveState::Applying.to_string(), "applying");
        assert_eq!(SlaveState::Degraded.to_string(), "degraded");
    }

    #[test]
    fn publish_outcomes_are_comparable() {
        assert_ne!(
            PublishOutcome::NoSlaves,
            PublishOutcome::Published {
                version: 1,
                term: 2
            }
        );
        assert_eq!(
            PublishOutcome::TooLarge { bytes: 2, limit: 1 },
            PublishOutcome::TooLarge { bytes: 2, limit: 1 }
        );
    }
}
