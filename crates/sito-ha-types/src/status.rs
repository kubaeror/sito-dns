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

/// Local publication state of the master's active bundle.
///
/// ADR-0010 distinguishes the last bundle this node *published* (the witness
/// baseline) from a bundle it has staged but not yet published. The pending
/// bundle version is local only and must never be sent to the witness as an
/// acquisition or renewal baseline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicationState {
    /// A promotion staged `version` locally but has not started publishing it.
    Pending,
    /// The first push of the staged bundle has started (or may have completed
    /// before a crash). Reconciliation decides whether it succeeded.
    Publishing,
    /// `published_version`/`published_hash` identify the last published bundle.
    Published,
}

impl PublicationState {
    /// Whether a bundle is staged but not yet confirmed published.
    #[must_use]
    pub const fn is_pending(self) -> bool {
        matches!(self, Self::Pending | Self::Publishing)
    }
}

/// Summary of a connected slave exposed via `/api/v2/ha/slaves` REST API.
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
    /// True when the peer advertised `have_bundle_hash` in its Hello.
    ///
    /// Promotion-enabled clusters require this capability during candidate
    /// reconciliation; legacy v2 peers omit it and must be upgraded first.
    #[serde(default)]
    pub bundle_hash_known: bool,
    /// Bounded recent ACK history for this slave, newest last.
    #[serde(default)]
    pub recent_acks: Vec<SlaveAckRecord>,
}

/// One bounded per-slave ACK/publish record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlaveAckRecord {
    pub version: u64,
    pub term: u64,
    pub applied: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conflict: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub at: String,
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
    /// The bundle was persisted and at least one connected slave was observed.
    ///
    /// This is a *queue outcome*, not delivery confirmation: `slaves_queued`
    /// counts direct channel enqueues, `slaves_coalesced` counts deferred
    /// fallback deliveries (slow/full queue), and `slaves_connected` is the
    /// number of connected slaves observed during the publish. Both queue
    /// counters may be zero when every connected channel was already closed;
    /// such a publish must not be reported as `NoSlaves` or as delivered.
    Published {
        version: u64,
        term: u64,
        slaves_connected: usize,
        slaves_queued: usize,
        slaves_coalesced: usize,
    },
    /// The bundle was persisted but no slave is currently connected.
    NoSlaves,
    /// The signed envelope exceeds the WebSocket message limit and was not
    /// persisted or broadcast.
    ///
    /// Retrying the same document cannot shrink it, so this is not scheduled
    /// for automatic retry; the caller must change the configuration.
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
    fn publication_states_serialize_as_snake_case_and_mark_pending() {
        assert!(PublicationState::Pending.is_pending());
        assert!(PublicationState::Publishing.is_pending());
        assert!(!PublicationState::Published.is_pending());
        assert_eq!(
            serde_json::to_string(&PublicationState::Publishing).unwrap(),
            "\"publishing\""
        );
        assert_eq!(
            serde_json::from_str::<PublicationState>("\"pending\"").unwrap(),
            PublicationState::Pending
        );
    }

    #[test]
    fn publish_outcomes_are_comparable() {
        assert_ne!(
            PublishOutcome::NoSlaves,
            PublishOutcome::Published {
                version: 1,
                term: 2,
                slaves_connected: 1,
                slaves_queued: 1,
                slaves_coalesced: 0,
            }
        );
        assert_eq!(
            PublishOutcome::TooLarge { bytes: 2, limit: 1 },
            PublishOutcome::TooLarge { bytes: 2, limit: 1 }
        );
    }
}
