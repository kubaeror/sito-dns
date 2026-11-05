//! In-memory tracking of connected replica slaves.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::time::Instant;
use tokio::sync::mpsc;

use crate::protocol::HaMessage;

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

/// Full tracking state of an active slave connection on the master.
pub struct ActiveSlave {
    pub instance: String,
    pub remote_addr: SocketAddr,
    pub synced_version: u64,
    pub last_ping: Instant,
    pub connected_at: DateTime<Utc>,
    pub last_stats: Option<SlaveStatsSummary>,
    pub sender: mpsc::Sender<HaMessage>,
    /// Capabilities advertised in the slave's Hello (e.g. `stats-v1`).
    pub capabilities: Vec<String>,
    /// Monotonic id of the connection that registered this entry. A
    /// reconnecting slave replaces the entry; the superseded session must not
    /// remove or update the newer one during cleanup.
    pub connection_id: u64,
}

impl ActiveSlave {
    /// Builds the API summary.
    ///
    /// `latched_divergence` is true when the coordinator has a sticky
    /// divergence record for this instance (fork, newer term, or same-term
    /// version gap). It is OR'ed with the version-comparison fallback so a
    /// rejected push is never reported as simply in sync.
    pub fn to_summary(&self, current_version: u64, latched_divergence: bool) -> SlaveSummary {
        let diverged = latched_divergence || self.synced_version > current_version;
        let lag = if diverged {
            0
        } else {
            current_version.saturating_sub(self.synced_version)
        };
        SlaveSummary {
            instance: self.instance.clone(),
            remote_addr: self.remote_addr.to_string(),
            synced_version: self.synced_version,
            lag,
            diverged,
            last_ping_secs_ago: self.last_ping.elapsed().as_secs(),
            connected_at: self.connected_at.to_rfc3339(),
            last_stats: self.last_stats.clone(),
        }
    }
}
