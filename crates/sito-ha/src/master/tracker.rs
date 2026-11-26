//! In-memory tracking of connected replica slaves.

use chrono::{DateTime, Utc};
use std::net::SocketAddr;
use std::time::Instant;
use tokio::sync::mpsc;

use crate::protocol::HaMessage;

pub use sito_ha_types::status::{SlaveAckRecord, SlaveStatsSummary, SlaveSummary};

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
    /// Term advertised in the slave's `Hello` at registration.
    ///
    /// ADR-0010 reconciliation uses the term/version/hash report the peer sent
    /// before the master's first publish, never a later inferred value.
    pub have_term: u64,
    /// Version advertised in the slave's `Hello` at registration.
    pub have_version: u64,
    /// Signed-payload hash advertised in the slave's `Hello`, if the peer
    /// reported one (old v2 peers omit it).
    pub have_bundle_hash: Option<String>,
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
            bundle_hash_known: self.have_bundle_hash.is_some(),
            recent_acks: Vec::new(),
        }
    }
}
