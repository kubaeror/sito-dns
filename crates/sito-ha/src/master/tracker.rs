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
    pub last_ping_secs_ago: u64,
    pub connected_at: String,
    pub last_stats: Option<SlaveStatsSummary>,
}

/// Aggregated stats snapshot reported by a slave node.
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
}

impl ActiveSlave {
    pub fn to_summary(&self, current_version: u64) -> SlaveSummary {
        let lag = current_version.saturating_sub(self.synced_version);
        SlaveSummary {
            instance: self.instance.clone(),
            remote_addr: self.remote_addr.to_string(),
            synced_version: self.synced_version,
            lag,
            last_ping_secs_ago: self.last_ping.elapsed().as_secs(),
            connected_at: self.connected_at.to_rfc3339(),
            last_stats: self.last_stats.clone(),
        }
    }
}
