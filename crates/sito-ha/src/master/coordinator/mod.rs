//! Master node replication coordinator.
//!
//! Shared state lives here; publishing/history, session handling, and listener
//! bootstrap are separate modules so protocol I/O cannot grow into the state
//! machine.

//! Master HA coordinator managing connected replica slaves and configuration push dissemination.

use chrono::Utc;
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, watch};
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tracing::{debug, error, info, warn};

use sito_stats::MetricsRegistry;

use crate::bundle::{ConfigBundle, build_and_sign_push};
use crate::config::HaConfig;
use crate::crypto::Ed25519SigningKey;
use crate::error::HaError;
use crate::master::tracker::{ActiveSlave, SlaveStatsSummary, SlaveSummary};
use crate::protocol::{AckConflict, HaMessage};
use crate::readiness::{HaReadiness, HaReadinessState};
use crate::transport::{MAX_WS_MESSAGE_SIZE, WS_SEND_TIMEOUT, build_server_tls_config, ws_config};

/// Maximum number of published envelopes kept for delayed ACK binding.
///
/// A slave may acknowledge a bundle after the master has published newer
/// ones, and multiple slaves may report a fork for the same envelope. The
/// history is coordinator-wide and pruned only by this bound, never by an
/// individual slave's ACK.
pub const MAX_PUBLISH_HISTORY: usize = 64;

/// Maximum bytes queued for one slave before the master falls back to
/// coalesced delivery.
///
/// The channel capacity alone bounds the number of queued pushes, not their
/// size: with 1 MiB bundles a slow peer could otherwise pin tens of MiB.
pub const MAX_SLAVE_QUEUE_BYTES: usize = MAX_WS_MESSAGE_SIZE * 4;

/// Maximum concurrently unauthenticated/active handshake slots per source IP.
const MAX_HANDSHAKES_PER_IP: usize = 8;

/// Identifies one slave session for queue accounting.
///
/// `instance` alone is not unique across reconnects: a superseded session can
/// still drain its channel after the replacement registered. Keying by the
/// connection id keeps the old session's bytes from being charged to (or
/// subtracted from) the new session.
type SessionKey = (String, u64);

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

/// A published envelope retained for delayed ACK binding.
///
/// Entries are shared by all slaves and pruned only in publish order by
/// [`MAX_PUBLISH_HISTORY`]; an individual ACK must not remove an entry because
/// another slave may still report a fork for the same envelope.
#[derive(Debug, Clone)]
struct PublishedEnvelope {
    term: u64,
    version: u64,
    payload_hash: String,
}

/// On-disk master state.
///
/// `ConfigBundle` is flattened so files written by 1.9.3 (a bare bundle JSON
/// document) still deserialize. New writes add the signing-key identity; an
/// older reader ignores the unknown top-level field.
#[derive(Debug, Serialize, Deserialize)]
struct PersistedMasterState {
    #[serde(flatten)]
    bundle: ConfigBundle,
    /// Hex Ed25519 public key that signed the persisted bundle/state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    signing_key_pubkey: Option<String>,
}

/// Maximum amount by which an authenticated peer may report being ahead of the
/// master's sequence before the report is treated as implausible (and therefore
/// hostile or corrupt) instead of as promotion evidence.
///
/// A single replica must never be able to freeze publishing by reporting a
/// gigantic version: values above this bound are rejected without touching the
/// master's counter or persisted state.
pub const MAX_PEER_VERSION_LEAD: u64 = 1_000_000;

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

/// Test-only hook invoked inside the blocking state writer before the file is
/// written. It receives the version of the bundle being persisted so a test can
/// observe and slow down individual writes without affecting production builds.
#[cfg(test)]
type StateWriteHook = Arc<dyn Fn(u64) + Send + Sync>;

/// Severity of a recorded divergence. Ordered so a fork outranks a term
/// mismatch, which outranks a same-term version gap; `mark_diverged` never
/// downgrades an existing higher-severity record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum DivergenceKind {
    /// Same term, peer reports a version above the master.
    Ahead,
    /// Peer reports a newer term (this master is stale).
    Term,
    /// Same term and version but a different signed payload (fork).
    Fork,
}

/// A divergence observed for one connected slave.
#[derive(Debug, Clone)]
struct Divergence {
    kind: DivergenceKind,
    acked_version: u64,
    acked_term: u64,
    reason: String,
}

/// Per-IP accounting for accepted HA connections.
///
/// The global connection semaphore bounds total slots, but a single source
/// could still consume all of them before authenticating. This budget makes
/// the unauthenticated handshake/session surface per-IP as well.
#[derive(Debug, Default)]
struct HandshakeBudget {
    active: Mutex<HashMap<IpAddr, usize>>,
}

impl HandshakeBudget {
    fn try_acquire(self: &Arc<Self>, ip: IpAddr) -> Option<HandshakePermit> {
        let mut active = sito_core::sync::lock_or_recover(&self.active);
        let count = active.entry(ip).or_insert(0);
        if *count >= MAX_HANDSHAKES_PER_IP {
            return None;
        }
        *count += 1;
        Some(HandshakePermit {
            budget: Arc::clone(self),
            ip,
        })
    }
}

struct HandshakePermit {
    budget: Arc<HandshakeBudget>,
    ip: IpAddr,
}

impl Drop for HandshakePermit {
    fn drop(&mut self) {
        let mut active = sito_core::sync::lock_or_recover(&self.budget.active);
        if let Some(count) = active.get_mut(&self.ip) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                active.remove(&self.ip);
            }
        }
    }
}

/// Master HA coordinator.
#[derive(Clone)]
pub struct MasterCoordinator {
    pub instance_name: String,
    pub signing_key: Arc<Ed25519SigningKey>,
    pub current_version: Arc<AtomicU64>,
    /// Cluster epoch/term. Bumped only by an explicit operator promotion
    /// (`with_term` or a restored `ha_state.toml`), never by peer input.
    pub current_term: Arc<AtomicU64>,
    pub active_bundle: Arc<Mutex<Option<ConfigBundle>>>,
    pub active_push: Arc<Mutex<Option<HaMessage>>>,
    pub slaves: Arc<Mutex<HashMap<String, ActiveSlave>>>,
    pub metrics: MetricsRegistry,
    pub slave_token: Option<String>,
    /// Heartbeat interval in seconds (watchdog removes slaves silent for 3× this).
    pub ping_interval_secs: u64,
    /// Path where the active version/bundle are persisted across restarts.
    state_path: Arc<Mutex<Option<PathBuf>>>,
    /// Slaves with an asynchronous fallback delivery already scheduled.
    pending_fallbacks: Arc<Mutex<HashSet<SessionKey>>>,
    /// Last stale version for which a catch-up push was already attempted per slave.
    stale_repushes: Arc<Mutex<HashMap<String, u64>>>,
    /// Serializes bundle publication so the version check and store cannot
    /// interleave and regress the active version.
    publish_lock: Arc<Mutex<()>>,
    /// Serializes asynchronous publication (including the state write) so two
    /// concurrent async publishers cannot complete their writes out of order.
    persist_lock: Arc<tokio::sync::Mutex<()>>,
    /// Monotonic id assigned to each accepted slave connection.
    next_connection_id: Arc<AtomicU64>,
    /// Test-only hook called by the asynchronous state writer.
    #[cfg(test)]
    state_write_hook: Arc<Mutex<Option<StateWriteHook>>>,
    /// Divergence records per currently connected slave. They are sticky: only
    /// that slave's applied ACK for the current term/version or a disconnect
    /// removes them, never an unrelated version advance or a global resync.
    diverged: Arc<Mutex<HashMap<String, Divergence>>>,
    /// Bounded, coordinator-wide history of published envelopes used to bind
    /// delayed ACKs (including forks reported by multiple slaves).
    active_push_history: Arc<Mutex<VecDeque<PublishedEnvelope>>>,
    /// Bytes currently queued per slave session.
    queued_bytes: Arc<Mutex<HashMap<SessionKey, usize>>>,
    /// Most recent publish failure, surfaced through HA readiness.
    last_publish_error: Arc<Mutex<Option<String>>>,
    /// True while a background publish retry is already scheduled.
    publish_retry_running: Arc<AtomicBool>,
    /// Whether the replication listener is actually serving. Updated by
    /// `spawn_master_server` and surfaced by `/ha/status` and `/health`.
    readiness: HaReadinessState,
}

mod message;
mod publish;
mod server;
mod session;
mod session_state;
mod state;

use server::send_master_message;
pub use server::spawn_master_server;
use session_state::{HeartbeatAction, HelloFields, SessionMachine};

#[cfg(test)]
mod tests;
