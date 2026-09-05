//! High Availability slave state machine representation.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

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

/// Shared runtime state of the slave HA controller.
#[derive(Debug, Clone)]
pub struct SlaveStatusTracker {
    pub instance_name: String,
    pub current_version: Arc<AtomicU64>,
    pub state: Arc<Mutex<SlaveState>>,
    pub degraded_reason: Arc<Mutex<Option<String>>>,
    pub last_synced_at: Arc<Mutex<Option<DateTime<Utc>>>>,
    pub master_url: Option<String>,
    pub local_secrets: Arc<Mutex<HashMap<String, String>>>,
}

impl SlaveStatusTracker {
    pub fn new(instance_name: String, initial_version: u64, master_url: Option<String>) -> Self {
        Self {
            instance_name,
            current_version: Arc::new(AtomicU64::new(initial_version)),
            state: Arc::new(Mutex::new(SlaveState::Connecting)),
            degraded_reason: Arc::new(Mutex::new(None)),
            last_synced_at: Arc::new(Mutex::new(None)),
            master_url,
            local_secrets: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn get_state(&self) -> SlaveState {
        *self.state.lock().unwrap()
    }

    pub fn set_state(&self, new_state: SlaveState) {
        *self.state.lock().unwrap() = new_state;
    }

    pub fn get_version(&self) -> u64 {
        self.current_version.load(Ordering::SeqCst)
    }

    pub fn set_version(&self, version: u64) {
        self.current_version.store(version, Ordering::SeqCst);
    }

    pub fn mark_synced(&self, version: u64) {
        self.set_version(version);
        *self.state.lock().unwrap() = SlaveState::Synced;
        *self.degraded_reason.lock().unwrap() = None;
        *self.last_synced_at.lock().unwrap() = Some(Utc::now());
    }

    pub fn mark_degraded(&self, reason: String) {
        *self.state.lock().unwrap() = SlaveState::Degraded;
        *self.degraded_reason.lock().unwrap() = Some(reason);
    }

    pub fn register_secret(&self, name: String, value: String) {
        self.local_secrets.lock().unwrap().insert(name, value);
    }
}
