//! Application state management per section 3.3.

use crate::config::Config;
use arc_swap::ArcSwap;
use std::sync::Arc;

/// Root runtime state container for the sito server.
/// Holds atomic snapshots for lock-free reader access on the hot query path.
pub struct AppState {
    pub config: ArcSwap<Config>,
}

impl AppState {
    /// Create a new application state from an initial configuration.
    pub fn new(config: Config) -> Self {
        Self {
            config: ArcSwap::from_pointee(config),
        }
    }

    /// Load the current configuration snapshot.
    pub fn load_config(&self) -> Arc<Config> {
        self.config.load_full()
    }

    /// Atomically swap the configuration snapshot.
    pub fn store_config(&self, new_config: Arc<Config>) {
        self.config.store(new_config);
    }
}
