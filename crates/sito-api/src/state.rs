//! Shared server context and Axum state extractors.

use crate::auth::manager::AuthManager;
use arc_swap::ArcSwap;
use sito_cache::DnsCache;
use sito_clients::ClientRegistry;
use sito_core::config::Config;
use sito_filter::HostsFilterEngine;
use sito_rewrites::RewriteTable;
use sito_stats::{MetricsRegistry, QueryLogSender, StatsDb};
use sito_upstream::UpstreamManager;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// Shared application state container across all REST API handlers.
#[derive(Clone)]
pub struct ServerContext {
    pub config: Arc<ArcSwap<Config>>,
    pub config_path: PathBuf,
    pub auth_mgr: Arc<AuthManager>,
    pub stats_db: StatsDb,
    pub querylog_sender: QueryLogSender,
    pub metrics: MetricsRegistry,
    pub filter: Arc<HostsFilterEngine>,
    pub cache: Arc<DnsCache>,
    pub upstream: Arc<UpstreamManager>,
    pub clients: Arc<ArcSwap<ClientRegistry>>,
    pub rewrites: Arc<ArcSwap<RewriteTable>>,
    pub start_time: Instant,
    /// Pending backup restorations awaiting confirmation token: token -> (toml_content, expires_at).
    pub restore_tokens: Arc<Mutex<HashMap<String, (String, Instant)>>>,
    pub master_coordinator: Option<sito_ha::MasterCoordinator>,
    pub slave_tracker: Option<sito_ha::SlaveStatusTracker>,
    pub resync_sender: Option<tokio::sync::mpsc::Sender<()>>,
}

impl ServerContext {
    /// Resolves the URL of the master node for redirect headers (`X-Dnsd-Master`).
    pub fn resolve_master_url(&self) -> String {
        if let Some(ref tracker) = self.slave_tracker {
            if let Some(ref url) = tracker.master_url {
                return url.clone();
            }
        }
        if let Some(ref ha_val) = self.config.load().ha {
            if let Ok(ha_cfg) = sito_ha::HaConfig::from_toml_value(ha_val) {
                if let Some(ref url) = ha_cfg.master_url {
                    return url.clone();
                }
            }
        }
        "wss://master.local:8953".to_string()
    }
}

// Axum FromRef implementations for modular extractors

impl axum::extract::FromRef<ServerContext> for Arc<AuthManager> {
    fn from_ref(input: &ServerContext) -> Self {
        input.auth_mgr.clone()
    }
}

impl axum::extract::FromRef<ServerContext> for StatsDb {
    fn from_ref(input: &ServerContext) -> Self {
        input.stats_db.clone()
    }
}

impl axum::extract::FromRef<ServerContext> for QueryLogSender {
    fn from_ref(input: &ServerContext) -> Self {
        input.querylog_sender.clone()
    }
}

impl axum::extract::FromRef<ServerContext> for MetricsRegistry {
    fn from_ref(input: &ServerContext) -> Self {
        input.metrics.clone()
    }
}
