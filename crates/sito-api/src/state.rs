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
        if let Some(ref tracker) = self.slave_tracker
            && let Some(ref url) = tracker.master_url
        {
            return url.clone();
        }
        if let Some(ref ha_val) = self.config.load().ha
            && let Ok(ha_cfg) = sito_ha::HaConfig::from_toml_value(ha_val)
            && let Some(ref url) = ha_cfg.master_url
        {
            return url.clone();
        }
        "wss://master.local:8953".to_string()
    }

    /// Publishes an updated HA configuration bundle to all connected replica slaves,
    /// incrementing the configuration version monotonic counter.
    pub fn publish_bundle(&self) {
        let Some(ref coordinator) = self.master_coordinator else {
            return;
        };

        let config = self.config.load();
        let raw_toml = std::fs::read_to_string(&self.config_path)
            .unwrap_or_else(|_| toml::to_string_pretty(&**config).unwrap_or_default());
        let sanitized_toml = sito_ha::sanitize_config_for_bundle(&raw_toml).unwrap_or_default();
        let list_metadata = config
            .filtering
            .lists
            .iter()
            .map(|l| sito_ha::FilterListMetadata {
                name: l.name.clone(),
                url: l.url.clone(),
                enabled: l.enabled,
                refresh_hours: l.refresh_hours,
            })
            .collect();

        let new_version = coordinator.get_current_version().saturating_add(1);
        #[allow(clippy::cast_sign_loss)]
        let bundle = sito_ha::ConfigBundle {
            version: new_version,
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
            config_toml: sanitized_toml,
            custom_rules: config.filtering.custom_rules.clone(),
            rewrites: config.rewrites.clone(),
            clients: config.clients.clone(),
            lists: list_metadata,
        };

        if let Err(e) = coordinator.update_bundle(bundle) {
            tracing::error!(
                version = new_version,
                "Failed to update HA bundle and broadcast to slaves: {e}"
            );
        } else {
            tracing::info!(
                version = new_version,
                "Updated HA bundle and broadcasted to slaves"
            );
        }
    }
}

/// Helper function to publish an updated configuration bundle to replica slaves.
pub fn publish_bundle(ctx: &ServerContext) {
    ctx.publish_bundle();
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
