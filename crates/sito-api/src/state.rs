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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::sync::mpsc::UnboundedSender;

/// Shared application state container across all REST API handlers.
#[derive(Clone)]
pub struct ServerContext {
    pub config: Arc<ArcSwap<Config>>,
    /// Atomic view over config, clients and rewrites for the DNS pipeline.
    pub runtime: Arc<sito_runtime::RuntimeState>,
    /// Hot-swappable parental/service registries and their refresh status.
    pub runtime_lists: Arc<sito_clients::RuntimeLists>,
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
    pub setup_pending: Arc<AtomicBool>,
    pub dns_starter: Option<UnboundedSender<()>>,
    /// Serializes every configuration apply/persist path (HA applier, file
    /// watcher, REST/UI handlers) so a slower older document cannot overwrite
    /// a newer one after the newer push already reached the runtime.
    pub apply_lock: Arc<tokio::sync::Mutex<()>>,
}

impl ServerContext {
    /// Publishes a new configuration to the pipeline and UI atomically.
    pub fn set_config(&self, config: Config) {
        self.runtime.set_config(config);
    }

    /// Publishes a new client registry to the pipeline and UI atomically.
    pub fn set_clients(&self, clients: ClientRegistry) {
        self.runtime.set_clients(clients);
    }

    /// Publishes a new rewrite table to the pipeline and UI atomically.
    pub fn set_rewrites(&self, rewrites: RewriteTable) {
        self.runtime.set_rewrites(rewrites);
    }

    /// Returns whether the server is running in setup-pending bootstrap mode.
    pub fn is_setup_pending(&self) -> bool {
        self.setup_pending.load(Ordering::SeqCst)
    }

    /// Updates the setup-pending state.
    pub fn set_setup_pending(&self, pending: bool) {
        self.setup_pending.store(pending, Ordering::SeqCst);
    }

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
        // No configured master URL: return empty and let callers omit the
        // header rather than pointing clients at a placeholder host.
        String::new()
    }

    /// Publishes an updated HA configuration bundle to all connected replica slaves,
    /// incrementing the configuration version monotonic counter.
    pub async fn publish_bundle(&self) {
        let Some(ref coordinator) = self.master_coordinator else {
            return;
        };

        let config = self.config.load();
        let raw_toml = match tokio::fs::read_to_string(&self.config_path).await {
            Ok(raw) => raw,
            Err(_) => toml::to_string_pretty(&**config).unwrap_or_default(),
        };
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

        // Defense in depth: refuse to broadcast a bundle that embeds a known
        // secret in plaintext.
        if let Some(ref ha_val) = self.config.load().ha
            && let Ok(ha_cfg) = sito_ha::HaConfig::from_toml_value(ha_val)
            && let Some(ref token) = ha_cfg.slave_token
            && let Err(e) = sito_ha::scan_for_secrets(&sanitized_toml, &[token.as_str()])
        {
            tracing::error!("Refusing to publish HA bundle: {e}");
            return;
        }

        let new_version = coordinator.get_current_version().saturating_add(1);
        #[allow(clippy::cast_sign_loss)]
        let bundle = sito_ha::ConfigBundle {
            version: new_version,
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
            config_toml: sanitized_toml,
            custom_rules: config.filtering.custom_rules.clone(),
            rewrites: config.rewrites.clone(),
            clients: sanitize_clients_for_bundle(config.clients.as_ref()),
            lists: list_metadata,
        };

        if let Err(e) = coordinator.update_bundle_async(bundle).await {
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

/// Strips `client_id_secrets` from the structured `[clients]` value before it
/// is replicated. The raw `config_toml` is sanitized by the HA crate; the
/// structured field must be sanitized here for the same reason.
#[must_use]
pub fn sanitize_clients_for_bundle(clients: Option<&toml::Value>) -> Option<toml::Value> {
    let mut table = clients?.as_table()?.clone();
    table.remove("client_id_secrets");
    Some(toml::Value::Table(table))
}

/// Helper function to publish an updated configuration bundle to replica slaves.
pub async fn publish_bundle(ctx: &ServerContext) {
    ctx.publish_bundle().await;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_clients_for_bundle_strips_shared_secrets() {
        let clients: toml::Value = toml::from_str(
            r#"
            [client_id_secrets]
            "phone" = "super-secret"
            [[entries]]
            name = "phone"
            ids = ["10.0.0.5"]
            "#,
        )
        .unwrap();

        let sanitized = sanitize_clients_for_bundle(Some(&clients)).expect("table");
        assert!(
            sanitized.get("client_id_secrets").is_none(),
            "structured HA clients must not carry shared secrets: {sanitized}"
        );
        assert!(
            sanitized.get("entries").is_some(),
            "non-secret client fields must survive"
        );
        assert!(!sanitized.to_string().contains("super-secret"));

        assert!(sanitize_clients_for_bundle(None).is_none());
    }
}
