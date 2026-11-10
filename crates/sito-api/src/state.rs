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
    /// Live ACME challenge-listener state when ACME is enabled; used by
    /// readiness reporting (D12 `acme_challenge_unavailable`).
    pub acme_challenges: Option<sito_transport::AcmeChallengeAvailability>,
    pub dns_starter: Option<UnboundedSender<()>>,
    /// Serializes every configuration apply/persist path (HA applier, file
    /// watcher, REST/UI handlers) so a slower older document cannot overwrite
    /// a newer one after the newer push already reached the runtime.
    pub apply_lock: Arc<tokio::sync::Mutex<()>>,
}

/// ACME readiness derived from the live challenge-listener state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcmeReadiness {
    /// ACME is enabled in the effective configuration.
    pub enabled: bool,
    /// A challenge path is available and the last issuance check succeeded.
    pub ready: bool,
    /// HTTP-01 listener bound.
    pub http01_available: bool,
    /// TCP 443 DoH listener bound with `acme-tls/1`.
    pub tls_alpn_available: bool,
    /// Stable reason code when not ready.
    pub reason: Option<&'static str>,
    /// Most recent issuance/renewal error, for the authenticated status view.
    pub last_error: Option<String>,
}

/// Computes ACME readiness from the live challenge state and configuration.
fn acme_readiness_for(
    challenges: Option<&sito_transport::AcmeChallengeAvailability>,
    config: &Config,
) -> AcmeReadiness {
    let enabled = config.get_acme_config().is_some_and(|acme| acme.enabled);
    if !enabled {
        return AcmeReadiness {
            enabled: false,
            ready: true,
            http01_available: false,
            tls_alpn_available: false,
            reason: None,
            last_error: None,
        };
    }
    let Some(challenges) = challenges else {
        return AcmeReadiness {
            enabled: true,
            ready: false,
            http01_available: false,
            tls_alpn_available: false,
            reason: Some("acme_challenge_unavailable"),
            last_error: None,
        };
    };
    let options = challenges.options();
    let last_error = challenges.last_error();
    let (ready, reason) = if challenges.challenge_unavailable() {
        (false, Some("acme_challenge_unavailable"))
    } else if last_error.is_some() {
        (false, Some("acme_issuance_failed"))
    } else {
        (true, None)
    };
    AcmeReadiness {
        enabled,
        ready,
        http01_available: options.http01_available,
        tls_alpn_available: options.tls_alpn_available,
        reason,
        last_error,
    }
}

/// Whether the configuration makes HA replication part of the node's role.
///
/// `/health` and the healthcheck use this to avoid gating non-HA deployments
/// while still failing closed for a master with a listener or a slave enrolled
/// in a cluster.
#[must_use]
pub fn ha_readiness_required(config: &Config) -> bool {
    sito_ha::HaConfig::readiness_required(&config.server.role, config.ha.as_ref())
}

impl ServerContext {
    /// Current HA readiness for the configured role.
    ///
    /// Returns ready when replication is not part of the deployment. When it
    /// is, a missing runtime or an unready listener/worker is reported with a
    /// reason instead of silently treating the node as healthy.
    #[must_use]
    pub fn ha_readiness(&self, config: &Config) -> sito_ha::HaReadiness {
        // A role with no `[ha]` section is simply not an HA deployment. A
        // master that *did* configure `[ha]` but explicitly disabled the
        // listener (`replication_port = 0`) still has a meaningful state: the
        // coordinator carries the "replication disabled" explanation and must
        // be surfaced instead of being discarded as a generic ready.
        if !ha_readiness_required(config) {
            if config.ha.is_some()
                && config.server.role == "master"
                && let Some(coordinator) = self.master_coordinator.as_ref()
            {
                return coordinator.readiness();
            }
            return sito_ha::HaReadiness::ready();
        }
        match config.server.role.as_str() {
            "master" => self.master_coordinator.as_ref().map_or_else(
                || {
                    sito_ha::HaReadiness::not_ready(
                        "master coordinator is not initialized; replication cannot run",
                    )
                },
                sito_ha::MasterCoordinator::readiness,
            ),
            "slave" => self.slave_tracker.as_ref().map_or_else(
                || {
                    sito_ha::HaReadiness::not_ready(
                        "slave tracker is not initialized; replication cannot run",
                    )
                },
                sito_ha::SlaveStatusTracker::readiness,
            ),
            _ => sito_ha::HaReadiness::ready(),
        }
    }

    /// Current ACME readiness.
    ///
    /// D12: when ACME is enabled but neither port 80 (HTTP-01) nor a TCP 443
    /// DoH listener (TLS-ALPN-01) is available, readiness is false with the
    /// stable reason `acme_challenge_unavailable`. A failed issuance is
    /// reported separately so an existing certificate can still serve traffic.
    #[must_use]
    pub fn acme_readiness(&self, config: &Config) -> AcmeReadiness {
        acme_readiness_for(self.acme_challenges.as_ref(), config)
    }

    /// Acquires the configuration apply/persist lock.
    ///
    /// Every writer must hold this guard from *before* it reads
    /// [`ServerContext::config`] until it has called a `*_locked` apply variant,
    /// so a concurrent writer cannot read an older snapshot and overwrite a
    /// newer one (lost update).
    pub async fn lock_config_apply(&self) -> tokio::sync::OwnedMutexGuard<()> {
        self.apply_lock.clone().lock_owned().await
    }

    /// Publishes a new configuration to the pipeline and UI atomically.
    ///
    /// Only for startup/restore paths that cannot use the runtime apply
    /// pipeline; admin write handlers must go through
    /// [`crate::config_apply::apply_and_persist_config`] or its `_locked`
    /// variant.
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
    ///
    /// Returns the observable publish outcome. Sanitization/read/persist
    /// failures are errors, never an empty bundle; an oversized envelope is
    /// `TooLarge` because it is a configuration error the caller must surface
    /// (and roll back). A failed publish is also recorded in HA readiness and
    /// a bounded background retry is scheduled.
    pub async fn publish_bundle(&self) -> Result<sito_ha::PublishOutcome, sito_ha::HaError> {
        self.publish_bundle_with_retry().await.0
    }

    /// Like [`Self::publish_bundle`], but also reports the delay before the
    /// first attempt of a newly scheduled background retry.
    ///
    /// `None` means no new retry loop was started (no HA coordinator, or one is
    /// already running with its own backoff schedule). Callers that expose a
    /// `retry_at` timestamp must omit it in that case instead of guessing.
    pub async fn publish_bundle_with_retry(
        &self,
    ) -> (
        Result<sito_ha::PublishOutcome, sito_ha::HaError>,
        Option<std::time::Duration>,
    ) {
        let result = self.publish_bundle_inner().await;
        let mut retry_delay = None;
        if let Err(e) = &result {
            // Some failures happen before the coordinator sees a bundle
            // (unreadable/empty/sanitize/secret/version errors). They must
            // still make HA readiness false, not only return an API error.
            if let Some(ref coordinator) = self.master_coordinator {
                coordinator.mark_publish_failed(e.to_string());
            }
            retry_delay = self.schedule_publish_retry();
        }
        (result, retry_delay)
    }

    async fn publish_bundle_inner(&self) -> Result<sito_ha::PublishOutcome, sito_ha::HaError> {
        use sito_ha::HaError;

        let Some(ref coordinator) = self.master_coordinator else {
            return Ok(sito_ha::PublishOutcome::NoSlaves);
        };

        let config = self.config.load();
        let raw_toml = match tokio::fs::read_to_string(&self.config_path).await {
            Ok(raw) => raw,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => toml::to_string_pretty(&**config)
                .map_err(|e| {
                    HaError::Serialization(format!(
                        "Failed to serialize the running configuration for HA publication: {e}"
                    ))
                })?,
            Err(e) => {
                return Err(HaError::Io(std::io::Error::new(
                    e.kind(),
                    format!(
                        "Failed to read '{}' for HA publication: {e}",
                        self.config_path.display()
                    ),
                )));
            }
        };
        let sanitized_toml = sito_ha::sanitize_config_for_bundle(&raw_toml)?;
        if sanitized_toml.trim().is_empty() {
            return Err(HaError::Validation {
                field: "config_toml".to_string(),
                reason: format!(
                    "Refusing to publish an empty HA bundle derived from '{}'; \
                     check the configuration before retrying",
                    self.config_path.display()
                ),
            });
        }
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
        if let Some(ref ha_val) = config.ha
            && let Ok(ha_cfg) = sito_ha::HaConfig::from_toml_value(ha_val)
            && let Some(ref token) = ha_cfg.slave_token
        {
            sito_ha::scan_for_secrets(&sanitized_toml, &[token.as_str()])?;
        }

        let new_version = coordinator
            .get_current_version()
            .checked_add(1)
            .ok_or_else(|| HaError::Validation {
                field: "version".to_string(),
                reason:
                    "Refusing to publish HA bundle: the configuration version sequence is exhausted"
                        .to_string(),
            })?;
        #[allow(clippy::cast_sign_loss)]
        let bundle = sito_ha::ConfigBundle {
            version: new_version,
            term: coordinator.get_current_term(),
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
            config_toml: sanitized_toml,
            custom_rules: config.filtering.custom_rules.clone(),
            rewrites: config.rewrites.clone(),
            clients: sanitize_clients_for_bundle(config.clients.as_ref()),
            lists: list_metadata,
        };

        match coordinator.publish_bundle_async(bundle).await {
            Ok(outcome) => {
                tracing::info!(
                    version = new_version,
                    outcome = ?outcome,
                    "Updated HA bundle"
                );
                Ok(outcome)
            }
            Err(e) => {
                tracing::error!(
                    version = new_version,
                    "Failed to update HA bundle and broadcast to slaves: {e}"
                );
                Err(e)
            }
        }
    }

    /// Schedules one bounded background retry loop with exponential backoff.
    ///
    /// The local configuration has already been persisted by the caller and
    /// must not be rolled back because of an HA failure (D8). The coordinator
    /// guard keeps a burst of failed API writes from spawning many loops.
    ///
    /// Returns the initial delay only when this call started a new loop;
    /// `None` means an existing loop owns the schedule (or HA is not active).
    fn schedule_publish_retry(&self) -> Option<std::time::Duration> {
        let coordinator = self.master_coordinator.as_ref()?;
        if !coordinator.begin_publish_retry() {
            return None;
        }
        let initial_delay = std::time::Duration::from_secs(1);
        let retry_ctx = self.clone();
        let retry_coordinator = coordinator.clone();
        tokio::spawn(async move {
            let mut delay = initial_delay;
            for attempt in 1..=5 {
                tokio::time::sleep(delay).await;
                match retry_ctx.publish_bundle().await {
                    Ok(outcome) => {
                        tracing::info!(
                            attempt,
                            outcome = ?outcome,
                            "HA publish retry completed"
                        );
                        break;
                    }
                    Err(e) => {
                        tracing::warn!(
                            attempt,
                            error = %e,
                            "HA publish retry failed; backing off"
                        );
                        delay = (delay * 2).min(std::time::Duration::from_secs(30));
                    }
                }
            }
            retry_coordinator.end_publish_retry();
        });
        Some(initial_delay)
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
pub async fn publish_bundle(
    ctx: &ServerContext,
) -> Result<sito_ha::PublishOutcome, sito_ha::HaError> {
    ctx.publish_bundle().await
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

    /// D12: an ACME deployment with neither a port 80 listener nor a TCP 443
    /// TLS-ALPN challenge path must report `acme_challenge_unavailable`.
    #[test]
    fn test_acme_readiness_no_80_no_443() {
        let mut config = Config::default();
        config.acme = Some(sito_core::config::AcmeConfig {
            enabled: true,
            email: Some("admin@example.com".to_string()),
            domains: vec!["dns.example.com".to_string()],
            ..Default::default()
        });

        // No challenge listener at all (fresh defaults are fail-safe false).
        let challenges = sito_transport::AcmeChallengeAvailability::new(false, false);
        let readiness = acme_readiness_for(Some(&challenges), &config);
        assert!(!readiness.ready);
        assert_eq!(readiness.reason, Some("acme_challenge_unavailable"));

        // Either bound listener makes ACME issuable.
        let http = sito_transport::AcmeChallengeAvailability::new(false, true);
        let readiness = acme_readiness_for(Some(&http), &config);
        assert!(
            readiness.ready,
            "HTTP-01 on port 80 is a usable path: {readiness:?}"
        );

        let tls_alpn = sito_transport::AcmeChallengeAvailability::new(true, false);
        let readiness = acme_readiness_for(Some(&tls_alpn), &config);
        assert!(
            readiness.ready,
            "TLS-ALPN-01 on 443 is a usable path: {readiness:?}"
        );

        // A failed issuance is surfaced separately but does not claim the
        // challenge path is missing.
        tls_alpn.record_error("order failed");
        let readiness = acme_readiness_for(Some(&tls_alpn), &config);
        assert!(!readiness.ready);
        assert_eq!(readiness.reason, Some("acme_issuance_failed"));
        assert_eq!(readiness.last_error.as_deref(), Some("order failed"));

        // Disabled ACME is always "ready" and produces no warning signal.
        config.acme.as_mut().unwrap().enabled = false;
        let readiness = acme_readiness_for(Some(&challenges), &config);
        assert!(readiness.ready);
        assert!(!readiness.enabled);
        assert_eq!(readiness.reason, None);
    }
}
