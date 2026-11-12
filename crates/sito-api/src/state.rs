//! Shared server context and Axum state extractors.

use crate::auth::manager::AuthManager;
use arc_swap::ArcSwap;
use sito_cache::DnsCache;
use sito_clients::ClientRegistry;
use sito_core::config::Config;
use sito_filter::HostsFilterEngine;
use sito_rewrites::RewriteTable;
use sito_stats::{MetricsRegistry, QueryLogSender, StatsDb};
use sito_transport::{AcmeServiceConfig, CertificateValidity, CertificateValidityCache};
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
    /// Server-owned readiness (listeners/TLS) published by the DNS startup
    /// path and read by `/health` and `/status`.
    pub readiness: Arc<crate::readiness::ReadinessState>,
    /// Mtime/size cache for certificate validity so the unauthenticated
    /// `/health` probe does not re-read and parse `cert.pem` on every request.
    pub cert_validity_cache: Arc<CertificateValidityCache>,
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
    cert_validity_cache: &CertificateValidityCache,
) -> AcmeReadiness {
    let acme_cfg = config.get_acme_config();
    let enabled = acme_cfg.as_ref().is_some_and(|acme| acme.enabled);
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
    let validity = acme_cfg
        .as_ref()
        .map_or(CertificateValidity::Missing, |acme| {
            acme_certificate_validity(config, acme, cert_validity_cache)
        });
    let (ready, reason) = acme_readiness_state(
        challenges.challenge_unavailable(),
        validity,
        last_error.is_some(),
    );
    AcmeReadiness {
        enabled,
        ready,
        http01_available: options.http01_available,
        tls_alpn_available: options.tls_alpn_available,
        reason,
        last_error,
    }
}

/// Returns the effective ACME certificate validity for readiness.
fn acme_certificate_validity(
    config: &Config,
    acme: &sito_core::config::AcmeConfig,
    cert_validity_cache: &CertificateValidityCache,
) -> CertificateValidity {
    let storage_dir = acme
        .cache_dir
        .clone()
        .unwrap_or_else(|| config.server.data_dir.join("acme"));
    let service = AcmeServiceConfig::new(
        acme.email
            .clone()
            .unwrap_or_else(|| "admin@example.com".to_string()),
        acme.domains.clone(),
        storage_dir,
    );
    cert_validity_cache.acme_validity(&service)
}

/// Maps a certificate validity to TLS component readiness (D12).
///
/// A valid certificate is ready, one expiring inside the warning window is
/// degraded (still serving), and an expired/unparseable certificate is
/// not-ready.
#[must_use]
pub fn tls_certificate_readiness(
    validity: CertificateValidity,
) -> crate::readiness::ComponentReadiness {
    match validity {
        CertificateValidity::Expired => crate::readiness::ComponentReadiness::unavailable(
            "tls_cert_expired",
            "configured static TLS certificate is expired; encrypted listeners cannot serve",
        ),
        CertificateValidity::Expiring { days_remaining } => {
            crate::readiness::ComponentReadiness::degraded(
                "tls_cert_expiring",
                format!("configured static TLS certificate expires in {days_remaining} day(s)"),
            )
        }
        CertificateValidity::Valid { .. }
        | CertificateValidity::Missing
        | CertificateValidity::Bootstrap => crate::readiness::ComponentReadiness::ready(),
    }
}

/// Whether an enabled ACME deployment has a usable current certificate that
/// takes precedence over the static pair (D12 ACME + static matrix).
fn acme_has_serving_certificate(
    config: &Config,
    cert_validity_cache: &CertificateValidityCache,
) -> bool {
    config.get_acme_config().is_some_and(|acme| {
        acme.enabled
            && matches!(
                acme_certificate_validity(config, &acme, cert_validity_cache),
                CertificateValidity::Valid { .. } | CertificateValidity::Expiring { .. }
            )
    })
}

/// Re-evaluates the configured static certificate's validity after startup.
///
/// D12 requires an expired static certificate to make `/health` not-ready even
/// when the process started with a valid one, and a hot-reloaded replacement to
/// clear the previous `tls_cert_expired`/`tls_cert_expiring` reason. Startup and
/// the certificate watcher call this directly; readiness aggregation also calls
/// it so a process that simply runs past expiry is observed on the next probe.
/// The mtime/size cache keeps the unauthenticated `/health` path cheap.
pub fn refresh_tls_certificate_readiness(
    readiness: &crate::readiness::ReadinessState,
    config: &Config,
    cert_validity_cache: &CertificateValidityCache,
) {
    let Some(tls) = config.get_tls_config() else {
        return;
    };
    let Some(cert) = tls.cert.as_deref() else {
        return;
    };
    if tls.key.is_none() {
        return;
    }

    // Never overwrite a startup/acceptor failure with a certificate verdict.
    // Only a previous certificate reason (or no reason at all) may be revised.
    if let Some(code) = readiness.tls().code
        && code != "tls_cert_expired"
        && code != "tls_cert_expiring"
    {
        return;
    }

    if acme_has_serving_certificate(config, cert_validity_cache) {
        readiness.set_tls_ready();
        return;
    }

    let state = tls_certificate_readiness(cert_validity_cache.validity(cert));
    if !state.ready {
        readiness.set_tls_unavailable(
            state.code.unwrap_or("tls_cert_expired"),
            state
                .message
                .unwrap_or_else(|| "static TLS certificate is expired".to_string()),
        );
    } else if state.code.is_some() {
        readiness.set_tls_degraded(
            state.code.unwrap_or("tls_cert_expiring"),
            state
                .message
                .unwrap_or_else(|| "static TLS certificate is expiring".to_string()),
        );
    } else {
        readiness.set_tls_ready();
    }
}

/// D12 readiness ladder for a challenge path and certificate lifetime.
///
/// A valid certificate keeps serving while renewal retries (degraded, not
/// blocking); an expiring certificate is also degraded; an expired certificate
/// or a missing challenge path is not-ready. A first boot with no certificate
/// yet and no error is issuance-pending (advisory): DNS listeners still bind.
fn acme_readiness_state(
    challenge_unavailable: bool,
    validity: CertificateValidity,
    renewal_error: bool,
) -> (bool, Option<&'static str>) {
    if challenge_unavailable {
        return (false, Some("acme_challenge_unavailable"));
    }
    match validity {
        CertificateValidity::Missing => {
            if renewal_error {
                (false, Some("acme_issuance_failed"))
            } else {
                (true, Some("acme_issuance_pending"))
            }
        }
        CertificateValidity::Bootstrap => (true, Some("acme_bootstrap_cert")),
        CertificateValidity::Expired => (false, Some("acme_cert_expired")),
        CertificateValidity::Expiring { .. } => (
            true,
            Some(if renewal_error {
                "acme_renewal_failed"
            } else {
                "acme_cert_expiring"
            }),
        ),
        CertificateValidity::Valid { .. } => {
            if renewal_error {
                (true, Some("acme_renewal_failed"))
            } else {
                (true, None)
            }
        }
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
        acme_readiness_for(
            self.acme_challenges.as_ref(),
            config,
            &self.cert_validity_cache,
        )
    }

    /// Blocking-only readiness used by the unauthenticated `/health` probe.
    ///
    /// The advisory stats database probe is deliberately excluded: `/health`
    /// only renders the status word, so running a `SELECT 1` there would add
    /// unauthenticated storage I/O without changing the response. `/status` and
    /// the UI use [`Self::readiness_report`], which includes the probe.
    #[must_use]
    pub fn health_report(&self) -> crate::readiness::ReadinessReport {
        self.build_readiness_report(None)
    }

    /// Aggregated readiness used by `/status` and the UI.
    ///
    /// Blocking components are listeners, TLS, ACME, HA and a filter engine
    /// with no usable snapshot. A retained/partial filter snapshot, an expiring
    /// certificate and a stats database/writer outage are advisory reasons
    /// only: resolution still works, so they are surfaced in `/status` without
    /// failing `/health` (P2-89/D8/D12 policy).
    pub async fn readiness_report(&self) -> crate::readiness::ReadinessReport {
        let stats = self.stats_readiness_message().await;
        self.build_readiness_report(stats.as_deref())
    }

    fn build_readiness_report(&self, stats: Option<&str>) -> crate::readiness::ReadinessReport {
        let config = self.config.load();
        // A process can outlive its static certificate. Re-evaluate it on every
        // readiness build (cached by mtime/size) so `/health` flips to not-ready
        // at expiry and recovers after a watcher reload, without a rebind or
        // restart. Startup/acceptor failures are preserved by the guard inside.
        refresh_tls_certificate_readiness(&self.readiness, &config, &self.cert_validity_cache);
        let acme = self.acme_readiness(&config);
        let ha = self.ha_readiness(&config);
        let filter = self.filter.status();

        crate::readiness::ReadinessReport::from_parts(crate::readiness::ReadinessInputs {
            listeners: self.readiness.listeners(),
            tls: self.readiness.tls(),
            acme: &acme,
            ha: &ha,
            filter: &filter,
            stats,
        })
    }

    /// Probes the stats database/writer for `/status`.
    ///
    /// The probe is bounded so a locked SQLite pool cannot stall an admin
    /// request or the container healthcheck. A failure is advisory: it is
    /// reported as a readiness reason but does not make the DNS service
    /// not-ready.
    async fn stats_readiness_message(&self) -> Option<String> {
        if self.stats_db.is_closed() || self.querylog_sender.is_closed() {
            return Some("stats database or query-log writer is closed".to_string());
        }
        let probe = tokio::time::timeout(
            std::time::Duration::from_millis(750),
            self.stats_db.health_check(),
        )
        .await;
        match probe {
            Ok(Ok(())) => None,
            Ok(Err(e)) => {
                tracing::warn!(error = %e, "Stats readiness probe failed");
                Some("stats database probe failed".to_string())
            }
            Err(_) => {
                tracing::warn!("Stats readiness probe timed out");
                Some("stats database probe timed out".to_string())
            }
        }
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

    /// Publishes a mirror config handle for startup/test helpers.
    ///
    /// This is not an apply: it does not advance the runtime generation, does
    /// not update the DNSSEC validator/cache epoch, and does not publish the
    /// filter. Admin writes, the watcher, restore and HA must go through
    /// [`crate::config_apply::apply_and_persist_config`] or its `_locked`
    /// variant. Retained for test/bootstrap code only.
    pub fn set_config(&self, config: Config) {
        self.runtime.set_config(config);
    }

    /// Publishes a mirror client-registry handle for startup/test helpers.
    ///
    /// Not an apply; production client changes go through the config apply
    /// pipeline so the registry and the published config generation agree.
    pub fn set_clients(&self, clients: ClientRegistry) {
        self.runtime.set_clients(clients);
    }

    /// Publishes a mirror rewrite-table handle for startup/test helpers.
    ///
    /// Not an apply; production rewrite changes go through the config apply
    /// pipeline.
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
    use std::time::Duration;

    /// Deferred D4b review: `publish_bundle_with_retry` must report the delay
    /// only for a newly started retry loop. A second failure while that loop is
    /// still active returns `None`, so the REST `retry_at` is omitted instead
    /// of advertising a duplicate schedule.
    #[tokio::test]
    async fn test_publish_bundle_with_retry_reports_only_new_loop_delay() {
        let temp_dir = crate::test_support::temp_dir("sito_ha_retry_report");
        let mut ctx = crate::test_support::mock_context(&temp_dir).await;
        ctx.master_coordinator = Some(sito_ha::MasterCoordinator::new(
            "retry-report-test".to_string(),
            0,
            Arc::new(
                sito_ha::Ed25519SigningKey::generate().expect("test signing key must generate"),
            ),
            ctx.metrics.clone(),
        ));
        // Force a deterministic pre-coordinator publish failure: reading the
        // configured path as a file fails when it is a directory.
        std::fs::create_dir_all(&ctx.config_path).expect("create directory at config path");

        let (first, first_delay) = ctx.publish_bundle_with_retry().await;
        assert!(first.is_err(), "the first publish must fail");
        assert_eq!(
            first_delay,
            Some(Duration::from_secs(1)),
            "the call that starts the retry loop reports its initial delay"
        );
        let first_report =
            crate::config_apply::HaPublishReport::failed_with_retry("publish failed", first_delay);
        assert!(
            first_report.retry_at.is_some(),
            "REST retry_at must be present for the newly scheduled loop"
        );

        let (second, second_delay) = ctx.publish_bundle_with_retry().await;
        assert!(second.is_err(), "the second publish must fail too");
        assert_eq!(
            second_delay, None,
            "an already-running retry loop must not report a second schedule"
        );
        let second_report =
            crate::config_apply::HaPublishReport::failed_with_retry("publish failed", second_delay);
        assert!(
            second_report.retry_at.is_none(),
            "REST retry_at must be omitted while the existing loop owns the schedule"
        );

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

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
        let readiness =
            acme_readiness_for(Some(&challenges), &config, &CertificateValidityCache::new());
        assert!(!readiness.ready);
        assert_eq!(readiness.reason, Some("acme_challenge_unavailable"));

        // Either bound listener makes ACME issuable.
        let http = sito_transport::AcmeChallengeAvailability::new(false, true);
        let readiness = acme_readiness_for(Some(&http), &config, &CertificateValidityCache::new());
        assert!(
            readiness.ready,
            "HTTP-01 on port 80 is a usable path: {readiness:?}"
        );

        let tls_alpn = sito_transport::AcmeChallengeAvailability::new(true, false);
        let readiness =
            acme_readiness_for(Some(&tls_alpn), &config, &CertificateValidityCache::new());
        assert!(
            readiness.ready,
            "TLS-ALPN-01 on 443 is a usable path: {readiness:?}"
        );

        // A failed issuance is surfaced separately but does not claim the
        // challenge path is missing.
        tls_alpn.record_error("order failed");
        let readiness =
            acme_readiness_for(Some(&tls_alpn), &config, &CertificateValidityCache::new());
        assert!(!readiness.ready);
        assert_eq!(readiness.reason, Some("acme_issuance_failed"));
        assert_eq!(readiness.last_error.as_deref(), Some("order failed"));

        // Disabled ACME is always "ready" and produces no warning signal.
        config.acme.as_mut().unwrap().enabled = false;
        let readiness =
            acme_readiness_for(Some(&challenges), &config, &CertificateValidityCache::new());
        assert!(readiness.ready);
        assert!(!readiness.enabled);
        assert_eq!(readiness.reason, None);
    }
}

#[cfg(test)]
mod readiness_tests {
    /// `/health` must not run the advisory stats `SELECT 1`; the authenticated
    /// `/status` report keeps it.
    #[tokio::test]
    async fn test_health_report_skips_the_stats_probe() {
        let dir = crate::test_support::temp_dir("sito_health_stats_split");
        let ctx = crate::test_support::mock_context(&dir).await;
        ctx.stats_db.pool().close().await;

        let health = ctx.health_report();
        assert!(health.ready);
        assert!(
            health
                .reasons
                .iter()
                .all(|reason| reason.component != "stats"),
            "/health must not spend an advisory stats probe: {:?}",
            health.reasons
        );

        let status = ctx.readiness_report().await;
        assert!(
            status
                .reasons
                .iter()
                .any(|reason| reason.component == "stats" && reason.code == "stats_unavailable"),
            "/status must still report the stats outage: {:?}",
            status.reasons
        );
        assert!(status.ready, "a stats outage stays advisory");

        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod acme_readiness_ladder_tests {
    use super::*;

    #[test]
    fn test_valid_certificate_is_ready() {
        assert_eq!(
            acme_readiness_state(
                false,
                CertificateValidity::Valid { days_remaining: 90 },
                false
            ),
            (true, None)
        );
    }

    #[test]
    fn test_valid_certificate_with_renewal_error_is_degraded() {
        assert_eq!(
            acme_readiness_state(
                false,
                CertificateValidity::Valid { days_remaining: 90 },
                true
            ),
            (true, Some("acme_renewal_failed"))
        );
    }

    #[test]
    fn test_expiring_certificate_is_degraded() {
        assert_eq!(
            acme_readiness_state(
                false,
                CertificateValidity::Expiring { days_remaining: 10 },
                false
            ),
            (true, Some("acme_cert_expiring"))
        );
        assert_eq!(
            acme_readiness_state(
                false,
                CertificateValidity::Expiring { days_remaining: 10 },
                true
            ),
            (true, Some("acme_renewal_failed"))
        );
    }

    #[test]
    fn test_expired_certificate_is_not_ready() {
        assert_eq!(
            acme_readiness_state(false, CertificateValidity::Expired, true),
            (false, Some("acme_cert_expired"))
        );
    }

    #[test]
    fn test_missing_certificate_is_pending_or_failed() {
        assert_eq!(
            acme_readiness_state(false, CertificateValidity::Missing, false),
            (true, Some("acme_issuance_pending"))
        );
        assert_eq!(
            acme_readiness_state(false, CertificateValidity::Missing, true),
            (false, Some("acme_issuance_failed"))
        );
    }

    #[test]
    fn test_bootstrap_certificate_is_advisory() {
        assert_eq!(
            acme_readiness_state(false, CertificateValidity::Bootstrap, false),
            (true, Some("acme_bootstrap_cert"))
        );
    }

    #[test]
    fn test_challenge_unavailable_is_not_ready_regardless_of_certificate() {
        assert_eq!(
            acme_readiness_state(
                true,
                CertificateValidity::Valid { days_remaining: 90 },
                false
            ),
            (false, Some("acme_challenge_unavailable"))
        );
    }
}
