//! HA runtime construction and slave config application.

#[allow(clippy::wildcard_imports)]
use super::*;

/// Builds per-client upstream managers, reusing existing managers by key so a
/// hot reload does not re-resolve unchanged upstream scopes.
pub(super) async fn build_scoped_upstreams(
    config: &Config,
    clients: &sito_clients::ClientsConfig,
    existing: &HashMap<String, Arc<UpstreamManager>>,
) -> HashMap<String, Arc<UpstreamManager>> {
    // Build from the current config on every call. Capturing a startup resolver
    // here would leave scoped upstreams on old bootstrap/allow_private_targets
    // settings after a hot reload.
    let bootstrap = BootstrapResolver::from_config(&config.upstream);
    let mut scoped: HashMap<String, Arc<UpstreamManager>> = HashMap::new();
    for entry in &clients.entries {
        if entry.use_global_upstreams {
            continue;
        }
        let Some(ref servers) = entry.upstreams else {
            continue;
        };
        if servers.is_empty() {
            continue;
        }
        let key = scoped_upstream_key(config, servers);
        if scoped.contains_key(&key) {
            continue;
        }
        if let Some(manager) = existing.get(&key) {
            scoped.insert(key, manager.clone());
            continue;
        }
        let mut upstream_cfg = config.upstream.clone();
        upstream_cfg.servers.clone_from(servers);
        upstream_cfg.per_domain.clear();
        match UpstreamManager::from_config(&upstream_cfg, &bootstrap).await {
            Ok(manager) => {
                info!(
                    client = %entry.name,
                    servers = ?servers,
                    "Initialized per-client upstream scope"
                );
                scoped.insert(key, Arc::new(manager));
            }
            Err(e) => warn!(
                client = %entry.name,
                error = %e,
                "Failed to initialize per-client upstreams; this client falls back to global upstreams"
            ),
        }
    }
    scoped
}

/// Reuse key for a per-client upstream scope.
///
/// Includes every inherited `[upstream]` setting that affects manager
/// construction, not just the server list. Otherwise a reload that only changes
/// the bootstrap, timeout, strategy, pool size or `allow_private_targets` would
/// keep the stale manager (and its old SSRF policy) alive.
pub(super) fn scoped_upstream_key(config: &Config, servers: &[String]) -> String {
    let up = &config.upstream;
    format!(
        "{}|bootstrap={:?}|timeout_ms={}|strategy={:?}|pool_size={}|allow_private_targets={}",
        servers.join(","),
        up.bootstrap,
        up.timeout_ms,
        up.strategy,
        up.pool_size,
        up.allow_private_targets
    )
}

/// High-availability role setup produced by [`init_ha`].
pub(super) struct HaRuntime {
    pub(super) config: sito_ha::HaConfig,
    pub(super) coordinator: Option<sito_ha::MasterCoordinator>,
    pub(super) tracker: Option<sito_ha::SlaveStatusTracker>,
    pub(super) resync_sender: Option<tokio::sync::mpsc::Sender<()>>,
    /// Slave worker receiver, spawned only after [`ServerContext`] and the
    /// apply hooks exist so the worker can receive the shared
    /// [`HaConfigApplier`].
    pub(super) resync_receiver: Option<tokio::sync::mpsc::Receiver<()>>,
}

/// Initializes the HA role. Master setup is complete on return; a slave only
/// gets its tracker and resync channel here because its worker needs the
/// server context and apply hooks built later in startup.
pub(super) fn init_ha(
    config: &Config,
    config_path: &Path,
    metrics: &sito_stats::MetricsRegistry,
    shutdown_rx: &watch::Receiver<bool>,
) -> anyhow::Result<HaRuntime> {
    let ha_config: sito_ha::HaConfig = config
        .ha
        .as_ref()
        .map(sito_ha::HaConfig::from_toml_value)
        .transpose()
        .map_err(|e| anyhow::anyhow!("Invalid HA configuration: {e}"))?
        .unwrap_or_else(|| sito_ha::HaConfig {
            replication_port: 0,
            ..Default::default()
        });

    ha_config
        .validate(&config.server.role)
        .map_err(|e| anyhow::anyhow!("HA configuration validation failed: {e}"))?;

    let (master_coordinator, slave_tracker, resync_sender, resync_receiver) = if config.server.role
        == "master"
    {
        // The replication listener is only spawned when the port is non-zero;
        // record the no-op here so a production master with
        // `replication_port = 0` is observable. `spawn_master_server` no longer
        // increments this counter (it would double count when both run).
        if ha_config.replication_port == 0 {
            metrics.inc_ha_startup_noop("master", "replication_disabled");
            info!("Master HA replication is disabled (replication_port is 0)");
        }

        // Load or create master Ed25519 signing key (0600 on Unix)
        let signing_key_path = config.server.data_dir.join("ha_signing.key");
        let signing_key = Arc::new(sito_ha::Ed25519SigningKey::load_or_create(
            &signing_key_path,
        )?);

        let coordinator = sito_ha::MasterCoordinator::new(
            config.server.instance_name.clone(),
            0,
            signing_key.clone(),
            metrics.clone(),
        )
        .with_state_path(config.server.data_dir.join("ha_state.toml"));

        if ha_config.replication_port == 0 {
            coordinator.mark_replication_disabled();
        }

        // Continue the version sequence across restarts; only a master with no
        // recoverable state starts a fresh v1 sequence.
        let restored_version = coordinator.restore_state()?;

        let initial_toml = match std::fs::read_to_string(config_path) {
            Ok(raw) => raw,
            Err(_) => toml::to_string_pretty(config).map_err(|e| {
                anyhow::anyhow!(
                    "Failed to serialize the running configuration for the initial HA bundle: {e}"
                )
            })?,
        };
        let sanitized_toml = sito_ha::sanitize_config_for_bundle(&initial_toml).map_err(|e| {
            anyhow::anyhow!(
                "Failed to sanitize '{}' for the HA bundle: {e}",
                config_path.display()
            )
        })?;
        if sanitized_toml.trim().is_empty() {
            anyhow::bail!(
                "Refusing to publish an empty initial HA bundle derived from '{}'",
                config_path.display()
            );
        }
        if let Some(ref token) = ha_config.slave_token
            && let Err(e) = sito_ha::scan_for_secrets(&sanitized_toml, &[token.as_str()])
        {
            anyhow::bail!("Refusing to publish HA bundle with a leaked secret: {e}");
        }
        let list_metadata: Vec<sito_ha::FilterListMetadata> = config
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

        // Runs on every startup and on an explicit reconciliation: the bundle
        // is always built from the configuration currently on disk.
        let build_bundle = |version: u64| -> sito_ha::ConfigBundle {
            #[allow(clippy::cast_sign_loss)]
            sito_ha::ConfigBundle {
                version,
                term: coordinator.get_current_term(),
                timestamp: chrono::Utc::now().timestamp_millis() as u64,
                config_toml: sanitized_toml.clone(),
                custom_rules: config.filtering.custom_rules.clone(),
                rewrites: config.rewrites.clone(),
                clients: config.clients.clone(),
                lists: list_metadata.clone(),
            }
        };

        if let Some(restored_version) = restored_version {
            // A restart must never resume a bundle that no longer matches the
            // current `config.toml`: slaves would stay on the old shared
            // configuration indefinitely. Republish a fresh `N + 1` bundle
            // whenever the sanitized document differs (semantically, so a
            // formatting-only rewrite does not churn the sequence).
            let restored_bundle = coordinator
                .active_bundle
                .lock()
                .unwrap()
                .as_ref()
                .map(|bundle| bundle.config_toml.clone());
            let config_changed = restored_bundle
                .as_deref()
                .is_none_or(|restored| !sanitized_configs_equal(restored, &sanitized_toml));

            if config_changed {
                let next_version = restored_version.checked_add(1).ok_or_else(|| {
                    anyhow::anyhow!(
                        "Cannot reconcile the HA bundle: persisted version {restored_version} cannot advance"
                    )
                })?;
                coordinator.update_bundle(build_bundle(next_version))?;
                info!(
                    version = next_version,
                    previous_version = restored_version,
                    "Republished HA configuration bundle because config.toml changed since the persisted bundle"
                );
            } else {
                info!(
                    version = restored_version,
                    "Resumed HA configuration sequence from persisted state"
                );
            }
        } else {
            coordinator.update_bundle(build_bundle(1))?;
            info!("Published initial HA configuration bundle version 1");
        }

        // Spawn master replication listener if replication_port > 0
        let _master_server_handle = if ha_config.replication_port > 0 {
            Some(sito_ha::spawn_master_server(
                ha_config.clone(),
                coordinator.clone(),
                shutdown_rx.clone(),
            ))
        } else {
            None
        };

        (Some(coordinator), None, None, None)
    } else {
        // Slave role. The worker is spawned by `run_server_full` once the
        // server context and apply hooks exist, so a push can apply every
        // component before it is acknowledged.
        let tracker = sito_ha::SlaveStatusTracker::new(
            config.server.instance_name.clone(),
            0,
            ha_config.master_url.clone(),
        )
        .with_watermark_path(config.server.data_dir.join("ha_watermark.toml"))?;
        // A local edit/revert while the process was stopped must not let the
        // next identical push take the same-version early-ACK path. Compare the
        // on-disk document with the digest recorded when the bundle was applied.
        if let Ok(document) = std::fs::read_to_string(config_path) {
            tracker
                .verify_applied_config(&document)
                .map_err(|e| anyhow::anyhow!("Failed to verify applied HA configuration: {e}"))?;
            if tracker.requires_full_apply() {
                tracing::warn!(
                    path = %config_path.display(),
                    local_drift = tracker.has_local_config_drift(),
                    "Local HA configuration is unverified or drifted from the last applied bundle; a full apply is required before an early Synced ACK"
                );
            }
        }
        let (resync_tx, resync_rx) = tokio::sync::mpsc::channel(4);
        (None, Some(tracker), Some(resync_tx), Some(resync_rx))
    };

    Ok(HaRuntime {
        config: ha_config,
        coordinator: master_coordinator,
        tracker: slave_tracker,
        resync_sender,
        resync_receiver,
    })
}

/// Production [`sito_ha::SlaveConfigApplier`] backed by the shared
/// [`ServerContext`] and the hook-owned components.
///
/// This is the single apply/persist path for pushed HA configurations: the
/// slave worker calls it before advancing the applied-version watermark or
/// ACKing `applied: true`.
pub struct HaConfigApplier {
    pub(super) ctx: sito_api::ServerContext,
    pub(super) hooks: Arc<dyn sito_api::config_apply::ConfigApplyHooks>,
    /// Set only after `init_tls_and_acme` and `DnsListenerManager::start` have
    /// produced the listener generation and shared rate limiters. Before that,
    /// a push must not be acknowledged: applying it would silently skip the
    /// listener/rate-limit components.
    pub(super) listeners_ready: Arc<std::sync::atomic::AtomicBool>,
}

impl HaConfigApplier {
    #[must_use]
    pub fn new(
        ctx: sito_api::ServerContext,
        hooks: Arc<dyn sito_api::config_apply::ConfigApplyHooks>,
    ) -> Self {
        Self {
            ctx,
            hooks,
            listeners_ready: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    /// Opens the readiness gate after the DNS listeners and rate limiters exist.
    pub fn mark_listeners_ready(&self) {
        self.listeners_ready
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

impl sito_ha::SlaveConfigApplier for HaConfigApplier {
    fn apply_and_persist<'a>(
        &'a self,
        cfg: &'a Config,
        document: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + 'a>> {
        // Never acknowledge a push before the listener generation and shared
        // rate limiters exist: otherwise a listener/rate-limit change would be
        // silently skipped while the rest is applied and persisted.
        if !self
            .listeners_ready
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return Box::pin(async {
                Err("DNS listeners and rate limiters are not initialized yet".to_string())
            });
        }

        Box::pin(async move {
            // A restart-only field cannot take effect in this process. The HA
            // persist path rejects such a push *before* applying or persisting
            // anything: the worker then ACKs `applied: false`, and the live
            // configuration and the persisted file both keep the previous
            // state instead of claiming a change only a restart could honor.
            match sito_api::config_apply::apply_and_persist_document_rejecting_restart(
                &self.ctx,
                cfg,
                document,
                sito_api::config_apply::FilterApply::Sync,
                Some(&*self.hooks),
            )
            .await
            {
                Ok(report) => {
                    if !report.restart_required.is_empty() {
                        // The lock-held pre-check uses the same matrix, so this
                        // is a defensive backstop rather than a normal path.
                        warn!(
                            fields = ?report.restart_required,
                            "HA push applied but reported restart-only fields; the acknowledgement may be incomplete"
                        );
                    }
                    Ok(())
                }
                Err(e) => Err(e.detail),
            }
        })
    }
}
