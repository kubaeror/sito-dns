//! HA runtime construction and slave config application.

#[allow(clippy::wildcard_imports)]
use super::*;

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
    /// ADR-0010 write gate shared with the API middleware.
    pub(super) write_gate: Arc<sito_api::state::HaWriteGate>,
    /// Per-slave worker shutdown so a promotion can stop the slave role.
    pub(super) slave_shutdown: Option<tokio::sync::watch::Sender<bool>>,
    /// Promotion runtime state (enabled only).
    pub(super) promotion: Option<Arc<PromotionRuntimeState>>,
    /// Coordinator created by an in-memory slave→master promotion, shared with
    /// `ServerContext` so normal API/watcher publishes are not dropped.
    pub(super) promoted_master: Arc<Mutex<Option<sito_ha::MasterCoordinator>>>,
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
    let ha_config = sito_ha::config_from_unvalidated(config)
        .map_err(|e| anyhow::anyhow!("Invalid HA configuration: {e}"))?;
    ha_config
        .validate(&config.server.role)
        .map_err(|e| anyhow::anyhow!("HA configuration validation failed: {e}"))?;

    let write_gate = Arc::new(sito_api::state::HaWriteGate::new());
    let promoted_master = Arc::new(Mutex::new(None));
    if ha_config.promotion.enabled {
        write_gate.block("ha_promotion_starting");
    }

    // ADR-0010: with promotion disabled the entire section is inert. A
    // disabled `candidate = true` remains accepted for upgrade compatibility,
    // but it must not silently look like an active candidate.
    if !ha_config.promotion.enabled && ha_config.promotion.candidate {
        tracing::warn!(
            "ha.promotion.candidate = true is ignored because ha.promotion.enabled = false; set enabled = true on every HA node to use automatic promotion"
        );
    }

    let promotion_enabled = ha_config.promotion.enabled;
    let (master_coordinator, slave_tracker, resync_sender, resync_receiver, promotion) = if config
        .server
        .role
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
        .with_state_path(config.server.data_dir.join("ha_state.toml"))
        .with_slave_requirements(ha_config.require_slaves, ha_config.require_all_slaves);

        if ha_config.replication_port == 0 {
            coordinator.mark_replication_disabled();
        }

        // Continue the version sequence across restarts in the normal path.
        // With promotion enabled the engine reads the state file strictly and
        // must not mutate anything before it holds the lease, so the
        // coordinator is not restored/written here.
        let restored_version = if promotion_enabled {
            None
        } else {
            coordinator.restore_state()?
        };

        let initial_toml = match std::fs::read_to_string(config_path) {
            Ok(raw) => raw,
            Err(_) => toml::to_string_pretty(config).map_err(|e| {
                anyhow::anyhow!(
                    "Failed to serialize the running configuration for the initial HA bundle: {e}"
                )
            })?,
        };
        let known_secrets: Vec<&str> = ha_config.slave_token.as_deref().into_iter().collect();

        // Runs on every startup and on an explicit reconciliation: the bundle
        // is always built from the configuration currently on disk.
        let build_bundle = |version: u64| -> anyhow::Result<sito_ha::ConfigBundle> {
            sito_ha::build_config_bundle(
                config,
                &initial_toml,
                version,
                coordinator.get_current_term(),
                &known_secrets,
            )
            .map_err(|e| {
                anyhow::anyhow!(
                    "Failed to build the HA bundle from '{}': {e}",
                    config_path.display()
                )
            })
        };

        if promotion_enabled {
            // The promotion supervisor acquires the lease, quiesces,
            // reconciles and publishes the first bundle. Nothing may mutate or
            // publish before that point.
            info!(
                "Automatic promotion is enabled; master starts read-only until the lease is acquired"
            );
        } else if let Some(restored_version) = restored_version {
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
            // Build once with the restored version: its sanitized document is
            // what the comparison consumes.
            let comparison_bundle = build_bundle(restored_version)?;
            let config_changed = restored_bundle.as_deref().is_none_or(|restored| {
                !sito_ha::sanitized_configs_equal(restored, &comparison_bundle.config_toml)
            });

            if config_changed {
                let next_version = restored_version.checked_add(1).ok_or_else(|| {
                    anyhow::anyhow!(
                        "Cannot reconcile the HA bundle: persisted version {restored_version} cannot advance"
                    )
                })?;
                // Rebuild at the version that will actually be signed and
                // persisted, so the final-bundle secret scan covers exactly
                // that document instead of a mutated copy of the comparison
                // bundle.
                coordinator.update_bundle(build_bundle(next_version)?)?;
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
            coordinator.update_bundle(build_bundle(1)?)?;
            info!("Published initial HA configuration bundle version 1");
        }

        // Spawn master replication listener if replication_port > 0. A
        // promotion-enabled master gets its own shutdown switch so fencing can
        // stop accepting new slaves; the global shutdown is forwarded to it.
        let mut configured_master_shutdown = None;
        let _master_server_handle = if ha_config.replication_port > 0 {
            let listener_shutdown = if promotion_enabled {
                let (tx, rx) = watch::channel(false);
                let mut global = shutdown_rx.clone();
                let forward_tx = tx.clone();
                tokio::spawn(async move {
                    loop {
                        if *global.borrow() {
                            let _ = forward_tx.send(true);
                            break;
                        }
                        if global.changed().await.is_err() {
                            let _ = forward_tx.send(true);
                            break;
                        }
                    }
                });
                configured_master_shutdown = Some(tx);
                rx
            } else {
                shutdown_rx.clone()
            };
            Some(sito_ha::spawn_master_server(
                ha_config.clone(),
                coordinator.clone(),
                listener_shutdown,
            ))
        } else {
            None
        };

        let promotion = promotion_enabled.then(|| {
            Arc::new(PromotionRuntimeState {
                config: config.clone(),
                config_path: config_path.to_path_buf(),
                ha_config: ha_config.clone(),
                role: sito_ha::ConfiguredRole::Master,
                metrics: metrics.clone(),
                write_gate: Arc::clone(&write_gate),
                signing_key: Mutex::new(Some(signing_key.clone())),
                coordinator: Mutex::new(Some(coordinator.clone())),
                tracker: None,
                slave_shutdown: Mutex::new(None),
                master_shutdown: Mutex::new(configured_master_shutdown),
                live_config: Mutex::new(None),
                slave_handle: Mutex::new(None),
                master_slot: Arc::clone(&promoted_master),
                initial_toml: Mutex::new(Some(initial_toml.clone())),
                known_secrets: known_secrets.iter().map(|s| (*s).to_string()).collect(),
            })
        });

        (Some(coordinator), None, None, None, promotion)
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
        let promotion = promotion_enabled.then(|| {
            Arc::new(PromotionRuntimeState {
                config: config.clone(),
                config_path: config_path.to_path_buf(),
                ha_config: ha_config.clone(),
                role: sito_ha::ConfiguredRole::Slave,
                metrics: metrics.clone(),
                write_gate: Arc::clone(&write_gate),
                signing_key: Mutex::new(None),
                coordinator: Mutex::new(None),
                tracker: Some(tracker.clone()),
                slave_shutdown: Mutex::new(None),
                master_shutdown: Mutex::new(None),
                live_config: Mutex::new(None),
                slave_handle: Mutex::new(None),
                master_slot: Arc::clone(&promoted_master),
                initial_toml: Mutex::new(None),
                known_secrets: Vec::new(),
            })
        });
        (
            None,
            Some(tracker),
            Some(resync_tx),
            Some(resync_rx),
            promotion,
        )
    };

    Ok(HaRuntime {
        config: ha_config,
        coordinator: master_coordinator,
        tracker: slave_tracker,
        resync_sender,
        resync_receiver,
        write_gate,
        slave_shutdown: None,
        promotion,
        promoted_master,
    })
}

impl HaRuntime {
    /// Starts the master promotion supervisor after the live config handle
    /// exists. Candidate promotion is started by the slave worker bootstrap.
    pub(super) fn start_master_promotion(
        &self,
        config: Arc<ArcSwap<Config>>,
        shutdown_rx: &watch::Receiver<bool>,
    ) {
        let Some(promotion) = self.promotion.as_ref() else {
            return;
        };
        if promotion.role != sito_ha::ConfiguredRole::Master {
            return;
        }
        if let Ok(mut slot) = promotion.live_config.lock() {
            *slot = Some(config);
        }
        spawn_promotion_supervisor(Arc::clone(promotion), shutdown_rx.clone());
    }
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
