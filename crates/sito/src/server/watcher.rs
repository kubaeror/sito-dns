//! Config watcher, apply hooks, and deferred slave worker startup.

#[allow(clippy::wildcard_imports)]
use super::*;

/// Handles shared with [`run_config_watcher`].
pub(super) struct ConfigWatcher {
    pub(super) ctx: sito_api::ServerContext,
    /// Hook-owned components shared with the REST/UI config write paths.
    pub(super) hooks: Arc<ServerApplyHooks>,
    pub(super) shutdown_rx: watch::Receiver<bool>,
}

/// Applies the components that are not reachable through [`ServerContext`]:
/// DNSSEC validator, per-client scoped upstreams, rate limiters, DNS listener
/// rebind and the log level. Shared by the file watcher and the API/UI config
/// write paths through [`sito_api::config_apply::ConfigApplyHooks`].
pub(super) struct ServerApplyHooks {
    pub(super) dnssec: Arc<ArcSwap<DnssecValidator>>,
    /// Authenticated DNSSEC chain statuses shared across validator swaps. A
    /// hot reload must not forget that a zone was proven signed/unsigned.
    pub(super) dnssec_chain_cache: Arc<sito_dnssec::ChainCache>,
    pub(super) scoped_upstreams: Arc<ArcSwap<HashMap<String, Arc<UpstreamManager>>>>,
    pub(super) rate_limiters: Arc<std::sync::Mutex<Vec<Arc<sito_transport::RateLimiter>>>>,
    pub(super) listener_manager: Arc<tokio::sync::Mutex<Option<DnsListenerManager>>>,
    pub(super) listener_acceptors: Arc<tokio::sync::Mutex<Option<ListenerAcceptors>>>,
    pub(super) pipeline: Arc<DnsPipeline>,
    /// Server-owned readiness published to `/health` and `/status`.
    pub(super) readiness: Arc<sito_api::ReadinessState>,
    /// Shared certificate-validity cache used by readiness refreshes.
    pub(super) cert_validity_cache: Arc<sito_transport::CertificateValidityCache>,
}

/// Hook-owned components prepared for one staged apply, not yet installed.
pub(super) struct PreparedServerComponents {
    /// Candidate configuration this payload was prepared from. Commit must
    /// use it: the live config handle is still the previous generation.
    pub(super) config: Config,
    pub(super) dnssec_validator: Arc<DnssecValidator>,
    pub(super) scoped_upstreams: HashMap<String, Arc<UpstreamManager>>,
}

impl sito_api::config_apply::ConfigApplyHooks for ServerApplyHooks {
    fn prepare<'a>(
        &'a self,
        cfg: &'a Config,
        clients: &'a sito_clients::ClientsConfig,
    ) -> sito_api::config_apply::PrepareFuture<'a> {
        Box::pin(async move {
            // DNSSEC: build the validator with the shared chain cache, but do
            // not install it. The prepared validator travels in the plan and
            // becomes visible with the runtime snapshot.
            let validator = Arc::new(DnssecValidator::from_config_with_cache(
                &cfg.dns.dnssec,
                Some(self.dnssec_chain_cache.clone()),
            ));
            let dnssec_policy =
                sito_runtime::DnssecPolicy::from_validator(&cfg.dns.dnssec, Arc::clone(&validator));

            // Per-client upstream scopes, reusing managers whose upstream set
            // is unchanged. Built here so a bad scope fails the apply before
            // anything is published.
            let scoped_upstreams = {
                let existing = self.scoped_upstreams.load_full();
                build_scoped_upstreams(cfg, clients, &existing)
                    .await
                    .map_err(|e| {
                        // A scope that cannot be constructed must fail the staged
                        // apply before anything is published. Falling back to the
                        // global upstreams would silently bypass the client's
                        // `use_global_upstreams = false` policy.
                        sito_runtime::ApplyError::Internal(format!(
                            "per-client upstream scope preparation failed: {e}"
                        ))
                    })?
            };

            Ok(sito_api::config_apply::PreparedHooks {
                dnssec_policy,
                commit: Box::new(PreparedServerComponents {
                    config: cfg.clone(),
                    dnssec_validator: validator,
                    scoped_upstreams,
                }),
            })
        })
    }

    fn commit(
        &self,
        prepared: sito_api::config_apply::PreparedHooks,
    ) -> sito_api::config_apply::ApplyFuture<'_> {
        Box::pin(async move {
            let prepared = prepared
                .commit
                .downcast::<PreparedServerComponents>()
                .map_err(|_| {
                    sito_runtime::ApplyError::Internal(
                        "server apply hook received an unexpected prepared payload".to_string(),
                    )
                })?;

            // Rebind listeners first: this is the only fallible commit step.
            // A failure leaves every other component and the runtime snapshot
            // on the previous generation.
            let listener_config = prepared.config;
            if crate::logging::reload_level(&listener_config.server.log_level) {
                info!(
                    level = %listener_config.server.log_level,
                    "Applied hot-reloaded log level"
                );
            }
            {
                let mut slot = self.listener_manager.lock().await;
                if let Some(manager) = slot.as_mut()
                    && manager.needs_restart(&listener_config)
                {
                    let acceptors = self.listener_acceptors.lock().await.clone();
                    if let Some(acceptors) = acceptors {
                        info!("DNS listener bindings changed; rebinding in-process");
                        if let Err(error) = manager
                            .restart(
                                &listener_config,
                                self.pipeline.clone(),
                                acceptors,
                                self.rate_limiters.clone(),
                            )
                            .await
                        {
                            // A failed rebind that restored the previous
                            // generation still serves DNS; a failed revert
                            // leaves the listener slot empty and must make
                            // `/health` unavailable.
                            if manager.is_running() {
                                self.readiness.set_listeners_ready();
                            } else {
                                self.readiness.set_listeners_unavailable(
                                    "listener_bind_failed",
                                    "DNS listeners could not be rebound and no previous generation is running",
                                );
                            }
                            return Err(sito_runtime::ApplyError::Tls(
                                sito_transport::TlsError::Config(format!(
                                    "Failed to rebind DNS listeners: {error}"
                                )),
                            ));
                        }
                        self.readiness.set_listeners_ready();
                    } else {
                        warn!("Listener TLS acceptors unavailable; keeping current listeners");
                        self.readiness.set_listeners_unavailable(
                            "listener_rebind_skipped",
                            "listener changes could not be applied because TLS acceptors are unavailable",
                        );
                        publish_tls_readiness(
                            &self.readiness,
                            &listener_config,
                            None,
                            None,
                            &self.cert_validity_cache,
                        );
                    }
                }
            }

            // Infallible component installs.
            self.dnssec.store(prepared.dnssec_validator);
            self.scoped_upstreams
                .store(Arc::new(prepared.scoped_upstreams));
            {
                let limiters = sito_core::sync::lock_or_recover(&self.rate_limiters);
                for limiter in limiters.iter() {
                    limiter.set_rate(listener_config.dns.rate_limit_per_ip);
                }
            }
            Ok(())
        })
    }
}

/// Spawns the pending slave worker once the listener generation and shared
/// rate limiters exist.
///
/// The applier's readiness gate is opened here, immediately before spawning, so
/// a push can never be acknowledged while listener/rate-limit components are
/// still uninitialized. Master roles have no pending receiver and are a no-op.
#[allow(clippy::too_many_arguments)]
pub(super) fn spawn_slave_worker_after_listeners(
    ha_runtime: &mut HaRuntime,
    server_ctx: &sito_api::ServerContext,
    hooks: &Arc<ServerApplyHooks>,
    runtime: &Arc<sito_runtime::RuntimeState>,
    filter_engine: &Arc<HostsFilterEngine>,
    metrics: &sito_stats::MetricsRegistry,
    config_path: &Path,
    shutdown_rx: &watch::Receiver<bool>,
) {
    let (Some(tracker), Some(resync_rx)) = (
        ha_runtime.tracker.clone(),
        ha_runtime.resync_receiver.take(),
    ) else {
        return;
    };
    if ha_runtime.config.master_url.is_none() {
        metrics.inc_ha_startup_noop("slave", "missing_master_url");
        tracker.set_connection_error(Some(
            "master_url is not configured; replication cannot start".to_string(),
        ));
        warn!("Slave role configured without master_url; replication worker idle");
        return;
    }

    let applier = Arc::new(HaConfigApplier::new(server_ctx.clone(), hooks.clone()));
    applier.mark_listeners_ready();
    let slave_handles = sito_ha::SlaveAppHandles {
        runtime: runtime.clone(),
        filter: filter_engine.clone(),
        metrics: metrics.clone(),
        config_path: Some(config_path.to_path_buf()),
        applier,
    };
    let _slave_worker_handle = sito_ha::spawn_slave_worker(
        ha_runtime.config.clone(),
        tracker,
        slave_handles,
        resync_rx,
        shutdown_rx.clone(),
    );
}

/// Watches the configuration file and applies hot reloads in-process. Returns
/// when shutdown is signalled, when the watcher cannot be initialized, or when
/// the watched directory disappears.
pub(super) async fn run_config_watcher(watcher: ConfigWatcher) {
    let ConfigWatcher {
        ctx,
        hooks,
        shutdown_rx: mut watcher_shutdown_rx,
    } = watcher;
    let watcher_config_path = ctx.config_path.clone();

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let event_filter_path = watcher_config_path.clone();
    let mut watcher = match notify::recommended_watcher(move |res: Result<Event, _>| {
        if let Ok(event) = res
            && (event.kind.is_modify() || event.kind.is_create())
            && event.paths.iter().any(|path| {
                path == &event_filter_path || path.file_name() == event_filter_path.file_name()
            })
        {
            let _ = tx.send(());
        }
    }) {
        Ok(w) => w,
        Err(e) => {
            error!(
                error = %e,
                "Failed to initialize config file watcher; hot reload is DISABLED until restart"
            );
            return;
        }
    };

    // Watch the parent directory so a config file created after startup
    // (first-run wizard) is also picked up.
    let watch_target = watcher_config_path
        .parent()
        .map_or_else(|| watcher_config_path.clone(), std::path::Path::to_path_buf);
    if let Err(e) = watcher.watch(&watch_target, RecursiveMode::NonRecursive) {
        error!(
            error = %e,
            path = %watch_target.display(),
            "Failed to watch config directory; hot reload is DISABLED until restart"
        );
        return;
    }

    loop {
        tokio::select! {
            res = watcher_shutdown_rx.changed() => {
                if res.is_err() || *watcher_shutdown_rx.borrow() {
                    break;
                }
            }
            Some(()) = rx.recv() => {
                // Debounce brief bursts of file writes
                tokio::time::sleep(WATCHER_DEBOUNCE).await;
                while rx.try_recv().is_ok() {}

                match tokio::fs::read_to_string(&watcher_config_path).await {
                    Ok(content) => {
                        use sito_api::config_apply::ConfigFileApplyOutcome;
                        // Same apply/validate pipeline as every API write path.
                        // A document that already matches the runtime (the HA
                        // applier's own write or an identical save) is skipped.
                        match sito_api::config_apply::apply_config_document_event(
                            &ctx,
                            &content,
                            sito_api::config_apply::FilterApply::Sync,
                            Some(&*hooks),
                        )
                        .await
                        {
                            ConfigFileApplyOutcome::SelfWriteIgnored => {
                                info!(
                                    "Ignoring file-watcher event: the file already matches the running configuration (self-write or unchanged)"
                                );
                            }
                            ConfigFileApplyOutcome::Applied(report) => {
                                info!("Detected external configuration file change; hot-reloaded");
                                if !report.restart_required.is_empty() {
                                    warn!(
                                        fields = ?report.restart_required,
                                        "Configuration hot-reloaded; these settings need a restart to take effect"
                                    );
                                }
                            }
                            ConfigFileApplyOutcome::Rejected(e) => {
                                error!(
                                    status = e.status,
                                    detail = %e.detail,
                                    "Rejecting config hot-reload: configuration cannot be applied"
                                );
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Failed to read modified configuration file: {e}");
                    }
                }
            }
        }
    }
}
