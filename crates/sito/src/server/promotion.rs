//! Production runtime adapter for ADR-0010 automatic promotion.
//!
//! The safety-critical state machine lives in `sito-ha::promotion`; this module
//! supplies the daemon pieces it needs (config bundle construction, the
//! coordinator, slave-worker shutdown, API write gate and the long-running
//! retry/renew loops).

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sito_core::config::Config;
use sito_ha::promotion::{
    ConfiguredRole, EffectiveRole, Eligibility, HaStateStore, LoadedState, PreparedBundle,
    PromotionEngine, PromotionHost, PromotionOutcome, WitnessClient,
};
use sito_ha::{
    AppliedWatermark, ConfigBundle, Ed25519SigningKey, HaConfig, MasterCoordinator,
    PublicationBaseline, SlaveStatusTracker, build_and_sign_push, build_config_bundle,
    push_payload_hash,
};
use tokio::sync::watch;
use tracing::{error, info, warn};

/// Shared runtime state for one promotion-enabled node.
pub(super) struct PromotionRuntimeState {
    pub(super) config: Config,
    pub(super) config_path: PathBuf,
    pub(super) ha_config: HaConfig,
    pub(super) role: ConfiguredRole,
    pub(super) metrics: sito_stats::MetricsRegistry,
    pub(super) write_gate: Arc<sito_api::state::HaWriteGate>,
    pub(super) signing_key: Mutex<Option<Arc<Ed25519SigningKey>>>,
    pub(super) coordinator: Mutex<Option<MasterCoordinator>>,
    pub(super) tracker: Option<SlaveStatusTracker>,
    pub(super) slave_shutdown: Mutex<Option<watch::Sender<bool>>>,
    pub(super) master_shutdown: Mutex<Option<watch::Sender<bool>>>,
    pub(super) initial_toml: Mutex<Option<String>>,
    pub(super) known_secrets: Vec<String>,
}

impl PromotionRuntimeState {
    fn data_dir(&self) -> PathBuf {
        self.config.server.data_dir.clone()
    }

    fn state_path(&self) -> PathBuf {
        self.data_dir().join("ha_state.toml")
    }

    fn heartbeat_timeout(&self) -> Duration {
        Duration::from_secs(
            self.ha_config
                .promotion
                .effective_heartbeat_timeout_secs(self.ha_config.ping_interval_secs),
        )
    }

    fn signing_key(&self) -> Option<Arc<Ed25519SigningKey>> {
        self.signing_key.lock().ok()?.clone()
    }

    fn coordinator(&self) -> Option<MasterCoordinator> {
        self.coordinator.lock().ok()?.clone()
    }
}

/// Starts the promotion supervisor. It never exits the process on witness
/// failure: the node stays read-only and retries.
pub(super) fn spawn_promotion_supervisor(
    state: Arc<PromotionRuntimeState>,
    shutdown_rx: watch::Receiver<bool>,
) {
    if !state.ha_config.promotion.enabled {
        return;
    }
    tokio::spawn(async move {
        run_supervisor(state, shutdown_rx).await;
    });
}

async fn run_supervisor(state: Arc<PromotionRuntimeState>, mut shutdown_rx: watch::Receiver<bool>) {
    let mut backoff = sito_ha::ExponentialBackoff::default();
    let backend = loop {
        if *shutdown_rx.borrow() {
            return;
        }
        match WitnessClient::new(&state.ha_config.promotion) {
            Ok(client) => break Arc::new(client),
            Err(error) => {
                state
                    .write_gate
                    .block(format!("witness_config_invalid: {error}"));
                warn!(error = %error, "Promotion witness client is not usable yet; staying read-only");
                tokio::select! {
                    () = tokio::time::sleep(backoff.next_delay()) => {}
                    _ = shutdown_rx.changed() => { if *shutdown_rx.borrow() { return; } }
                }
            }
        }
    };
    let host = Arc::new(RuntimePromotionHost {
        state: Arc::clone(&state),
    });
    let engine = match PromotionEngine::new(
        state.ha_config.promotion.clone(),
        state.role,
        state.data_dir(),
        backend,
        host.clone(),
    ) {
        Ok(engine) => {
            Arc::new(engine.with_heartbeat_timeout_secs(state.heartbeat_timeout().as_secs()))
        }
        Err(error) => {
            state.write_gate.block("promotion_config_invalid");
            error!(error = %error, "Automatic promotion configuration failed at runtime");
            return;
        }
    };

    match engine.boot() {
        Ok(PromotionOutcome::Fenced) => {
            state.write_gate.fence("ha_promotion_fenced");
            return;
        }
        Ok(_) => {}
        Err(error) => {
            state.write_gate.block("promotion_interrupted");
            error!(error = %error, "Automatic promotion boot refused; staying read-only");
            return;
        }
    }

    match state.role {
        ConfiguredRole::Master => loop {
            if *shutdown_rx.borrow() {
                return;
            }
            match engine.start_master().await {
                PromotionOutcome::Master => {
                    state.write_gate.allow();
                    break;
                }
                PromotionOutcome::Fenced => {
                    state.write_gate.fence("ha_promotion_fenced");
                    return;
                }
                PromotionOutcome::ReadOnly { reason, retryable } => {
                    state.write_gate.block(reason.clone());
                    if !retryable {
                        warn!(reason = %reason, "Automatic promotion refused; staying read-only");
                        return;
                    }
                    warn!(reason = %reason, "Automatic promotion not ready; retrying");
                    tokio::select! {
                        () = tokio::time::sleep(backoff.next_delay()) => {}
                        _ = shutdown_rx.changed() => { if *shutdown_rx.borrow() { return; } }
                    }
                }
                PromotionOutcome::Disabled
                | PromotionOutcome::Waiting
                | PromotionOutcome::ManualConfirmationRequired => {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        },
        ConfiguredRole::Slave => {
            if !state.ha_config.promotion.candidate {
                state.write_gate.block("not_candidate");
                return;
            }
            let started = std::time::Instant::now();
            let heartbeat = state.heartbeat_timeout();
            let Some(tracker) = state.tracker.clone() else {
                state.write_gate.block("not_candidate");
                return;
            };
            loop {
                if *shutdown_rx.borrow() {
                    return;
                }
                let seen_master = tracker.seconds_since_master_frame().is_some();
                let master_alive = tracker.master_alive(heartbeat);
                if master_alive || (!seen_master && started.elapsed() < heartbeat) {
                    state.write_gate.block("master_alive");
                    tokio::select! {
                        () = tokio::time::sleep(Duration::from_secs(1)) => {}
                        _ = shutdown_rx.changed() => { if *shutdown_rx.borrow() { return; } }
                    }
                    continue;
                }
                match engine.candidate_attempt(false).await {
                    PromotionOutcome::Master => {
                        state.write_gate.allow();
                        break;
                    }
                    PromotionOutcome::Fenced => {
                        state.write_gate.fence("ha_promotion_fenced");
                        return;
                    }
                    PromotionOutcome::ManualConfirmationRequired => {
                        state.write_gate.block("manual_confirmation_required");
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                    PromotionOutcome::Waiting => {
                        state.write_gate.block("master_alive");
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                    PromotionOutcome::ReadOnly { reason, retryable } => {
                        state.write_gate.block(reason.clone());
                        if !retryable {
                            warn!(reason = %reason, "Candidate refused promotion; staying read-only");
                            return;
                        }
                        tokio::select! {
                            () = tokio::time::sleep(backoff.next_delay()) => {}
                            _ = shutdown_rx.changed() => { if *shutdown_rx.borrow() { return; } }
                        }
                    }
                    PromotionOutcome::Disabled => return,
                }
            }
        }
    }

    // Renewal/self-fence loop after a successful promotion or master startup.
    let renew_interval = Duration::from_secs(state.ha_config.promotion.renew_interval_secs.max(1));
    let mut next_renew = std::time::Instant::now();
    loop {
        if *shutdown_rx.borrow() {
            return;
        }
        match engine.check_self_fence() {
            Ok(true) => {
                state.write_gate.fence("ha_promotion_fenced");
                error!("HA promotion self-fenced; lease renewals stopped");
                return;
            }
            Ok(false) => {}
            Err(error) => {
                state.write_gate.fence("ha_promotion_fenced");
                error!(error = %error, "HA promotion self-fence failed critically");
                return;
            }
        }
        if std::time::Instant::now() >= next_renew {
            match engine.renew_once().await {
                Ok(_) => {}
                Err(error) => {
                    if engine.snapshot().fenced {
                        state.write_gate.fence("ha_promotion_fenced");
                        return;
                    }
                    warn!(error = %error, "Lease renewal failed; retrying before the self-fence deadline");
                }
            }
            next_renew = std::time::Instant::now() + renew_interval;
        }
        tokio::select! {
            () = tokio::time::sleep(Duration::from_millis(250)) => {}
            _ = shutdown_rx.changed() => { if *shutdown_rx.borrow() { return; } }
        }
    }
}

struct RuntimePromotionHost {
    state: Arc<PromotionRuntimeState>,
}

impl RuntimePromotionHost {
    fn config_document(&self) -> String {
        if let Ok(raw) = std::fs::read_to_string(&self.state.config_path) {
            return raw;
        }
        self.state
            .initial_toml
            .lock()
            .ok()
            .and_then(|toml| toml.clone())
            .unwrap_or_default()
    }

    fn key(&self) -> Result<Arc<Ed25519SigningKey>, String> {
        if let Some(key) = self.state.signing_key() {
            return Ok(key);
        }
        let path = self.state.data_dir().join("ha_signing.key");
        let bytes = std::fs::read(&path).map_err(|error| {
            format!(
                "candidate_identity_mismatch: cannot read master signing key '{}': {error}",
                path.display()
            )
        })?;
        let key = Ed25519SigningKey::from_pkcs8(&bytes)
            .map_err(|error| format!("cannot parse the master signing key: {error}"))?;
        if let Some(expected) = self.state.ha_config.master_pubkey.as_deref() {
            let expected = sito_ha::parse_public_key(expected)
                .map_err(|error| format!("invalid master_pubkey: {error}"))?;
            if key.public_key() != expected {
                return Err(
                    "candidate_identity_mismatch: ha_signing.key does not match master_pubkey"
                        .to_string(),
                );
            }
        }
        let key = Arc::new(key);
        if let Ok(mut slot) = self.state.signing_key.lock() {
            *slot = Some(Arc::clone(&key));
        }
        Ok(key)
    }

    fn coordinator(&self) -> Result<MasterCoordinator, String> {
        self.state
            .coordinator()
            .ok_or_else(|| "promotion coordinator is not initialized".to_string())
    }
}

impl PromotionHost for RuntimePromotionHost {
    fn prepare_bundle(&self, term: u64, version: u64) -> Result<PreparedBundle, String> {
        let document = self.config_document();
        let bundle = build_config_bundle(
            &self.state.config,
            &document,
            version,
            term,
            &self
                .state
                .known_secrets
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
        )
        .map_err(|error| error.to_string())?;
        let key = self.key()?;
        let push = build_and_sign_push(&bundle, &key).map_err(|error| error.to_string())?;
        let hash = push_payload_hash(&push).map_err(|error| error.to_string())?;
        Ok(PreparedBundle { bundle, hash })
    }

    fn applied_watermark(&self) -> Option<AppliedWatermark> {
        self.state
            .tracker
            .as_ref()
            .and_then(SlaveStatusTracker::get_watermark)
    }

    fn current_published_baseline(&self) -> Option<PublicationBaseline> {
        if let Some(coordinator) = self.state.coordinator() {
            if let Some(bookkeeping) = coordinator.promotion_bookkeeping() {
                return Some(PublicationBaseline {
                    version: bookkeeping.published_version,
                    hash: bookkeeping.published_hash,
                });
            }
            if let Some(hash) = coordinator.active_payload_hash() {
                return Some(PublicationBaseline {
                    version: coordinator.get_current_version(),
                    hash,
                });
            }
        }
        None
    }

    fn hash_bundle(&self, bundle: &ConfigBundle) -> Result<String, String> {
        let key = self.key()?;
        let push = build_and_sign_push(bundle, &key).map_err(|error| error.to_string())?;
        push_payload_hash(&push).map_err(|error| error.to_string())
    }

    fn eligibility(&self) -> Eligibility {
        let Some(tracker) = self.state.tracker.as_ref() else {
            return Eligibility::default();
        };
        Eligibility {
            degraded: tracker.get_state() == sito_ha::SlaveState::Degraded,
            diverged_or_forked: tracker.is_forked(),
            restart_required: false,
            foreign_or_stale_state: false,
            identity_mismatch: self.key().is_err(),
        }
    }

    fn master_alive(&self) -> bool {
        self.state
            .tracker
            .as_ref()
            .is_some_and(|tracker| tracker.master_alive(self.state.heartbeat_timeout()))
    }

    fn set_writable(&self, writable: bool, reason: Option<String>) {
        if writable {
            self.state.write_gate.allow();
        } else if reason
            .as_deref()
            .is_some_and(|reason| reason.starts_with("ha_promotion_fenced"))
        {
            self.state.write_gate.fence("ha_promotion_fenced");
        } else {
            self.state
                .write_gate
                .block(reason.unwrap_or_else(|| "ha_promotion_read_only".to_string()));
        }
    }

    fn switch_role(
        &self,
        role: EffectiveRole,
    ) -> sito_ha::promotion::BoxFuture<'_, Result<(), String>> {
        Box::pin(async move {
            if role != EffectiveRole::Master {
                return Ok(());
            }
            if self.state.coordinator().is_some() {
                self.state.write_gate.mark_effective_master();
                return Ok(());
            }
            if let Some(tx) = self
                .state
                .slave_shutdown
                .lock()
                .ok()
                .and_then(|slot| slot.as_ref().cloned())
            {
                let _ = tx.send(true);
            }
            let key = self.key()?;
            if self.state.ha_config.replication_port > 0
                && !self.state.ha_config.allow_insecure_ws
                && (self.state.ha_config.cert.is_none() || self.state.ha_config.key.is_none())
            {
                return Err(
                    "candidate_identity_mismatch: promoted master has no mTLS certificate/key"
                        .to_string(),
                );
            }
            let coordinator = MasterCoordinator::new(
                self.state.config.server.instance_name.clone(),
                0,
                key,
                self.state.metrics.clone(),
            )
            .with_state_path(self.state.state_path())
            .with_slave_requirements(
                self.state.ha_config.require_slaves,
                self.state.ha_config.require_all_slaves,
            );
            let (master_shutdown_tx, master_shutdown_rx) = watch::channel(false);
            let _handle = sito_ha::spawn_master_server(
                self.state.ha_config.clone(),
                coordinator.clone(),
                master_shutdown_rx,
            );
            if let Ok(mut slot) = self.state.master_shutdown.lock() {
                *slot = Some(master_shutdown_tx);
            }
            *self
                .state
                .coordinator
                .lock()
                .map_err(|_| "promotion coordinator lock poisoned".to_string())? =
                Some(coordinator);
            self.state.write_gate.mark_effective_master();
            info!("Promoted node switched to the master replication role");
            Ok(())
        })
    }

    fn begin_hello_only(&self) -> sito_ha::promotion::BoxFuture<'_, Result<(), String>> {
        Box::pin(async move {
            self.coordinator()?.begin_hello_only();
            Ok(())
        })
    }

    fn end_hello_only(&self) -> sito_ha::promotion::BoxFuture<'_, Result<(), String>> {
        Box::pin(async move {
            self.coordinator()?.end_hello_only();
            Ok(())
        })
    }

    fn collect_reconcile_reports(
        &self,
    ) -> sito_ha::promotion::BoxFuture<'_, Result<Vec<sito_ha::promotion::PeerReport>, String>>
    {
        Box::pin(async move { Ok(self.coordinator()?.hello_only_peer_reports()) })
    }

    fn publish_first(
        &self,
        prepared: &PreparedBundle,
    ) -> sito_ha::promotion::BoxFuture<'_, Result<String, String>> {
        let prepared = prepared.clone();
        Box::pin(async move {
            let coordinator = self.coordinator()?;
            coordinator.set_term(prepared.bundle.term);
            let store = HaStateStore::new(self.state.state_path());
            if let Ok(LoadedState::Present { bookkeeping, .. }) = store.load() {
                coordinator.set_promotion_bookkeeping(bookkeeping);
            }
            coordinator
                .publish_promoted_bundle(prepared.bundle)
                .map_err(|error| error.to_string())
        })
    }

    fn adopt_published(
        &self,
        prepared: &PreparedBundle,
    ) -> sito_ha::promotion::BoxFuture<'_, Result<(), String>> {
        let prepared = prepared.clone();
        Box::pin(async move {
            let coordinator = self.coordinator()?;
            coordinator.set_term(prepared.bundle.term);
            coordinator
                .adopt_promoted_bundle(prepared.bundle)
                .map(|_| ())
                .map_err(|error| error.to_string())
        })
    }

    fn stop_publishing(&self) {
        if let Some(tx) = self
            .state
            .master_shutdown
            .lock()
            .ok()
            .and_then(|slot| slot.as_ref().cloned())
        {
            let _ = tx.send(true);
        }
        if let Some(coordinator) = self.state.coordinator() {
            coordinator.close_all_sessions();
        }
    }

    fn close_replication_sessions(&self, _reason: &str) {
        if let Some(coordinator) = self.state.coordinator() {
            coordinator.close_all_sessions();
        }
    }

    fn critical_local_failure(&self, reason: &str) {
        error!(
            reason,
            "CRITICAL: HA promotion fence could not be recorded; exiting"
        );
        std::process::exit(70);
    }
}
