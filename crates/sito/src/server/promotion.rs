//! Production runtime adapter for ADR-0010 automatic promotion.
//!
//! The safety-critical state machine lives in `sito-ha::promotion`; this module
//! supplies the daemon pieces it needs (config bundle construction, the
//! coordinator, slave-worker shutdown, API write gate and the long-running
//! retry/renew loops).

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use arc_swap::ArcSwap;
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
    pub(super) master_handle: Mutex<Option<tokio::task::JoinHandle<()>>>,
    pub(super) live_config: Mutex<Option<Arc<ArcSwap<Config>>>>,
    pub(super) slave_handle: Mutex<Option<tokio::task::JoinHandle<()>>>,
    pub(super) master_slot: Arc<Mutex<Option<MasterCoordinator>>>,
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
        self.signing_key
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn coordinator(&self) -> Option<MasterCoordinator> {
        self.coordinator
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
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

/// Stops the slave replication worker and waits for it to exit.
///
/// The master listener must not accept a session before this returns: running
/// both roles at once is forbidden by ADR-0010.
async fn stop_slave_worker(state: &PromotionRuntimeState) {
    let handle = state
        .slave_handle
        .lock()
        .ok()
        .and_then(|mut slot| slot.take());
    if let Some(tx) = state
        .slave_shutdown
        .lock()
        .ok()
        .and_then(|slot| slot.as_ref().cloned())
    {
        let _ = tx.send(true);
    }
    if let Some(handle) = handle {
        let _ = handle.await;
    }
}

/// Evaluates the ADR-0010 candidate gates that depend on the slave tracker and
/// the local `ha_state.toml`.
fn candidate_eligibility(
    tracker: &SlaveStatusTracker,
    state_path: &std::path::Path,
    cluster_id: Option<&str>,
    node_id: Option<&str>,
    identity_mismatch: bool,
) -> Eligibility {
    let watermark = tracker.get_watermark();
    let applied_term = watermark.as_ref().map_or(0, |watermark| watermark.term);
    let applied_version = watermark.as_ref().map_or(0, |watermark| watermark.version);
    let mut store = HaStateStore::new(state_path.to_path_buf());
    if let (Some(cluster_id), Some(node_id)) = (cluster_id, node_id) {
        store = store.with_identity(cluster_id, node_id);
    }
    let loaded = store.load();
    let foreign_or_stale_state = match loaded {
        Ok(LoadedState::Missing) => false,
        Ok(loaded @ LoadedState::Present { .. }) => {
            if matches!(
                loaded,
                LoadedState::Present {
                    bookkeeping: Some(_),
                    ..
                }
            ) {
                false
            } else {
                loaded.bundle().is_some_and(|bundle| {
                    bundle.term > applied_term || bundle.version > applied_version
                })
            }
        }
        Err(_) => true,
    };
    Eligibility {
        degraded: tracker.get_state() == sito_ha::SlaveState::Degraded,
        diverged_or_forked: tracker.is_forked() || tracker.has_local_config_drift(),
        restart_required: tracker.requires_full_apply(),
        foreign_or_stale_state,
        identity_mismatch,
    }
}

struct RuntimePromotionHost {
    state: Arc<PromotionRuntimeState>,
}

impl RuntimePromotionHost {
    fn live_config(&self) -> Config {
        self.state
            .live_config
            .lock()
            .ok()
            .and_then(|slot| slot.as_ref().map(|config| (**config.load()).clone()))
            .unwrap_or_else(|| self.state.config.clone())
    }

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
        let live_config = self.live_config();
        let bundle = build_config_bundle(
            &live_config,
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
        candidate_eligibility(
            tracker,
            &self.state.state_path(),
            self.state.ha_config.promotion.cluster_id.as_deref(),
            self.state.ha_config.promotion.node_id.as_deref(),
            self.key().is_err(),
        )
    }

    fn master_alive(&self) -> bool {
        self.state
            .tracker
            .as_ref()
            .is_some_and(|tracker| tracker.master_alive(self.state.heartbeat_timeout()))
    }

    fn set_writable(&self, writable: bool, reason: Option<String>) {
        if let Some(coordinator) = self.state.coordinator() {
            if writable {
                if coordinator.is_fenced() {
                    return;
                }
                coordinator.set_serving(true);
                coordinator.allow_sessions();
            } else {
                // A terminal/read-only transition always ends hello-only and
                // denies admissions. A fence is sticky.
                if reason
                    .as_deref()
                    .is_some_and(|reason| reason.starts_with("ha_promotion_fenced"))
                {
                    coordinator.mark_fenced();
                }
                coordinator.end_hello_only();
                coordinator.close_all_sessions();
                coordinator.deny_sessions(
                    reason
                        .clone()
                        .unwrap_or_else(|| "ha_promotion_read_only".to_string()),
                );
            }
        }
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
            if let Some(coordinator) = self.state.coordinator() {
                match self.state.master_slot.lock() {
                    Ok(mut slot) => *slot = Some(coordinator),
                    Err(poisoned) => {
                        poisoned.into_inner().take();
                        return Err("promotion coordinator slot poisoned".to_string());
                    }
                }
                self.state.write_gate.mark_effective_master();
                return Ok(());
            }
            stop_slave_worker(&self.state).await;
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
            coordinator.set_serving(false);
            coordinator.deny_sessions("read_only");
            let (master_shutdown_tx, master_shutdown_rx) = watch::channel(false);
            let handle = sito_ha::spawn_master_server(
                self.state.ha_config.clone(),
                coordinator.clone(),
                master_shutdown_rx,
            );
            if let Ok(mut slot) = self.state.master_shutdown.lock() {
                *slot = Some(master_shutdown_tx);
            }
            if let Ok(mut slot) = self.state.master_handle.lock() {
                *slot = Some(handle);
            }
            *self
                .state
                .coordinator
                .lock()
                .map_err(|_| "promotion coordinator lock poisoned".to_string())? =
                Some(coordinator.clone());
            match self.state.master_slot.lock() {
                Ok(mut slot) => *slot = Some(coordinator),
                Err(poisoned) => {
                    // A poisoned slot cannot be trusted to receive normal
                    // publishes; keep the node read-only rather than report a
                    // writable-but-not-replicating master.
                    poisoned.into_inner().take();
                    return Err("promotion coordinator slot poisoned".to_string());
                }
            }
            self.state.write_gate.mark_effective_master();
            info!("Promoted node switched to the master replication role");
            Ok(())
        })
    }

    fn begin_hello_only(&self) -> sito_ha::promotion::BoxFuture<'_, Result<(), String>> {
        Box::pin(async move {
            let coordinator = self.coordinator()?;
            coordinator.set_serving(false);
            coordinator.allow_sessions();
            coordinator.begin_hello_only();
            Ok(())
        })
    }

    fn end_hello_only(&self) -> sito_ha::promotion::BoxFuture<'_, Result<(), String>> {
        Box::pin(async move {
            let coordinator = self.coordinator()?;
            coordinator.set_serving(false);
            coordinator.allow_sessions();
            coordinator.end_hello_only();
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
            // The first push is the one publish allowed while the API gate is
            // still closed. It is enabled only for the duration of this call.
            if coordinator.is_fenced() {
                return Err("fenced: the master cannot publish".to_string());
            }
            // Keep serving enabled after a successful enqueue: the session task
            // may dequeue after this method returns. Failure paths call
            // set_writable(false), which denies and closes sessions.
            coordinator.set_serving(true);
            let result = coordinator
                .publish_promoted_bundle(prepared.bundle)
                .map_err(|error| error.to_string());
            if result.is_err() {
                coordinator.set_serving(false);
            }
            result
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
        // Synchronous serving flag first: an in-flight Hello/handshake must not
        // enqueue a push after this returns, even before the listener joins.
        if let Some(coordinator) = self.state.coordinator() {
            coordinator.mark_fenced();
            coordinator.close_all_sessions();
        }
        if let Some(tx) = self
            .state
            .master_shutdown
            .lock()
            .ok()
            .and_then(|slot| slot.as_ref().cloned())
        {
            let _ = tx.send(true);
        }
        if let Some(handle) = self
            .state
            .master_handle
            .lock()
            .ok()
            .and_then(|mut slot| slot.take())
        {
            tokio::spawn(async move {
                let _ = handle.await;
            });
        }
    }

    fn close_replication_sessions(&self, reason: &str) {
        if let Some(coordinator) = self.state.coordinator() {
            coordinator.deny_sessions(reason);
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    fn test_state(label: &str) -> Arc<PromotionRuntimeState> {
        let dir = std::env::temp_dir().join(format!(
            "sito_promotion_runtime_{label}_{}_{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let mut config = Config::default();
        config.server.data_dir = dir;
        Arc::new(PromotionRuntimeState {
            config_path: std::path::PathBuf::from("missing-config.toml"),
            config,
            ha_config: HaConfig::default(),
            role: ConfiguredRole::Slave,
            metrics: sito_stats::MetricsRegistry::new("2.0.0", "test"),
            write_gate: Arc::new(sito_api::state::HaWriteGate::new()),
            signing_key: Mutex::new(None),
            coordinator: Mutex::new(None),
            tracker: None,
            slave_shutdown: Mutex::new(None),
            master_shutdown: Mutex::new(None),
            master_handle: Mutex::new(None),
            live_config: Mutex::new(None),
            slave_handle: Mutex::new(None),
            master_slot: Arc::new(Mutex::new(None)),
            initial_toml: Mutex::new(None),
            known_secrets: Vec::new(),
        })
    }

    #[tokio::test]
    async fn role_switch_waits_for_the_slave_worker_to_exit() {
        let mut state = test_state("handoff_wait");
        let stopped = Arc::new(AtomicBool::new(false));
        let worker_stopped = Arc::clone(&stopped);
        let handle = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            worker_stopped.store(true, Ordering::SeqCst);
        });
        *state.slave_handle.lock().unwrap() = Some(handle);

        let key = Arc::new(Ed25519SigningKey::generate().unwrap());
        {
            let state = Arc::get_mut(&mut state).expect("unique test state");
            state.signing_key.lock().unwrap().replace(key.clone());
            state.ha_config.master_pubkey = Some(key.public_key_hex());
            state.ha_config.replication_port = 0;
        }
        let host = RuntimePromotionHost {
            state: Arc::clone(&state),
        };
        let started = std::time::Instant::now();
        host.switch_role(EffectiveRole::Master)
            .await
            .expect("role switch");
        assert!(
            stopped.load(Ordering::SeqCst),
            "the handoff must wait for the worker join, not just send shutdown"
        );
        assert!(started.elapsed() >= Duration::from_millis(80));
        assert!(state.slave_handle.lock().unwrap().is_none());
    }

    #[tokio::test]
    async fn host_begin_hello_only_allows_admission_and_fence_is_sticky() {
        let state = test_state("host_hello");
        let key = Arc::new(Ed25519SigningKey::generate().unwrap());
        let coordinator = MasterCoordinator::new(
            "promoted".to_string(),
            1,
            key,
            sito_stats::MetricsRegistry::new("2.0.0", "test"),
        );
        *state.coordinator.lock().unwrap() = Some(coordinator.clone());
        let host = RuntimePromotionHost {
            state: Arc::clone(&state),
        };
        host.begin_hello_only().await.unwrap();
        assert!(!coordinator.is_serving());
        assert!(coordinator.is_accepting_sessions());
        assert!(coordinator.is_hello_only());

        // Fencing while hello-only is active must be sticky, even if the engine
        // (or a later transition) tries to re-enter hello-only.
        host.stop_publishing();
        assert!(coordinator.is_fenced());
        host.begin_hello_only().await.unwrap();
        assert!(!coordinator.is_accepting_sessions());
        assert!(!coordinator.is_serving());
        assert!(!coordinator.is_hello_only());
    }

    #[tokio::test]
    async fn publish_first_keeps_serving_enabled_for_the_queued_first_push() {
        use chrono::Utc;
        use sito_ha::master::ActiveSlave;

        let state = test_state("publish_first_delivery");
        let key = Arc::new(Ed25519SigningKey::generate().unwrap());
        let coordinator = MasterCoordinator::new(
            "promoted".to_string(),
            1,
            key.clone(),
            sito_stats::MetricsRegistry::new("2.0.0", "test"),
        );
        coordinator.set_term(1);
        *state.coordinator.lock().unwrap() = Some(coordinator.clone());
        *state.signing_key.lock().unwrap() = Some(key);
        let mut live = Config::default();
        live.server.role = "slave".to_string();
        let toml_doc = toml::to_string_pretty(&live).unwrap();
        *state.live_config.lock().unwrap() = Some(Arc::new(ArcSwap::from_pointee(live)));
        *state.initial_toml.lock().unwrap() = Some(toml_doc);
        let (tx, mut rx) = tokio::sync::mpsc::channel(4);
        coordinator.slaves.lock().unwrap().insert(
            "slave-1".to_string(),
            ActiveSlave {
                instance: "slave-1".to_string(),
                remote_addr: "127.0.0.1:1000".parse().unwrap(),
                synced_version: 1,
                last_ping: std::time::Instant::now(),
                connected_at: Utc::now(),
                last_stats: None,
                sender: tx,
                capabilities: vec![],
                have_term: 1,
                have_version: 1,
                have_bundle_hash: None,
                connection_id: 1,
            },
        );
        let host = RuntimePromotionHost {
            state: Arc::clone(&state),
        };
        let prepared = host.prepare_bundle(1, 2).expect("bundle");
        host.publish_first(&prepared).await.expect("first publish");
        assert!(
            coordinator.is_serving(),
            "serving must stay enabled for the queued first push"
        );
        let delivered = rx.try_recv().expect("first push queued");
        assert!(matches!(
            delivered,
            sito_ha::HaMessage::ConfigPush { version: 2, .. }
        ));

        // A terminal read-only transition closes admission/serving.
        host.set_writable(false, Some("promotion_interrupted".to_string()));
        assert!(!coordinator.is_serving());
        assert!(!coordinator.is_accepting_sessions());
    }

    fn write_legacy_state(path: &std::path::Path, term: u64, version: u64) {
        let bundle = ConfigBundle {
            version,
            term,
            config_toml: "config_version = 2\n[server]\nrole = \"slave\"\n".to_string(),
            ..ConfigBundle::default()
        };
        let state = serde_json::json!({
            "protocol_version": 2,
            "bundle": serde_json::to_value(&bundle).unwrap(),
        });
        std::fs::write(path, serde_json::to_vec(&state).unwrap()).unwrap();
    }

    #[test]
    fn candidate_eligibility_rejects_legacy_state_ahead_of_the_watermark() {
        let state = test_state("eligibility");
        let tracker = SlaveStatusTracker::new("slave".to_string(), 0, None);
        tracker.persist_watermark(5, 1, "abc").unwrap();
        let path = state.state_path();

        write_legacy_state(&path, 2, 9);
        let eligibility =
            candidate_eligibility(&tracker, &path, Some("home-dns"), Some("node-b"), false);
        assert!(
            eligibility.foreign_or_stale_state,
            "a legacy state ahead of the watermark must block candidacy"
        );

        write_legacy_state(&path, 1, 5);
        let eligibility =
            candidate_eligibility(&tracker, &path, Some("home-dns"), Some("node-b"), false);
        assert!(!eligibility.foreign_or_stale_state);
        assert!(
            eligibility.restart_required,
            "a watermark without an applied-config digest requires a full apply"
        );
    }

    #[tokio::test]
    async fn prepare_bundle_uses_the_live_hot_reloaded_config() {
        let state = test_state("live_config");
        let key = Arc::new(Ed25519SigningKey::generate().unwrap());
        *state.signing_key.lock().unwrap() = Some(key);
        *state.initial_toml.lock().unwrap() = Some(
            "config_version = 2\n[server]\nrole = \"slave\"\n[upstream]\nservers = [\"1.1.1.1\"]\n"
                .to_string(),
        );
        let mut live = Config::default();
        live.filtering.custom_rules = vec!["||live.example^".to_string()];
        *state.live_config.lock().unwrap() = Some(Arc::new(ArcSwap::from_pointee(live)));

        let host = RuntimePromotionHost { state };
        let prepared = host.prepare_bundle(1, 1).expect("bundle");
        assert_eq!(prepared.bundle.custom_rules, vec!["||live.example^"]);
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    use chrono::Utc;
    use sito_ha::master::ActiveSlave;
    use sito_ha::{ManualClock, WitnessClient, WitnessConfig, start_witness_server};

    fn write_secret(path: &std::path::Path, bytes: &[u8]) {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt as _;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .unwrap();
        file.write_all(bytes).unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn candidate_promotes_end_to_end_and_shared_publish_reaches_slave_and_witness() {
        let dir = temp_path("candidate_e2e");
        let certs = sito_ha::generate_ha_certs(&dir.join("certs"), true, false).unwrap();
        let token_file = dir.join("witness.token");
        write_secret(&token_file, b"test-token-0123456789abcdef");
        let witness_clock = Arc::new(ManualClock::new(1_760_000_000_000));
        let witness = start_witness_server(
            WitnessConfig {
                listen: "127.0.0.1:0".parse().unwrap(),
                cluster_id: "home-dns".to_string(),
                cert: certs.master_cert_path.clone().unwrap(),
                key: certs.master_key_path.clone().unwrap(),
                token_file: token_file.clone(),
                state_dir: dir.join("witness-state"),
            },
            witness_clock.clone(),
        )
        .await
        .unwrap();
        let witness_addr = witness.local_addr();

        let mut promotion = HaConfig::default().promotion;
        promotion.enabled = true;
        promotion.candidate = true;
        promotion.cluster_id = Some("home-dns".to_string());
        promotion.node_id = Some("node-b".to_string());
        promotion.lease_ttl_secs = 5;
        promotion.renew_interval_secs = 1;
        promotion.heartbeat_timeout_secs = Some(3);
        promotion.reconcile_window_secs = 1;
        promotion.witness.url = Some(format!("https://{witness_addr}"));
        promotion.witness.ca = Some(certs.ca_cert_path.clone());
        promotion.witness.token_file = Some(token_file.clone());

        let baseline = format!("{:02x}", 0xab).repeat(32);
        let client = WitnessClient::new(&promotion).unwrap();
        let seed = client
            .acquire(&sito_ha::witness::AcquireRequest {
                holder: "node-a/seed".to_string(),
                node_id: "node-a".to_string(),
                expected_term: None,
                expected_revision: None,
                term: 1,
                version: 5,
                bundle_hash: baseline.clone(),
                ttl_secs: 5,
            })
            .await
            .unwrap();
        assert_eq!(seed.version, 5);
        witness_clock.advance(5_000);

        let mut config = Config::default();
        config.server.role = "slave".to_string();
        config.server.instance_name = "candidate-b".to_string();
        config.server.data_dir = dir.clone();
        let config_path = dir.join("config.toml");
        std::fs::write(&config_path, toml::to_string_pretty(&config).unwrap()).unwrap();

        let signing = Ed25519SigningKey::generate().unwrap();
        let signing_path = dir.join("ha_signing.key");
        write_secret(&signing_path, signing.pkcs8_bytes());

        let watermark_path = dir.join("ha_watermark.toml");
        let tracker = SlaveStatusTracker::new("candidate-b".to_string(), 0, None)
            .with_watermark_path(watermark_path)
            .unwrap();
        tracker
            .persist_watermark_with_config_digest(5, 1, &baseline, Some("digest"))
            .unwrap();

        let mut ha_config = HaConfig {
            replication_port: reserve_port(),
            listen_addr: "127.0.0.1".to_string(),
            master_url: Some("ws://127.0.0.1:1".to_string()),
            master_pubkey: Some(signing.public_key_hex()),
            allow_insecure_ws: true,
            slave_token: Some("test-token".to_string()),
            ping_interval_secs: 1,
            ..HaConfig::default()
        };
        ha_config.promotion = promotion.clone();

        let gate = Arc::new(sito_api::state::HaWriteGate::new());
        gate.block("ha_promotion_starting");
        let master_slot = Arc::new(Mutex::new(None));
        let state = Arc::new(PromotionRuntimeState {
            config: config.clone(),
            config_path,
            ha_config,
            role: ConfiguredRole::Slave,
            metrics: sito_stats::MetricsRegistry::new("2.0.0", "test"),
            write_gate: gate.clone(),
            signing_key: Mutex::new(Some(Arc::new(signing))),
            coordinator: Mutex::new(None),
            tracker: Some(tracker),
            slave_shutdown: Mutex::new(None),
            master_shutdown: Mutex::new(None),
            master_handle: Mutex::new(None),
            live_config: Mutex::new(Some(Arc::new(ArcSwap::from_pointee(config.clone())))),
            slave_handle: Mutex::new(None),
            master_slot: master_slot.clone(),
            initial_toml: Mutex::new(Some(toml::to_string_pretty(&config).unwrap())),
            known_secrets: Vec::new(),
        });
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        spawn_promotion_supervisor(state.clone(), shutdown_rx);

        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            if gate.blocked().is_none() && master_slot.lock().unwrap().is_some() {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "candidate did not promote: gate={:?}",
                gate.blocked()
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let coordinator = master_slot.lock().unwrap().clone().unwrap();
        assert_eq!(coordinator.get_current_term(), 2);
        assert_eq!(coordinator.get_current_version(), 6);
        assert!(gate.is_effective_master());

        // Normal API publish through the shared context slot reaches a slave
        // and the running renewal loop advances the witness baseline.
        let ctx_dir = temp_path("candidate_ctx");
        let ctx = sito_api::test_support::mock_context(&ctx_dir).await;
        let mut context_config = (*ctx.config.load_full()).clone();
        context_config.server.role = "slave".to_string();
        ctx.config.store(Arc::new(context_config.clone()));
        std::fs::write(
            ctx.config_path.clone(),
            toml::to_string_pretty(&context_config).unwrap(),
        )
        .unwrap();
        ctx.promoted_master_coordinator
            .lock()
            .unwrap()
            .replace(coordinator.clone());
        ctx.ha_write_gate.mark_effective_master();
        ctx.ha_write_gate.allow();
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        coordinator.slaves.lock().unwrap().insert(
            "slave-1".to_string(),
            ActiveSlave {
                instance: "slave-1".to_string(),
                remote_addr: "127.0.0.1:1000".parse().unwrap(),
                synced_version: 6,
                last_ping: std::time::Instant::now(),
                connected_at: Utc::now(),
                last_stats: None,
                sender: tx,
                capabilities: vec![],
                have_term: 2,
                have_version: 6,
                have_bundle_hash: None,
                connection_id: 1,
            },
        );
        assert_eq!(
            coordinator.connected_slave_count(),
            1,
            "test slave must be registered before publish"
        );
        let outcome = ctx.publish_bundle().await.expect("promoted publish");
        assert!(
            matches!(
                outcome,
                sito_ha::PublishOutcome::Published { version: 7, .. }
            ),
            "unexpected publish outcome {outcome:?} (coordinator version {}, connected {}, slot same {}, gate {:?}, fence {:?})",
            coordinator.get_current_version(),
            coordinator.connected_slave_count(),
            ctx.active_master_coordinator().is_some(),
            gate.blocked(),
            sito_ha::FenceStore::new(&dir, "home-dns", "node-b")
                .load()
                .ok()
                .flatten()
        );
        assert!(matches!(
            rx.try_recv().unwrap(),
            sito_ha::HaMessage::ConfigPush { version: 7, .. }
        ));

        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            let record = client.lease().await.unwrap().unwrap();
            if record.version == 7 {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "witness baseline did not advance to the normal-published version: {record:?}"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        let _ = shutdown_tx.send(true);
        witness.shutdown().await;
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&ctx_dir);
    }

    fn temp_path(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "sito_promotion_{label}_{}_{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn reserve_port() -> u16 {
        sito_test_support::reserve_port_number().expect("reserve port")
    }
}
