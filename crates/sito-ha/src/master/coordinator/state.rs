//! Coordinator construction, readiness, term, and persisted state.

#[allow(clippy::wildcard_imports)]
use super::*;

impl MasterCoordinator {
    pub fn new(
        instance_name: String,
        initial_version: u64,
        signing_key: Arc<Ed25519SigningKey>,
        metrics: MetricsRegistry,
    ) -> Self {
        #[allow(clippy::cast_precision_loss)]
        {
            metrics.set_ha_config_version("local", initial_version as f64);
            metrics.set_ha_config_version(&instance_name, initial_version as f64);
        }
        metrics.set_ha_slaves_connected(0);

        Self {
            instance_name,
            signing_key,
            current_version: Arc::new(AtomicU64::new(initial_version)),
            current_term: Arc::new(AtomicU64::new(0)),
            active_bundle: Arc::new(Mutex::new(None)),
            active_push: Arc::new(Mutex::new(None)),
            slaves: Arc::new(Mutex::new(HashMap::new())),
            metrics,
            slave_token: None,
            ping_interval_secs: 15,
            state_path: Arc::new(Mutex::new(None)),
            pending_fallbacks: Arc::new(Mutex::new(HashSet::new())),
            stale_repushes: Arc::new(Mutex::new(HashMap::new())),
            publish_lock: Arc::new(Mutex::new(())),
            persist_lock: Arc::new(tokio::sync::Mutex::new(())),
            next_connection_id: Arc::new(AtomicU64::new(1)),
            #[cfg(test)]
            state_write_hook: Arc::new(Mutex::new(None)),
            diverged: Arc::new(Mutex::new(HashMap::new())),
            active_push_history: Arc::new(Mutex::new(VecDeque::new())),
            queued_bytes: Arc::new(Mutex::new(HashMap::new())),
            last_publish_error: Arc::new(Mutex::new(None)),
            publish_retry_running: Arc::new(AtomicBool::new(false)),
            readiness: HaReadinessState::not_ready("master replication listener has not started"),
        }
    }

    /// Current readiness of the master replication path.
    ///
    /// A running listener is not enough: a publish that failed to persist or
    /// broadcast must make the node unready until a later publish succeeds, so
    /// `/health` cannot stay green while slaves never receive the config.
    #[must_use]
    pub fn readiness(&self) -> HaReadiness {
        let listener = self.readiness.snapshot();
        if !listener.ready {
            return listener;
        }
        if let Some(error) = sito_core::sync::lock_or_recover(&self.last_publish_error).clone() {
            return HaReadiness::not_ready(format!(
                "last HA configuration publish failed: {error}"
            ));
        }
        listener
    }

    pub(super) fn set_publish_error(&self, error: Option<String>) {
        *sito_core::sync::lock_or_recover(&self.last_publish_error) = error;
    }

    /// Records a publish failure detected before the bundle reaches the
    /// coordinator (read/serialize/sanitize/empty/secret-scan errors).
    ///
    /// Keeps HA readiness false so `/health` cannot stay green while the API
    /// cannot build a replicable bundle.
    pub fn mark_publish_failed(&self, reason: impl Into<String>) {
        self.set_publish_error(Some(reason.into()));
    }

    /// Starts a publish retry if one is not already running.
    ///
    /// Returns false when a retry task is already in flight so a burst of
    /// failed API applies cannot spawn an unbounded number of retry loops.
    pub fn begin_publish_retry(&self) -> bool {
        !self.publish_retry_running.swap(true, Ordering::SeqCst)
    }

    /// Marks the background publish retry as finished.
    pub fn end_publish_retry(&self) {
        self.publish_retry_running.store(false, Ordering::SeqCst);
    }

    /// Marks the replication listener as serving connections.
    pub fn mark_replication_ready(&self) {
        self.readiness.mark_ready();
    }

    /// Records a listener/TLS failure that prevents replication.
    pub fn mark_replication_failed(&self, reason: impl Into<String>) {
        self.readiness.mark_failed(reason);
    }

    /// Records an intentionally disabled listener (`replication_port = 0`).
    ///
    /// This is not a failure: the operator explicitly turned HA off. Keeping a
    /// reason makes the disabled state visible in `/ha/status`.
    pub fn mark_replication_disabled(&self) {
        self.readiness
            .mark_ready_with_reason("replication_port is 0 (replication disabled)");
    }

    /// Enables persistence of the active configuration version/bundle to `path`.
    #[must_use]
    pub fn with_state_path(mut self, path: PathBuf) -> Self {
        self.state_path = Arc::new(Mutex::new(Some(path)));
        self
    }

    /// Sets the cluster epoch/term for an explicit promotion.
    ///
    /// Normal nodes restore the term from `ha_state.toml`. This builder exists
    /// for an embedded/operator promotion path (and tests): every bundle
    /// published afterwards must carry this term. A stale master that has not
    /// been promoted this way can never overwrite a newer slave.
    #[must_use]
    pub fn with_term(self, term: u64) -> Self {
        self.current_term.store(term, Ordering::SeqCst);
        self
    }

    /// Installs a test-only hook invoked inside the blocking state writer.
    #[cfg(test)]
    #[must_use]
    pub(super) fn with_state_write_hook(mut self, hook: StateWriteHook) -> Self {
        self.state_write_hook = Arc::new(Mutex::new(Some(hook)));
        self
    }

    /// Writes `payload` to `path` atomically (0600 temp file, fsync, rename).
    pub(super) fn write_state_file(path: &std::path::Path, payload: &[u8]) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp = path.with_extension("tmp");
        #[cfg(unix)]
        {
            use std::io::Write as _;
            use std::os::unix::fs::OpenOptionsExt as _;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)?;
            file.write_all(payload)?;
            file.sync_all()?;
        }
        #[cfg(not(unix))]
        {
            use std::io::Write as _;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&tmp)?;
            file.write_all(payload)?;
            file.sync_all()?;
        }
        std::fs::rename(&tmp, path)
    }

    /// Serializes `bundle` for the state file, if a state path exists.
    pub(super) fn serialized_bundle(
        &self,
        bundle: &ConfigBundle,
    ) -> std::io::Result<Option<(PathBuf, Vec<u8>)>> {
        let path = sito_core::sync::lock_or_recover(&self.state_path).clone();
        let Some(path) = path else {
            return Ok(None);
        };
        let state = PersistedMasterState {
            bundle: bundle.clone(),
            signing_key_pubkey: Some(self.signing_key.public_key_hex()),
        };
        let payload = serde_json::to_vec_pretty(&state).map_err(|e| {
            std::io::Error::other(format!("failed to serialize HA master state: {e}"))
        })?;
        Ok(Some((path, payload)))
    }

    /// Persists `bundle` synchronously.
    pub(super) fn persist_bundle(&self, bundle: &ConfigBundle) -> std::io::Result<()> {
        if let Some((path, payload)) = self.serialized_bundle(bundle)? {
            Self::write_state_file(&path, &payload)?;
        }
        Ok(())
    }

    /// Persists `bundle` on the blocking pool.
    ///
    /// The caller thread only clones the path/payload; all filesystem work
    /// (directory creation, 0600 write, `sync_all`, rename) runs in
    /// `spawn_blocking` so a slow disk cannot stall a tokio worker.
    pub(super) async fn persist_bundle_async(&self, bundle: &ConfigBundle) -> std::io::Result<()> {
        let Some((path, payload)) = self.serialized_bundle(bundle)? else {
            return Ok(());
        };
        #[cfg(test)]
        let version = bundle.version;
        #[cfg(test)]
        let hook = sito_core::sync::lock_or_recover(&self.state_write_hook).clone();
        tokio::task::spawn_blocking(move || {
            #[cfg(test)]
            if let Some(hook) = hook.as_ref() {
                hook(version);
            }
            Self::write_state_file(&path, &payload)
        })
        .await
        .map_err(|e| std::io::Error::other(format!("HA state writer task failed: {e}")))?
    }

    /// Restores the persisted version/bundle, if any.
    ///
    /// A corrupt state file is moved aside and treated as absent so a master
    /// never silently publishes a rollback; the sequence then restarts from a
    /// fresh v1 only when no state can be recovered.
    pub fn restore_state(&self) -> Result<Option<u64>, HaError> {
        let path = sito_core::sync::lock_or_recover(&self.state_path).clone();
        let Some(path) = path else {
            return Ok(None);
        };
        let data = match std::fs::read_to_string(&path) {
            Ok(data) => data,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => {
                return Err(HaError::Validation {
                    field: "ha_state".to_string(),
                    reason: format!("Failed to read {}: {e}", path.display()),
                });
            }
        };
        let state: PersistedMasterState = match serde_json::from_str(&data) {
            Ok(state) => state,
            Err(e) => {
                let backup = path.with_extension(format!("corrupt.{}", Utc::now().timestamp()));
                if let Err(rename_err) = std::fs::rename(&path, &backup) {
                    warn!(error = %rename_err, "Failed to move corrupt HA state aside");
                }
                warn!(
                    error = %e,
                    backup = %backup.display(),
                    "Corrupt HA state detected; backing up and starting fresh"
                );
                return Ok(None);
            }
        };
        if let Some(expected) = state.signing_key_pubkey {
            let actual = self.signing_key.public_key_hex();
            if expected != actual {
                return Err(HaError::Validation {
                    field: "ha_signing_key".to_string(),
                    reason: format!(
                        "HA state at {} was written by signing key {expected}, but the loaded key is {actual}. ha_signing.key was lost or replaced. Restore the original key from backup, or delete the state file and re-enroll every slave with this master's new master_pubkey after an explicit higher-version promotion",
                        path.display()
                    ),
                });
            }
        }
        let bundle = state.bundle;
        if bundle.version == 0 {
            return Ok(None);
        }
        if bundle.version == u64::MAX {
            // A state file at the ceiling can never advance again. Treat it as
            // a hard error instead of silently resuming a frozen master; the
            // operator must restore a backup or re-seed the sequence.
            return Err(HaError::Validation {
                field: "version".to_string(),
                reason: format!(
                    "Persisted HA state at {} has version u64::MAX and can never advance; restore the state file from backup or re-seed an explicit version",
                    path.display()
                ),
            });
        }
        if bundle.term == u64::MAX {
            return Err(HaError::Validation {
                field: "term".to_string(),
                reason: format!(
                    "Persisted HA state at {} has term u64::MAX and can never advance; restore the state file from backup or re-seed an explicit term",
                    path.display()
                ),
            });
        }
        // State files written by older versions may still embed structured
        // client secrets; strip them before signing/broadcasting.
        let mut bundle = bundle;
        bundle.strip_structured_secrets();
        let push = build_and_sign_push(&bundle, &self.signing_key)?;
        Self::ensure_push_fits(&push)?;
        self.current_version.store(bundle.version, Ordering::SeqCst);
        self.current_term.store(bundle.term, Ordering::SeqCst);
        *sito_core::sync::lock_or_recover(&self.active_bundle) = Some(bundle.clone());
        *sito_core::sync::lock_or_recover(&self.active_push) = Some(push.clone());
        self.record_published_envelope(&push);
        // Upgrade a legacy state file with the signing-key identity so a
        // future key loss is detectable. A write failure here is actionable:
        // silently continuing would keep the key-loss blind spot.
        self.persist_bundle(&bundle)?;
        #[allow(clippy::cast_precision_loss)]
        {
            self.metrics
                .set_ha_config_version("local", bundle.version as f64);
            self.metrics
                .set_ha_config_version(&self.instance_name, bundle.version as f64);
        }
        info!(
            version = bundle.version,
            "Restored persisted HA master state"
        );
        Ok(Some(bundle.version))
    }

    /// Sets the heartbeat ping interval (used for the liveness watchdog).
    #[must_use]
    pub fn with_ping_interval_secs(mut self, secs: u64) -> Self {
        self.ping_interval_secs = secs.max(1);
        self
    }

    /// Sets the required slave authentication token.
    #[must_use]
    pub fn with_token(mut self, token: Option<String>) -> Self {
        self.slave_token = token;
        self
    }

    /// Returns the currently active master configuration version.
    pub fn get_current_version(&self) -> u64 {
        self.current_version.load(Ordering::SeqCst)
    }

    /// Returns the current cluster epoch/term.
    pub fn get_current_term(&self) -> u64 {
        self.current_term.load(Ordering::SeqCst)
    }

    /// Returns true when any divergence (version gap, stale term, or fork) is
    /// currently latched.
    pub fn is_diverged(&self) -> bool {
        !sito_core::sync::lock_or_recover(&self.diverged).is_empty()
    }

    /// Returns the most severe recorded divergence reason, if any.
    pub fn diverged_reason(&self) -> Option<String> {
        sito_core::sync::lock_or_recover(&self.diverged)
            .values()
            .max_by_key(|d| (d.kind, d.acked_version, d.acked_term))
            .map(|d| d.reason.clone())
    }
}
