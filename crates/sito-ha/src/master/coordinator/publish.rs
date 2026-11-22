//! Publish/ACK, envelope history, divergence, and queue accounting.

#[allow(clippy::wildcard_imports)]
use super::*;

/// Counts returned by a broadcast attempt.
///
/// `queued` counts direct channel enqueues, `coalesced` counts deferred
/// fallback tasks, and `connected` is the number of tracked slave entries.
/// Delivery is acknowledged separately by the slave's ACK.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct BroadcastOutcome {
    pub connected: usize,
    pub queued: usize,
    pub coalesced: usize,
}

impl MasterCoordinator {
    /// Records a divergence for one instance, keeping the most severe kind and
    /// version that instance reported.
    ///
    /// Records are deliberately sticky: nothing here is cleared by an
    /// unrelated version advance or by another slave's success. Only that
    /// slave's applied ACK for the master's current term/version, an explicit
    /// disconnect, or an explicit operator promotion clears them.
    pub(super) fn mark_diverged(
        &self,
        kind: DivergenceKind,
        instance: &str,
        acked_version: u64,
        acked_term: u64,
        reason: String,
    ) {
        let mut diverged = sito_core::sync::lock_or_recover(&self.diverged);
        if diverged
            .get(instance)
            .is_none_or(|d| (kind, acked_version) >= (d.kind, d.acked_version))
        {
            diverged.insert(
                instance.to_string(),
                Divergence {
                    kind,
                    acked_version,
                    acked_term,
                    reason,
                },
            );
            self.metrics.set_ha_diverged(instance, true);
        }
    }

    /// Clears one instance's divergence record after it successfully applied
    /// the master's current bundle/term.
    ///
    /// Divergence is per-slave and clearing it is per-slave: an operator
    /// resync only re-pushes the bundle and never clears another slave's
    /// advisory record before that slave proves recovery by ACKing the current
    /// term/version.
    pub(super) fn clear_divergence_for(&self, instance: &str) {
        let slaves = sito_core::sync::lock_or_recover(&self.slaves);
        let mut diverged = sito_core::sync::lock_or_recover(&self.diverged);
        if diverged.remove(instance).is_some() && slaves.contains_key(instance) {
            self.metrics.set_ha_diverged(instance, false);
        }
    }

    /// Validates monotonicity, sanitizes and signs `bundle` without publishing
    /// it. Returns the prepared bundle, version, push message and the version
    /// that was current at validation time. The caller must hold
    /// [`Self::publish_lock`].
    pub(super) fn prepare_bundle(
        &self,
        bundle: ConfigBundle,
    ) -> Result<(ConfigBundle, u64, HaMessage, u64), HaError> {
        // Secret material must never be stored, persisted or signed: the
        // structured `clients` value is sanitized exactly like `config_toml`.
        let mut bundle = bundle;
        bundle.strip_structured_secrets();
        // Bind the signed identity before persisting or broadcasting so the
        // stored bundle, the pushed envelope, and the slave watermark all name
        // the same key/config digest.
        seal_bundle_identity(&mut bundle, &self.signing_key.public_key());

        let version = bundle.version;
        let current = self.current_version.load(Ordering::SeqCst);
        if version <= current {
            return Err(HaError::Validation {
                field: "version".to_string(),
                reason: format!(
                    "Refusing to publish non-monotonic configuration version {version} (current {current})"
                ),
            });
        }
        if version == u64::MAX {
            return Err(HaError::Validation {
                field: "version".to_string(),
                reason: "Refusing to publish configuration version u64::MAX: the sequence could never advance again"
                    .to_string(),
            });
        }
        let current_term = self.get_current_term();
        if bundle.term != current_term {
            return Err(HaError::Validation {
                field: "term".to_string(),
                reason: format!(
                    "Refusing to publish bundle term {} while the master is at term {current_term}; term changes are an explicit promotion",
                    bundle.term
                ),
            });
        }
        if bundle.term == u64::MAX {
            return Err(HaError::Validation {
                field: "term".to_string(),
                reason: "Refusing to publish term u64::MAX: the epoch could never advance again"
                    .to_string(),
            });
        }

        let push_msg = build_and_sign_push(&bundle, &self.signing_key)?;
        Self::ensure_push_fits(&push_msg)?;
        Ok((bundle, version, push_msg, current))
    }

    /// Rejects a signed envelope that cannot fit the WebSocket message limit
    /// before it is persisted or broadcast. An oversized bundle must be an
    /// apply error, not a config that every slave rejects forever.
    pub(super) fn ensure_push_fits(push: &HaMessage) -> Result<(), HaError> {
        // `wire_size` reports 0 for a message it cannot serialize; use the
        // fallible length here so an impossible serialization failure cannot
        // silently bypass the size guard.
        let bytes = push
            .to_json()
            .map_err(|e| {
                HaError::Serialization(format!(
                    "Failed to measure the signed HA push before broadcast: {e}"
                ))
            })?
            .len();
        if bytes > MAX_WS_MESSAGE_SIZE {
            return Err(HaError::BundleTooLarge {
                bytes,
                limit: MAX_WS_MESSAGE_SIZE,
            });
        }
        Ok(())
    }

    /// Records a published envelope in the bounded ACK-binding history.
    pub(super) fn record_published_envelope(&self, push: &HaMessage) {
        let HaMessage::ConfigPush {
            term,
            version,
            payload_hash_blake3,
            ..
        } = push
        else {
            return;
        };
        let mut history = sito_core::sync::lock_or_recover(&self.active_push_history);
        history.push_back(PublishedEnvelope {
            term: *term,
            version: *version,
            payload_hash: payload_hash_blake3
                .trim_start_matches("blake3:")
                .to_string(),
        });
        while history.len() > MAX_PUBLISH_HISTORY {
            history.pop_front();
        }
    }

    /// Publishes a prepared bundle. The caller must hold
    /// [`Self::publish_lock`] and have persisted the bundle first.
    pub(super) fn publish_prepared(
        &self,
        bundle: ConfigBundle,
        version: u64,
        push_msg: &HaMessage,
    ) {
        if !self.is_serving() {
            warn!(
                version,
                "Refusing to install an active bundle while the master is not serving"
            );
            return;
        }
        if self.is_hello_only() {
            warn!(
                version,
                "Refusing to install an active bundle during hello-only reconciliation"
            );
            return;
        }
        self.current_version.store(version, Ordering::SeqCst);
        *sito_core::sync::lock_or_recover(&self.active_bundle) = Some(bundle);
        *sito_core::sync::lock_or_recover(&self.active_push) = Some(push_msg.clone());
        self.record_published_envelope(push_msg);
    }

    /// Publishes the active configuration version to the HA metrics.
    pub(super) fn record_published_version(&self, version: u64) {
        #[allow(clippy::cast_precision_loss)]
        {
            self.metrics.set_ha_config_version("local", version as f64);
            self.metrics
                .set_ha_config_version(&self.instance_name, version as f64);
        }
    }

    /// Advances the in-memory/durable promotion baseline from a prepared push.
    fn record_published_from_push(&self, push: &HaMessage) {
        if let HaMessage::ConfigPush {
            version,
            payload_hash_blake3,
            ..
        } = push
        {
            self.record_published_baseline(*version, payload_hash_blake3);
        }
    }

    /// Publishes a bundle already validated by the ADR-0010 promotion engine.
    ///
    /// Unlike [`Self::update_bundle`], this accepts an equal version when the
    /// engine is publishing a pending bundle at the term it re-acquired. The
    /// engine has already confirmed the version is above the published
    /// baseline; this method must not be used by normal API publishes.
    pub fn publish_promoted_bundle(&self, bundle: ConfigBundle) -> Result<String, HaError> {
        let mut bundle = bundle;
        bundle.strip_structured_secrets();
        seal_bundle_identity(&mut bundle, &self.signing_key.public_key());
        let current = self.get_current_version();
        if bundle.version < current {
            return Err(HaError::Validation {
                field: "version".to_string(),
                reason: format!(
                    "promotion publish version {} is below the active version {current}",
                    bundle.version
                ),
            });
        }
        if bundle.term != self.get_current_term() {
            return Err(HaError::Validation {
                field: "term".to_string(),
                reason: format!(
                    "promotion publish term {} does not match the coordinator term {}",
                    bundle.term,
                    self.get_current_term()
                ),
            });
        }
        let push = build_and_sign_push(&bundle, &self.signing_key)?;
        Self::ensure_push_fits(&push)?;
        let hash = crate::bundle::push_payload_hash(&push)?;
        let version = bundle.version;
        {
            let _publish_guard = sito_core::sync::lock_or_recover(&self.publish_lock);
            self.persist_bundle(&bundle)?;
            self.publish_prepared(bundle.clone(), version, &push);
        }
        self.record_published_from_push(&push);
        self.persist_bundle(&bundle)?;
        self.record_published_version(version);
        self.broadcast(&push);
        Ok(hash)
    }

    /// Makes a bundle published by an interrupted promotion active without
    /// re-pushing it. Used only by the ADR-0010 reconciliation recovery path.
    pub fn adopt_promoted_bundle(&self, bundle: ConfigBundle) -> Result<String, HaError> {
        let mut bundle = bundle;
        bundle.strip_structured_secrets();
        seal_bundle_identity(&mut bundle, &self.signing_key.public_key());
        if bundle.term != self.get_current_term() {
            return Err(HaError::Validation {
                field: "term".to_string(),
                reason: format!(
                    "adopted promotion term {} does not match the coordinator term {}",
                    bundle.term,
                    self.get_current_term()
                ),
            });
        }
        let push = build_and_sign_push(&bundle, &self.signing_key)?;
        Self::ensure_push_fits(&push)?;
        let hash = crate::bundle::push_payload_hash(&push)?;
        let version = bundle.version;
        {
            let _publish_guard = sito_core::sync::lock_or_recover(&self.publish_lock);
            self.persist_bundle(&bundle)?;
            self.publish_prepared(bundle, version, &push);
        }
        self.record_published_version(version);
        Ok(hash)
    }

    /// Returns the signed-payload hash of the current active bundle.
    #[must_use]
    pub fn active_payload_hash(&self) -> Option<String> {
        sito_core::sync::lock_or_recover(&self.active_push)
            .as_ref()
            .and_then(|push| crate::bundle::push_payload_hash(push).ok())
    }

    /// Stops serving and drops every tracked replication session (fence path).
    pub fn close_all_sessions(&self) {
        self.set_serving(false);
        let mut slaves = sito_core::sync::lock_or_recover(&self.slaves);
        slaves.clear();
        self.metrics.set_ha_slaves_connected(0);
    }

    /// Sets and signs a new configuration bundle, immediately broadcasting it to all connected slaves.
    ///
    /// This synchronous variant is startup/test-only: `init_ha` publishes the
    /// initial bundle before the async replication loop starts. It does not take
    /// [`Self::persist_lock`], so it must not race [`Self::update_bundle_async`]
    /// in production, otherwise a sync write landing during an async
    /// conflict-restore could overwrite the newer state file.
    pub fn update_bundle(&self, bundle: ConfigBundle) -> Result<u64, HaError> {
        let result = self.update_bundle_inner(bundle);
        self.record_publish_result(&result);
        result
    }

    pub(super) fn update_bundle_inner(&self, bundle: ConfigBundle) -> Result<u64, HaError> {
        if !self.is_serving() {
            return Err(HaError::Validation {
                field: "ha_promotion".to_string(),
                reason: "configuration publishes are disabled while the master is not serving"
                    .to_string(),
            });
        }
        if self.is_hello_only() {
            return Err(HaError::Validation {
                field: "ha_promotion".to_string(),
                reason: "configuration publishes are disabled during hello-only reconciliation"
                    .to_string(),
            });
        }
        // Serialize the check-then-store: two concurrent publishers could
        // otherwise both pass the monotonicity check and store out of order,
        // regressing the active version and broadcasting a stale bundle.
        let _publish_guard = sito_core::sync::lock_or_recover(&self.publish_lock);

        let (bundle, version, push_msg, _previous) = self.prepare_bundle(bundle)?;
        // Persist before publishing: a failed write must leave both the
        // in-memory active bundle/push and the version sequence untouched.
        let bundle_for_state = bundle.clone();
        let promotion_baseline = self.promotion_bookkeeping().is_some();
        self.persist_bundle(&bundle)?;
        self.publish_prepared(bundle, version, &push_msg);
        if promotion_baseline {
            // ADR-0010: after a successful publish the durable published
            // baseline advances with the active bundle. The witness is renewed
            // by the promotion engine only after this second write, so an
            // unpublished version is never advertised.
            self.record_published_from_push(&push_msg);
            self.persist_bundle(&bundle_for_state)?;
        }
        self.record_published_version(version);

        // Broadcast to all active slaves
        self.broadcast(&push_msg);

        info!(
            version,
            "Master updated configuration bundle and broadcasted push to connected slaves"
        );

        Ok(version)
    }

    pub(super) fn record_publish_result<T>(&self, result: &Result<T, HaError>) {
        match result {
            Ok(_) => self.set_publish_error(None),
            Err(HaError::BundleTooLarge { bytes, limit }) => self.set_publish_error(Some(format!(
                "bundle would be {bytes} bytes, above the {limit}-byte replication limit"
            ))),
            Err(e) => self.set_publish_error(Some(e.to_string())),
        }
    }

    /// Async variant of [`Self::update_bundle`] that persists state on the
    /// blocking pool.
    ///
    /// `persist_lock` serializes the whole publish-and-write sequence so two
    /// concurrent async publishers cannot complete their state writes out of
    /// order. The standard `publish_lock` is only held for the in-memory
    /// check/store/sign step and is dropped before awaiting the disk write.
    pub async fn update_bundle_async(&self, bundle: ConfigBundle) -> Result<u64, HaError> {
        let result = self.update_bundle_async_inner(bundle).await;
        self.record_publish_result(&result);
        result.map(|(version, _)| version)
    }

    /// Publishes a bundle and reports the observable outcome.
    ///
    /// This is the variant API/config callers use: a `TooLarge` outcome is not
    /// a transport error, it is a configuration that cannot be replicated and
    /// must be treated as an apply error by the caller. Publication failures
    /// are also recorded in HA readiness. `TooLarge` is deliberately not
    /// retried in the background: retrying the same document cannot shrink it,
    /// so the caller must change the configuration.
    pub async fn publish_bundle_async(
        &self,
        bundle: ConfigBundle,
    ) -> Result<PublishOutcome, HaError> {
        match self.update_bundle_async_inner(bundle).await {
            Ok((version, broadcast)) => {
                self.set_publish_error(None);
                if broadcast.connected == 0 {
                    Ok(PublishOutcome::NoSlaves)
                } else {
                    Ok(PublishOutcome::Published {
                        version,
                        term: self.get_current_term(),
                        slaves_connected: broadcast.connected,
                        slaves_queued: broadcast.queued,
                        slaves_coalesced: broadcast.coalesced,
                    })
                }
            }
            Err(HaError::BundleTooLarge { bytes, limit }) => {
                self.set_publish_error(Some(format!(
                    "bundle would be {bytes} bytes, above the {limit}-byte replication limit"
                )));
                Ok(PublishOutcome::TooLarge { bytes, limit })
            }
            Err(e) => {
                self.set_publish_error(Some(e.to_string()));
                Err(e)
            }
        }
    }

    pub(super) async fn update_bundle_async_inner(
        &self,
        bundle: ConfigBundle,
    ) -> Result<(u64, BroadcastOutcome), HaError> {
        if !self.is_serving() {
            return Err(HaError::Validation {
                field: "ha_promotion".to_string(),
                reason: "configuration publishes are disabled while the master is not serving"
                    .to_string(),
            });
        }
        if self.is_hello_only() {
            return Err(HaError::Validation {
                field: "ha_promotion".to_string(),
                reason: "configuration publishes are disabled during hello-only reconciliation"
                    .to_string(),
            });
        }
        let _persist_guard = self.persist_lock.lock().await;

        let (bundle, version, push_msg, previous_version) = {
            let _publish_guard = sito_core::sync::lock_or_recover(&self.publish_lock);
            self.prepare_bundle(bundle)?
        };

        // Persist the prepared document first. Until this succeeds nothing is
        // visible through `active_push`/`current_version`, so a newly
        // connecting slave can never receive a bundle the master did not
        // durably publish.
        let bundle_for_state = bundle.clone();
        let promotion_baseline = self.promotion_bookkeeping().is_some();
        if let Err(e) = self.persist_bundle_async(&bundle).await {
            error!(error = %e, "Failed to persist HA master state");
            return Err(HaError::Io(e));
        }

        let conflict = {
            let _publish_guard = sito_core::sync::lock_or_recover(&self.publish_lock);
            // A synchronous publisher may have advanced the sequence while the
            // write was in flight. Publishing our older prepared version would
            // regress the cluster, so report the conflict and restore the
            // now-active bundle instead. Only detect and clone under the
            // standard lock: it must never be held across the awaited write.
            if self.current_version.load(Ordering::SeqCst) == previous_version {
                self.publish_prepared(bundle, version, &push_msg);
                None
            } else {
                Some(sito_core::sync::lock_or_recover(&self.active_bundle).clone())
            }
        };

        if let Some(active) = conflict {
            // `persist_lock` is still held, so no async publisher can interleave
            // with this restore. The write runs on the blocking pool: a
            // synchronous `std::fs` write here would stall a tokio worker.
            if let Some(active) = active
                && let Err(e) = self.persist_bundle_async(&active).await
            {
                error!(error = %e, "Failed to restore HA master state after a concurrent publish");
            }
            return Err(HaError::Validation {
                field: "version".to_string(),
                reason: format!(
                    "Concurrent publish advanced the HA configuration version above {version}"
                ),
            });
        }

        if promotion_baseline {
            // ADR-0010: persist the advanced published baseline only after the
            // active bundle is published in memory. A failure here is a publish
            // failure and no broadcast is attempted with an unrecorded baseline.
            self.record_published_from_push(&push_msg);
            if let Err(e) = self.persist_bundle_async(&bundle_for_state).await {
                error!(error = %e, "Failed to persist the published promotion baseline");
                return Err(HaError::Io(e));
            }
        }
        self.record_published_version(version);

        // Broadcast to all active slaves. Keep connected/queued/coalesced
        // counts distinct: a connected slave with a closed channel must not
        // turn the outcome into NoSlaves.
        let broadcast = self.broadcast_with_counts(&push_msg);

        info!(
            version,
            connected = broadcast.connected,
            queued = broadcast.queued,
            coalesced = broadcast.coalesced,
            "Master updated configuration bundle and broadcasted push to connected slaves"
        );

        Ok((version, broadcast))
    }

    /// Broadcasts a message to all connected slaves.
    ///
    /// Returns the number of slaves for which delivery was queued (a full
    /// queue with a coalesced fallback task counts as queued). This is a queue
    /// count, not delivery confirmation.
    pub fn broadcast(&self, msg: &HaMessage) -> usize {
        let outcome = self.broadcast_with_counts(msg);
        outcome.queued + outcome.coalesced
    }

    /// Broadcasts a message and reports connected/queued/coalesced counts.
    ///
    /// A connected slave whose channel is already closed is counted in
    /// `connected` only: it must not disappear from the publish outcome (that
    /// would turn "all channels closed" into a misleading `NoSlaves`).
    pub(super) fn broadcast_with_counts(&self, msg: &HaMessage) -> BroadcastOutcome {
        if !self.is_serving() {
            return BroadcastOutcome {
                connected: sito_core::sync::lock_or_recover(&self.slaves).len(),
                queued: 0,
                coalesced: 0,
            };
        }
        if self.is_hello_only() {
            // The reconcile window is silent: no ConfigPush may reach a peer
            // before the ahead/fork/hash checks complete.
            let connected = sito_core::sync::lock_or_recover(&self.slaves).len();
            debug!(
                connected,
                "Suppressing HA broadcast during hello-only reconciliation"
            );
            return BroadcastOutcome {
                connected,
                queued: 0,
                coalesced: 0,
            };
        }
        let message_bytes = wire_size(msg);
        let mut queued = 0;
        let mut coalesced = 0;
        let slaves = sito_core::sync::lock_or_recover(&self.slaves);
        let connected = slaves.len();
        let mut queued_bytes = sito_core::sync::lock_or_recover(&self.queued_bytes);
        for slave in slaves.values() {
            let instance = &slave.instance;
            let session = (instance.clone(), slave.connection_id);
            let current = queued_bytes.get(&session).copied().unwrap_or(0);
            if message_bytes > 0 && current.saturating_add(message_bytes) > MAX_SLAVE_QUEUE_BYTES {
                // The per-slave byte budget is exhausted even though the
                // message-count channel may still have room: coalesce instead
                // of letting a slow peer pin tens of MiB of bundles.
                warn!(
                    instance = %instance,
                    queued_bytes = current,
                    message_bytes,
                    limit = MAX_SLAVE_QUEUE_BYTES,
                    "HA push byte budget exhausted; scheduling coalesced delivery"
                );
                self.schedule_coalesced_delivery(instance, slave.connection_id, &slave.sender, msg);
                coalesced += 1;
                continue;
            }
            match slave.sender.try_send(msg.clone()) {
                Ok(()) => {
                    if message_bytes > 0 {
                        *queued_bytes.entry(session).or_insert(0) += message_bytes;
                    }
                    queued += 1;
                }
                Err(mpsc::error::TrySendError::Full(_)) => {
                    // Queue is full: do not silently drop the update. Coalesce
                    // fallback deliveries per slave so a slow or stalled replica
                    // cannot spawn unbounded tasks; the task sends the latest
                    // active bundle when the channel has room.
                    self.schedule_coalesced_delivery(
                        instance,
                        slave.connection_id,
                        &slave.sender,
                        msg,
                    );
                    // The push will be delivered by the coalesced fallback
                    // task (either this one or one already pending).
                    coalesced += 1;
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    debug!(instance = %slave.instance, "HA push channel closed");
                }
            }
        }
        BroadcastOutcome {
            connected,
            queued,
            coalesced,
        }
    }

    /// Queues `msg` for one slave session and records its wire size in the
    /// per-session byte budget when the queue accepted it.
    ///
    /// Every non-broadcast send path (initial push, resync, catch-up repush)
    /// must go through this helper so the coalesced-delivery budget reflects
    /// all bytes queued for a slave, not only broadcast traffic. The caller
    /// passes the precomputed `wire_size` so the budget decision and the send
    /// use the same value.
    ///
    /// An over-budget send is refused before touching the channel; callers may
    /// coalesce it instead of growing the queue.
    pub(super) fn try_queue_accounted(
        &self,
        instance: &str,
        connection_id: u64,
        sender: &mpsc::Sender<HaMessage>,
        wire_size: usize,
        msg: HaMessage,
    ) -> Result<(), String> {
        let session = (instance.to_string(), connection_id);
        // Hold the accounting lock across the budget check, `try_send` and the
        // increment: the session loop subtracts under the same lock, and
        // releasing it in between would let the subtract observe the old value
        // and turn the later increment into phantom bytes.
        let mut queued = sito_core::sync::lock_or_recover(&self.queued_bytes);
        // Registration installs the session key and reconnect removes every
        // old key for the instance. A missing key therefore means this sender
        // belongs to a superseded session: refuse instead of recreating
        // accounting for a channel nobody will drain.
        let Some(current) = queued.get(&session).copied() else {
            return Err("slave session is no longer active".to_string());
        };
        if wire_size > 0 && current.saturating_add(wire_size) > MAX_SLAVE_QUEUE_BYTES {
            return Err(format!(
                "per-slave queue byte budget exhausted ({current} + {wire_size} > {MAX_SLAVE_QUEUE_BYTES})"
            ));
        }
        sender.try_send(msg).map_err(|e| e.to_string())?;
        if wire_size > 0 {
            *queued.entry(session).or_insert(0) += wire_size;
        }
        Ok(())
    }

    /// Removes `wire_size` from one session's queued-byte accounting.
    ///
    /// Keying by `(instance, connection_id)` ensures a superseded session that
    /// drains its old channel after a reconnect cannot subtract from the
    /// replacement session's budget.
    pub(super) fn account_drained(&self, instance: &str, connection_id: u64, wire_size: usize) {
        if wire_size == 0 {
            return;
        }
        let mut queued = sito_core::sync::lock_or_recover(&self.queued_bytes);
        if let Some(current) = queued.get_mut(&(instance.to_string(), connection_id)) {
            *current = current.saturating_sub(wire_size);
        }
    }

    /// Schedules at most one coalesced delivery task per slave session.
    ///
    /// The task captures the session's `connection_id` and re-checks ownership
    /// before waiting, delivering, or charging bytes. A superseded task must
    /// never charge the replacement session, and it must stop waiting on the
    /// old session's budget.
    pub(super) fn schedule_coalesced_delivery(
        &self,
        instance: &str,
        connection_id: u64,
        sender: &mpsc::Sender<HaMessage>,
        fallback_msg: &HaMessage,
    ) {
        let instance = instance.to_string();
        let session = (instance.clone(), connection_id);
        let first_schedule =
            sito_core::sync::lock_or_recover(&self.pending_fallbacks).insert(session.clone());
        if !first_schedule {
            debug!(
                instance = %instance,
                connection_id,
                "HA fallback delivery already pending; coalescing push"
            );
            return;
        }
        let coordinator = self.clone();
        let sender = sender.clone();
        let fallback = fallback_msg.clone();
        tokio::spawn(async move {
            // Prefer the latest active bundle; fall back to the message that
            // could not be enqueued.
            let latest = sito_core::sync::lock_or_recover(&coordinator.active_push)
                .clone()
                .or(Some(fallback));
            if let Some(latest) = latest {
                let size = wire_size(&latest);
                // Wait only while this exact session still owns the active
                // entry. After a reconnect the old task must not wait on,
                // deliver to, or charge the replacement session.
                //
                // The bytes are reserved *before* the awaited send: the
                // session loop can receive and subtract as soon as the send
                // completes, so accounting after the await would race and
                // leave phantom bytes.
                let mut reserved = false;
                loop {
                    let (owns, has_room) = {
                        let slaves = sito_core::sync::lock_or_recover(&coordinator.slaves);
                        let owns = slaves
                            .get(&instance)
                            .is_some_and(|s| s.connection_id == connection_id);
                        if owns {
                            let mut queued =
                                sito_core::sync::lock_or_recover(&coordinator.queued_bytes);
                            let current = queued.get(&session).copied().unwrap_or(0);
                            if size == 0 || current.saturating_add(size) <= MAX_SLAVE_QUEUE_BYTES {
                                if size > 0 {
                                    *queued.entry(session.clone()).or_insert(0) += size;
                                }
                                (true, true)
                            } else {
                                (true, false)
                            }
                        } else {
                            (false, false)
                        }
                    };
                    if !owns {
                        break;
                    }
                    if has_room {
                        reserved = true;
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                if reserved && let Err(e) = sender.send(latest).await {
                    // The send failed, so release the reservation. The key may
                    // already be gone if a reconnect superseded this session.
                    if size > 0 {
                        let mut queued =
                            sito_core::sync::lock_or_recover(&coordinator.queued_bytes);
                        if let Some(current) = queued.get_mut(&session) {
                            *current = current.saturating_sub(size);
                        }
                    }
                    warn!(instance = %instance, "Failed to deliver queued HA push: {e}");
                }
            }
            sito_core::sync::lock_or_recover(&coordinator.pending_fallbacks).remove(&session);
        });
    }

    /// Re-pushes the active bundle to one slave that acknowledged a stale
    /// version, at most once per acknowledged version to avoid retry loops.
    pub(super) fn maybe_repush(&self, instance: &str, stale_version: u64) {
        let mut repushed = sito_core::sync::lock_or_recover(&self.stale_repushes);
        if repushed.get(instance) == Some(&stale_version) {
            return;
        }
        repushed.insert(instance.to_string(), stale_version);
        drop(repushed);

        if let Some(push) = sito_core::sync::lock_or_recover(&self.active_push).clone() {
            let target = {
                let slaves = sito_core::sync::lock_or_recover(&self.slaves);
                slaves
                    .get(instance)
                    .map(|slave| (slave.sender.clone(), slave.connection_id))
            };
            if let Some((sender, connection_id)) = target {
                let push_bytes = wire_size(&push);
                if let Err(e) = self.try_queue_accounted(
                    instance,
                    connection_id,
                    &sender,
                    push_bytes,
                    push.clone(),
                ) {
                    warn!(
                        instance = %instance,
                        error = %e,
                        "Catch-up push could not be queued; coalescing"
                    );
                    self.schedule_coalesced_delivery(instance, connection_id, &sender, &push);
                }
            }
        }
    }

    /// Triggers a re-push of the current active configuration bundle to all slaves.
    ///
    /// This is the explicit operator recovery action. It does **not** clear any
    /// divergence record: H-10 requires the record to clear only after that
    /// specific slave ACKs the current term/version, because a queued re-push
    /// is not proof that the slave recovered.
    pub fn trigger_resync(&self) -> ResyncOutcome {
        let push_opt = sito_core::sync::lock_or_recover(&self.active_push).clone();
        let slaves_notified = match push_opt {
            Some(ref push) => self.broadcast(push),
            None => 0,
        };
        ResyncOutcome {
            version: self.get_current_version(),
            active_bundle: push_opt.is_some(),
            slaves_notified,
        }
    }

    /// Returns a list of summaries for all currently connected replica slaves.
    pub fn list_slaves(&self) -> Vec<SlaveSummary> {
        let cur_v = self.get_current_version();
        let slaves = sito_core::sync::lock_or_recover(&self.slaves);
        let diverged = sito_core::sync::lock_or_recover(&self.diverged);
        slaves
            .values()
            .map(|s| s.to_summary(cur_v, diverged.contains_key(&s.instance)))
            .collect()
    }

    /// Returns the count of currently connected slaves.
    pub fn connected_slave_count(&self) -> usize {
        sito_core::sync::lock_or_recover(&self.slaves).len()
    }
}
