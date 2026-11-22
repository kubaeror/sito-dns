//! HA master session state machine.
//!
//! The WebSocket I/O loop lives in `session.rs`; this module owns admission,
//! registration, heartbeat decisions, and teardown so protocol state does not
//! leak into transport code.

#[allow(clippy::wildcard_imports)]
use super::*;

/// Fields carried by a slave `Hello`.
pub(super) struct HelloFields {
    pub instance: String,
    pub have_version: u64,
    pub have_term: u64,
    pub capabilities: Vec<String>,
    pub token: Option<String>,
    pub role: Option<String>,
    pub protocol_version: Option<u32>,
    /// Applied signed-payload hash advertised by the slave, if any.
    pub have_bundle_hash: Option<String>,
}

/// The per-connection identity and negotiated state.
pub(super) struct SessionState {
    pub slave_instance: String,
    pub connection_id: u64,
    pub peer_addr: SocketAddr,
    pub capabilities: Vec<String>,
    pub have_version: u64,
    pub have_term: u64,
    pub have_bundle_hash: Option<String>,
}

impl SessionState {
    fn new(
        slave_instance: String,
        connection_id: u64,
        peer_addr: SocketAddr,
        capabilities: Vec<String>,
        have_version: u64,
        have_term: u64,
        have_bundle_hash: Option<String>,
    ) -> Self {
        Self {
            slave_instance,
            connection_id,
            peer_addr,
            capabilities,
            have_version,
            have_term,
            have_bundle_hash,
        }
    }
}

/// What the session loop should do on a heartbeat tick.
pub(super) enum HeartbeatAction {
    Superseded,
    Stale,
    Ping(u64),
}

pub(super) struct SessionMachine<'a> {
    coordinator: &'a MasterCoordinator,
    pub state: SessionState,
    ping_secs: u64,
}

impl<'a> SessionMachine<'a> {
    /// Validates a Hello (protocol, role, token, version continuity) and
    /// returns a machine only when the peer may be admitted.
    ///
    /// Returns `Err(reason)` for a peer that must be closed. The reason is an
    /// operator-facing, actionable `protocol_mismatch: ...` explanation where
    /// applicable. A rejected peer is never registered and never affects the
    /// coordinator's own readiness; the listener keeps serving other slaves.
    pub(super) fn admit(
        coordinator: &'a MasterCoordinator,
        peer_addr: SocketAddr,
        hello: HelloFields,
    ) -> Result<Self, String> {
        let HelloFields {
            instance: slave_instance,
            have_version,
            have_term,
            capabilities,
            token,
            role,
            protocol_version,
            have_bundle_hash,
        } = hello;

        // Protocol version negotiation: a Hello without the field comes from a
        // v1 slave, which is not compatible with v2 semantics.
        let peer_version = protocol_version.unwrap_or(1);
        if peer_version != crate::protocol::PROTOCOL_VERSION {
            let reason = format!(
                "protocol_mismatch: slave '{slave_instance}' speaks HA protocol v{peer_version} but this master requires v{}. Upgrade the slave (or this master) so both run the same HA protocol",
                crate::protocol::PROTOCOL_VERSION
            );
            coordinator
                .metrics
                .inc_ha_protocol_rejection("master", "version_mismatch");
            error!(
                instance = %slave_instance,
                peer = %peer_addr,
                version = peer_version,
                expected = crate::protocol::PROTOCOL_VERSION,
                "{reason}"
            );
            return Err(reason);
        }

        // Role validation: only replica slaves may connect.
        match role.as_deref() {
            Some("slave") => {}
            Some(other) => {
                return Err(format!(
                    "invalid_role: instance '{slave_instance}' announced role '{other}'; only role \"slave\" may connect to a master"
                ));
            }
            None => {
                warn!(
                    instance = %slave_instance,
                    peer = %peer_addr,
                    "Legacy Hello without role field; assuming slave for backwards compatibility"
                );
            }
        }

        // Verify slave authentication token if configured (constant-time compare)
        if let Some(ref required_token) = coordinator.slave_token {
            let provided = token.as_deref().unwrap_or("");
            let tokens_match = provided.len() == required_token.len()
                && bool::from(provided.as_bytes().ct_eq(required_token.as_bytes()));
            if !tokens_match {
                return Err(format!(
                    "authentication_failed: slave '{slave_instance}' presented an invalid or missing token; check the shared [ha] slave_token"
                ));
            }
        }

        info!(
            instance = %slave_instance,
            have_version,
            have_bundle_hash = ?have_bundle_hash,
            peer = %peer_addr,
            "Received authenticated Hello from replica slave"
        );

        // Reject implausible peer versions before they can influence the local
        // sequence. An authenticated replica reporting `u64::MAX` (or any
        // value far beyond the master's counter) would otherwise seed the
        // version and make every subsequent publish non-monotonic.
        let current = coordinator.get_current_version();
        if have_version > current.saturating_add(MAX_PEER_VERSION_LEAD) {
            error!(
                instance = %slave_instance,
                peer = %peer_addr,
                have_version,
                current,
                max_lead = MAX_PEER_VERSION_LEAD,
                "Rejecting Hello with an implausible have_version"
            );
            return Err(format!(
                "implausible_version: slave '{slave_instance}' reported have_version {have_version}, more than {MAX_PEER_VERSION_LEAD} above this master's {current}; fix the slave's ha_state/watermark"
            ));
        }

        // Term/version continuity is checked, never repaired automatically from
        // peer input. Surface the divergence and require explicit promotion.
        let current = coordinator.get_current_version();
        let current_term = coordinator.get_current_term();
        if have_term > current_term {
            let reason = format!(
                "slave '{slave_instance}' reports term {have_term} above the master's term {current_term}: this master is stale and must not overwrite the cluster"
            );
            error!(
                instance = %slave_instance,
                peer = %peer_addr,
                have_term,
                current_term,
                "{reason}"
            );
            coordinator.mark_diverged(
                DivergenceKind::Term,
                &slave_instance,
                have_version,
                have_term,
                reason,
            );
        }
        if have_term == current_term && have_version > current {
            let reason = format!(
                "slave '{slave_instance}' reports version {have_version} above the master's version {current} in term {current_term}: version continuity is broken (promoted slave or lost/corrupt ha_state.toml); explicit promotion is required"
            );
            error!(
                instance = %slave_instance,
                peer = %peer_addr,
                have_version,
                current,
                current_term,
                "{reason}"
            );
            coordinator.mark_diverged(
                DivergenceKind::Ahead,
                &slave_instance,
                have_version,
                current_term,
                reason,
            );
        }

        let ping_secs = coordinator.ping_interval_secs.max(1);
        let state = SessionState::new(
            slave_instance,
            coordinator
                .next_connection_id
                .fetch_add(1, Ordering::Relaxed),
            peer_addr,
            capabilities,
            have_version,
            have_term,
            have_bundle_hash,
        );
        Ok(Self {
            coordinator,
            state,
            ping_secs,
        })
    }

    /// Registers the slave and queues the current bundle. Returns the outgoing
    /// receiver; the sender is retained in the tracker.
    pub(super) fn register(&self) -> mpsc::Receiver<HaMessage> {
        let slave_instance = &self.state.slave_instance;
        let connection_id = self.state.connection_id;
        let (tx, rx) = mpsc::channel::<HaMessage>(32);

        // Register slave in tracking map. A reconnecting instance replaces the
        // previous entry; `connection_id` lets the superseded session detect
        // that it no longer owns the entry.
        {
            let mut slaves = sito_core::sync::lock_or_recover(&self.coordinator.slaves);
            // A reconnecting instance starts with an empty queue; accounting
            // from every superseded session must not leak into the new one.
            {
                let mut queued = sito_core::sync::lock_or_recover(&self.coordinator.queued_bytes);
                queued.retain(|(instance, _), _| instance != slave_instance);
                queued.insert((slave_instance.clone(), connection_id), 0);
            }
            slaves.insert(
                slave_instance.clone(),
                ActiveSlave {
                    instance: slave_instance.clone(),
                    remote_addr: self.state.peer_addr,
                    // Never trust the peer's Hello claim for the *reported*
                    // synced version: only an applied ACK proves it.
                    synced_version: 0,
                    last_ping: Instant::now(),
                    connected_at: Utc::now(),
                    last_stats: None,
                    sender: tx.clone(),
                    capabilities: self.state.capabilities.clone(),
                    have_term: self.state.have_term,
                    have_version: self.state.have_version,
                    have_bundle_hash: self.state.have_bundle_hash.clone(),
                    connection_id,
                },
            );
            #[allow(clippy::cast_possible_wrap)]
            self.coordinator
                .metrics
                .set_ha_slaves_connected(slaves.len() as i64);
            self.coordinator
                .metrics
                .set_ha_config_version(slave_instance, 0.0);
        }

        // Hello-only reconciliation mode accepts the connection and records
        // the peer's report but sends no `ConfigPush`: a forked slave must not
        // apply a pending bundle before the window's checks complete.
        if self.coordinator.is_hello_only() {
            info!(
                instance = %slave_instance,
                have_version = self.state.have_version,
                have_term = self.state.have_term,
                have_bundle_hash = ?self.state.have_bundle_hash,
                "Reconciliation window: registered hello-only slave; no push queued"
            );
            return rx;
        }

        // Always enqueue the current push on connect; a slave that is already
        // up to date acknowledges without re-applying.
        if let Some(ref push) = *sito_core::sync::lock_or_recover(&self.coordinator.active_push) {
            let cur_v = self.coordinator.get_current_version();
            info!(
                instance = %slave_instance,
                have_version = self.state.have_version,
                cur_v,
                "Pushing current configuration bundle to newly connected slave"
            );
            let push_bytes = wire_size(push);
            if let Err(e) = self.coordinator.try_queue_accounted(
                slave_instance,
                connection_id,
                &tx,
                push_bytes,
                push.clone(),
            ) {
                warn!(instance = %slave_instance, error = %e, "Initial HA push could not be queued; coalescing");
                self.coordinator.schedule_coalesced_delivery(
                    slave_instance,
                    connection_id,
                    &tx,
                    push,
                );
            }
        }
        rx
    }

    pub(super) fn ping_secs(&self) -> u64 {
        self.ping_secs
    }

    pub(super) fn heartbeat(&self) -> HeartbeatAction {
        let volume = Duration::from_secs(self.ping_secs.saturating_mul(3));
        let (superseded, stale) = {
            let slaves = sito_core::sync::lock_or_recover(&self.coordinator.slaves);
            match slaves.get(&self.state.slave_instance) {
                Some(s) if s.connection_id == self.state.connection_id => {
                    (false, s.last_ping.elapsed() > volume)
                }
                // Replaced by a newer connection (or removed): this session
                // must stop acting on the entry.
                _ => (true, false),
            }
        };
        if superseded {
            HeartbeatAction::Superseded
        } else if stale {
            HeartbeatAction::Stale
        } else {
            #[allow(clippy::cast_sign_loss)]
            let ts = Utc::now().timestamp_millis() as u64;
            HeartbeatAction::Ping(ts)
        }
    }

    pub(super) fn record_pong(&self) {
        let mut slaves = sito_core::sync::lock_or_recover(&self.coordinator.slaves);
        if let Some(s) = slaves.get_mut(&self.state.slave_instance)
            && s.connection_id == self.state.connection_id
        {
            s.last_ping = Instant::now();
        }
    }

    pub(super) fn account_drained(&self, wire_size: usize) {
        self.coordinator.account_drained(
            &self.state.slave_instance,
            self.state.connection_id,
            wire_size,
        );
    }

    pub(super) fn on_text(&self, text: &str) -> bool {
        self.coordinator.process_slave_msg(
            &self.state.slave_instance,
            self.state.connection_id,
            text,
        )
    }

    pub(super) fn unregister(&self) -> bool {
        let removed = self
            .coordinator
            .unregister_session(&self.state.slave_instance, self.state.connection_id);
        if removed {
            self.coordinator
                .metrics
                .remove_ha_config_version(&self.state.slave_instance);
            info!(
                instance = %self.state.slave_instance,
                "Unregistered replica slave from active tracker"
            );
        } else {
            debug!(
                instance = %self.state.slave_instance,
                "Superseded HA session ended; live entry left untouched"
            );
        }
        removed
    }
}
