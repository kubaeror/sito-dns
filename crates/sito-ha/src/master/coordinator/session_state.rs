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
}

/// The per-connection identity and negotiated state.
pub(super) struct SessionState {
    pub slave_instance: String,
    pub connection_id: u64,
    pub peer_addr: SocketAddr,
    pub capabilities: Vec<String>,
    pub have_version: u64,
}

impl SessionState {
    fn new(
        slave_instance: String,
        connection_id: u64,
        peer_addr: SocketAddr,
        capabilities: Vec<String>,
        have_version: u64,
    ) -> Self {
        Self {
            slave_instance,
            connection_id,
            peer_addr,
            capabilities,
            have_version,
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
    pub(super) fn admit(
        coordinator: &'a MasterCoordinator,
        peer_addr: SocketAddr,
        hello: HelloFields,
    ) -> Option<Self> {
        let HelloFields {
            instance: slave_instance,
            have_version,
            have_term,
            capabilities,
            token,
            role,
            protocol_version,
        } = hello;

        // Protocol version negotiation
        if let Some(version) = protocol_version
            && version != crate::protocol::PROTOCOL_VERSION
        {
            warn!(
                instance = %slave_instance,
                peer = %peer_addr,
                version,
                expected = crate::protocol::PROTOCOL_VERSION,
                "Rejecting slave with incompatible HA protocol version"
            );
            return None;
        }

        // Role validation: only replica slaves may connect.
        match role.as_deref() {
            Some("slave") => {}
            Some(other) => {
                warn!(
                    instance = %slave_instance,
                    peer = %peer_addr,
                    role = %other,
                    "Rejecting HA connection with non-slave role"
                );
                return None;
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
                warn!(
                    instance = %slave_instance,
                    peer = %peer_addr,
                    "Slave authentication failed: invalid or missing token"
                );
                return None;
            }
        }

        info!(
            instance = %slave_instance,
            have_version,
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
            return None;
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
        );
        Some(Self {
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
            let wire_size = push.to_json().map_or(0, |json| json.len());
            if let Err(e) = self.coordinator.try_queue_accounted(
                slave_instance,
                connection_id,
                &tx,
                wire_size,
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
