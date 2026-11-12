//! Classified slave-message handlers.

#[allow(clippy::wildcard_imports)]
use super::*;

impl MasterCoordinator {
    /// Parses one incoming frame and dispatches it to a classified handler.
    pub(super) fn process_slave_msg(
        &self,
        slave_instance: &str,
        connection_id: u64,
        text: &str,
    ) -> bool {
        let msg = match HaMessage::from_json(text) {
            Ok(m) => m,
            Err(e) => {
                warn!(instance = %slave_instance, "Failed to parse incoming message: {e}");
                return true;
            }
        };

        match msg {
            HaMessage::Ack {
                version,
                term,
                applied,
                conflict,
                error,
            } => self.process_ack(
                slave_instance,
                connection_id,
                version,
                term,
                applied,
                conflict,
                error.as_ref(),
            ),
            HaMessage::StatsReport {
                window_s,
                queries,
                blocked,
                upstreams,
            } => self.process_stats_report(
                slave_instance,
                connection_id,
                window_s,
                queries,
                blocked,
                &upstreams,
            ),
            HaMessage::Pong { .. } => {
                self.process_pong(slave_instance, connection_id);
                true
            }
            HaMessage::Hello { .. } => {
                self.process_hello(slave_instance, connection_id);
                true
            }
            _ => true,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn process_ack(
        &self,
        slave_instance: &str,
        connection_id: u64,
        version: u64,
        term: u64,
        applied: bool,
        conflict: Option<AckConflict>,
        error: Option<&String>,
    ) -> bool {
        // Ignore acknowledgements from a superseded connection: the
        // entry now belongs to a newer session.
        let owned = {
            let slaves = self.slaves.lock().unwrap();
            slaves
                .get(slave_instance)
                .is_some_and(|s| s.connection_id == connection_id)
        };
        if !owned {
            return true;
        }

        let current = self.get_current_version();
        let current_term = self.get_current_term();
        if version > current.saturating_add(MAX_PEER_VERSION_LEAD) {
            // Never use an implausible peer-driven version as a seed,
            // a rebase input, or a persisted value. A single replica
            // must not be able to freeze publishing with `u64::MAX`.
            // This applies to `applied:false` ACKs too: a forged
            // rejection must not carry an unbounded version.
            error!(
                instance = %slave_instance,
                acked_version = version,
                current,
                max_lead = MAX_PEER_VERSION_LEAD,
                applied,
                "Ignoring ACK with an implausible version"
            );
            return true;
        }

        if term > current_term {
            // The replica knows a newer epoch: this master is stale.
            // Adopting the peer's counter would let a partitioned old
            // master overwrite newer configuration, so only surface the
            // divergence and require an explicit promotion.
            let reason = format!(
                "slave '{slave_instance}' acknowledged term {term} above the master's term {current_term}: this master is stale and must not overwrite the cluster"
            );
            error!(
                instance = %slave_instance,
                acked_version = version,
                acked_term = term,
                current,
                current_term,
                "{reason}"
            );
            self.mark_diverged(DivergenceKind::Term, slave_instance, version, term, reason);
            return true;
        }

        if !applied {
            if conflict == Some(AckConflict::SameVersionFork) {
                // Only a push the master actually sent can prove a
                // fork. The bounded published-envelope history keeps
                // recently superseded bundles, so an ACK that arrives
                // after a newer publish is still attributed correctly.
                // Without this binding an authenticated replica could
                // latch a fabricated fork for any version.
                let Some(published_hash) = self.published_envelope_hash(term, version) else {
                    warn!(
                        instance = %slave_instance,
                        acked_version = version,
                        acked_term = term,
                        current,
                        current_term,
                        "Ignoring same-version fork ACK without a matching published envelope"
                    );
                    return true;
                };
                // Same term and version but different content: this is
                // the fork signal. Record it so the slave is reported
                // unsynced and can never silently "win" the fork; this
                // does not stop publishing to other replicas.
                let reason = format!(
                    "slave '{slave_instance}' rejected term {term} version {version} with a same-version payload-hash fork (published envelope {published_hash}): resolve the fork or promote the slave"
                );
                error!(
                    instance = %slave_instance,
                    acked_version = version,
                    acked_term = term,
                    current_term,
                    "{reason}"
                );
                self.mark_diverged(DivergenceKind::Fork, slave_instance, version, term, reason);
                if let Some(slave) = self.slaves.lock().unwrap().get_mut(slave_instance)
                    && slave.connection_id == connection_id
                {
                    slave.synced_version = 0;
                }
            }
            warn!(
                instance = %slave_instance,
                version,
                term,
                conflict = ?conflict,
                error = ?error,
                "Slave failed to apply configuration bundle"
            );
            return true;
        }

        if term < current_term {
            // Our epoch is newer; the replica is stale even if its
            // old-epoch version counter is higher. Re-push the active
            // bundle of the current term so it adopts the promotion.
            warn!(
                instance = %slave_instance,
                acked_version = version,
                acked_term = term,
                current_term,
                "Slave acknowledged an older term; re-pushing the current-term active bundle"
            );
            self.maybe_repush(slave_instance, version);
        } else if version == current {
            info!(
                instance = %slave_instance,
                version,
                term,
                "Slave successfully applied configuration bundle"
            );
            let mut slaves = self.slaves.lock().unwrap();
            if let Some(s) = slaves.get_mut(slave_instance)
                && s.connection_id == connection_id
            {
                s.synced_version = version;
            } else {
                // An older connection acknowledging after its entry was
                // replaced must not update the live session.
                return true;
            }
            drop(slaves);
            #[allow(clippy::cast_precision_loss)]
            self.metrics
                .set_ha_config_version(slave_instance, version as f64);
            self.stale_repushes.lock().unwrap().remove(slave_instance);
            // This slave has accepted the current term/version, so any
            // divergence record for it (fork, ahead, newer-term) is now
            // resolved. Other slaves' records are untouched: H-10
            // clears divergence per acknowledging slave.
            self.clear_divergence_for(slave_instance);
        } else if version < current {
            warn!(
                instance = %slave_instance,
                acked_version = version,
                current,
                "Slave acknowledged a stale configuration version; re-pushing the active bundle"
            );
            self.maybe_repush(slave_instance, version);
        } else {
            // Same term but a version above the master's means version
            // continuity is broken (promoted slave, restored from an
            // older state file, or forked master). Do not auto-rebase:
            // that would let this stale master overwrite newer slaves.
            let reason = format!(
                "slave '{slave_instance}' acknowledged version {version} above the master's current version {current} in term {current_term}: version continuity is broken (promoted slave or lost/corrupt ha_state.toml); explicit promotion is required"
            );
            error!(
                instance = %slave_instance,
                acked_version = version,
                current,
                current_term,
                "{reason}"
            );
            self.mark_diverged(
                DivergenceKind::Ahead,
                slave_instance,
                version,
                current_term,
                reason,
            );
        }
        true
    }
    #[allow(clippy::too_many_arguments)]
    fn process_stats_report(
        &self,
        slave_instance: &str,
        connection_id: u64,
        window_s: u64,
        queries: u64,
        blocked: u64,
        upstreams: &HashMap<String, crate::protocol::UpstreamReport>,
    ) -> bool {
        let upstreams_count = upstreams.len();
        let mut slaves = self.slaves.lock().unwrap();
        let Some(s) = slaves.get_mut(slave_instance) else {
            return true;
        };
        if s.connection_id != connection_id {
            return true;
        }
        if !s.capabilities.iter().any(|c| c == "stats-v1") {
            warn!(
                instance = %slave_instance,
                "Ignoring StatsReport from slave that did not advertise the 'stats-v1' capability"
            );
            return true;
        }
        s.last_stats = Some(SlaveStatsSummary {
            window_s,
            queries,
            blocked,
            upstreams_count,
        });
        true
    }
    fn process_pong(&self, slave_instance: &str, connection_id: u64) {
        let mut slaves = self.slaves.lock().unwrap();
        if let Some(s) = slaves.get_mut(slave_instance)
            && s.connection_id == connection_id
        {
            s.last_ping = Instant::now();
        }
    }
    fn process_hello(&self, slave_instance: &str, connection_id: u64) {
        if let Some(ref push) = *self.active_push.lock().unwrap() {
            let sender = {
                let slaves = self.slaves.lock().unwrap();
                slaves
                    .get(slave_instance)
                    .filter(|s| s.connection_id == connection_id)
                    .map(|s| s.sender.clone())
            };
            if let Some(sender) = sender {
                let wire_size = push.to_json().map_or(0, |json| json.len());
                if let Err(e) = self.try_queue_accounted(
                    slave_instance,
                    connection_id,
                    &sender,
                    wire_size,
                    push.clone(),
                ) {
                    warn!(
                        instance = %slave_instance,
                        error = %e,
                        "Resync push could not be queued; coalescing"
                    );
                    self.schedule_coalesced_delivery(slave_instance, connection_id, &sender, push);
                }
            }
        }
    }
}
