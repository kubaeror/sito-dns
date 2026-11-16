//! WebSocket session I/O and teardown for connected slaves.

#[allow(clippy::wildcard_imports)]
use super::*;

/// Reads and parses the opening Hello frame within the handshake deadline.
async fn read_hello<S>(
    ws_stream: &mut tokio_tungstenite::WebSocketStream<S>,
    peer_addr: SocketAddr,
) -> Option<HelloFields>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let Ok(Some(Ok(frame))) = tokio::time::timeout(Duration::from_secs(10), ws_stream.next()).await
    else {
        warn!(peer = %peer_addr, "Timed out or connection closed before Hello received");
        return None;
    };
    let Some(text) = frame_text(&frame) else {
        // Ping/Pong/Close and other non-text frames cannot carry the opening
        // Hello. Report them distinctly from a timeout or closed connection so
        // an operator can tell a protocol mismatch from a vanished peer. Log
        // only the frame kind and size: a pre-Hello binary frame can be up to
        // the WebSocket limit and must not be dumped into the log.
        let (kind, len) = match &frame {
            WsMessage::Text(text) => ("text", text.len()),
            WsMessage::Binary(bytes) => ("binary", bytes.len()),
            WsMessage::Ping(bytes) => ("ping", bytes.len()),
            WsMessage::Pong(bytes) => ("pong", bytes.len()),
            WsMessage::Close(_) => ("close", 0),
            WsMessage::Frame(_) => ("raw", 0),
        };
        warn!(
            peer = %peer_addr,
            frame_kind = kind,
            frame_len = len,
            "Unsupported frame before Hello (expected a text JSON frame)"
        );
        return None;
    };
    match HaMessage::from_json(text) {
        Ok(HaMessage::Hello {
            instance,
            have_version,
            have_term,
            capabilities,
            token,
            role,
            protocol_version,
        }) => Some(HelloFields {
            instance,
            have_version,
            have_term,
            capabilities,
            token,
            role,
            protocol_version,
        }),
        Ok(other) => {
            warn!(peer = %peer_addr, "Unexpected message instead of Hello: {other:?}");
            None
        }
        Err(e) => {
            warn!(peer = %peer_addr, "Invalid Hello message JSON: {e}");
            None
        }
    }
}

impl MasterCoordinator {
    /// Handles a new incoming WebSocket connection from a replica slave.
    ///
    /// Admission, registration, heartbeat decisions, and teardown live in
    /// [`SessionMachine`]; this loop only moves frames.
    pub async fn handle_connection<S>(
        &self,
        mut ws_stream: tokio_tungstenite::WebSocketStream<S>,
        peer_addr: SocketAddr,
    ) where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        info!(peer = %peer_addr, "Accepted incoming HA replica connection; waiting for Hello");

        let Some(hello) = read_hello(&mut ws_stream, peer_addr).await else {
            return;
        };
        let Some(session) = SessionMachine::admit(self, peer_addr, hello) else {
            return;
        };
        let mut rx = session.register();

        let ping_secs = session.ping_secs();
        let mut ping_interval = tokio::time::interval(Duration::from_secs(ping_secs));
        ping_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                // Outgoing messages queued for this slave
                Some(msg) = rx.recv() => {
                    session.account_drained(wire_size(&msg));
                    if send_ha_message(&mut ws_stream, &msg, "master", "configuration push").await.is_err() {
                        break;
                    }
                }

                // Periodic ping + liveness watchdog
                _ = ping_interval.tick() => {
                    match session.heartbeat() {
                        HeartbeatAction::Superseded => {
                            debug!(
                                instance = %session.state.slave_instance,
                                "HA session superseded by a newer connection; closing"
                            );
                            break;
                        }
                        HeartbeatAction::Stale => {
                            warn!(
                                instance = %session.state.slave_instance,
                                "HA slave heartbeat timed out; closing replication session"
                            );
                            break;
                        }
                        HeartbeatAction::Ping(ts) => {
                            let ping = HaMessage::Ping { ts };
                            if send_ha_message(&mut ws_stream, &ping, "master", "heartbeat ping").await.is_err() {
                                break;
                            }
                        }
                    }
                }

                // Incoming messages from slave
                msg_opt = ws_stream.next() => {
                    match msg_opt {
                        Some(Ok(frame)) => {
                            if let Some(txt) = frame_text(&frame) {
                                if !session.on_text(txt) {
                                    break;
                                }
                            } else {
                                match frame {
                                    WsMessage::Pong(_) => session.record_pong(),
                                    WsMessage::Close(_) => {
                                        info!(instance = %session.state.slave_instance, "Replica slave disconnected");
                                        break;
                                    }
                                    _ => {}
                                }
                            }
                        }
                        None => {
                            info!(instance = %session.state.slave_instance, "Replica slave disconnected");
                            break;
                        }
                        Some(Err(e)) => {
                            warn!(instance = %session.state.slave_instance, "WebSocket receive error: {e}");
                            break;
                        }
                    }
                }
            }
        }

        session.unregister();
    }

    /// Removes the tracked slave entry if it still belongs to `connection_id`.
    ///
    /// Returns true when this session owned the entry (and removed it); false
    /// when a newer connection has replaced it, in which case the live entry is
    /// left untouched.
    pub(super) fn unregister_session(&self, instance: &str, connection_id: u64) -> bool {
        let mut slaves = sito_core::sync::lock_or_recover(&self.slaves);
        let owned = slaves
            .get(instance)
            .is_some_and(|s| s.connection_id == connection_id);
        if owned {
            slaves.remove(instance);
            // Drop the per-slave catch-up and divergence bookkeeping with the
            // session so neither map nor its metric label can grow across
            // reconnects.
            sito_core::sync::lock_or_recover(&self.stale_repushes).remove(instance);
            sito_core::sync::lock_or_recover(&self.diverged).remove(instance);
            sito_core::sync::lock_or_recover(&self.queued_bytes)
                .remove(&(instance.to_string(), connection_id));
            self.metrics.remove_ha_diverged(instance);
        }
        #[allow(clippy::cast_possible_wrap)]
        self.metrics.set_ha_slaves_connected(slaves.len() as i64);
        owned
    }

    /// Returns the payload hash of a still-retained published envelope.
    pub(super) fn published_envelope_hash(&self, term: u64, version: u64) -> Option<String> {
        sito_core::sync::lock_or_recover(&self.active_push_history)
            .iter()
            .find(|envelope| envelope.term == term && envelope.version == version)
            .map(|envelope| envelope.payload_hash.clone())
    }
}
