//! WebSocket session lifecycle for the slave replication worker.

use std::time::{Duration, Instant};

use futures_util::StreamExt;
use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, watch};
use tokio_rustls::TlsConnector;
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tracing::{error, info, warn};

use crate::bundle::watermark_covers;
use crate::config::HaConfig;
use crate::crypto::parse_public_key;
use crate::error::HaError;
use crate::protocol::{AckConflict, HaMessage, PROTOCOL_VERSION};
use crate::session::{frame_text, send_frame, send_ha_message};
use crate::slave::state::{SlaveState, SlaveStatusTracker};
use crate::transport::{
    ExponentialBackoff, SLAVE_HANDSHAKE_TIMEOUT, build_client_tls_config, ws_config,
};

use super::SlaveAppHandles;
use super::apply::apply_config_push;
use super::stats::build_stats_report;

/// The applied bundle hash to advertise in `Hello`, if it is known and valid.
///
/// ADR-0010 adds this field additively: absent means unknown (old peer or a
/// watermark written by an older binary). A malformed/stale watermark value is
/// omitted rather than sent, because a malformed present value would be
/// rejected by the master's strict wire parser.
fn hello_bundle_hash(tracker: &SlaveStatusTracker) -> Option<String> {
    let watermark = tracker.get_watermark()?;
    if watermark.version == 0 {
        return None;
    }
    sito_ha_types::hash::normalize_blake3_hash(&watermark.payload_hash).ok()
}

/// Capabilities advertised in every `Hello`. `client_acl` tells the master this
/// slave enforces the ADR-0011 source-address ACL, so a deny policy can be
/// enabled cluster-wide only after every DNS-serving node is upgraded.
fn hello_capabilities() -> Vec<String> {
    vec![
        "stats-v1".to_string(),
        crate::protocol::CAPABILITY_CLIENT_ACL.to_string(),
    ]
}

/// Delay before reconnecting after a clean master close.
///
/// A clean close usually means a master restart/rollout, so reconnect promptly
/// with a fixed delay instead of growing an error backoff. Error paths still
/// use the exponential backoff; a clean close resets it so a later failure
/// starts from the minimum.
pub(super) const CLEAN_CLOSE_RECONNECT_DELAY: Duration = Duration::from_secs(1);

/// Spawns the slave replication worker loop.
pub fn spawn_slave_worker(
    ha_config: HaConfig,
    tracker: SlaveStatusTracker,
    handles: SlaveAppHandles,
    mut resync_rx: mpsc::Receiver<()>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let Some(master_url) = ha_config.master_url.clone() else {
            handles
                .metrics
                .inc_ha_startup_noop("slave", "missing_master_url");
            tracker.set_connection_error(Some(
                "master_url is not configured; replication cannot start".to_string(),
            ));
            warn!("Slave role configured without master_url; replication worker idle");
            return;
        };

        let master_pubkey = ha_config.master_pubkey.as_deref().and_then(|pk_str| {
            parse_public_key(pk_str)
                .map_err(|e| error!("Invalid master_pubkey in [ha] configuration: {e}"))
                .ok()
        });

        let mut backoff = ExponentialBackoff::default();
        // Tracks whether the resync channel still has senders; a closed channel
        // returns `None` immediately and would otherwise busy-spin the select.
        let mut resync_open = true;

        loop {
            if *shutdown_rx.borrow() {
                break;
            }

            // A previously failed apply stays visible while reconnecting: the
            // `Degraded` state (and its reason) is only cleared by a successful
            // apply or an early ACK for the version already running.
            mark_session_ended(&tracker);
            info!(url = %master_url, "Connecting to master WebSocket replication server");

            match connect_and_run(
                &master_url,
                &ha_config,
                &tracker,
                &handles,
                master_pubkey.as_ref(),
                &mut resync_rx,
                &mut shutdown_rx,
            )
            .await
            {
                Ok(()) => {
                    info!("Replication connection finished cleanly");
                    backoff.reset();
                    // The session is over: stop advertising readiness until
                    // the next successful sync even though DNS keeps serving.
                    // A failed apply stays Degraded with its reason.
                    mark_session_ended(&tracker);
                    // Avoid a tight reconnect loop when the master accepts and
                    // immediately closes the connection. A clean close is a
                    // fixed-delay reconnect (master restart/rollout), not an
                    // error backoff.
                    tokio::select! {
                        () = tokio::time::sleep(CLEAN_CLOSE_RECONNECT_DELAY) => {}
                        msg = resync_rx.recv(), if resync_open => {
                            if msg.is_none() {
                                resync_open = false;
                            } else {
                                info!("Manual resync triggered; reconnecting immediately");
                            }
                        }
                        _ = shutdown_rx.changed() => {
                            if *shutdown_rx.borrow() {
                                break;
                            }
                        }
                    }
                }
                Err(e) => {
                    tracker.set_connection_error(Some(e.to_string()));
                    warn!("Replication connection error: {e}");
                    let delay = backoff.next_delay();
                    info!("Backing off for {:?} before reconnecting", delay);
                    tokio::select! {
                        () = tokio::time::sleep(delay) => {}
                        msg = resync_rx.recv(), if resync_open => {
                            if msg.is_none() {
                                resync_open = false;
                            } else {
                                info!("Manual resync triggered during backoff; reconnecting immediately");
                                backoff.reset();
                            }
                        }
                        _ = shutdown_rx.changed() => {
                            if *shutdown_rx.borrow() {
                                break;
                            }
                        }
                    }
                }
            }
        }
    })
}

pub(super) fn parse_ws_url(url: &str) -> Result<(bool, String, u16), HaError> {
    let (scheme, rest) = url
        .split_once("://")
        .ok_or_else(|| HaError::Connection(format!("Invalid URL: missing '://' in '{url}'")))?;
    let is_secure = match scheme {
        "wss" => true,
        "ws" => false,
        other => {
            return Err(HaError::Connection(format!(
                "Unsupported scheme '{other}' in '{url}'"
            )));
        }
    };

    let host_port = rest.split('/').next().unwrap_or(rest);
    let (host, port) = if let Some(stripped) = host_port.strip_prefix('[') {
        let (ip, port_part) = stripped.split_once(']').ok_or_else(|| {
            HaError::Connection(format!("Unclosed IPv6 bracket in '{host_port}'"))
        })?;
        let port = if let Some(p) = port_part.strip_prefix(':') {
            p.parse::<u16>()
                .map_err(|e| HaError::Connection(format!("Invalid port: {e}")))?
        } else {
            8953
        };
        (ip.to_string(), port)
    } else if let Some((h, p)) = host_port.rsplit_once(':') {
        let port = p
            .parse::<u16>()
            .map_err(|e| HaError::Connection(format!("Invalid port: {e}")))?;
        (h.to_string(), port)
    } else {
        (host_port.to_string(), 8953)
    };

    Ok((is_secure, host, port))
}

pub(super) async fn connect_and_run(
    master_url: &str,
    ha_config: &HaConfig,
    tracker: &SlaveStatusTracker,
    handles: &SlaveAppHandles,
    master_pubkey: Option<&[u8; 32]>,
    resync_rx: &mut mpsc::Receiver<()>,
    shutdown_rx: &mut watch::Receiver<bool>,
) -> Result<(), HaError> {
    let (is_secure, host, port) = parse_ws_url(master_url)?;
    let addr_str = format!("{host}:{port}");

    // Resolve and connect with the host/port pair instead of formatting a
    // socket address: bracketed IPv6 literals (`[::1]`) must not become
    // `::1:8953`, and DNS names must still go through the resolver.
    let tcp_stream = tokio::time::timeout(
        Duration::from_secs(10),
        TcpStream::connect((host.as_str(), port)),
    )
    .await
    .map_err(|_| HaError::Timeout(format!("Connection to master '{addr_str}' timed out")))?
    .map_err(|e| HaError::Connection(format!("TCP connect error to '{addr_str}': {e}")))?;

    if is_secure {
        let tls_cfg = build_client_tls_config(
            ha_config.cert.as_deref(),
            ha_config.key.as_deref(),
            ha_config.master_fingerprint.as_deref(),
            ha_config.allow_unpinned_tls,
            ha_config.ca.as_deref(),
        )?;

        let server_name = ServerName::try_from(host.clone())
            .map_err(|e| HaError::Tls(format!("Invalid server name '{host}': {e}")))?;

        let connector = TlsConnector::from(tls_cfg);
        let tls_stream = tokio::time::timeout(
            SLAVE_HANDSHAKE_TIMEOUT,
            connector.connect(server_name, tcp_stream),
        )
        .await
        .map_err(|_| {
            HaError::Timeout(format!(
                "mTLS handshake with master '{addr_str}' timed out after {SLAVE_HANDSHAKE_TIMEOUT:?}"
            ))
        })?
        .map_err(|e| {
            HaError::Tls(format!(
                "mTLS handshake failed with master '{addr_str}': {e}"
            ))
        })?;

        let (ws_stream, _) = tokio::time::timeout(
            SLAVE_HANDSHAKE_TIMEOUT,
            tokio_tungstenite::client_async_with_config(master_url, tls_stream, Some(ws_config())),
        )
        .await
        .map_err(|_| {
            HaError::Timeout(format!(
                "WebSocket handshake with master '{addr_str}' timed out after {SLAVE_HANDSHAKE_TIMEOUT:?}"
            ))
        })?
        .map_err(|e| HaError::Connection(format!("WebSocket client handshake failed: {e}")))?;

        tracker.set_connection_error(None);
        run_ws_session(
            ws_stream,
            ha_config,
            tracker,
            handles,
            master_pubkey,
            resync_rx,
            shutdown_rx,
        )
        .await
    } else {
        if !ha_config.allow_insecure_ws {
            return Err(HaError::Validation {
                field: "master_url".to_string(),
                reason: "Plaintext ws:// replication is rejected by default. Use wss:// or explicitly set allow_insecure_ws = true".to_string(),
            });
        }

        let (ws_stream, _) = tokio::time::timeout(
            SLAVE_HANDSHAKE_TIMEOUT,
            tokio_tungstenite::client_async_with_config(master_url, tcp_stream, Some(ws_config())),
        )
        .await
        .map_err(|_| {
            HaError::Timeout(format!(
                "Plain WebSocket handshake with '{addr_str}' timed out after {SLAVE_HANDSHAKE_TIMEOUT:?}"
            ))
        })?
        .map_err(|e| {
            HaError::Connection(format!("Plain WebSocket client handshake failed: {e}"))
        })?;

        tracker.set_connection_error(None);
        run_ws_session(
            ws_stream,
            ha_config,
            tracker,
            handles,
            master_pubkey,
            resync_rx,
            shutdown_rx,
        )
        .await
    }
}

/// Marks the replication link as not ready after a master-liveness loss.
///
/// A `Degraded` state is preserved: it records a failed apply and is only
/// cleared by a successful apply (or an early ACK for the already-running
/// version). Overwriting it with `Connecting` would hide the operator's
/// apply-failure reason from `/ha/status`.
pub(super) fn record_master_liveness_loss(tracker: &SlaveStatusTracker, reason: String) {
    tracker.set_connection_error(Some(reason));
    mark_session_ended(tracker);
}

/// Drops out of `Synced` when a replication session ends.
///
/// A `Degraded` state records a failed apply and is only cleared by a
/// successful apply; a clean disconnect or a new connection attempt must not
/// erase the operator-visible reason.
pub(super) fn mark_session_ended(tracker: &SlaveStatusTracker) {
    if tracker.get_state() != SlaveState::Degraded {
        tracker.set_state(SlaveState::Connecting);
    }
}

async fn run_ws_session<S>(
    mut ws_stream: tokio_tungstenite::WebSocketStream<S>,
    ha_config: &HaConfig,
    tracker: &SlaveStatusTracker,
    handles: &SlaveAppHandles,
    master_pubkey: Option<&[u8; 32]>,
    resync_rx: &mut mpsc::Receiver<()>,
    shutdown_rx: &mut watch::Receiver<bool>,
) -> Result<(), HaError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    // 1. Send Hello message
    let have_version = tracker.get_version();
    let hello = HaMessage::Hello {
        instance: tracker.instance_name.clone(),
        have_version,
        have_term: tracker.get_term(),
        capabilities: hello_capabilities(),
        token: ha_config.slave_token.clone(),
        role: Some("slave".to_string()),
        protocol_version: Some(crate::protocol::PROTOCOL_VERSION),
        have_bundle_hash: hello_bundle_hash(tracker),
    };
    send_ha_message(&mut ws_stream, &hello, "slave", "Hello").await?;

    tracker.set_state(SlaveState::HelloSent);
    info!(
        instance = %tracker.instance_name,
        have_version,
        "Sent Hello to master"
    );

    let stats_interval_secs = ha_config.stats_interval_secs.max(1);
    let mut stats_ticker = tokio::time::interval_at(
        tokio::time::Instant::now() + Duration::from_secs(stats_interval_secs),
        Duration::from_secs(stats_interval_secs),
    );
    stats_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // Registry counters are lifetime totals: remember the previous snapshot
    // and report window-scoped deltas instead of mislabelling lifetime values
    // as a `window_s` measurement. `window_started_at` tracks the real length
    // of each reporting window (which can exceed the ticker interval when the
    // session loop is delayed).
    let mut window_started_at = Instant::now();
    let mut last_stats_snapshot = handles.metrics.snapshot();
    // See `spawn_slave_worker`: a closed channel must disable the branch
    // instead of resolving `None` forever.
    let mut resync_open = true;

    // Master-loss deadline: the master pings every `ping_interval_secs`; a
    // partition, blackholed peer or hung master must not leave the slave
    // reporting `Synced` (and `/health` green) forever. Any received frame
    // (ping/pong, stats, push) proves the session is alive.
    let ping_secs = ha_config.ping_interval_secs.max(1);
    let liveness_deadline = Duration::from_secs(ping_secs.saturating_mul(3));
    let mut liveness_interval = tokio::time::interval(Duration::from_secs(ping_secs));
    liveness_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut last_frame = Instant::now();

    loop {
        tokio::select! {
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    break;
                }
            }

            _ = liveness_interval.tick() => {
                if last_frame.elapsed() > liveness_deadline {
                    let reason = format!(
                        "master heartbeat timed out: no frame for {:?} (deadline {:?}); marking replication not ready",
                        last_frame.elapsed(),
                        liveness_deadline
                    );
                    record_master_liveness_loss(tracker, reason.clone());
                    return Err(HaError::Timeout(reason));
                }
            }

            msg = resync_rx.recv(), if resync_open => {
                if msg.is_none() {
                    resync_open = false;
                    continue;
                }
                info!("Manual resync triggered; re-sending Hello with current version");
                let cur_v = tracker.get_version();
                let hello = HaMessage::Hello {
                    instance: tracker.instance_name.clone(),
                    have_version: cur_v,
                    have_term: tracker.get_term(),
                    capabilities: hello_capabilities(),
                    token: ha_config.slave_token.clone(),
                    role: Some("slave".to_string()),
                    protocol_version: Some(crate::protocol::PROTOCOL_VERSION),
                    have_bundle_hash: hello_bundle_hash(tracker),
                };
                send_ha_message(&mut ws_stream, &hello, "slave", "resync Hello").await?;
            }

            _ = stats_ticker.tick() => {
                // Report the activity observed since the previous report; the
                // registry only exposes lifetime totals and lifetime upstream
                // RTT accumulators.
                let window_s = window_started_at.elapsed().as_secs().max(1);
                window_started_at = Instant::now();
                let (stats, snapshot) =
                    build_stats_report(&handles.metrics, &last_stats_snapshot, window_s);
                last_stats_snapshot = snapshot;
                // A stats report is advisory: a serialization failure must not
                // tear down replication or clear the synchronized state. Send
                // the bytes already produced instead of re-serializing them.
                match stats.to_json() {
                    Ok(json) => {
                        send_frame(
                            &mut ws_stream,
                            WsMessage::Text(json.into()),
                            "slave",
                            "stats report",
                        )
                        .await?;
                    }
                    Err(e) => {
                        warn!(
                            error = %e,
                            "Failed to serialize HA stats report; skipping this interval"
                        );
                    }
                }
            }

            msg_opt = ws_stream.next() => {
                last_frame = Instant::now();
                match msg_opt {
                    Some(Ok(frame)) => {
                        if let Some(text) = frame_text(&frame) {
                            handle_master_message(text, &mut ws_stream, tracker, handles, master_pubkey).await?;
                            // An apply can take longer than the liveness deadline;
                            // the frame arrived in time, so restart the clock after
                            // processing it instead of falsely timing out.
                            last_frame = Instant::now();
                        } else if let WsMessage::Ping(p) = frame {
                            send_frame(&mut ws_stream, WsMessage::Pong(p), "slave", "Pong").await?;
                        } else if let WsMessage::Close(_) = frame {
                            info!("Master closed replication WebSocket connection");
                            return Ok(());
                        }
                    }
                    Some(Err(e)) => {
                        return Err(HaError::Connection(format!("WebSocket receive error: {e}")));
                    }
                    None => {
                        info!("Replication connection closed by peer");
                        return Ok(());
                    }
                }
            }
        }
    }

    Ok(())
}

pub(super) async fn handle_master_message<S>(
    text: &str,
    ws_stream: &mut tokio_tungstenite::WebSocketStream<S>,
    tracker: &SlaveStatusTracker,
    handles: &SlaveAppHandles,
    master_pubkey: Option<&[u8; 32]>,
) -> Result<(), HaError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let msg = HaMessage::from_json(text)?;
    macro_rules! send_ack {
        ($ack:expr) => {
            send_ha_message(ws_stream, &$ack, "slave", "Ack").await?
        };
    }
    match msg {
        HaMessage::Ping { ts } => {
            let pong = HaMessage::Pong { ts };
            send_ha_message(ws_stream, &pong, "slave", "Pong").await?;
        }
        HaMessage::ConfigPush {
            ref version,
            protocol_version,
            ref term,
            ref payload_hash_blake3,
            ..
        } => {
            let target_version = *version;
            let push_term = *term;

            // Verify the master's protocol before applying the first (or any)
            // config push. A v1 master omits the field (deserialized as 0) and
            // must never have its bundle interpreted with v2 semantics.
            let master_version = if protocol_version == 0 {
                1
            } else {
                protocol_version
            };
            if master_version != PROTOCOL_VERSION {
                let reason = format!(
                    "protocol_mismatch: master speaks HA protocol v{master_version} but this slave requires v{PROTOCOL_VERSION}; upgrade the master or this slave so both run the same HA protocol"
                );
                tracker.set_connection_error(Some(reason.clone()));
                handles
                    .metrics
                    .inc_ha_protocol_rejection("slave", "version_mismatch");
                warn!(instance = %tracker.instance_name, "{reason}");
                let ack = HaMessage::Ack {
                    version: tracker.get_version(),
                    term: tracker.get_term(),
                    applied: false,
                    conflict: None,
                    error: Some(reason.clone()),
                };
                send_ack!(ack);
                return Err(HaError::Protocol(reason));
            }

            // A push from an older epoch is a stale master and must never
            // overwrite newer configuration, even when its version counter is
            // higher. Within the same epoch the version must advance, and a
            // same-version push is only acceptable when it is the identical
            // signed payload.
            if let Some(watermark) = tracker.get_watermark() {
                if watermark.forked && push_term <= watermark.term {
                    // A fork was already latched: only a strictly higher-term
                    // promotion may resume replication.
                    if let Err(e) = tracker.latch_fork(watermark.version, watermark.term) {
                        warn!(
                            error = %e,
                            "Failed to re-persist the HA fork latch; the in-memory latch still applies"
                        );
                    }
                    tracker.mark_degraded(format!(
                        "HA fork latched at term {} version {}: refusing term {push_term} until explicit higher-term promotion",
                        watermark.term, watermark.forked_at_version
                    ));
                    let ack = HaMessage::Ack {
                        version: watermark.version,
                        term: watermark.term,
                        applied: false,
                        conflict: Some(AckConflict::SameVersionFork),
                        error: Some(format!(
                            "Term {push_term} is blocked by the latched same-version fork at term {} version {}",
                            watermark.term, watermark.forked_at_version
                        )),
                    };
                    send_ack!(ack);
                    return Ok(());
                }
                if push_term < watermark.term {
                    let ack = HaMessage::Ack {
                        version: watermark.version,
                        term: watermark.term,
                        applied: false,
                        conflict: Some(AckConflict::StaleTerm),
                        error: Some(format!(
                            "Push term {push_term} is below the applied term {} (stale master/epoch rejected)",
                            watermark.term
                        )),
                    };
                    send_ack!(ack);
                    return Ok(());
                }
                if push_term > watermark.term && target_version <= watermark.version {
                    let reason = format!(
                        "Higher-term push (term {push_term} version {target_version}) must continue above the applied version {}; a term bump does not permit a version rollback",
                        watermark.version
                    );
                    tracker.mark_degraded(reason.clone());
                    let ack = HaMessage::Ack {
                        version: watermark.version,
                        term: watermark.term,
                        applied: false,
                        conflict: Some(AckConflict::StaleVersion),
                        error: Some(reason),
                    };
                    send_ack!(ack);
                    return Ok(());
                }
                if push_term == watermark.term {
                    if target_version < watermark.version {
                        let ack = HaMessage::Ack {
                            version: watermark.version,
                            term: watermark.term,
                            applied: false,
                            conflict: Some(AckConflict::StaleVersion),
                            error: Some(format!(
                                "Push version {target_version} is below the applied watermark {} (replay rejected)",
                                watermark.version
                            )),
                        };
                        send_ack!(ack);
                        return Ok(());
                    }
                    if target_version == watermark.version && !tracker.requires_full_apply() {
                        if !watermark_covers(
                            &watermark,
                            push_term,
                            target_version,
                            payload_hash_blake3,
                        ) {
                            // Same term and version but different content: this
                            // is a fork. Latch it (in memory and durably) so
                            // the next same-term version from the forked master
                            // cannot overwrite the applied configuration. A
                            // failed durable write still leaves the in-memory
                            // latch, but is reported in the ACK.
                            let latch_error = match tracker
                                .latch_fork(watermark.version, watermark.term)
                            {
                                Ok(()) => None,
                                Err(e) => {
                                    warn!(
                                        error = %e,
                                        "Failed to persist the HA fork latch; keeping the in-memory latch"
                                    );
                                    Some(e.to_string())
                                }
                            };
                            let reason = format!(
                                "Same-version payload fork at term {} version {}: master content differs from the applied bundle",
                                watermark.term, watermark.version
                            );
                            tracker.mark_degraded(reason.clone());
                            let ack = HaMessage::Ack {
                                version: watermark.version,
                                term: watermark.term,
                                applied: false,
                                conflict: Some(AckConflict::SameVersionFork),
                                error: Some(match latch_error {
                                    Some(e) => {
                                        format!("{reason} (fork latch could not be persisted: {e})")
                                    }
                                    None => reason,
                                }),
                            };
                            send_ack!(ack);
                            return Ok(());
                        }
                        let ack = HaMessage::Ack {
                            version: watermark.version,
                            term: watermark.term,
                            applied: true,
                            conflict: None,
                            error: None,
                        };
                        send_ack!(ack);
                        if tracker.get_state() != SlaveState::Degraded {
                            tracker.mark_synced_with_term(watermark.version, watermark.term);
                        }
                        return Ok(());
                    }
                }
            }

            if push_term < tracker.get_term() {
                let ack = HaMessage::Ack {
                    version: tracker.get_version(),
                    term: tracker.get_term(),
                    applied: false,
                    conflict: Some(AckConflict::StaleTerm),
                    error: Some(format!(
                        "Push term {push_term} is below the current term {} (stale master/epoch rejected)",
                        tracker.get_term()
                    )),
                };
                send_ack!(ack);
                return Ok(());
            }

            // Already at (or ahead of) this version in the same term:
            // acknowledge without re-applying. The master always pushes on
            // connect. A locally drifted configuration or an unverified legacy
            // watermark must not take this early-ACK path: it has to apply the
            // bundle and persist a fresh digest first.
            if push_term == tracker.get_term()
                && target_version <= tracker.get_version()
                && !tracker.requires_full_apply()
            {
                let ack = HaMessage::Ack {
                    version: tracker.get_version(),
                    term: tracker.get_term(),
                    applied: true,
                    conflict: None,
                    error: None,
                };
                send_ack!(ack);
                // The connection is fully synchronized: reflect that instead of
                // leaving the state at `hello_sent`. A `Degraded` state is only
                // cleared by a successful apply, so an early ACK for the
                // already-running version must not clear it.
                if tracker.get_state() != SlaveState::Degraded {
                    tracker.mark_synced(tracker.get_version());
                }
                return Ok(());
            }

            tracker.set_state(SlaveState::Applying);

            let pubkey = master_pubkey.ok_or_else(|| {
                HaError::Crypto(
                    "No master_pubkey configured on slave; cannot verify signed push".to_string(),
                )
            });

            let apply_res = match pubkey {
                Ok(pk) => apply_config_push(&msg, tracker, handles, pk).await,
                Err(e) => Err(e),
            };

            match apply_res {
                Ok(v) => {
                    let ack = HaMessage::Ack {
                        version: v,
                        term: tracker.get_term(),
                        applied: true,
                        conflict: None,
                        error: None,
                    };
                    send_ack!(ack);
                }
                Err(e) => {
                    let ack = HaMessage::Ack {
                        version: target_version,
                        term: push_term,
                        applied: false,
                        conflict: None,
                        error: Some(e.to_string()),
                    };
                    send_ack!(ack);
                }
            }
        }
        _ => {}
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hello_hash_comes_from_a_valid_applied_watermark_only() {
        let tracker = SlaveStatusTracker::new("slave-1".to_string(), 0, None);
        assert_eq!(hello_bundle_hash(&tracker), None, "no watermark is unknown");

        tracker
            .persist_watermark(0, 1, "none")
            .expect("version-zero watermark");
        assert_eq!(hello_bundle_hash(&tracker), None, "version 0 has no bundle");

        let hash = "ab".repeat(32);
        tracker
            .persist_watermark(3, 1, &hash)
            .expect("applied watermark");
        assert_eq!(hello_bundle_hash(&tracker), Some(hash));

        // A malformed legacy watermark is omitted rather than sent as a
        // present-but-invalid hash, which the master would reject.
        tracker.persist_watermark(4, 1, "not-a-hash").unwrap();
        assert_eq!(hello_bundle_hash(&tracker), None);
    }

    #[test]
    fn hello_advertises_client_acl_capability() {
        let capabilities = hello_capabilities();
        assert!(capabilities.iter().any(|c| c == "stats-v1"));
        assert!(
            capabilities
                .iter()
                .any(|c| c == crate::protocol::CAPABILITY_CLIENT_ACL),
            "a slave must advertise client_acl so a deny master can require it"
        );
    }
}
