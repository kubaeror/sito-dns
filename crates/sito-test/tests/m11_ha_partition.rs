//! WP-0.4 acceptance: HA partition detection, applied-config integrity,
//! delayed fork diagnostics and publish failure/oversize handling.
//!
//! These tests exercise the observable behaviour (readiness, divergence and
//! publish outcomes), not private helpers, so they stay honest when the
//! internal HA state machine is reshaped in 2.0.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use futures_util::{SinkExt, StreamExt};
use sito_api::config_apply::{ConfigFileApplyOutcome, FilterApply};
use sito_api::state::ServerContext;
use sito_cache::DnsCache;
use sito_clients::ClientRegistry;
use sito_core::config::Config;
use sito_filter::HostsFilterEngine;
use sito_ha::{
    ConfigBundle, Ed25519SigningKey, FilterListMetadata, HaConfig, HaMessage, MasterCoordinator,
    PublishOutcome, SlaveAppHandles, SlaveConfigApplier, SlaveState, SlaveStatusTracker,
    build_and_sign_push, config_digest, push_payload_hash, spawn_slave_worker,
};
use sito_rewrites::RewriteTable;
use sito_stats::{MetricsRegistry, QueryLogWriter, StatsDb};
use sito_upstream::UpstreamManager;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, watch};
use tokio_tungstenite::tungstenite::Message as WsMessage;

// ---------------------------------------------------------------------------
// Slave harness
// ---------------------------------------------------------------------------

struct TestApplier {
    runtime: Arc<sito_runtime::RuntimeState>,
    config_path: Option<PathBuf>,
}

impl SlaveConfigApplier for TestApplier {
    fn apply_and_persist<'a>(
        &'a self,
        cfg: &'a Config,
        document: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            let previous = self.runtime.snapshot();
            self.runtime.replace(sito_runtime::RuntimeSnapshot {
                config: Arc::new(cfg.clone()),
                clients: previous.clients.clone(),
                rewrites: previous.rewrites.clone(),
            });
            if let Some(path) = self.config_path.as_deref()
                && let Err(e) = tokio::fs::write(path, document).await
            {
                self.runtime.replace((*previous).clone());
                return Err(e.to_string());
            }
            Ok(())
        })
    }
}

async fn slave_handles(base_config: Config, config_path: Option<PathBuf>) -> SlaveAppHandles {
    let config_arc = Arc::new(ArcSwap::new(Arc::new(base_config.clone())));
    let filter = Arc::new(
        HostsFilterEngine::init(base_config.filtering.clone(), std::env::temp_dir()).await,
    );
    let rewrites = Arc::new(ArcSwap::new(Arc::new(
        RewriteTable::new(Default::default()),
    )));
    let clients = Arc::new(ArcSwap::new(Arc::new(ClientRegistry::new(
        Default::default(),
    ))));
    let runtime = Arc::new(sito_runtime::RuntimeState::new(
        config_arc, clients, rewrites,
    ));
    SlaveAppHandles {
        runtime: runtime.clone(),
        filter,
        metrics: MetricsRegistry::new("0.1.0", "m11-ha"),
        config_path: config_path.clone(),
        applier: Arc::new(TestApplier {
            runtime,
            config_path,
        }),
    }
}

fn signed_push(
    version: u64,
    term: u64,
    config_toml: &str,
    custom_rules: Vec<String>,
    key: &Ed25519SigningKey,
) -> HaMessage {
    build_and_sign_push(
        &ConfigBundle {
            version,
            term,
            timestamp: 1,
            config_toml: config_toml.to_string(),
            custom_rules,
            rewrites: None,
            clients: None,
            lists: Vec::<FilterListMetadata>::new(),
        },
        key,
    )
    .expect("sign test push")
}

async fn wait_until(mut cond: impl FnMut() -> bool, timeout: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if cond() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    cond()
}

fn temp_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "sito_m11_ha_{label}_{}_{}",
        std::process::id(),
        rand::random::<u64>()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

// ---------------------------------------------------------------------------
// 1. Liveness: a blackholed master must make the slave not-ready.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_slave_goes_not_ready_when_master_stops_sending_frames() {
    let key = Ed25519SigningKey::generate().unwrap();
    let push = signed_push(
        2,
        0,
        "config_version = 1\n[server]\nrole = \"slave\"\n",
        vec![],
        &key,
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let fake_master = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
        // Authenticate/attach exactly like a real master, then go silent: the
        // TCP connection stays open but no heartbeats or pushes arrive.
        let _ = ws.next().await;
        ws.send(WsMessage::Text(push.to_json().unwrap().into()))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_secs(30)).await;
    });

    let ha_config = HaConfig {
        master_url: Some(format!("ws://127.0.0.1:{port}")),
        master_pubkey: Some(key.public_key_hex()),
        allow_insecure_ws: true,
        ping_interval_secs: 1,
        stats_interval_secs: 60,
        ..Default::default()
    };
    let tracker = SlaveStatusTracker::new(
        "liveness-slave".to_string(),
        0,
        Some(ha_config.master_url.clone().unwrap()),
    );
    let handles = slave_handles(Config::default(), None).await;
    let (_resync_tx, resync_rx) = mpsc::channel(1);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let worker = spawn_slave_worker(ha_config, tracker.clone(), handles, resync_rx, shutdown_rx);

    assert!(
        wait_until(
            || tracker.get_state() == SlaveState::Synced,
            Duration::from_secs(5)
        )
        .await,
        "the slave must first sync the pushed bundle (state: {:?})",
        tracker.get_state()
    );

    let became_unready = wait_until(|| !tracker.readiness().ready, Duration::from_secs(8)).await;
    assert!(
        became_unready,
        "a slave whose master stopped sending frames must stop being ready"
    );
    let reason = tracker.readiness().reason.unwrap_or_default();
    assert!(
        reason.to_lowercase().contains("heartbeat") || reason.to_lowercase().contains("timeout"),
        "the readiness reason must explain the lost master heartbeat, got: {reason}"
    );

    let _ = shutdown_tx.send(true);
    worker.abort();
    fake_master.abort();
}

// ---------------------------------------------------------------------------
// 2. Applied-config integrity: a local shared-config edit must not early-ACK.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_restart_with_locally_modified_shared_config_does_not_early_ack_synced() {
    let dir = temp_dir("drift");
    let config_path = dir.join("config.toml");
    let watermark_path = dir.join("ha_watermark.toml");
    let key = Ed25519SigningKey::generate().unwrap();

    let applied_doc = r#"config_version = 1
[server]
role = "slave"
instance_name = "drift-slave"

[upstream]
servers = ["9.9.9.9"]
"#;
    std::fs::write(&config_path, applied_doc).unwrap();
    let push = signed_push(5, 0, applied_doc, vec![], &key);
    let payload_hash = push_payload_hash(&push).unwrap();

    let first = SlaveStatusTracker::new("drift-slave".to_string(), 0, None)
        .with_watermark_path(watermark_path.clone())
        .unwrap();
    first
        .persist_watermark_with_config_digest(
            5,
            0,
            &payload_hash,
            Some(&config_digest(applied_doc)),
        )
        .unwrap();

    // The operator edits a shared field while the process is stopped.
    let modified_doc = applied_doc.replace("9.9.9.9", "1.1.1.1");
    std::fs::write(&config_path, &modified_doc).unwrap();

    let restarted = SlaveStatusTracker::new("drift-slave".to_string(), 0, None)
        .with_watermark_path(watermark_path.clone())
        .unwrap();
    assert!(
        restarted
            .verify_applied_config(&modified_doc)
            .expect("digest check"),
        "a modified local configuration must be detected as drift"
    );
    assert!(restarted.has_local_config_drift());
    assert_eq!(restarted.get_state(), SlaveState::Degraded);
    assert!(
        !restarted.readiness().ready,
        "a drifted slave must not report healthy before re-applying"
    );

    // The master re-pushes the current bundle. The slave must not take the
    // same-version early-ACK path: it has to apply the shared config and only
    // then advertise sync.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let fake_master = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
        let _ = ws.next().await;
        ws.send(WsMessage::Text(push.to_json().unwrap().into()))
            .await
            .unwrap();
        // Read the apply ACK (a same-version early ACK is still an ACK, so the
        // test asserts the resulting state instead of the ACK text).
        let _ = ws.next().await;
        tokio::time::sleep(Duration::from_secs(30)).await;
    });

    let ha_config = HaConfig {
        master_url: Some(format!("ws://127.0.0.1:{port}")),
        master_pubkey: Some(key.public_key_hex()),
        allow_insecure_ws: true,
        ping_interval_secs: 60,
        stats_interval_secs: 60,
        ..Default::default()
    };
    let handles = slave_handles(Config::default(), Some(config_path.clone())).await;
    let (_resync_tx, resync_rx) = mpsc::channel(1);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let worker = spawn_slave_worker(
        ha_config,
        restarted.clone(),
        handles,
        resync_rx,
        shutdown_rx,
    );

    assert!(
        wait_until(
            || restarted.get_state() == SlaveState::Synced && !restarted.has_local_config_drift(),
            Duration::from_secs(5)
        )
        .await,
        "the drifted slave must apply the identical push before reporting synced (state: {:?}, drift: {})",
        restarted.get_state(),
        restarted.has_local_config_drift()
    );
    assert!(restarted.readiness().ready);

    let _ = shutdown_tx.send(true);
    worker.abort();
    fake_master.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// 2b. Legacy watermarks without a digest must force one full apply.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_legacy_watermark_without_digest_forces_full_apply() {
    let dir = temp_dir("legacy-digest");
    let config_path = dir.join("config.toml");
    let watermark_path = dir.join("ha_watermark.toml");
    let key = Ed25519SigningKey::generate().unwrap();

    let applied_doc = r#"config_version = 1
[server]
role = "slave"
instance_name = "legacy-slave"

[upstream]
servers = ["9.9.9.9"]
"#;
    std::fs::write(&config_path, applied_doc).unwrap();
    let push = signed_push(5, 0, applied_doc, vec![], &key);
    let payload_hash = push_payload_hash(&push).unwrap();
    // A 1.9.3 watermark: no `applied_config_digest`.
    std::fs::write(
        &watermark_path,
        format!(
            r#"{{"version":5,"term":0,"payload_hash":"{payload_hash}","timestamp":1,"forked":false,"forked_at_version":0}}"#
        ),
    )
    .unwrap();

    let restarted = SlaveStatusTracker::new("legacy-slave".to_string(), 0, None)
        .with_watermark_path(watermark_path.clone())
        .unwrap();
    assert!(
        !restarted
            .verify_applied_config(applied_doc)
            .expect("legacy digest check")
    );
    assert!(
        !restarted.has_local_config_drift(),
        "a legacy watermark is unverified, not proven drift"
    );
    assert!(
        restarted.requires_full_apply(),
        "an unverified legacy watermark must force a full apply"
    );
    assert_ne!(
        restarted.get_state(),
        SlaveState::Degraded,
        "a legacy watermark must not be marked degraded before it reconnects"
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let fake_master = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
        let _ = ws.next().await;
        ws.send(WsMessage::Text(push.to_json().unwrap().into()))
            .await
            .unwrap();
        let _ = ws.next().await;
        tokio::time::sleep(Duration::from_secs(30)).await;
    });

    let ha_config = HaConfig {
        master_url: Some(format!("ws://127.0.0.1:{port}")),
        master_pubkey: Some(key.public_key_hex()),
        allow_insecure_ws: true,
        ping_interval_secs: 60,
        stats_interval_secs: 60,
        ..Default::default()
    };
    let handles = slave_handles(Config::default(), Some(config_path.clone())).await;
    let (_resync_tx, resync_rx) = mpsc::channel(1);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let worker = spawn_slave_worker(
        ha_config,
        restarted.clone(),
        handles,
        resync_rx,
        shutdown_rx,
    );

    // The watermark only gains a digest when the slave actually applies the
    // same-version push; an early ACK leaves it absent.
    let applied = wait_until(
        || {
            std::fs::read_to_string(&watermark_path)
                .is_ok_and(|raw| raw.contains("applied_config_digest"))
                && restarted.get_state() == SlaveState::Synced
        },
        Duration::from_secs(5),
    )
    .await;
    assert!(
        applied,
        "a legacy watermark must be upgraded by a full apply, not an early ACK (state: {:?}, watermark: {:?})",
        restarted.get_state(),
        std::fs::read_to_string(&watermark_path).unwrap_or_default()
    );
    assert!(!restarted.requires_full_apply());

    let _ = shutdown_tx.send(true);
    worker.abort();
    fake_master.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// 3. Delayed same-version fork ACK after a newer publish.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_delayed_same_version_fork_ack_after_newer_publish_is_divergence() {
    use tokio_tungstenite::tungstenite::protocol::{Role, WebSocketConfig};

    let key = Arc::new(Ed25519SigningKey::generate().unwrap());
    let coordinator = MasterCoordinator::new(
        "fork-master".to_string(),
        1,
        key,
        MetricsRegistry::new("0.1.0", "m11-ha"),
    );
    coordinator.update_bundle(bundle(2)).unwrap();

    let (server_socket, client_socket) = tokio::io::duplex(128 * 1024);
    let server_ws = tokio_tungstenite::WebSocketStream::from_raw_socket(
        server_socket,
        Role::Server,
        Some(WebSocketConfig::default()),
    )
    .await;
    let mut client_ws = tokio_tungstenite::WebSocketStream::from_raw_socket(
        client_socket,
        Role::Client,
        Some(WebSocketConfig::default()),
    )
    .await;

    let coord = coordinator.clone();
    let session = tokio::spawn(async move {
        coord
            .handle_connection(server_ws, "127.0.0.1:9000".parse().unwrap())
            .await;
    });

    client_ws
        .send(WsMessage::Text(
            HaMessage::Hello {
                instance: "delayed-fork".to_string(),
                have_version: 1,
                have_term: 0,
                capabilities: vec![],
                token: None,
                role: Some("slave".to_string()),
                protocol_version: Some(sito_ha::PROTOCOL_VERSION),
            }
            .to_json()
            .unwrap()
            .into(),
        ))
        .await
        .unwrap();

    // Receive the v2 push and let the master publish v3 before the slave's
    // same-version fork ACK for v2 reaches it.
    let _push_v2 = client_ws.next().await.unwrap().unwrap();
    assert_eq!(coordinator.update_bundle(bundle(3)).unwrap(), 3);

    client_ws
        .send(WsMessage::Text(
            HaMessage::Ack {
                version: 2,
                term: 0,
                applied: false,
                conflict: Some(sito_ha::AckConflict::SameVersionFork),
                error: Some("delayed same-version fork".to_string()),
            }
            .to_json()
            .unwrap()
            .into(),
        ))
        .await
        .unwrap();

    assert!(
        wait_until(|| coordinator.is_diverged(), Duration::from_secs(2)).await,
        "a delayed fork ACK for a still-published envelope must be recorded"
    );
    let reason = coordinator.diverged_reason().unwrap_or_default();
    assert!(
        reason.to_lowercase().contains("fork"),
        "the operator-visible reason must mention the fork: {reason}"
    );
    assert!(
        coordinator
            .list_slaves()
            .iter()
            .any(|s| s.instance == "delayed-fork" && s.diverged),
        "the forked slave must be reported as diverged"
    );

    drop(client_ws);
    session.abort();
}

fn bundle(version: u64) -> ConfigBundle {
    ConfigBundle {
        version,
        term: 0,
        timestamp: 1,
        config_toml: "config_version = 1\n[server]\nrole = \"slave\"\n".to_string(),
        custom_rules: vec![],
        rewrites: None,
        clients: None,
        lists: vec![],
    }
}

// ---------------------------------------------------------------------------
// 4. Publish failures and oversized bundles are visible, not logged away.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_publish_bundle_propagates_sanitize_failure_and_rejects_oversize() {
    let dir = temp_dir("publish");
    let config_path = dir.join("config.toml");
    // A file that cannot be sanitized (invalid TOML) must not silently turn
    // into an empty bundle.
    std::fs::write(&config_path, "this is not = [valid toml").unwrap();
    let ctx = publish_context(&dir, &config_path).await;

    let err = ctx
        .publish_bundle()
        .await
        .expect_err("an unsanitizable config must fail the publish");
    assert!(
        !err.to_string().is_empty(),
        "the publish error must be actionable"
    );
    let live_config = (**ctx.config.load()).clone();
    let readiness = ctx.ha_readiness(&live_config);
    assert!(
        !readiness.ready,
        "a pre-coordinator publish failure must make HA not-ready"
    );
    assert!(
        readiness
            .reason
            .unwrap_or_default()
            .contains("publish failed"),
        "the readiness reason must explain the publish failure"
    );

    // An empty document must be rejected instead of being broadcast as an
    // empty configuration.
    std::fs::write(&config_path, "").unwrap();
    let err = ctx
        .publish_bundle()
        .await
        .expect_err("an empty config must not become an empty HA bundle");
    assert!(
        err.to_string().contains("empty"),
        "the empty-bundle error must be explicit: {err}"
    );
    assert!(!ctx.ha_readiness(&live_config).ready);

    // A bundle whose signed WebSocket envelope exceeds the 1 MiB protocol cap
    // must be rejected before persist/broadcast.
    let key = Arc::new(Ed25519SigningKey::generate().unwrap());
    let state_path = dir.join("ha_state.toml");
    let coordinator = MasterCoordinator::new(
        "oversize-master".to_string(),
        0,
        key,
        MetricsRegistry::new("0.1.0", "m11-ha"),
    )
    .with_state_path(state_path.clone());

    let oversized = ConfigBundle {
        version: 1,
        term: 0,
        timestamp: 1,
        config_toml: "x".repeat(1024 * 1024),
        custom_rules: vec![],
        rewrites: None,
        clients: None,
        lists: vec![],
    };
    let outcome = coordinator
        .publish_bundle_async(oversized)
        .await
        .expect("oversize is an outcome, not a transport error");
    assert!(
        matches!(outcome, PublishOutcome::TooLarge { .. }),
        "an oversized bundle must return TooLarge, got {outcome:?}"
    );
    assert_eq!(
        coordinator.get_current_version(),
        0,
        "a rejected oversized bundle must not advance the sequence"
    );
    assert!(
        coordinator.active_bundle.lock().unwrap().is_none(),
        "a rejected oversized bundle must not become active"
    );
    assert!(
        !state_path.exists(),
        "a rejected oversized bundle must never be persisted"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn test_file_watcher_rejects_oversized_bundle_and_rolls_back() {
    let dir = temp_dir("watcher-oversize");
    let config_path = dir.join("config.toml");
    // The watcher reads this file, so write a valid baseline first.
    std::fs::write(&config_path, "config_version = 1\n").unwrap();
    let ctx = publish_context(&dir, &config_path).await;
    let original_ttl = ctx.config.load().dns.cache.min_ttl;

    // A real small shared change plus a large unknown section: Config ignores
    // the unknown table, but the sanitized source document (and therefore the
    // signed bundle) keeps it and exceeds the 1 MiB WebSocket limit.
    let oversized_document = format!(
        "config_version = 1\n[server]\nrole = \"master\"\n[ha]\nreplication_port = 8953\nallow_insecure_ws = true\nslave_token = \"test-token\"\n[dns.cache]\nmin_ttl = {}\n[padding]\nblob = \"{}\"\n",
        original_ttl.saturating_add(7),
        "x".repeat(1_100_000)
    );
    std::fs::write(&config_path, &oversized_document).unwrap();

    let outcome = sito_api::config_apply::apply_config_document_event(
        &ctx,
        &oversized_document,
        FilterApply::Deferred,
        None,
    )
    .await;
    match outcome {
        ConfigFileApplyOutcome::Rejected(e) => {
            assert!(
                e.detail.contains("replication limit"),
                "the oversized watcher apply must be rejected explicitly: {}",
                e.detail
            );
        }
        other => panic!("oversized watcher apply must be rejected, got {other:?}"),
    }
    assert_eq!(
        ctx.config.load().dns.cache.min_ttl,
        original_ttl,
        "the live configuration must be rolled back after an oversized watcher apply"
    );
    // The file is the operator's external edit and is intentionally left in
    // place; only the running configuration rolls back.
    assert!(std::fs::read_to_string(&config_path).is_ok());

    let _ = std::fs::remove_dir_all(&dir);
}

async fn publish_context(dir: &Path, config_path: &Path) -> ServerContext {
    let stats_db = StatsDb::open(&dir.join("stats.db")).await.unwrap();
    let querylog_writer = QueryLogWriter::spawn(stats_db.clone(), 100);
    let metrics = MetricsRegistry::new("0.1.0", "m11-ha");
    let mut config = Config::default();
    config.server.role = "master".to_string();
    config.ha = Some(
        toml::from_str(
            "replication_port = 8953\nallow_insecure_ws = true\nslave_token = \"test-token\"",
        )
        .expect("valid [ha] test config"),
    );
    let config_arc = Arc::new(ArcSwap::new(Arc::new(config.clone())));
    let cache = Arc::new(DnsCache::new(config.dns.cache.clone()));
    let filter =
        Arc::new(HostsFilterEngine::init(config.filtering.clone(), dir.to_path_buf()).await);
    let bootstrap = sito_upstream::BootstrapResolver::new(
        vec!["127.0.0.1".parse().unwrap()],
        Duration::from_secs(1),
    );
    let upstream = Arc::new(
        UpstreamManager::from_config(&config.upstream, &bootstrap)
            .await
            .unwrap(),
    );
    let clients = Arc::new(ArcSwap::new(Arc::new(ClientRegistry::new(
        Default::default(),
    ))));
    let rewrites = Arc::new(ArcSwap::new(Arc::new(
        RewriteTable::new(Default::default()),
    )));
    let runtime = Arc::new(sito_runtime::RuntimeState::new(
        config_arc.clone(),
        clients.clone(),
        rewrites.clone(),
    ));
    let runtime_lists = Arc::new(sito_clients::RuntimeLists::from_arcs(
        Arc::new(sito_clients::ParentalRegistry::try_bundled().unwrap()),
        Arc::new(sito_clients::ServiceRegistry::try_bundled().unwrap()),
    ));
    let signing_key = Arc::new(Ed25519SigningKey::generate().unwrap());
    let coordinator = MasterCoordinator::new(
        "publish-master".to_string(),
        1,
        signing_key,
        metrics.clone(),
    );
    coordinator.mark_replication_ready();
    ServerContext {
        config: config_arc,
        runtime,
        runtime_lists,
        config_path: config_path.to_path_buf(),
        auth_mgr: Arc::new(sito_api::auth::AuthManager::new()),
        stats_db,
        querylog_sender: querylog_writer.sender(),
        metrics,
        filter,
        cache,
        upstream,
        clients,
        rewrites,
        start_time: Instant::now(),
        restore_tokens: Arc::new(Mutex::new(std::collections::HashMap::new())),
        master_coordinator: Some(coordinator),
        slave_tracker: None,
        resync_sender: None,
        setup_pending: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        dns_starter: None,
        apply_lock: Arc::new(tokio::sync::Mutex::new(())),
    }
}
