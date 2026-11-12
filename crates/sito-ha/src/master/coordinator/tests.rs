#![cfg(test)]

use super::*;
use crate::master::tracker::ActiveSlave;

fn test_coordinator() -> MasterCoordinator {
    let key = Arc::new(Ed25519SigningKey::generate().unwrap());
    MasterCoordinator::new(
        "test-master".to_string(),
        1,
        key,
        sito_stats::MetricsRegistry::new("test", "test"),
    )
}

fn test_bundle(version: u64) -> ConfigBundle {
    ConfigBundle {
        version,
        term: 0,
        timestamp: 1,
        config_toml: "config_version = 2\n[server]\nrole = \"slave\"\n".to_string(),
        custom_rules: vec![],
        rewrites: None,
        clients: None,
        lists: vec![],
    }
}

#[test]
fn test_update_bundle_rejects_non_monotonic_versions() {
    let coordinator = test_coordinator();
    assert_eq!(coordinator.update_bundle(test_bundle(2)).unwrap(), 2);

    // Equal and lower versions must be rejected.
    assert!(coordinator.update_bundle(test_bundle(2)).is_err());
    assert!(coordinator.update_bundle(test_bundle(1)).is_err());
    assert_eq!(coordinator.get_current_version(), 2);

    assert_eq!(coordinator.update_bundle(test_bundle(3)).unwrap(), 3);
}

#[test]
fn test_concurrent_update_bundle_never_regresses_version() {
    use std::sync::Arc as StdArc;

    let coordinator = StdArc::new(test_coordinator());
    let first = StdArc::clone(&coordinator);
    let second = StdArc::clone(&coordinator);

    // Versions 2 and 3 race: the lock must prevent 3 from being stored
    // and then overwritten by 2 (or vice versa).
    let t1 = std::thread::spawn(move || first.update_bundle(test_bundle(2)));
    let t2 = std::thread::spawn(move || second.update_bundle(test_bundle(3)));
    let r1 = t1.join().unwrap();
    let r2 = t2.join().unwrap();

    let final_version = coordinator.get_current_version();
    assert!(
        final_version == 2 || final_version == 3,
        "unexpected final version {final_version}"
    );
    let active = coordinator
        .active_bundle
        .lock()
        .unwrap()
        .clone()
        .expect("active bundle");
    assert_eq!(
        active.version, final_version,
        "active bundle must match the published version"
    );
    // Any successful publish must not exceed the final version.
    for version in [r1, r2].into_iter().flatten() {
        assert!(version <= final_version);
    }
}

#[test]
fn test_state_persists_and_restores_across_restart() {
    let dir = std::env::temp_dir().join(format!("sito_ha_state_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let state_path = dir.join("ha_state.toml");
    let key = Arc::new(Ed25519SigningKey::generate().unwrap());

    let first = MasterCoordinator::new(
        "test-master".to_string(),
        0,
        key.clone(),
        sito_stats::MetricsRegistry::new("test", "test"),
    )
    .with_state_path(state_path.clone());
    assert_eq!(first.restore_state().unwrap(), None);
    assert_eq!(first.update_bundle(test_bundle(1)).unwrap(), 1);
    assert_eq!(first.update_bundle(test_bundle(2)).unwrap(), 2);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&state_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "persisted HA state must remain owner-only");
    }

    // Simulate a restart: the same signing key and state path must resume
    // at v2 instead of resetting to v1 (which slaves reject as a rollback).
    let second = MasterCoordinator::new(
        "test-master".to_string(),
        0,
        key,
        sito_stats::MetricsRegistry::new("test", "test"),
    )
    .with_state_path(state_path.clone());
    assert_eq!(second.restore_state().unwrap(), Some(2));
    assert_eq!(second.get_current_version(), 2);
    assert!(second.update_bundle(test_bundle(2)).is_err());
    assert_eq!(second.update_bundle(test_bundle(3)).unwrap(), 3);

    // Corrupt state is moved aside and treated as absent.
    std::fs::write(&state_path, "not-json").unwrap();
    let third = MasterCoordinator::new(
        "test-master".to_string(),
        0,
        Arc::new(Ed25519SigningKey::generate().unwrap()),
        sito_stats::MetricsRegistry::new("test", "test"),
    )
    .with_state_path(state_path.clone());
    assert_eq!(third.restore_state().unwrap(), None);
    let corrupt_backups: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with("ha_state.corrupt.")
        })
        .collect();
    assert_eq!(
        corrupt_backups.len(),
        1,
        "corrupt state must be moved aside instead of deleted"
    );
    assert_eq!(third.update_bundle(test_bundle(1)).unwrap(), 1);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_restore_preserves_term_and_legacy_state_defaults_to_zero() {
    let dir = std::env::temp_dir().join(format!(
        "sito_ha_term_state_{}_{}",
        std::process::id(),
        rand::random::<u64>()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let state_path = dir.join("ha_state.toml");
    let key = Arc::new(Ed25519SigningKey::generate().unwrap());

    let mut promoted = test_bundle(5);
    promoted.term = 2;
    std::fs::write(&state_path, serde_json::to_vec(&promoted).unwrap()).unwrap();
    let restored = MasterCoordinator::new(
        "test-master".to_string(),
        0,
        key.clone(),
        sito_stats::MetricsRegistry::new("test", "test"),
    )
    .with_state_path(state_path.clone());
    assert_eq!(restored.restore_state().unwrap(), Some(5));
    assert_eq!(restored.get_current_term(), 2);

    // State written before terms existed has no `term` field and must load
    // as epoch 0.
    let legacy = r#"{"version":6,"timestamp":1,"config_toml":"config_version = 2\n[server]\nrole = \"slave\"\n","custom_rules":[],"lists":[]}"#;
    std::fs::write(&state_path, legacy).unwrap();
    let legacy_restored = MasterCoordinator::new(
        "test-master".to_string(),
        0,
        key,
        sito_stats::MetricsRegistry::new("test", "test"),
    )
    .with_state_path(state_path.clone());
    assert_eq!(legacy_restored.restore_state().unwrap(), Some(6));
    assert_eq!(legacy_restored.get_current_term(), 0);

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn test_async_persist_roundtrip_and_permissions() {
    let dir = std::env::temp_dir().join(format!(
        "sito_ha_async_state_{}_{}",
        std::process::id(),
        rand::random::<u64>()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let state_path = dir.join("ha_state.toml");
    let key = Arc::new(Ed25519SigningKey::generate().unwrap());
    let coordinator = MasterCoordinator::new(
        "test-master".to_string(),
        1,
        key.clone(),
        sito_stats::MetricsRegistry::new("test", "test"),
    )
    .with_state_path(state_path.clone());

    assert_eq!(
        coordinator
            .update_bundle_async(test_bundle(4))
            .await
            .unwrap(),
        4
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&state_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "async state writes must stay owner-only");
    }
    assert!(
        !state_path.with_extension("tmp").exists(),
        "the temporary file must be renamed away"
    );

    // The same signing key must restore the persisted state. Using a new
    // key must fail closed with an actionable error (H-08).
    let wrong = test_coordinator().with_state_path(state_path.clone());
    let err = wrong
        .restore_state()
        .expect_err("a replaced signing key must not silently re-sign persisted state");
    assert!(
        err.to_string()
            .contains("ha_signing.key was lost or replaced"),
        "the key-loss error must be actionable: {err}"
    );

    let restored = MasterCoordinator::new(
        "test-master".to_string(),
        1,
        key,
        sito_stats::MetricsRegistry::new("test", "test"),
    )
    .with_state_path(state_path);
    assert_eq!(restored.restore_state().unwrap(), Some(4));

    let _ = std::fs::remove_dir_all(&dir);
}

/// On a current-thread runtime a synchronous state write would starve the
/// ticker; `spawn_blocking` keeps the runtime responsive.
#[tokio::test]
async fn test_state_write_does_not_block_runtime() {
    let dir = std::env::temp_dir().join(format!(
        "sito_ha_nonblocking_{}_{}",
        std::process::id(),
        rand::random::<u64>()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let coordinator = test_coordinator()
        .with_state_path(dir.join("ha_state.toml"))
        .with_state_write_hook(Arc::new(|_version| {
            // Simulate a slow disk inside the blocking-pool writer instead
            // of using an unreplicable multi-MiB bundle (which publish must
            // now reject before persisting).
            std::thread::sleep(Duration::from_millis(200));
        }));

    let ticks = Arc::new(AtomicU64::new(0));
    let ticker_ticks = ticks.clone();
    let ticker = tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_millis(1)).await;
            ticker_ticks.fetch_add(1, Ordering::Relaxed);
        }
    });
    // Let the ticker start before measuring.
    tokio::task::yield_now().await;
    let before = ticks.load(Ordering::Relaxed);

    coordinator
        .update_bundle_async(test_bundle(2))
        .await
        .unwrap();
    let after = ticks.load(Ordering::Relaxed);

    ticker.abort();
    assert!(
        after > before,
        "the tokio runtime must keep ticking while HA state is written (before={before}, after={after})"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Forces the conflict branch and asserts the state write restoring the
/// concurrent publisher's active bundle runs on the blocking pool: on a
/// current-thread runtime a synchronous write would starve the ticker.
#[tokio::test(flavor = "current_thread")]
async fn test_conflict_restore_uses_blocking_pool() {
    let dir = std::env::temp_dir().join(format!(
        "sito_ha_conflict_blocking_{}_{}",
        std::process::id(),
        rand::random::<u64>()
    ));
    std::fs::create_dir_all(&dir).unwrap();

    let ticks = Arc::new(AtomicU64::new(0));
    let ticker_ticks = ticks.clone();
    let ticker = tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_millis(1)).await;
            ticker_ticks.fetch_add(1, Ordering::Relaxed);
        }
    });

    // Track each async state write and how far the ticker advanced while
    // the conflict-restore write ran (the second write).
    let writes = Arc::new(AtomicU64::new(0));
    let restore_ticks = Arc::new(AtomicU64::new(0));
    let written_versions = Arc::new(Mutex::new(Vec::new()));
    let first_write_started = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let hook = {
        let ticks = ticks.clone();
        let writes = writes.clone();
        let restore_ticks = restore_ticks.clone();
        let written_versions = written_versions.clone();
        let first_write_started = first_write_started.clone();
        Arc::new(move |version: u64| {
            let write_index = writes.fetch_add(1, Ordering::SeqCst) + 1;
            written_versions.lock().unwrap().push(version);
            if write_index == 1 {
                first_write_started.store(true, Ordering::SeqCst);
            }
            let start = ticks.load(Ordering::Relaxed);
            std::thread::sleep(Duration::from_millis(150));
            if write_index == 2 {
                let end = ticks.load(Ordering::Relaxed);
                restore_ticks.store(end.saturating_sub(start), Ordering::SeqCst);
            }
        })
    };

    let coordinator = test_coordinator()
        .with_state_path(dir.join("ha_state.toml"))
        .with_state_write_hook(hook);

    // Advance the sequence synchronously while the stale publisher's first
    // write is in flight: this forces the conflict-restore branch.
    let sync_coordinator = coordinator.clone();
    let started = first_write_started.clone();
    let sync_advance = tokio::spawn(async move {
        while !started.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
        sync_coordinator.update_bundle(test_bundle(3)).unwrap();
    });

    let err = coordinator
        .update_bundle_async(test_bundle(2))
        .await
        .expect_err("the stale async publish must report a conflict");
    assert!(
        matches!(err, HaError::Validation { .. }),
        "expected a version conflict, got {err:?}"
    );
    sync_advance.await.unwrap();

    assert_eq!(
        *written_versions.lock().unwrap(),
        vec![2, 3],
        "both the stale write and the conflict restore must use the async writer"
    );
    assert!(
        restore_ticks.load(Ordering::SeqCst) > 0,
        "the tokio runtime must keep ticking while the conflict restore writes state"
    );

    ticker.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

/// The conflict restore must leave the concurrently published active bundle
/// (not the stale prepared one) on disk.
#[tokio::test(flavor = "current_thread")]
async fn test_conflict_restore_persists_active_bundle() {
    let dir = std::env::temp_dir().join(format!(
        "sito_ha_conflict_persist_{}_{}",
        std::process::id(),
        rand::random::<u64>()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let state_path = dir.join("ha_state.toml");

    let first_write_started = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let hook = {
        let started = first_write_started.clone();
        Arc::new(move |_version: u64| {
            started.store(true, Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(100));
        })
    };
    let coordinator = test_coordinator()
        .with_state_path(state_path.clone())
        .with_state_write_hook(hook);

    let sync_coordinator = coordinator.clone();
    let started = first_write_started.clone();
    let sync_advance = tokio::spawn(async move {
        while !started.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
        sync_coordinator.update_bundle(test_bundle(3)).unwrap();
    });

    let err = coordinator
        .update_bundle_async(test_bundle(2))
        .await
        .expect_err("the stale async publish must report a conflict");
    assert!(
        matches!(err, HaError::Validation { .. }),
        "expected a version conflict, got {err:?}"
    );
    sync_advance.await.unwrap();

    assert_eq!(
        coordinator.get_current_version(),
        3,
        "the concurrent publish must not regress"
    );
    let active = coordinator
        .active_bundle
        .lock()
        .unwrap()
        .clone()
        .expect("active bundle");
    assert_eq!(active.version, 3);
    let persisted: ConfigBundle =
        serde_json::from_str(&std::fs::read_to_string(&state_path).unwrap()).unwrap();
    assert_eq!(
        persisted, active,
        "the restored state file must contain the active bundle"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn test_persist_failure_propagates() {
    let dir = std::env::temp_dir().join(format!(
        "sito_ha_persist_fail_{}_{}",
        std::process::id(),
        rand::random::<u64>()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let coordinator = test_coordinator().with_state_path(dir.join("ha_state.toml"));
    // Establish a previous good publish so "unchanged" is meaningful.
    coordinator.update_bundle(test_bundle(2)).unwrap();
    let before_version = coordinator.get_current_version();
    let before_bundle = coordinator
        .active_bundle
        .lock()
        .unwrap()
        .clone()
        .expect("previous active bundle");
    let before_push = coordinator
        .active_push
        .lock()
        .unwrap()
        .clone()
        .expect("previous active push");
    let before_push_version = match before_push {
        HaMessage::ConfigPush { version, .. } => version,
        other => panic!("expected a ConfigPush, got {other:?}"),
    };

    // A regular file where the state directory should be makes every
    // create_dir_all/write attempt fail deterministically.
    let blocker = dir.join("not-a-directory");
    std::fs::write(&blocker, b"blocked").unwrap();
    *coordinator.state_path.lock().unwrap() = Some(blocker.join("ha_state.toml"));

    let err = coordinator
        .update_bundle_async(test_bundle(3))
        .await
        .expect_err("a failed state write must not be reported as success");
    assert!(
        matches!(err, HaError::Io(_)),
        "expected an I/O error, got {err:?}"
    );
    assert_eq!(
        coordinator.get_current_version(),
        before_version,
        "a failed persist must not advance the published version"
    );
    assert_eq!(
        *coordinator.active_bundle.lock().unwrap(),
        Some(before_bundle),
        "a failed persist must leave the previously active bundle in place"
    );
    let after_push = coordinator
        .active_push
        .lock()
        .unwrap()
        .clone()
        .expect("active push must remain");
    let after_push_version = match after_push {
        HaMessage::ConfigPush { version, .. } => version,
        other => panic!("expected a ConfigPush, got {other:?}"),
    };
    assert_eq!(
        after_push_version, before_push_version,
        "a failed persist must not replace the active push"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// I5: `init_ha` owns the `replication_disabled` no-op counter. The spawned
/// listener must not double count it when `init_ha` already recorded it.
#[tokio::test]
async fn test_master_replication_disabled_is_not_double_counted() {
    let coordinator = test_coordinator();
    let metrics = coordinator.metrics.clone();
    metrics.inc_ha_startup_noop("master", "replication_disabled");
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let handle = spawn_master_server(
        HaConfig {
            replication_port: 0,
            ..Default::default()
        },
        coordinator,
        shutdown_rx,
    );
    handle.await.unwrap();

    let rendered = metrics.render_prometheus();
    assert!(
        rendered.contains(
            r#"sito_ha_startup_noop_total{role="master",reason="replication_disabled"} 1"#
        ),
        "the disabled listener must stay observable without double counting: {rendered}"
    );
    assert!(
        !rendered.contains(
            r#"sito_ha_startup_noop_total{role="master",reason="replication_disabled"} 2"#
        ),
        "spawn_master_server must not increment the startup no-op again"
    );
    let _ = shutdown_tx.send(true);
}

#[tokio::test]
async fn test_master_bind_failure_records_startup_noop() {
    // Keep the probe listener bound so the master cannot bind the port.
    let port_lease = sito_test_support::reserve_port().unwrap();
    let port = port_lease.port();
    let coordinator = test_coordinator();
    let metrics = coordinator.metrics.clone();
    let (_shutdown_tx, shutdown_rx) = watch::channel(false);
    let handle = spawn_master_server(
        HaConfig {
            replication_port: port,
            listen_addr: "127.0.0.1".to_string(),
            allow_insecure_ws: true,
            slave_token: Some("tok".to_string()),
            ..Default::default()
        },
        coordinator,
        shutdown_rx,
    );
    handle.await.unwrap();

    let rendered = metrics.render_prometheus();
    assert!(
        rendered.contains(r#"sito_ha_startup_noop_total{role="master",reason="bind_failed"} 1"#),
        "a listener bind failure must be observable: {rendered}"
    );
    drop(port_lease);
}

#[tokio::test]
async fn test_master_tls_init_failure_records_startup_noop() {
    let coordinator = test_coordinator();
    let observer = coordinator.clone();
    let metrics = coordinator.metrics.clone();
    let (_shutdown_tx, shutdown_rx) = watch::channel(false);
    let handle = spawn_master_server(
        HaConfig {
            replication_port: 1,
            listen_addr: "127.0.0.1".to_string(),
            cert: Some(PathBuf::from("/nonexistent/sito-master.crt")),
            key: Some(PathBuf::from("/nonexistent/sito-master.key")),
            pinned_slave_fingerprints: vec!["blake3:deadbeef".to_string()],
            ..Default::default()
        },
        coordinator,
        shutdown_rx,
    );
    handle.await.unwrap();

    let rendered = metrics.render_prometheus();
    assert!(
        rendered
            .contains(r#"sito_ha_startup_noop_total{role="master",reason="tls_init_failed"} 1"#),
        "a TLS init failure must be observable: {rendered}"
    );

    // The operator-facing readiness signal must carry the same failure:
    // DNS health alone used to hide a master that never started replication.
    let readiness = observer.readiness();
    assert!(!readiness.ready, "TLS failure must leave HA not ready");
    let reason = readiness.reason.unwrap_or_default();
    assert!(
        reason.contains("mTLS"),
        "readiness must name the TLS failure: {reason}"
    );
}

#[tokio::test]
async fn test_master_listener_bind_marks_readiness_ready() {
    let coordinator = test_coordinator();
    let observer = coordinator.clone();
    let port = sito_test_support::reserve_port_number().unwrap();

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let handle = spawn_master_server(
        HaConfig {
            replication_port: port,
            listen_addr: "127.0.0.1".to_string(),
            allow_insecure_ws: true,
            slave_token: Some("tok".to_string()),
            ..Default::default()
        },
        coordinator,
        shutdown_rx,
    );

    let mut readiness = observer.readiness();
    for _ in 0..50 {
        if readiness.ready {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
        readiness = observer.readiness();
    }
    assert!(
        readiness.ready,
        "a bound replication listener must be reported ready: {readiness:?}"
    );
    assert!(readiness.reason.is_none());

    let _ = shutdown_tx.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
}

#[tokio::test]
async fn test_master_bind_failure_marks_readiness_failed() {
    // Keep the probe listener bound so the master cannot bind the port.
    let port_lease = sito_test_support::reserve_port().unwrap();
    let port = port_lease.port();
    let coordinator = test_coordinator();
    let observer = coordinator.clone();
    let (_shutdown_tx, shutdown_rx) = watch::channel(false);
    let handle = spawn_master_server(
        HaConfig {
            replication_port: port,
            listen_addr: "127.0.0.1".to_string(),
            allow_insecure_ws: true,
            slave_token: Some("tok".to_string()),
            ..Default::default()
        },
        coordinator,
        shutdown_rx,
    );
    handle.await.unwrap();

    let readiness = observer.readiness();
    assert!(!readiness.ready, "a bind failure must leave HA not ready");
    assert!(
        readiness
            .reason
            .unwrap_or_default()
            .contains("Failed to bind"),
        "readiness must name the bind failure"
    );
    drop(port_lease);
}

#[tokio::test]
async fn test_master_replication_disabled_is_ready_and_explained() {
    let coordinator = test_coordinator();
    coordinator.mark_replication_disabled();
    let readiness = coordinator.readiness();
    assert!(
        readiness.ready,
        "an explicitly disabled replication listener is not a failure"
    );
    assert!(
        readiness
            .reason
            .unwrap_or_default()
            .contains("replication_port"),
        "the disabled state must be explained"
    );
}

#[tokio::test]
async fn test_broadcast_falls_back_to_async_delivery_when_queue_full() {
    let coordinator = test_coordinator();
    coordinator.update_bundle(test_bundle(2)).unwrap();

    let (tx, mut rx) = mpsc::channel::<HaMessage>(1);
    // Fill the queue so broadcast's try_send fails.
    tx.send(HaMessage::Ping { ts: 1 }).await.unwrap();
    coordinator.slaves.lock().unwrap().insert(
        "slave-1".to_string(),
        ActiveSlave {
            instance: "slave-1".to_string(),
            remote_addr: "127.0.0.1:12345".parse().unwrap(),
            synced_version: 1,
            last_ping: Instant::now(),
            connected_at: Utc::now(),
            last_stats: None,
            sender: tx.clone(),
            capabilities: vec!["stats-v1".to_string()],
            connection_id: 1,
        },
    );

    coordinator.broadcast(&HaMessage::Ping { ts: 2 });

    // First message drains the queue; the coalesced fallback delivers the
    // latest active configuration bundle (not the superseded broadcast).
    assert!(rx.recv().await.is_some());
    let delivered = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("fallback delivery timed out")
        .expect("channel closed");
    assert!(matches!(delivered, HaMessage::ConfigPush { .. }));

    // Cleanup removes the per-instance metric label.
    coordinator.metrics.set_ha_config_version("slave-1", 1.0);
    coordinator.metrics.remove_ha_config_version("slave-1");
}

#[tokio::test]
async fn test_broadcast_respects_per_slave_queue_byte_budget() {
    let coordinator = test_coordinator();
    coordinator.update_bundle(test_bundle(2)).unwrap();

    let (tx, mut rx) = mpsc::channel::<HaMessage>(8);
    coordinator.slaves.lock().unwrap().insert(
        "slow-slave".to_string(),
        ActiveSlave {
            instance: "slow-slave".to_string(),
            remote_addr: "127.0.0.1:12345".parse().unwrap(),
            synced_version: 0,
            last_ping: Instant::now(),
            connected_at: Utc::now(),
            last_stats: None,
            sender: tx,
            capabilities: vec![],
            connection_id: 1,
        },
    );
    // Pretend the session has a full byte budget queued even though the
    // message-count channel has room.
    coordinator
        .queued_bytes
        .lock()
        .unwrap()
        .insert(("slow-slave".to_string(), 1), MAX_SLAVE_QUEUE_BYTES);

    assert_eq!(coordinator.broadcast(&HaMessage::Ping { ts: 2 }), 1);
    // The coalesced task must wait for the byte budget instead of queueing
    // another message.
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        rx.try_recv().is_err(),
        "the byte budget must block delivery while the queue is full"
    );

    // Draining the accounting (as the session loop does after a read)
    // releases the coalesced delivery.
    coordinator
        .queued_bytes
        .lock()
        .unwrap()
        .remove(&("slow-slave".to_string(), 1));
    let delivered = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("coalesced delivery timed out")
        .expect("channel closed");
    assert!(matches!(delivered, HaMessage::ConfigPush { .. }));
}

/// Regression (deferred D2): every non-broadcast send path must account
/// its bytes, a rejected send must not inflate the budget, and an
/// over-budget send must be refused before it touches the channel.
#[tokio::test]
async fn test_try_queue_accounted_tracks_bytes_and_rejects_full_queue() {
    let coordinator = test_coordinator();
    let (tx, mut rx) = mpsc::channel::<HaMessage>(1);
    let msg = HaMessage::Ping { ts: 7 };
    let size = msg.to_json().unwrap().len();
    let key = ("slave-1".to_string(), 1);
    // Registration installs the session key; the helper refuses to create
    // accounting for an unregistered/superseded session.
    coordinator
        .queued_bytes
        .lock()
        .unwrap()
        .insert(key.clone(), 0);

    coordinator
        .try_queue_accounted("slave-1", 1, &tx, size, msg.clone())
        .expect("queue has room");
    assert_eq!(
        coordinator.queued_bytes.lock().unwrap().get(&key).copied(),
        Some(size),
        "a queued message must be accounted"
    );

    // The single-slot channel is full: a rejected send must not add bytes.
    assert!(
        coordinator
            .try_queue_accounted("slave-1", 1, &tx, size, msg.clone())
            .is_err()
    );
    assert_eq!(
        coordinator.queued_bytes.lock().unwrap().get(&key).copied(),
        Some(size),
        "a rejected send must not change the accounting"
    );

    let _ = rx.recv().await;
    drop(rx);
    // A closed channel must not add bytes either.
    assert!(
        coordinator
            .try_queue_accounted("slave-1", 1, &tx, size, msg.clone())
            .is_err()
    );
    assert_eq!(
        coordinator.queued_bytes.lock().unwrap().get(&key).copied(),
        Some(size)
    );

    // A sender whose session key was removed by a reconnect must not
    // recreate accounting for a channel nobody will drain.
    let (unregistered_tx, mut unregistered_rx) = mpsc::channel::<HaMessage>(4);
    assert!(
        coordinator
            .try_queue_accounted("slave-3", 3, &unregistered_tx, size, msg.clone())
            .is_err(),
        "an unregistered/superseded session must be refused"
    );
    assert!(
        unregistered_rx.try_recv().is_err(),
        "a refused session must not receive the message"
    );

    // An over-budget send is refused before it is queued, so a coalesced
    // fallback can take over instead of growing the queue.
    let (over_tx, mut over_rx) = mpsc::channel::<HaMessage>(4);
    let over_key = ("slave-2".to_string(), 9);
    coordinator
        .queued_bytes
        .lock()
        .unwrap()
        .insert(over_key.clone(), MAX_SLAVE_QUEUE_BYTES);
    let err = coordinator
        .try_queue_accounted("slave-2", 9, &over_tx, size, msg)
        .expect_err("an over-budget send must be refused");
    assert!(err.contains("budget"), "unexpected error: {err}");
    assert!(
        over_rx.try_recv().is_err(),
        "an over-budget send must not touch the channel"
    );
    assert_eq!(
        coordinator
            .queued_bytes
            .lock()
            .unwrap()
            .get(&over_key)
            .copied(),
        Some(MAX_SLAVE_QUEUE_BYTES),
        "a refused send must not change the accounting"
    );
}

/// Regression (deferred D2): a reconnecting instance used to inherit the
/// superseded session's `queued_bytes`, so the coalesced-delivery loop
/// could spin until phantom accounting cleared. Registration must reset it.
#[tokio::test]
async fn test_reconnect_resets_per_slave_queue_accounting() {
    use tokio_tungstenite::tungstenite::protocol::Role;
    use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

    let coordinator = test_coordinator();
    // No active bundle: registration has nothing to enqueue, so any
    // remaining value after registration is phantom accounting. The key
    // carries a superseded connection id.
    coordinator
        .queued_bytes
        .lock()
        .unwrap()
        .insert(("slave-1".to_string(), 999), MAX_SLAVE_QUEUE_BYTES);

    let (server_socket, client_socket) = tokio::io::duplex(64 * 1024);
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
            .handle_connection(server_ws, "127.0.0.1:1000".parse().unwrap())
            .await;
    });

    let hello = HaMessage::Hello {
        instance: "slave-1".to_string(),
        have_version: 0,
        have_term: 0,
        capabilities: vec![],
        token: None,
        role: Some("slave".to_string()),
        protocol_version: Some(crate::protocol::PROTOCOL_VERSION),
    };
    client_ws
        .send(WsMessage::Text(hello.to_json().unwrap().into()))
        .await
        .unwrap();

    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if coordinator.slaves.lock().unwrap().contains_key("slave-1") {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the reconnecting session must register");

    let active_connection_id = coordinator.slaves.lock().unwrap()["slave-1"].connection_id;
    let queued = coordinator.queued_bytes.lock().unwrap();
    assert_eq!(
        queued
            .get(&("slave-1".to_string(), active_connection_id))
            .copied(),
        Some(0),
        "registration must install a zero baseline for the new session"
    );
    assert!(
        !queued.contains_key(&("slave-1".to_string(), 999)),
        "phantom accounting from the superseded session must be reset"
    );

    session.abort();
}

/// Regression (deferred D2): a superseded session draining its old channel
/// must subtract from its own session key, not the replacement's.
#[tokio::test]
async fn test_superseded_session_drain_does_not_charge_new_session() {
    let coordinator = test_coordinator();
    let old_key = ("slave-1".to_string(), 1);
    let new_key = ("slave-1".to_string(), 2);
    coordinator
        .queued_bytes
        .lock()
        .unwrap()
        .insert(old_key.clone(), 500);
    coordinator
        .queued_bytes
        .lock()
        .unwrap()
        .insert(new_key.clone(), 700);

    // The old session drains after the reconnect completed.
    coordinator.account_drained("slave-1", 1, 500);

    let queued = coordinator.queued_bytes.lock().unwrap();
    assert_eq!(queued.get(&old_key).copied(), Some(0));
    assert_eq!(
        queued.get(&new_key).copied(),
        Some(700),
        "the replacement session's budget must not be reduced by the old drain"
    );
}

/// Regression (deferred D2): a coalesced fallback task spawned for a
/// superseded session must stop when it loses ownership, and must not
/// deliver to or charge the replacement session.
#[tokio::test]
async fn test_pending_coalesced_task_does_not_charge_reconnected_session() {
    let coordinator = test_coordinator();
    coordinator.update_bundle(test_bundle(2)).unwrap();

    let (old_tx, _old_rx) = mpsc::channel::<HaMessage>(4);
    coordinator.slaves.lock().unwrap().insert(
        "slave-1".to_string(),
        ActiveSlave {
            instance: "slave-1".to_string(),
            remote_addr: "127.0.0.1:1000".parse().unwrap(),
            synced_version: 0,
            last_ping: Instant::now(),
            connected_at: Utc::now(),
            last_stats: None,
            sender: old_tx,
            capabilities: vec![],
            connection_id: 1,
        },
    );
    let old_key = ("slave-1".to_string(), 1);
    coordinator
        .queued_bytes
        .lock()
        .unwrap()
        .insert(old_key.clone(), MAX_SLAVE_QUEUE_BYTES);

    // Broadcast sees the exhausted budget and schedules the fallback task.
    assert_eq!(coordinator.broadcast(&HaMessage::Ping { ts: 2 }), 1);
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if coordinator
                .pending_fallbacks
                .lock()
                .unwrap()
                .contains(&old_key)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the fallback task must be pending");

    // Reconnect: replace the active entry and reset the superseded
    // session's accounting.
    let (new_tx, mut new_rx) = mpsc::channel::<HaMessage>(4);
    {
        let mut slaves = coordinator.slaves.lock().unwrap();
        coordinator
            .queued_bytes
            .lock()
            .unwrap()
            .retain(|(instance, _), _| instance != "slave-1");
        slaves.insert(
            "slave-1".to_string(),
            ActiveSlave {
                instance: "slave-1".to_string(),
                remote_addr: "127.0.0.1:1001".parse().unwrap(),
                synced_version: 0,
                last_ping: Instant::now(),
                connected_at: Utc::now(),
                last_stats: None,
                sender: new_tx,
                capabilities: vec![],
                connection_id: 2,
            },
        );
    }

    // The old task must notice it lost ownership and exit.
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if !coordinator
                .pending_fallbacks
                .lock()
                .unwrap()
                .contains(&old_key)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the superseded fallback task must exit");

    assert_eq!(
        coordinator
            .queued_bytes
            .lock()
            .unwrap()
            .get(&("slave-1".to_string(), 2))
            .copied(),
        None,
        "the superseded task must not charge the replacement session"
    );
    assert!(
        new_rx.try_recv().is_err(),
        "the superseded task must not deliver to the replacement session"
    );
}

#[test]
fn test_per_ip_handshake_budget_is_bounded_and_released() {
    let budget = Arc::new(HandshakeBudget::default());
    let ip: IpAddr = "192.0.2.10".parse().unwrap();
    let mut permits = Vec::new();
    for _ in 0..MAX_HANDSHAKES_PER_IP {
        permits.push(
            budget
                .try_acquire(ip)
                .expect("a slot must be available below the per-IP limit"),
        );
    }
    assert!(
        budget.try_acquire(ip).is_none(),
        "the per-IP handshake budget must be bounded"
    );
    // A different source IP has its own budget.
    assert!(
        budget
            .try_acquire("198.51.100.20".parse().unwrap())
            .is_some()
    );
    permits.pop();
    assert!(
        budget.try_acquire(ip).is_some(),
        "dropping a permit must release a slot"
    );
}

#[test]
fn test_unregister_superseded_session_keeps_live_entry() {
    let coordinator = test_coordinator();
    let (old_tx, _old_rx) = mpsc::channel::<HaMessage>(1);
    let (new_tx, _new_rx) = mpsc::channel::<HaMessage>(1);

    let entry = |connection_id: u64, sender: mpsc::Sender<HaMessage>| ActiveSlave {
        instance: "slave-1".to_string(),
        remote_addr: "127.0.0.1:1000".parse().unwrap(),
        synced_version: 1,
        last_ping: Instant::now(),
        connected_at: Utc::now(),
        last_stats: None,
        sender,
        capabilities: vec![],
        connection_id,
    };

    coordinator
        .slaves
        .lock()
        .unwrap()
        .insert("slave-1".to_string(), entry(1, old_tx));
    // A reconnect replaces the tracked entry.
    coordinator
        .slaves
        .lock()
        .unwrap()
        .insert("slave-1".to_string(), entry(2, new_tx));

    // The old session tearing down later must not evict the live entry.
    assert!(!coordinator.unregister_session("slave-1", 1));
    assert!(
        coordinator.slaves.lock().unwrap().contains_key("slave-1"),
        "superseded session must not remove the reconnected slave"
    );

    // The owning session still cleans up normally.
    assert!(coordinator.unregister_session("slave-1", 2));
    assert!(!coordinator.slaves.lock().unwrap().contains_key("slave-1"));
}

#[tokio::test]
async fn test_stale_repushes_are_cleaned_up_on_disconnect() {
    let coordinator = test_coordinator();
    coordinator.update_bundle(test_bundle(2)).unwrap();

    let (tx, _rx) = mpsc::channel::<HaMessage>(4);
    coordinator.slaves.lock().unwrap().insert(
        "slave-1".to_string(),
        ActiveSlave {
            instance: "slave-1".to_string(),
            remote_addr: "127.0.0.1:1000".parse().unwrap(),
            synced_version: 1,
            last_ping: Instant::now(),
            connected_at: Utc::now(),
            last_stats: None,
            sender: tx,
            capabilities: vec![],
            connection_id: 7,
        },
    );

    // A stale ACK records one catch-up attempt for the session.
    let ack = HaMessage::Ack {
        version: 1,
        term: 0,
        conflict: None,
        applied: true,
        error: None,
    }
    .to_json()
    .unwrap();
    assert!(coordinator.process_slave_msg("slave-1", 7, &ack));
    assert_eq!(
        coordinator.stale_repushes.lock().unwrap().get("slave-1"),
        Some(&1),
        "the catch-up attempt must be recorded"
    );

    // Disconnecting must drop the bookkeeping, otherwise the map grows
    // without bound across reconnects.
    assert!(coordinator.unregister_session("slave-1", 7));
    assert!(
        coordinator.stale_repushes.lock().unwrap().is_empty(),
        "stale_repushes must not leak across sessions"
    );
}

#[test]
fn test_update_bundle_strips_structured_client_secrets() {
    let coordinator = test_coordinator();
    let mut secrets = toml::Table::new();
    secrets.insert(
        "kids-tablet".to_string(),
        toml::Value::String("client_shared_secret_9876".to_string()),
    );
    let mut clients = toml::Table::new();
    clients.insert("client_id_secrets".to_string(), toml::Value::Table(secrets));

    let bundle = ConfigBundle {
        clients: Some(toml::Value::Table(clients)),
        ..test_bundle(2)
    };
    coordinator.update_bundle(bundle).unwrap();

    let stored = coordinator
        .active_bundle
        .lock()
        .unwrap()
        .clone()
        .expect("active bundle");
    let serialized = stored.to_json().unwrap();
    assert!(
        !serialized.contains("client_shared_secret_9876"),
        "stored/persisted bundle must not contain client secrets: {serialized}"
    );
    assert!(!serialized.contains("client_id_secrets"));
    assert!(stored.clients.is_some(), "non-secret client data is kept");
}

#[tokio::test]
async fn test_ahead_slave_same_term_does_not_seed_or_rebase() {
    use tokio_tungstenite::tungstenite::protocol::Role;
    use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

    let coordinator = test_coordinator();
    // Active bundle at v2 while the connecting slave reports v10.
    coordinator.update_bundle(test_bundle(2)).unwrap();

    let (server_socket, client_socket) = tokio::io::duplex(256 * 1024);
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
            .handle_connection(server_ws, "127.0.0.1:1000".parse().unwrap())
            .await;
    });

    let hello = HaMessage::Hello {
        instance: "promoted-slave".to_string(),
        have_version: 10,
        have_term: 0,
        capabilities: vec![],
        token: None,
        role: Some("slave".to_string()),
        protocol_version: Some(crate::protocol::PROTOCOL_VERSION),
    };
    client_ws
        .send(WsMessage::Text(hello.to_json().unwrap().into()))
        .await
        .unwrap();

    // A slave ahead in the *same* term is divergence evidence, not
    // authority. The master must not adopt its version or re-publish its
    // own bundle above it.
    let pushed = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match client_ws.next().await {
                Some(Ok(WsMessage::Text(txt))) => {
                    if let Ok(msg @ HaMessage::ConfigPush { .. }) = HaMessage::from_json(&txt) {
                        break msg;
                    }
                }
                Some(Ok(_)) => {}
                _ => panic!("connection closed before a ConfigPush"),
            }
        }
    })
    .await
    .expect("timed out waiting for the current push");
    let (push_version, push_term) = match pushed {
        HaMessage::ConfigPush { version, term, .. } => (version, term),
        other => panic!("expected ConfigPush, got {other:?}"),
    };
    assert_eq!(push_version, 2, "the master must keep its own version");
    assert_eq!(push_term, 0, "the master must keep its own term");
    assert_eq!(coordinator.get_current_version(), 2);
    assert_eq!(coordinator.get_current_term(), 0);
    assert!(
        coordinator.is_diverged(),
        "a same-term version gap must be surfaced as divergence"
    );
    let reason = coordinator.diverged_reason().unwrap();
    assert!(
        reason.contains("continuity") && reason.contains("explicit promotion"),
        "reason: {reason}"
    );

    // No automatic rebase on the ahead ACK either.
    let ack = HaMessage::Ack {
        version: 10,
        term: 0,
        conflict: None,
        applied: true,
        error: None,
    };
    client_ws
        .send(WsMessage::Text(ack.to_json().unwrap().into()))
        .await
        .unwrap();
    let extra = tokio::time::timeout(Duration::from_millis(300), async {
        loop {
            match client_ws.next().await {
                Some(Ok(WsMessage::Text(txt))) => {
                    if matches!(HaMessage::from_json(&txt), Ok(HaMessage::ConfigPush { .. })) {
                        break true;
                    }
                }
                Some(Ok(_)) => {}
                _ => break false,
            }
        }
    })
    .await;
    assert!(
        !matches!(extra, Ok(true)),
        "an ahead ACK must not trigger an automatic rebase push"
    );
    assert_eq!(coordinator.get_current_version(), 2);
    assert_eq!(coordinator.get_current_term(), 0);

    session.abort();
}

#[tokio::test]
async fn test_slave_ahead_ack_marks_diverged_without_republishing() {
    let coordinator = test_coordinator();
    coordinator.update_bundle(test_bundle(2)).unwrap();

    let (tx, mut rx) = mpsc::channel::<HaMessage>(8);
    coordinator.slaves.lock().unwrap().insert(
        "slave-1".to_string(),
        ActiveSlave {
            instance: "slave-1".to_string(),
            remote_addr: "127.0.0.1:1000".parse().unwrap(),
            synced_version: 50,
            last_ping: Instant::now(),
            connected_at: Utc::now(),
            last_stats: None,
            sender: tx,
            capabilities: vec![],
            connection_id: 1,
        },
    );

    // A slave acknowledging a version above the master's is a continuity
    // error, not something to auto-repair: doing so would publish this
    // master's possibly-stale bundle over newer configuration.
    let ack = HaMessage::Ack {
        version: 50,
        term: 0,
        conflict: None,
        applied: true,
        error: None,
    }
    .to_json()
    .unwrap();
    assert!(coordinator.process_slave_msg("slave-1", 1, &ack));
    assert!(coordinator.is_diverged(), "divergence must be surfaced");
    let rendered = coordinator.metrics.render_prometheus();
    assert!(
        rendered.contains(r#"sito_ha_diverged{instance="slave-1"} 1"#),
        "the per-slave divergence gauge must be raised: {rendered}"
    );
    let reason = coordinator.diverged_reason().unwrap();
    assert!(
        reason.contains("continuity") && reason.contains("explicit promotion"),
        "reason: {reason}"
    );
    assert_eq!(
        coordinator.get_current_version(),
        2,
        "the master must not rebase to the divergent version"
    );
    assert!(
        rx.try_recv().is_err(),
        "no recovery push may be queued automatically"
    );
}

#[tokio::test]
async fn test_same_version_fork_ack_marks_divergence_and_unsyncs_slave() {
    let coordinator = test_coordinator();
    coordinator.update_bundle(test_bundle(2)).unwrap();

    let (tx, _rx) = mpsc::channel::<HaMessage>(8);
    coordinator.slaves.lock().unwrap().insert(
        "forked-slave".to_string(),
        ActiveSlave {
            instance: "forked-slave".to_string(),
            remote_addr: "127.0.0.1:1000".parse().unwrap(),
            synced_version: 2,
            last_ping: Instant::now(),
            connected_at: Utc::now(),
            last_stats: None,
            sender: tx,
            capabilities: vec![],
            connection_id: 1,
        },
    );

    let ack = HaMessage::Ack {
        version: 2,
        term: 0,
        applied: false,
        conflict: Some(AckConflict::SameVersionFork),
        error: Some("same-version payload fork".to_string()),
    }
    .to_json()
    .unwrap();
    assert!(coordinator.process_slave_msg("forked-slave", 1, &ack));
    assert!(
        coordinator.is_diverged(),
        "a fork ACK must latch divergence"
    );
    let reason = coordinator.diverged_reason().unwrap();
    assert!(reason.contains("fork"), "reason: {reason}");
    assert_eq!(
        coordinator.slaves.lock().unwrap()["forked-slave"].synced_version,
        0,
        "a rejected fork push must not leave the slave reported as synced"
    );
}

/// Important 1 regression: the published-envelope history is shared by all
/// slaves. One slave's ACK must not remove the envelope before another
/// slave reports the same-version fork for it.
#[tokio::test]
async fn test_two_slaves_both_record_fork_for_same_published_envelope() {
    let coordinator = test_coordinator();
    coordinator.update_bundle(test_bundle(2)).unwrap();

    for (instance, connection_id) in [("fork-a", 1), ("fork-b", 2)] {
        let (tx, _rx) = mpsc::channel::<HaMessage>(8);
        coordinator.slaves.lock().unwrap().insert(
            instance.to_string(),
            ActiveSlave {
                instance: instance.to_string(),
                remote_addr: format!("127.0.0.1:{connection_id}").parse().unwrap(),
                synced_version: 2,
                last_ping: Instant::now(),
                connected_at: Utc::now(),
                last_stats: None,
                sender: tx,
                capabilities: vec![],
                connection_id,
            },
        );
    }

    let ack = HaMessage::Ack {
        version: 2,
        term: 0,
        applied: false,
        conflict: Some(AckConflict::SameVersionFork),
        error: Some("same-version payload fork".to_string()),
    }
    .to_json()
    .unwrap();

    assert!(coordinator.process_slave_msg("fork-a", 1, &ack));
    assert!(coordinator.process_slave_msg("fork-b", 2, &ack));

    let summaries = coordinator.list_slaves();
    for instance in ["fork-a", "fork-b"] {
        let summary = summaries
            .iter()
            .find(|s| s.instance == instance)
            .expect("tracked slave");
        assert!(
            summary.diverged,
            "{instance} must be reported diverged for the shared envelope: {summaries:?}"
        );
        assert_eq!(
            summary.synced_version, 0,
            "{instance} must be marked unsynced after its fork ACK"
        );
    }
    assert!(coordinator.is_diverged());
}

#[tokio::test]
async fn test_term_divergence_survives_other_slave_and_clears_on_own_ack() {
    let coordinator = test_coordinator();
    coordinator.update_bundle(test_bundle(2)).unwrap();

    let (tx_a, _rx_a) = mpsc::channel::<HaMessage>(8);
    coordinator.slaves.lock().unwrap().insert(
        "newer-term-slave".to_string(),
        ActiveSlave {
            instance: "newer-term-slave".to_string(),
            remote_addr: "127.0.0.1:1000".parse().unwrap(),
            synced_version: 0,
            last_ping: Instant::now(),
            connected_at: Utc::now(),
            last_stats: None,
            sender: tx_a,
            capabilities: vec![],
            connection_id: 1,
        },
    );
    let (tx_b, _rx_b) = mpsc::channel::<HaMessage>(8);
    coordinator.slaves.lock().unwrap().insert(
        "synced-slave".to_string(),
        ActiveSlave {
            instance: "synced-slave".to_string(),
            remote_addr: "127.0.0.1:1001".parse().unwrap(),
            synced_version: 0,
            last_ping: Instant::now(),
            connected_at: Utc::now(),
            last_stats: None,
            sender: tx_b,
            capabilities: vec![],
            connection_id: 2,
        },
    );

    // Slave A knows a newer term: sticky term divergence.
    let newer_term = HaMessage::Ack {
        version: 3,
        term: 1,
        applied: true,
        conflict: None,
        error: None,
    }
    .to_json()
    .unwrap();
    assert!(coordinator.process_slave_msg("newer-term-slave", 1, &newer_term));
    assert!(coordinator.is_diverged());
    assert!(coordinator.diverged_reason().unwrap().contains("term"));

    // Slave B applying the master's current version must not clear the
    // unrelated term divergence.
    let synced = HaMessage::Ack {
        version: 2,
        term: 0,
        applied: true,
        conflict: None,
        error: None,
    }
    .to_json()
    .unwrap();
    assert!(coordinator.process_slave_msg("synced-slave", 2, &synced));
    assert!(
        coordinator.is_diverged(),
        "a different slave's success must not clear a term divergence"
    );
    assert!(coordinator.diverged_reason().unwrap().contains("term"));
    let summaries = coordinator.list_slaves();
    let newer = summaries
        .iter()
        .find(|s| s.instance == "newer-term-slave")
        .unwrap();
    assert!(
        newer.diverged,
        "latched divergence must be visible in the API summary"
    );
    let rendered = coordinator.metrics.render_prometheus();
    assert!(
        rendered.contains(r#"sito_ha_diverged{instance="newer-term-slave"} 1"#),
        "the sticky gauge must stay raised: {rendered}"
    );

    // H-10: an operator resync re-pushes the bundle but does not clear
    // another slave's advisory record before that slave proves recovery.
    coordinator.trigger_resync();
    assert!(
        coordinator.is_diverged(),
        "a resync must not clear divergence before the slave ACKs"
    );
    assert!(coordinator.process_slave_msg("newer-term-slave", 1, &synced));
    assert!(
        !coordinator.is_diverged(),
        "the acknowledging slave's own divergence must clear"
    );
    assert!(
        coordinator
            .metrics
            .render_prometheus()
            .contains(r#"sito_ha_diverged{instance="newer-term-slave"} 0"#),
        "the per-slave divergence gauge must be zeroed after the ACK"
    );
}

#[tokio::test]
async fn test_fork_divergence_does_not_block_publishing_and_clears_on_accept() {
    let coordinator = test_coordinator();
    coordinator.update_bundle(test_bundle(2)).unwrap();

    let (tx, _rx) = mpsc::channel::<HaMessage>(8);
    coordinator.slaves.lock().unwrap().insert(
        "forked-slave".to_string(),
        ActiveSlave {
            instance: "forked-slave".to_string(),
            remote_addr: "127.0.0.1:1000".parse().unwrap(),
            synced_version: 0,
            last_ping: Instant::now(),
            connected_at: Utc::now(),
            last_stats: None,
            sender: tx,
            capabilities: vec![],
            connection_id: 1,
        },
    );
    let (other_tx, mut other_rx) = mpsc::channel::<HaMessage>(8);
    coordinator.slaves.lock().unwrap().insert(
        "other-slave".to_string(),
        ActiveSlave {
            instance: "other-slave".to_string(),
            remote_addr: "127.0.0.1:1001".parse().unwrap(),
            synced_version: 0,
            last_ping: Instant::now(),
            connected_at: Utc::now(),
            last_stats: None,
            sender: other_tx,
            capabilities: vec![],
            connection_id: 2,
        },
    );

    let fork = HaMessage::Ack {
        version: 2,
        term: 0,
        applied: false,
        conflict: Some(AckConflict::SameVersionFork),
        error: Some("same-version payload fork".to_string()),
    }
    .to_json()
    .unwrap();
    assert!(coordinator.process_slave_msg("forked-slave", 1, &fork));
    assert!(coordinator.diverged_reason().unwrap().contains("fork"));

    // One forked replica must not stop the master's sequence or the push
    // to healthy replicas.
    assert_eq!(coordinator.update_bundle(test_bundle(3)).unwrap(), 3);
    match other_rx.try_recv().expect("healthy slave must receive v3") {
        HaMessage::ConfigPush { version, term, .. } => {
            assert_eq!(version, 3);
            assert_eq!(term, 0);
        }
        other => panic!("expected ConfigPush, got {other:?}"),
    }
    assert!(coordinator.is_diverged(), "the fork stays visible");
    let forked = coordinator
        .list_slaves()
        .into_iter()
        .find(|s| s.instance == "forked-slave")
        .unwrap();
    assert!(forked.diverged, "the forked slave must stay unsynced");

    // A resync does not fabricate recovery: it re-pushes the current
    // bundle and keeps the real fork latch until the slave accepts it.
    let outcome = coordinator.trigger_resync();
    assert!(outcome.active_bundle);
    assert!(
        coordinator.is_diverged(),
        "a resync must not clear a real fork latch"
    );

    // Once the slave accepts the current bundle (after promotion or local
    // reconciliation), its own latch clears.
    let accepted = HaMessage::Ack {
        version: 3,
        term: 0,
        applied: true,
        conflict: None,
        error: None,
    }
    .to_json()
    .unwrap();
    assert!(coordinator.process_slave_msg("forked-slave", 1, &accepted));
    assert!(!coordinator.is_diverged());
}

#[tokio::test]
async fn test_fabricated_fork_ack_without_matching_push_is_ignored() {
    let coordinator = test_coordinator();
    coordinator.update_bundle(test_bundle(2)).unwrap();

    let (tx, _rx) = mpsc::channel::<HaMessage>(8);
    coordinator.slaves.lock().unwrap().insert(
        "liar-slave".to_string(),
        ActiveSlave {
            instance: "liar-slave".to_string(),
            remote_addr: "127.0.0.1:1000".parse().unwrap(),
            synced_version: 0,
            last_ping: Instant::now(),
            connected_at: Utc::now(),
            last_stats: None,
            sender: tx,
            capabilities: vec![],
            connection_id: 1,
        },
    );

    // No push was ever sent at version 999, so this cannot prove a fork.
    let fabricated = HaMessage::Ack {
        version: 999,
        term: 0,
        applied: false,
        conflict: Some(AckConflict::SameVersionFork),
        error: Some("fabricated".to_string()),
    }
    .to_json()
    .unwrap();
    assert!(coordinator.process_slave_msg("liar-slave", 1, &fabricated));
    assert!(
        !coordinator.is_diverged(),
        "a fork ACK must be bound to a push the master sent"
    );

    // Even `u64::MAX` in an applied:false ACK is rejected before it can
    // influence state, and publishing continues.
    let huge = HaMessage::Ack {
        version: u64::MAX,
        term: 0,
        applied: false,
        conflict: Some(AckConflict::SameVersionFork),
        error: None,
    }
    .to_json()
    .unwrap();
    assert!(coordinator.process_slave_msg("liar-slave", 1, &huge));
    assert!(!coordinator.is_diverged());
    assert_eq!(coordinator.update_bundle(test_bundle(3)).unwrap(), 3);
}

#[tokio::test]
async fn test_same_term_ahead_divergence_clears_only_on_slave_ack() {
    let coordinator = test_coordinator();
    coordinator.update_bundle(test_bundle(2)).unwrap();

    let (tx, _rx) = mpsc::channel::<HaMessage>(8);
    coordinator.slaves.lock().unwrap().insert(
        "ahead-slave".to_string(),
        ActiveSlave {
            instance: "ahead-slave".to_string(),
            remote_addr: "127.0.0.1:1000".parse().unwrap(),
            synced_version: 0,
            last_ping: Instant::now(),
            connected_at: Utc::now(),
            last_stats: None,
            sender: tx,
            capabilities: vec![],
            connection_id: 1,
        },
    );

    let ahead = HaMessage::Ack {
        version: 50,
        term: 0,
        applied: true,
        conflict: None,
        error: None,
    }
    .to_json()
    .unwrap();
    assert!(coordinator.process_slave_msg("ahead-slave", 1, &ahead));
    assert!(coordinator.is_diverged());

    // The ACK for the master's own version proves this slave recovered:
    // per-slave divergence clears only now, not on a global resync.
    let current = HaMessage::Ack {
        version: 2,
        term: 0,
        applied: true,
        conflict: None,
        error: None,
    }
    .to_json()
    .unwrap();
    assert!(coordinator.process_slave_msg("ahead-slave", 1, &current));
    assert!(
        !coordinator.is_diverged(),
        "the acknowledging slave's ahead divergence must clear"
    );

    // A resync without a matching ACK does not clear anything.
    assert!(coordinator.process_slave_msg("ahead-slave", 1, &ahead));
    assert!(coordinator.is_diverged());
    coordinator.trigger_resync();
    assert!(
        coordinator.is_diverged(),
        "a resync alone must not clear divergence"
    );
}

#[tokio::test]
async fn test_ack_from_newer_term_marks_master_stale() {
    let coordinator = test_coordinator();
    coordinator.update_bundle(test_bundle(2)).unwrap();
    coordinator.current_term.store(1, Ordering::SeqCst);

    let (tx, mut rx) = mpsc::channel::<HaMessage>(8);
    coordinator.slaves.lock().unwrap().insert(
        "newer-slave".to_string(),
        ActiveSlave {
            instance: "newer-slave".to_string(),
            remote_addr: "127.0.0.1:1000".parse().unwrap(),
            synced_version: 3,
            last_ping: Instant::now(),
            connected_at: Utc::now(),
            last_stats: None,
            sender: tx,
            capabilities: vec![],
            connection_id: 1,
        },
    );

    let ack = HaMessage::Ack {
        version: 3,
        term: 2,
        conflict: None,
        applied: true,
        error: None,
    }
    .to_json()
    .unwrap();
    assert!(coordinator.process_slave_msg("newer-slave", 1, &ack));
    assert!(coordinator.is_diverged());
    let reason = coordinator.diverged_reason().unwrap();
    assert!(reason.contains("term"), "reason: {reason}");
    assert_eq!(
        coordinator.get_current_version(),
        2,
        "a stale master must not adopt a newer term's version"
    );
    assert_eq!(
        coordinator.get_current_term(),
        1,
        "the master must not raise its term from peer input"
    );
    assert!(
        rx.try_recv().is_err(),
        "a stale master must not republish over a newer epoch"
    );
}

#[tokio::test]
async fn test_hello_from_newer_term_rejects_stale_master() {
    use tokio_tungstenite::tungstenite::protocol::Role;
    use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

    let coordinator = test_coordinator();
    coordinator.update_bundle(test_bundle(2)).unwrap();

    let (server_socket, client_socket) = tokio::io::duplex(64 * 1024);
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
            .handle_connection(server_ws, "127.0.0.1:1000".parse().unwrap())
            .await;
    });

    let hello = HaMessage::Hello {
        instance: "newer-slave".to_string(),
        have_version: 3,
        have_term: 1,
        capabilities: vec![],
        token: None,
        role: Some("slave".to_string()),
        protocol_version: Some(crate::protocol::PROTOCOL_VERSION),
    };
    client_ws
        .send(WsMessage::Text(hello.to_json().unwrap().into()))
        .await
        .unwrap();

    // The stale master registers the replica and sends its own bundle; the
    // replica rejects it on term, and the master surfaces the divergence.
    let pushed = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            match client_ws.next().await {
                Some(Ok(WsMessage::Text(txt))) => {
                    if let Ok(msg @ HaMessage::ConfigPush { .. }) = HaMessage::from_json(&txt) {
                        break msg;
                    }
                }
                Some(Ok(_)) => {}
                _ => panic!("connection closed before a ConfigPush"),
            }
        }
    })
    .await
    .expect("timed out waiting for the master push");
    match pushed {
        HaMessage::ConfigPush { version, term, .. } => {
            assert_eq!(version, 2, "the stale master must not rebase its version");
            assert_eq!(term, 0, "the stale master must not adopt the newer term");
        }
        other => panic!("expected a ConfigPush, got {other:?}"),
    }
    assert_eq!(coordinator.get_current_version(), 2);
    assert_eq!(coordinator.get_current_term(), 0);
    assert!(
        coordinator.is_diverged(),
        "the newer-term replica must surface the divergence"
    );
    let reason = coordinator.diverged_reason().unwrap();
    assert!(reason.contains("term"), "reason: {reason}");

    session.abort();
}

#[test]
fn test_promoted_master_keeps_version_continuity_in_new_term() {
    let key = Arc::new(Ed25519SigningKey::generate().unwrap());
    let coordinator = MasterCoordinator::new(
        "promoted-master".to_string(),
        10,
        key,
        sito_stats::MetricsRegistry::new("test", "test"),
    )
    .with_term(1);

    // The explicit promotion continues above the previous sequence.
    let mut promoted = test_bundle(11);
    promoted.term = 1;
    assert_eq!(coordinator.update_bundle(promoted).unwrap(), 11);
    assert_eq!(coordinator.get_current_term(), 1);

    // A stale term-0 coordinator cannot publish a higher version into the
    // promoted cluster.
    let mut stale = test_bundle(12);
    stale.term = 0;
    let err = coordinator
        .update_bundle(stale)
        .expect_err("a stale term must not publish over the promoted epoch");
    assert!(matches!(err, HaError::Validation { ref field, .. } if field == "term"));
    assert_eq!(coordinator.get_current_version(), 11);
    assert_eq!(coordinator.get_current_term(), 1);
}

#[test]
fn test_unregister_removes_divergence_metric_series() {
    let coordinator = test_coordinator();
    let (tx, _rx) = mpsc::channel::<HaMessage>(1);
    coordinator.slaves.lock().unwrap().insert(
        "slave-1".to_string(),
        ActiveSlave {
            instance: "slave-1".to_string(),
            remote_addr: "127.0.0.1:1000".parse().unwrap(),
            synced_version: 1,
            last_ping: Instant::now(),
            connected_at: Utc::now(),
            last_stats: None,
            sender: tx,
            capabilities: vec![],
            connection_id: 1,
        },
    );
    coordinator.mark_diverged(
        DivergenceKind::Term,
        "slave-1",
        50,
        0,
        "continuity broken".to_string(),
    );
    assert!(
        coordinator
            .metrics
            .render_prometheus()
            .contains(r#"sito_ha_diverged{instance="slave-1"} 1"#),
        "the mark path must raise the gauge before disconnect"
    );

    assert!(coordinator.unregister_session("slave-1", 1));
    let rendered = coordinator.metrics.render_prometheus();
    assert!(
        !rendered.contains(r#"sito_ha_diverged{instance="slave-1"}"#),
        "the divergence series must be removed on disconnect: {rendered}"
    );
    assert!(
        !coordinator.is_diverged(),
        "the divergence record must be dropped with the session"
    );
}

/// A disconnected instance's divergence record and series are both removed,
/// so a later divergence on another instance must not recreate it.
#[test]
fn test_disconnected_divergence_is_never_recreated() {
    let coordinator = test_coordinator();
    let (tx, _rx) = mpsc::channel::<HaMessage>(1);
    coordinator.slaves.lock().unwrap().insert(
        "slave-a".to_string(),
        ActiveSlave {
            instance: "slave-a".to_string(),
            remote_addr: "127.0.0.1:1000".parse().unwrap(),
            synced_version: 1,
            last_ping: Instant::now(),
            connected_at: Utc::now(),
            last_stats: None,
            sender: tx,
            capabilities: vec![],
            connection_id: 1,
        },
    );
    coordinator.mark_diverged(
        DivergenceKind::Ahead,
        "slave-a",
        50,
        0,
        "a is ahead".to_string(),
    );
    assert!(coordinator.unregister_session("slave-a", 1));

    // A more severe divergence on a different, connected instance.
    let (tx, _rx) = mpsc::channel::<HaMessage>(1);
    coordinator.slaves.lock().unwrap().insert(
        "slave-b".to_string(),
        ActiveSlave {
            instance: "slave-b".to_string(),
            remote_addr: "127.0.0.1:1001".parse().unwrap(),
            synced_version: 1,
            last_ping: Instant::now(),
            connected_at: Utc::now(),
            last_stats: None,
            sender: tx,
            capabilities: vec![],
            connection_id: 2,
        },
    );
    coordinator.mark_diverged(
        DivergenceKind::Ahead,
        "slave-b",
        60,
        0,
        "b is ahead".to_string(),
    );

    let rendered = coordinator.metrics.render_prometheus();
    assert!(
        rendered.contains(r#"sito_ha_diverged{instance="slave-b"} 1"#),
        "the live divergence must be exposed: {rendered}"
    );
    assert!(
        !rendered.contains(r#"sito_ha_diverged{instance="slave-a"}"#),
        "a disconnected instance must not get a recreated series: {rendered}"
    );
    assert_eq!(coordinator.diverged_reason().as_deref(), Some("b is ahead"));
}

#[test]
fn test_slave_summary_flags_diverged_slave() {
    let entry = ActiveSlave {
        instance: "slave-1".to_string(),
        remote_addr: "127.0.0.1:1000".parse().unwrap(),
        synced_version: 9,
        last_ping: Instant::now(),
        connected_at: Utc::now(),
        last_stats: None,
        sender: mpsc::channel::<HaMessage>(1).0,
        capabilities: vec![],
        connection_id: 1,
    };
    let diverged = entry.to_summary(5, false);
    assert!(diverged.diverged);
    assert_eq!(diverged.lag, 0, "diverged lag must not look in sync");

    let synced = entry.to_summary(9, false);
    assert!(!synced.diverged);
    assert_eq!(synced.lag, 0);

    let behind = entry.to_summary(12, false);
    assert!(!behind.diverged);
    assert_eq!(behind.lag, 3);

    // A latched divergence (fork/term/ahead) must be visible even when the
    // version counter alone would look in sync.
    let latched = entry.to_summary(9, true);
    assert!(latched.diverged);
    assert_eq!(latched.lag, 0);
}

#[tokio::test]
async fn test_master_rejects_oversized_websocket_hello() {
    let port = sito_test_support::reserve_port_number().unwrap();
    let coordinator = test_coordinator().with_token(Some("tok".to_string()));
    let master_cfg = HaConfig {
        replication_port: port,
        listen_addr: "127.0.0.1".to_string(),
        allow_insecure_ws: true,
        slave_token: Some("tok".to_string()),
        ..Default::default()
    };
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let _server = spawn_master_server(master_cfg, coordinator.clone(), shutdown_rx);
    tokio::time::sleep(Duration::from_millis(100)).await;

    let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://127.0.0.1:{port}"))
        .await
        .expect("connect to master");

    // A valid Hello whose instance string blows past the 1 MiB cap: the
    // codec must reject it, so the slave is never registered.
    let hello = HaMessage::Hello {
        instance: "x".repeat(2 * 1024 * 1024),
        have_version: 0,
        have_term: 0,
        capabilities: vec![],
        token: Some("tok".to_string()),
        role: Some("slave".to_string()),
        protocol_version: Some(crate::protocol::PROTOCOL_VERSION),
    };
    let _ = ws
        .send(WsMessage::Text(hello.to_json().unwrap().into()))
        .await;

    let closed = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match ws.next().await {
                Some(Ok(WsMessage::Close(_)) | Err(_)) | None => break,
                _ => {}
            }
        }
    })
    .await;
    assert!(
        closed.is_ok(),
        "the master must close an oversized WebSocket message"
    );
    assert_eq!(
        coordinator.connected_slave_count(),
        0,
        "an oversized Hello must not register a slave"
    );

    let _ = shutdown_tx.send(true);
}

#[test]
fn test_update_bundle_rejects_u64_max_version() {
    let coordinator = test_coordinator();
    let err = coordinator
        .update_bundle(test_bundle(u64::MAX))
        .expect_err("u64::MAX must never be persisted as the active version");
    assert!(
        matches!(err, HaError::Validation { ref field, .. } if field == "version"),
        "unexpected error: {err:?}"
    );
    assert_eq!(
        coordinator.get_current_version(),
        1,
        "a rejected publish must not advance the sequence"
    );
    assert!(
        coordinator.active_bundle.lock().unwrap().is_none(),
        "a rejected publish must not store an active bundle"
    );
}

#[test]
fn test_restore_rejects_u64_max_state_instead_of_freezing() {
    let dir = std::env::temp_dir().join(format!(
        "sito_ha_max_state_{}_{}",
        std::process::id(),
        rand::random::<u64>()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let state_path = dir.join("ha_state.toml");
    std::fs::write(
        &state_path,
        serde_json::to_vec(&test_bundle(u64::MAX)).unwrap(),
    )
    .unwrap();

    let coordinator = test_coordinator().with_state_path(state_path);
    let err = coordinator
        .restore_state()
        .expect_err("a persisted u64::MAX sequence must fail closed");
    assert!(matches!(err, HaError::Validation { ref field, .. } if field == "version"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn test_hello_u64_max_does_not_seed_or_register() {
    use tokio_tungstenite::tungstenite::protocol::Role;
    use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

    let coordinator = test_coordinator();
    coordinator.update_bundle(test_bundle(2)).unwrap();

    let (server_socket, client_socket) = tokio::io::duplex(64 * 1024);
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
            .handle_connection(server_ws, "127.0.0.1:1000".parse().unwrap())
            .await;
    });

    let hello = HaMessage::Hello {
        instance: "hostile-slave".to_string(),
        have_version: u64::MAX,
        have_term: 0,
        capabilities: vec![],
        token: None,
        role: Some("slave".to_string()),
        protocol_version: Some(crate::protocol::PROTOCOL_VERSION),
    };
    client_ws
        .send(WsMessage::Text(hello.to_json().unwrap().into()))
        .await
        .unwrap();

    // The master closes the session without pushing or adopting the value.
    let closed = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            match client_ws.next().await {
                Some(Ok(WsMessage::Close(_)) | Err(_)) | None => break,
                _ => {}
            }
        }
    })
    .await;
    assert!(
        closed.is_ok(),
        "an implausible Hello must close the session"
    );
    session.await.unwrap();
    assert_eq!(
        coordinator.get_current_version(),
        2,
        "u64::MAX must never seed the master sequence"
    );
    assert_eq!(coordinator.connected_slave_count(), 0);
}

#[tokio::test]
async fn test_ack_u64_max_does_not_freeze_publishing() {
    let coordinator = test_coordinator();
    coordinator.update_bundle(test_bundle(2)).unwrap();

    let (tx, mut rx) = mpsc::channel::<HaMessage>(8);
    coordinator.slaves.lock().unwrap().insert(
        "hostile-slave".to_string(),
        ActiveSlave {
            instance: "hostile-slave".to_string(),
            remote_addr: "127.0.0.1:1000".parse().unwrap(),
            synced_version: 2,
            last_ping: Instant::now(),
            connected_at: Utc::now(),
            last_stats: None,
            sender: tx,
            capabilities: vec![],
            connection_id: 1,
        },
    );

    let ack = HaMessage::Ack {
        version: u64::MAX,
        term: 0,
        conflict: None,
        applied: true,
        error: None,
    }
    .to_json()
    .unwrap();
    assert!(coordinator.process_slave_msg("hostile-slave", 1, &ack));

    assert_eq!(
        coordinator.get_current_version(),
        2,
        "an implausible ACK must not change the master sequence"
    );
    assert!(
        rx.try_recv().is_err(),
        "an implausible ACK must not trigger a rebase push"
    );
    assert_eq!(
        coordinator.update_bundle(test_bundle(3)).unwrap(),
        3,
        "publishing must keep working after an implausible ACK"
    );
}
