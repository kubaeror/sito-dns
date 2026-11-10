//! Acceptance tests for Phase M8: High Availability (HA) Master/Slave.
//!
//! Authoritative documents:
//! - docs/phases/m8-ha.md
//! - docs/dns-server-plan-detailed.md (section 11, 12.1, 14.2, 17.3, 18.4)
//! - docs/adr/0002-ha-master-slave-push-no-raft.md

#![allow(clippy::pedantic)]
#![allow(clippy::unwrap_used)]

use arc_swap::ArcSwap;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use hickory_proto::rr::RecordType;
use sito_api::auth::AuthManager;
use sito_api::config_apply::{
    ApplyFuture, ConfigApplyHooks, ConfigFileApplyOutcome, FilterApply, apply_config_document_event,
};
use sito_api::router::create_router;
use sito_api::state::ServerContext;
use sito_cache::DnsCache;
use sito_core::ClientContext;
use sito_core::config::Config;
use sito_filter::HostsFilterEngine;
use sito_ha::{
    ConfigBundle, Ed25519SigningKey, HaConfig, HaError, HaMessage, MasterCoordinator,
    SlaveAppHandles, SlaveConfigApplier, SlaveState, SlaveStatusTracker, build_and_sign_push,
    generate_ha_certs, sanitize_config_for_bundle, scan_for_secrets, spawn_master_server,
    spawn_slave_worker, verify_and_unpack_push,
};
use sito_stats::{MetricsRegistry, QueryLogWriter, StatsDb};
use sito_test::wait_until;
use sito_upstream::UpstreamManager;
use std::collections::HashMap;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::watch;
use tower::ServiceExt;

/// Router tests exercise a configured deployment; a non-default admin password
/// keeps the first-boot gate from closing the API path under test.
const TEST_ADMIN_PASSWORD: &str = "TestAdminPassword123!";

/// Reserves a free loopback TCP port for HA replication listeners.
///
/// The returned lease must stay alive for the test so the port cannot be
/// selected by another test in this binary.
fn reserve_tcp_port() -> (u16, sito_test::harness::ReservedPort) {
    let mut lease = sito_test::harness::reserve_port().expect("reserve tcp port");
    let port = lease.port();
    lease.release_listener();
    (port, lease)
}

/// Minimal applier for tests that only need the push to update the filter and
/// the coherent runtime snapshot. The production applier is covered by
/// `test_m8_push_applies_upstream_and_dnssec_without_watcher`.
struct HarnessApplier {
    runtime: Arc<sito_runtime::RuntimeState>,
    filter: Arc<HostsFilterEngine>,
    config_path: Option<PathBuf>,
}

impl HarnessApplier {
    fn arc(
        runtime: Arc<sito_runtime::RuntimeState>,
        filter: Arc<HostsFilterEngine>,
        config_path: Option<PathBuf>,
    ) -> Arc<dyn SlaveConfigApplier> {
        Arc::new(Self {
            runtime,
            filter,
            config_path,
        })
    }
}

impl SlaveConfigApplier for HarnessApplier {
    fn apply_and_persist<'a>(
        &'a self,
        cfg: &'a Config,
        document: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            let previous = self.runtime.snapshot();
            let previous_config = previous.config.clone();
            self.filter
                .reload_with_config(&cfg.filtering)
                .await
                .map_err(|e| e.to_string())?;
            let clients: sito_clients::ClientsConfig = match cfg.clients.as_ref() {
                Some(value) => value.clone().try_into().map_err(|e| format!("{e}"))?,
                None => sito_clients::ClientsConfig::default(),
            };
            let rewrites: sito_rewrites::RewritesConfig = match cfg.rewrites.as_ref() {
                Some(value) => value.clone().try_into().map_err(|e| format!("{e}"))?,
                None => sito_rewrites::RewritesConfig::default(),
            };
            self.runtime.replace(sito_runtime::RuntimeSnapshot {
                config: Arc::new(cfg.clone()),
                clients: Arc::new(sito_clients::ClientRegistry::with_routeros_leases(
                    clients,
                    previous.clients.routeros_leases_store(),
                )),
                rewrites: Arc::new(sito_rewrites::RewriteTable::new(rewrites)),
            });
            if let Some(path) = self.config_path.as_deref()
                && let Err(e) = tokio::fs::write(path, document).await
            {
                self.runtime.replace((*previous).clone());
                let _ = self
                    .filter
                    .reload_with_config(&previous_config.filtering)
                    .await;
                return Err(e.to_string());
            }
            Ok(())
        })
    }
}

/// Creates a test ServerContext and temp directory.
async fn create_test_context(
    role: &str,
    master_coord: Option<MasterCoordinator>,
    slave_track: Option<SlaveStatusTracker>,
    resync_tx: Option<tokio::sync::mpsc::Sender<()>>,
) -> (ServerContext, String, PathBuf) {
    let temp_dir = std::env::temp_dir().join(format!("sito_m8_{}", rand::random::<u64>()));
    tokio::fs::create_dir_all(&temp_dir).await.unwrap();
    let db_path = temp_dir.join("test_stats.db");
    let stats_db = StatsDb::open(&db_path).await.unwrap();
    let querylog_writer = QueryLogWriter::spawn(stats_db.clone(), 100);
    let querylog_sender = querylog_writer.sender();
    let metrics = MetricsRegistry::new("0.1.0", "test-m8");

    let config_path = temp_dir.join("config.toml");
    let mut config = Config::default();
    config.server.role = role.to_string();
    config.server.instance_name = format!("{role}-test");
    config.server.data_dir = temp_dir.clone();
    let config_toml = toml::to_string_pretty(&config).unwrap();
    tokio::fs::write(&config_path, &config_toml).await.unwrap();

    let config_arc = Arc::new(ArcSwap::new(Arc::new(config.clone())));
    let cache = Arc::new(DnsCache::new(config.dns.cache.clone()));
    let filter = Arc::new(
        HostsFilterEngine::init_with_observer(
            config.filtering.clone(),
            temp_dir.clone(),
            Some(metrics.compile_observer()),
        )
        .await,
    );
    let bootstrap = sito_upstream::BootstrapResolver::new(
        vec!["127.0.0.1".parse().unwrap()],
        Duration::from_secs(1),
    );
    let upstream = Arc::new(
        UpstreamManager::from_config(&config.upstream, &bootstrap)
            .await
            .unwrap(),
    );
    let clients = Arc::new(ArcSwap::new(Arc::new(sito_clients::ClientRegistry::new(
        Default::default(),
    ))));
    let rewrites = Arc::new(ArcSwap::new(Arc::new(sito_rewrites::RewriteTable::new(
        Default::default(),
    ))));
    let auth_mgr = Arc::new(AuthManager::new());
    auth_mgr
        .update_user_password("admin", TEST_ADMIN_PASSWORD)
        .await;
    let (_meta, token_resp) = auth_mgr
        .create_token("admin", sito_api::auth::Role::Admin, None)
        .await
        .expect("token");
    let admin_token = token_resp.token;

    let runtime = Arc::new(sito_runtime::RuntimeState::new(
        config_arc.clone(),
        clients.clone(),
        rewrites.clone(),
    ));
    let runtime_lists = Arc::new(sito_clients::RuntimeLists::from_arcs(
        Arc::new(
            sito_clients::ParentalRegistry::try_bundled()
                .expect("bundled parental lists must load"),
        ),
        Arc::new(sito_clients::ServiceRegistry::try_bundled().expect("bundled services must load")),
    ));
    let ctx = ServerContext {
        config: config_arc,
        runtime,
        runtime_lists,
        config_path,
        auth_mgr,
        stats_db,
        querylog_sender,
        metrics,
        filter,
        cache,
        upstream,
        clients,
        rewrites,
        start_time: Instant::now(),
        restore_tokens: Arc::new(Mutex::new(HashMap::new())),
        apply_lock: Arc::new(tokio::sync::Mutex::new(())),
        master_coordinator: master_coord,
        slave_tracker: slave_track,
        resync_sender: resync_tx,
        setup_pending: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        acme_challenges: None,
        dns_starter: None,
    };

    (ctx, admin_token, temp_dir)
}

// ----------------------------------------------------------------------------
// Test 1: Gen-certs CLI, generation and BLAKE3 pinning
// ----------------------------------------------------------------------------
#[tokio::test]
async fn test_m8_gen_certs_cli_and_pinning() {
    let temp_dir = std::env::temp_dir().join(format!("sito_m8_certs_{}", rand::random::<u64>()));
    tokio::fs::create_dir_all(&temp_dir).await.unwrap();

    let certs = generate_ha_certs(&temp_dir, true, true).expect("generate_ha_certs should succeed");

    assert!(certs.ca_cert_path.exists());
    assert!(certs.ca_key_path.exists());
    assert!(certs.master_cert_path.as_ref().unwrap().exists());
    assert!(certs.master_key_path.as_ref().unwrap().exists());
    assert!(certs.slave_cert_path.as_ref().unwrap().exists());
    assert!(certs.slave_key_path.as_ref().unwrap().exists());

    let master_fp = certs.master_fingerprint.as_ref().unwrap();
    assert!(master_fp.starts_with("blake3:"));
    assert_eq!(master_fp.len(), 7 + 64);

    let slave_fp = certs.slave_fingerprint.as_ref().unwrap();
    assert!(slave_fp.starts_with("blake3:"));
    assert_eq!(slave_fp.len(), 7 + 64);

    let summary = certs.summary();
    assert!(summary.contains("sito HA mTLS Certificates Generated Successfully"));
    assert!(summary.contains("Fingerprint:"));

    let _ = std::fs::remove_dir_all(&temp_dir);
}

// ----------------------------------------------------------------------------
// Test 2: mTLS handshake rejects foreign or unpinned certificates
// ----------------------------------------------------------------------------
#[tokio::test]
async fn test_m8_mtls_handshake_rejects_foreign_cert() {
    let legit_dir = std::env::temp_dir().join(format!("sito_m8_legit_{}", rand::random::<u64>()));
    let foreign_dir =
        std::env::temp_dir().join(format!("sito_m8_foreign_{}", rand::random::<u64>()));
    tokio::fs::create_dir_all(&legit_dir).await.unwrap();
    tokio::fs::create_dir_all(&foreign_dir).await.unwrap();

    let legit_certs = generate_ha_certs(&legit_dir, true, true).unwrap();
    let foreign_certs = generate_ha_certs(&foreign_dir, true, true).unwrap();

    let signing_key = Arc::new(Ed25519SigningKey::generate().unwrap());
    let metrics = MetricsRegistry::new("0.1.0", "test");
    let coordinator =
        MasterCoordinator::new("master-mtls".to_string(), 1, signing_key, metrics.clone());

    let (replication_port, _replication_port_lease) = reserve_tcp_port();
    let master_ha_cfg = HaConfig {
        replication_port,
        listen_addr: "127.0.0.1".to_string(),
        cert: legit_certs.master_cert_path.clone(),
        key: legit_certs.master_key_path.clone(),
        ca: Some(legit_certs.ca_cert_path.clone()),
        pinned_slave_fingerprints: vec![legit_certs.slave_fingerprint.clone().unwrap()],
        ..Default::default()
    };

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let _server_handle = spawn_master_server(master_ha_cfg, coordinator.clone(), shutdown_rx);
    let master_ready = wait_until(Duration::from_secs(3), || async {
        tokio::net::TcpStream::connect(("127.0.0.1", replication_port))
            .await
            .is_ok()
    })
    .await;
    assert!(master_ready, "master replication listener did not start");

    // Connect with foreign cert/key (signed by different CA or unpinned fingerprint)
    let foreign_slave_cfg = HaConfig {
        master_url: Some(format!("wss://127.0.0.1:{replication_port}")),
        master_fingerprint: legit_certs.master_fingerprint.clone(),
        cert: foreign_certs.slave_cert_path.clone(),
        key: foreign_certs.slave_key_path.clone(),
        ca: Some(foreign_certs.ca_cert_path.clone()),
        ..Default::default()
    };

    let foreign_tracker = SlaveStatusTracker::new("foreign-slave".to_string(), 0, None);
    let base_config = Config::default();
    let config_arc = Arc::new(ArcSwap::new(Arc::new(base_config.clone())));
    let filter_engine =
        Arc::new(HostsFilterEngine::init(base_config.filtering.clone(), foreign_dir.clone()).await);
    let rewrites_arc = Arc::new(ArcSwap::new(Arc::new(sito_rewrites::RewriteTable::new(
        Default::default(),
    ))));
    let clients_arc = Arc::new(ArcSwap::new(Arc::new(sito_clients::ClientRegistry::new(
        Default::default(),
    ))));

    let runtime = Arc::new(sito_runtime::RuntimeState::new(
        config_arc.clone(),
        clients_arc.clone(),
        rewrites_arc.clone(),
    ));
    let handles = SlaveAppHandles {
        runtime: runtime.clone(),
        filter: filter_engine.clone(),
        metrics: metrics.clone(),
        config_path: None,
        applier: HarnessApplier::arc(runtime, filter_engine.clone(), None),
    };

    let (_resync_tx, resync_rx) = tokio::sync::mpsc::channel(1);
    let (foreign_shutdown_tx, foreign_shutdown_rx) = watch::channel(false);
    let _foreign_worker = spawn_slave_worker(
        foreign_slave_cfg,
        foreign_tracker.clone(),
        handles,
        resync_rx,
        foreign_shutdown_rx,
    );

    // Give the foreign slave a bounded window to (incorrectly) sync; it must
    // never reach Synced.
    let synced = wait_until(Duration::from_millis(600), || {
        let tracker = foreign_tracker.clone();
        async move { tracker.get_state() == SlaveState::Synced }
    })
    .await;
    assert!(
        !synced,
        "foreign slave with an unpinned certificate must not sync"
    );
    assert_eq!(coordinator.connected_slave_count(), 0);

    let _ = foreign_shutdown_tx.send(true);
    let _ = shutdown_tx.send(true);
    let _ = std::fs::remove_dir_all(&legit_dir);
    let _ = std::fs::remove_dir_all(&foreign_dir);
}

// ----------------------------------------------------------------------------
// Test 3: Secret redaction security scanner in CI
// ----------------------------------------------------------------------------
#[test]
fn test_m8_secret_redaction_security_scanner() {
    let sensitive_raw_toml = r#"
config_version = 1

[server]
role = "master"
instance_name = "master-prod"

[web]
cert = "/etc/sito/certs/web.crt"
key = "/etc/sito/certs/web.key"

[auth]
admin_password_hash = "$argon2id$v=19$m=65536,t=3,p=4$secret_argon_hash"
tokens = ["secret_auth_token_xyz"]

[ha]
replication_port = 8953
cert = "/etc/sito/certs/master.crt"
key = "/etc/sito/certs/master.key"
"#;

    let sanitized = sanitize_config_for_bundle(sensitive_raw_toml).unwrap();

    // 1. role must be slave
    assert!(sanitized.contains("role = \"slave\""));
    // 2. ha section must be stripped
    assert!(!sanitized.contains("[ha]"));
    assert!(!sanitized.contains("replication_port"));
    // 3. Legacy auth secret keys are stripped entirely: they are not part of
    // AuthConfig (credentials live in the node-local users.toml/tokens.toml),
    // and an unresolvable ${SECRET:...} placeholder would make every slave
    // reject the pushed configuration.
    assert!(!sanitized.contains("admin_password_hash"));
    assert!(!sanitized.contains("${SECRET:admin_password_hash}"));
    assert!(!sanitized.contains("${SECRET:auth_tokens}"));
    assert!(!sanitized.contains("secret_argon_hash"));
    assert!(!sanitized.contains("secret_auth_token_xyz"));

    let clean_bundle = ConfigBundle {
        version: 1,
        term: 0,
        timestamp: 1000,
        config_toml: sanitized,
        custom_rules: vec!["||example.com^".to_string()],
        rewrites: None,
        clients: None,
        lists: vec![],
    };

    let bundle_str = clean_bundle.to_json().unwrap();
    let known_secrets = &["secret_argon_hash", "secret_auth_token_xyz"];

    // Scanner must pass with no secret leaks
    assert!(scan_for_secrets(&bundle_str, known_secrets).is_ok());

    // Scanner must catch unmasked sensitive keys or private key material
    let mut leaked_bundle = clean_bundle.clone();
    leaked_bundle.config_toml = "admin_password_hash = \"secret_argon_hash\"".to_string();
    let leaked_str = leaked_bundle.to_json().unwrap();
    assert!(matches!(
        scan_for_secrets(&leaked_str, known_secrets),
        Err(HaError::SecretLeak { .. })
    ));

    let mut leaked_key_bundle = clean_bundle;
    leaked_key_bundle.config_toml = "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgk...".to_string();
    let leaked_key_str = leaked_key_bundle.to_json().unwrap();
    assert!(matches!(
        scan_for_secrets(&leaked_key_str, known_secrets),
        Err(HaError::SecretLeak { .. })
    ));
}

// ----------------------------------------------------------------------------
// Test 4: Monotonicity guard rejects out-of-order or replayed bundles
// ----------------------------------------------------------------------------
#[test]
fn test_m8_monotonicity_guard_rejects_replay() {
    let signing_key = Ed25519SigningKey::generate().unwrap();
    let pubkey = signing_key.public_key();

    let bundle = ConfigBundle {
        version: 5,
        term: 0,
        timestamp: 2000,
        config_toml: "config_version = 1\n[server]\nrole = \"slave\"\n".to_string(),
        custom_rules: vec!["||replay-test.com^".to_string()],
        rewrites: None,
        clients: None,
        lists: vec![],
    };

    let push_msg = build_and_sign_push(&bundle, &signing_key).unwrap();

    // Valid forward progress: slave have_version = 4 < 5 -> OK
    let unpacked =
        verify_and_unpack_push(&push_msg, 4, pubkey.as_ref()).expect("Should accept version 5");
    assert_eq!(unpacked.version, 5);

    // Replay attack: slave have_version = 5 >= 5 -> Error Monotonicity
    let replay_err = verify_and_unpack_push(&push_msg, 5, pubkey.as_ref());
    assert!(matches!(replay_err, Err(HaError::Validation { ref field, .. }) if field == "version"));

    // Stale message: slave have_version = 6 >= 5 -> Error Monotonicity
    let stale_err = verify_and_unpack_push(&push_msg, 6, pubkey.as_ref());
    assert!(matches!(stale_err, Err(HaError::Validation { ref field, .. }) if field == "version"));

    // Signature tampering check
    if let HaMessage::ConfigPush {
        version,
        hash_blake3,
        payload_b64,
        payload_hash_blake3,
        ..
    } = &push_msg
    {
        let fake_push = HaMessage::ConfigPush {
            version: *version,
            term: 0,
            hash_blake3: hash_blake3.clone(),
            signature_ed25519: "deadbeef".repeat(8),
            payload_b64: payload_b64.clone(),
            payload_hash_blake3: payload_hash_blake3.clone(),
        };
        let sig_err = verify_and_unpack_push(&fake_push, 4, pubkey.as_ref());
        assert!(matches!(
            sig_err,
            Err(HaError::SignatureVerification(_) | HaError::Crypto(_))
        ));
    }
}

// ----------------------------------------------------------------------------
// Test 5: Slave rollback on invalid bundle keeps old config & sets Degraded
// ----------------------------------------------------------------------------
#[tokio::test]
async fn test_m8_slave_rollback_on_invalid_bundle() {
    let temp_dir = std::env::temp_dir().join(format!("sito_m8_rollback_{}", rand::random::<u64>()));
    tokio::fs::create_dir_all(&temp_dir).await.unwrap();

    let tracker = SlaveStatusTracker::new("slave-rollback".to_string(), 1, None);
    tracker.set_state(SlaveState::Synced);

    let mut base_config = Config::default();
    base_config.filtering.custom_rules = vec!["||initial-block.org^".to_string()];

    let config_arc = Arc::new(ArcSwap::new(Arc::new(base_config.clone())));
    let filter_engine =
        Arc::new(HostsFilterEngine::init(base_config.filtering.clone(), temp_dir.clone()).await);
    let rewrites_arc = Arc::new(ArcSwap::new(Arc::new(sito_rewrites::RewriteTable::new(
        Default::default(),
    ))));
    let clients_arc = Arc::new(ArcSwap::new(Arc::new(sito_clients::ClientRegistry::new(
        Default::default(),
    ))));
    let metrics = MetricsRegistry::new("0.1.0", "test");

    let runtime = Arc::new(sito_runtime::RuntimeState::new(
        config_arc.clone(),
        clients_arc.clone(),
        rewrites_arc.clone(),
    ));
    let handles = SlaveAppHandles {
        runtime: runtime.clone(),
        filter: filter_engine.clone(),
        metrics,
        config_path: None,
        applier: HarnessApplier::arc(runtime, filter_engine.clone(), None),
    };

    // Verify initial rule is active
    let client = ClientContext::new("127.0.0.1".parse().unwrap());
    assert!(
        filter_engine
            .snapshot()
            .evaluate("initial-block.org", RecordType::A, &client)
            .is_blocked()
    );

    // Construct a corrupted bundle with invalid TOML syntax
    let corrupted_bundle = ConfigBundle {
        version: 2,
        term: 0,
        timestamp: 12345,
        config_toml: "corrupted_toml = [[ broken syntax {{{".to_string(),
        custom_rules: vec!["||should-not-apply.com^".to_string()],
        rewrites: None,
        clients: None,
        lists: vec![],
    };

    let signing_key = Ed25519SigningKey::generate().unwrap();
    let corrupted_push = build_and_sign_push(&corrupted_bundle, &signing_key).unwrap();

    // Apply corrupted push
    let apply_res = sito_ha::apply_config_push(
        &corrupted_push,
        &tracker,
        &handles,
        signing_key.public_key().as_ref(),
    )
    .await;
    assert!(apply_res.is_err(), "Corrupted bundle must fail apply");

    // Assert slave state transitioned to Degraded
    assert_eq!(tracker.get_state(), SlaveState::Degraded);
    // Version remained at 1
    assert_eq!(tracker.get_version(), 1);

    // Initial rule still active, continuous DNS resolution uninterrupted
    assert!(
        filter_engine
            .snapshot()
            .evaluate("initial-block.org", RecordType::A, &client)
            .is_blocked()
    );
    assert!(
        !filter_engine
            .snapshot()
            .evaluate("should-not-apply.com", RecordType::A, &client)
            .is_blocked()
    );

    let _ = std::fs::remove_dir_all(&temp_dir);
}

// ----------------------------------------------------------------------------
// Test 6: Slave read-only enforcement (409 Conflict + X-Dnsd-Master header)
// ----------------------------------------------------------------------------
#[tokio::test]
async fn test_m8_slave_read_only_enforcement() {
    let slave_tracker = SlaveStatusTracker::new(
        "slave-ro".to_string(),
        1,
        Some("https://master.sito.lan:3000".to_string()),
    );
    let (ctx, _token, temp_dir) =
        create_test_context("slave", None, Some(slave_tracker), None).await;
    let app = create_router(ctx);

    // Mutating request POST /api/v1/filtering/rules must be blocked with 409 Conflict
    let req = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/filtering/rules")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(r#"["||blocked.com^"]"#))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);

    let master_header = resp
        .headers()
        .get("X-Dnsd-Master")
        .expect("Must contain X-Dnsd-Master header")
        .to_str()
        .unwrap();
    assert_eq!(master_header, "https://master.sito.lan:3000");

    let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let body_str = String::from_utf8_lossy(&body_bytes);
    assert!(body_str.contains("Read-Only") || body_str.contains("disabled on HA replica slaves"));

    // Mutating request DELETE /api/v1/rewrites/1 must also be blocked
    let req_del = Request::builder()
        .method(Method::DELETE)
        .uri("/api/v1/rewrites/1")
        .body(Body::empty())
        .unwrap();
    let resp_del = app.clone().oneshot(req_del).await.unwrap();
    assert_eq!(resp_del.status(), StatusCode::CONFLICT);

    // Non-mutating request GET /api/v1/status must succeed (200 OK)
    let req_get = Request::builder()
        .method(Method::GET)
        .uri("/api/v1/status")
        .header(header::AUTHORIZATION, format!("Bearer {_token}"))
        .body(Body::empty())
        .unwrap();
    let resp_get = app.clone().oneshot(req_get).await.unwrap();
    assert_eq!(resp_get.status(), StatusCode::OK);

    let _ = std::fs::remove_dir_all(&temp_dir);
}

// ----------------------------------------------------------------------------
// Test 7: HA REST API endpoints (/ha/status, /ha/slaves, /ha/resync)
// ----------------------------------------------------------------------------
#[tokio::test]
async fn test_m8_ha_rest_api_endpoints() {
    let signing_key = Arc::new(Ed25519SigningKey::generate().unwrap());
    let metrics = MetricsRegistry::new("0.1.0", "test");
    let coordinator = MasterCoordinator::new("master-api".to_string(), 3, signing_key, metrics);

    let (master_ctx, master_token, master_dir) =
        create_test_context("master", Some(coordinator.clone()), None, None).await;
    let master_app = create_router(master_ctx);

    // 1. GET /api/v1/ha/status on master
    let req = Request::builder()
        .uri("/api/v1/ha/status")
        .header(header::AUTHORIZATION, format!("Bearer {master_token}"))
        .body(Body::empty())
        .unwrap();
    let resp = master_app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["role"], "master");
    assert_eq!(v["instance_name"], "master-test");
    assert_eq!(v["version"], 3);

    // 2. GET /api/v1/ha/slaves on master
    let req_slaves = Request::builder()
        .uri("/api/v1/ha/slaves")
        .header(header::AUTHORIZATION, format!("Bearer {master_token}"))
        .body(Body::empty())
        .unwrap();
    let resp_slaves = master_app.clone().oneshot(req_slaves).await.unwrap();
    assert_eq!(resp_slaves.status(), StatusCode::OK);

    // 3. POST /api/v1/ha/resync on master
    let req_resync = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/ha/resync")
        .header(header::AUTHORIZATION, format!("Bearer {master_token}"))
        .body(Body::empty())
        .unwrap();
    let resp_resync = master_app.clone().oneshot(req_resync).await.unwrap();
    assert_eq!(resp_resync.status(), StatusCode::OK);
    let resync_bytes = axum::body::to_bytes(resp_resync.into_body(), usize::MAX)
        .await
        .unwrap();
    let resync_v: serde_json::Value = serde_json::from_slice(&resync_bytes).unwrap();
    assert_eq!(resync_v["status"], "resync_triggered");
    assert_eq!(resync_v["version"], 3);

    // 4. HA status on slave
    let slave_tracker = SlaveStatusTracker::new(
        "slave-api".to_string(),
        3,
        Some("wss://master.internal:8953".to_string()),
    );
    slave_tracker.set_state(SlaveState::Synced);
    let (resync_tx, mut resync_rx) = tokio::sync::mpsc::channel(1);
    let (slave_ctx, slave_token, slave_dir) =
        create_test_context("slave", None, Some(slave_tracker), Some(resync_tx)).await;
    let slave_app = create_router(slave_ctx);

    let req_slave_status = Request::builder()
        .uri("/api/v1/ha/status")
        .header(header::AUTHORIZATION, format!("Bearer {slave_token}"))
        .body(Body::empty())
        .unwrap();
    let resp_slave_status = slave_app.clone().oneshot(req_slave_status).await.unwrap();
    assert_eq!(resp_slave_status.status(), StatusCode::OK);
    let s_bytes = axum::body::to_bytes(resp_slave_status.into_body(), usize::MAX)
        .await
        .unwrap();
    let s_v: serde_json::Value = serde_json::from_slice(&s_bytes).unwrap();
    assert_eq!(s_v["role"], "slave");
    assert_eq!(s_v["state"], "synced");
    assert_eq!(s_v["version"], 3);

    // 5. POST /api/v1/ha/resync on slave (exempted from read-only)
    let req_slave_resync = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/ha/resync")
        .header(header::AUTHORIZATION, format!("Bearer {slave_token}"))
        .body(Body::empty())
        .unwrap();
    let resp_slave_resync = slave_app.clone().oneshot(req_slave_resync).await.unwrap();
    assert_eq!(resp_slave_resync.status(), StatusCode::OK);
    assert!(resync_rx.try_recv().is_ok());

    let _ = std::fs::remove_dir_all(&master_dir);
    let _ = std::fs::remove_dir_all(&slave_dir);
}

// ----------------------------------------------------------------------------
// Test 7b: HA readiness is visible in /health and /ha/status
// ----------------------------------------------------------------------------
#[tokio::test]
async fn test_m8_ha_readiness_is_visible_in_health_and_status() {
    // Master: a listener/TLS failure must flip ready to false and expose a
    // reason instead of leaving DNS as the only health signal.
    let signing_key = Arc::new(Ed25519SigningKey::generate().unwrap());
    let metrics = MetricsRegistry::new("0.1.0", "test");
    let coordinator = MasterCoordinator::new("master-ready".to_string(), 1, signing_key, metrics);
    coordinator.mark_replication_ready();
    let (master_ctx, master_token, master_dir) =
        create_test_context("master", Some(coordinator.clone()), None, None).await;
    let mut master_cfg = (**master_ctx.config.load()).clone();
    master_cfg.ha = Some(toml::from_str("replication_port = 8953").unwrap());
    master_ctx.config.store(Arc::new(master_cfg));
    let master_app = create_router(master_ctx);

    let health = get_json(&master_app, "/health", None).await;
    assert_eq!(health["ha"]["required"], true);
    assert_eq!(health["ha"]["ready"], true);

    coordinator.mark_replication_failed("master mTLS initialization failed: Permission denied");
    let status = get_json(&master_app, "/api/v1/ha/status", Some(&master_token)).await;
    assert_eq!(
        status["ready"], false,
        "failed listener must not look active"
    );
    assert!(
        status["readiness_reason"]
            .as_str()
            .unwrap_or_default()
            .contains("Permission denied"),
        "readiness reason must survive to /ha/status: {status}"
    );
    let health = get_json(&master_app, "/health", None).await;
    assert_eq!(health["ha"]["required"], true);
    assert_eq!(health["ha"]["ready"], false);
    // `/health` is unauthenticated: it must not leak the detailed reason
    // (certificate path, OS error, internal master URL, TOML/validation text)
    // that remains available on the authenticated `/api/v1/ha/status`.
    let public_reason = health["ha"]["reason"].as_str().unwrap_or_default();
    assert_eq!(
        public_reason, "HA replication is not ready",
        "public health must use a generic HA reason: {health}"
    );
    assert!(
        !public_reason.contains('/'),
        "no filesystem paths in /health"
    );
    assert!(
        !public_reason.contains("Permission denied"),
        "no OS error detail in /health"
    );

    // Slave: readiness requires an actual sync, not just a configured URL.
    let tracker = SlaveStatusTracker::new(
        "slave-ready".to_string(),
        0,
        Some("wss://master.internal:8953".to_string()),
    );
    tracker.set_connection_error(Some("mTLS handshake failed with master".to_string()));
    let (slave_ctx, slave_token, slave_dir) =
        create_test_context("slave", None, Some(tracker.clone()), None).await;
    let mut slave_cfg = (**slave_ctx.config.load()).clone();
    slave_cfg.ha = Some(toml::from_str("master_url = \"wss://master.internal:8953\"").unwrap());
    slave_ctx.config.store(Arc::new(slave_cfg));
    let slave_app = create_router(slave_ctx);

    let status = get_json(&slave_app, "/api/v1/ha/status", Some(&slave_token)).await;
    assert_eq!(status["ready"], false);
    assert!(
        status["readiness_reason"]
            .as_str()
            .unwrap_or_default()
            .contains("mTLS handshake failed"),
        "handshake failure must reach /ha/status: {status}"
    );
    let slave_health = get_json(&slave_app, "/health", None).await;
    assert_eq!(slave_health["ha"]["ready"], false);
    assert_eq!(
        slave_health["ha"]["reason"], "HA replication is not ready",
        "slave /health must not expose the handshake/master URL detail"
    );

    tracker.mark_synced_with_term(1, 0);
    let status = get_json(&slave_app, "/api/v1/ha/status", Some(&slave_token)).await;
    assert_eq!(status["ready"], true);
    assert!(status["readiness_reason"].is_null());

    let _ = std::fs::remove_dir_all(&master_dir);
    let _ = std::fs::remove_dir_all(&slave_dir);
}

// ----------------------------------------------------------------------------
// Test 7c: An explicitly disabled master replication keeps its explanation
// ----------------------------------------------------------------------------
#[tokio::test]
async fn test_m8_ha_disabled_reason_is_exposed_in_status() {
    let signing_key = Arc::new(Ed25519SigningKey::generate().unwrap());
    let metrics = MetricsRegistry::new("0.1.0", "test");
    let coordinator =
        MasterCoordinator::new("master-disabled".to_string(), 1, signing_key, metrics);
    coordinator.mark_replication_disabled();
    let (master_ctx, master_token, master_dir) =
        create_test_context("master", Some(coordinator), None, None).await;
    let mut master_cfg = (**master_ctx.config.load()).clone();
    master_cfg.ha = Some(toml::from_str("replication_port = 0").unwrap());
    master_ctx.config.store(Arc::new(master_cfg));
    let master_app = create_router(master_ctx);

    // Replication is deliberately off, so the node is ready, but the reason
    // must not be lost: operators need to see why there is no listener.
    let status = get_json(&master_app, "/api/v1/ha/status", Some(&master_token)).await;
    assert_eq!(status["ready"], true);
    assert!(
        status["readiness_reason"]
            .as_str()
            .unwrap_or_default()
            .contains("replication_port"),
        "disabled replication must stay explained in /ha/status: {status}"
    );

    let health = get_json(&master_app, "/health", None).await;
    assert_eq!(health["ha"]["required"], false);
    assert_eq!(health["ha"]["ready"], true);
    assert!(
        health["ha"]["reason"].is_null(),
        "public /health must not expose the disabled explanation: {health}"
    );

    let _ = std::fs::remove_dir_all(&master_dir);
}

// ----------------------------------------------------------------------------
// Test 7c-b: a real unreadable key blocks mTLS until permissions are fixed
// ----------------------------------------------------------------------------
//
// Non-root-safe half of the ownership acceptance: mode 0000 on the key makes
// `build_server_tls_config` fail with a real permission error, and restoring
// mode 0600 makes the same call succeed. Root bypasses mode bits, so this test
// skips when euid is 0 (the root-gated test below covers that case).
#[cfg(unix)]
#[tokio::test]
async fn test_m8_unreadable_key_fails_tls_until_permissions_fixed() {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let dir = std::env::temp_dir().join(format!(
        "sito_m8_unreadable_key_{}_{}",
        std::process::id(),
        rand::random::<u64>()
    ));
    tokio::fs::create_dir_all(&dir).await.unwrap();
    let probe = dir.join("probe");
    std::fs::write(&probe, b"x").unwrap();
    if std::fs::metadata(&probe).unwrap().uid() == 0 {
        eprintln!(
            "skipping test_m8_unreadable_key_fails_tls_until_permissions_fixed: root ignores mode bits"
        );
        let _ = std::fs::remove_dir_all(&dir);
        return;
    }

    let certs = generate_ha_certs(&dir, true, true).unwrap();
    let cert = certs.master_cert_path.clone().unwrap();
    let key = certs.master_key_path.clone().unwrap();
    let fingerprint = certs.slave_fingerprint.clone().unwrap();

    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o000)).unwrap();
    let err =
        sito_ha::build_server_tls_config(&cert, &key, std::slice::from_ref(&fingerprint), None)
            .expect_err("an unreadable private key must fail mTLS initialization");
    assert!(
        err.to_string().contains("Permission denied"),
        "expected a real permission error, got: {err}"
    );

    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    sito_ha::build_server_tls_config(&cert, &key, &[fingerprint], None)
        .expect("restoring key permissions must make mTLS initialization succeed");

    let _ = std::fs::remove_dir_all(&dir);
}

// ----------------------------------------------------------------------------
// Test 7d: root-owned key is unreadable, and chown makes HA start (root only)
// ----------------------------------------------------------------------------
//
// Root-only verification of the runbook's systemd/Docker path. The parent
// process must be root so it can generate a root-owned 0600 key and run the
// child probe under uid/gid 65532 (the container runtime identity):
//
//   sudo env CARGO_TARGET_DIR=/home/ubuntu/sito-dns/target \
//     cargo test -p sito-test --test m8_acceptance \
//     test_m8_root_owned_key_chown_activates_ha -- --nocapture
//
// Or use `sudo scripts/test-ha-ownership-root.sh`. The test skips (and passes)
// when not run as root so ordinary unprivileged test runs stay green.
#[cfg(unix)]
#[tokio::test]
async fn test_m8_root_owned_key_chown_activates_ha() {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    use std::os::unix::process::CommandExt as _;

    let dir = std::env::temp_dir().join(format!(
        "sito_m8_root_owner_{}_{}",
        std::process::id(),
        rand::random::<u64>()
    ));
    tokio::fs::create_dir_all(&dir).await.unwrap();
    let probe_path = dir.join("probe");
    std::fs::write(&probe_path, b"x").unwrap();
    let euid = std::fs::metadata(&probe_path).unwrap().uid();
    if euid != 0 {
        eprintln!(
            "skipping test_m8_root_owned_key_chown_activates_ha: requires root (euid {euid})"
        );
        let _ = std::fs::remove_dir_all(&dir);
        return;
    }

    // Root-generated keys: exactly the state `sudo sito ha gen-certs` produced
    // before ownership transfer.
    let certs = generate_ha_certs(&dir, true, true).unwrap();
    let master_key = certs.master_key_path.clone().unwrap();
    let master_cert = certs.master_cert_path.clone().unwrap();
    let slave_fingerprint = certs.slave_fingerprint.clone().unwrap();
    let key_meta = std::fs::metadata(&master_key).unwrap();
    assert_eq!(key_meta.uid(), 0, "fixture key must be root-owned");
    assert_eq!(key_meta.mode() & 0o777, 0o600);

    // The test binary lives under the developer checkout (often mode 0750),
    // which uid 65532 cannot traverse; copy it somewhere world-executable.
    let child_exe = dir.join("m8_acceptance_child");
    std::fs::copy(std::env::current_exe().unwrap(), &child_exe).unwrap();
    std::fs::set_permissions(&child_exe, std::fs::Permissions::from_mode(0o755)).unwrap();

    let run_child = |mode: &str| {
        let mut command = std::process::Command::new(&child_exe);
        command
            .arg("--exact")
            .arg("test_m8_ha_runtime_child_probe")
            .arg("--nocapture")
            .env("SITO_HA_CHILD_MODE", mode)
            .env("SITO_HA_CHILD_CERT", &master_cert)
            .env("SITO_HA_CHILD_KEY", &master_key)
            .env("SITO_HA_CHILD_FINGERPRINT", &slave_fingerprint)
            .current_dir("/tmp");
        command.uid(65532).gid(65532);
        command.output().expect("spawn uid-65532 child probe")
    };

    // 1. Root-owned 0600 key is unreadable by the runtime user: real mTLS
    //    initialization must fail with a permission error, not injected state.
    let unreadable = run_child("unreadable");
    assert!(
        unreadable.status.success(),
        "runtime user unexpectedly read a root-owned key\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&unreadable.stdout),
        String::from_utf8_lossy(&unreadable.stderr)
    );

    // 2. Perform the documented chown, then let the same runtime user start
    //    the listener and verify the public readiness signal flips to ready.
    for path in [
        certs.ca_cert_path.as_path(),
        certs.ca_key_path.as_path(),
        master_cert.as_path(),
        master_key.as_path(),
        certs.slave_cert_path.as_ref().unwrap().as_path(),
        certs.slave_key_path.as_ref().unwrap().as_path(),
    ] {
        std::os::unix::fs::chown(path, Some(65532), Some(65532))
            .unwrap_or_else(|e| panic!("chown {}: {e}", path.display()));
    }

    let ready = run_child("ready");
    assert!(
        ready.status.success(),
        "runtime user could not start HA after chown\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&ready.stdout),
        String::from_utf8_lossy(&ready.stderr)
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Child process for [`test_m8_root_owned_key_chown_activates_ha`].
///
/// Runs only when `SITO_HA_CHILD_MODE` is set and is invoked under uid/gid
/// 65532. `unreadable` asserts TLS initialization fails against the
/// root-owned key; `ready` starts the real listener, then checks the API's
/// `/health` and `/ha/status` readiness.
#[cfg(unix)]
#[tokio::test]
async fn test_m8_ha_runtime_child_probe() {
    let Ok(mode) = std::env::var("SITO_HA_CHILD_MODE") else {
        return;
    };
    let cert = PathBuf::from(std::env::var("SITO_HA_CHILD_CERT").unwrap());
    let key = PathBuf::from(std::env::var("SITO_HA_CHILD_KEY").unwrap());
    let fingerprint = std::env::var("SITO_HA_CHILD_FINGERPRINT").unwrap();

    // Running as uid 65532: probe the real file permissions, never the
    // in-process readiness fields.
    use std::os::unix::fs::MetadataExt as _;
    let probe_uid = {
        let probe =
            std::env::temp_dir().join(format!("sito_m8_child_uid_{}", rand::random::<u64>()));
        std::fs::write(&probe, b"x").unwrap();
        let uid = std::fs::metadata(&probe).unwrap().uid();
        let _ = std::fs::remove_file(&probe);
        uid
    };
    assert_eq!(probe_uid, 65532, "child probe must run as uid 65532");

    match mode.as_str() {
        "unreadable" => {
            let err = sito_ha::build_server_tls_config(
                &cert,
                &key,
                std::slice::from_ref(&fingerprint),
                None,
            )
            .expect_err("a root-owned 0600 key must be unreadable by uid 65532");
            assert!(
                err.to_string().contains("Permission denied"),
                "expected a permission error, got: {err}"
            );
        }
        "ready" => {
            let signing_key = Arc::new(Ed25519SigningKey::generate().unwrap());
            let metrics = MetricsRegistry::new("0.1.0", "child");
            let coordinator =
                MasterCoordinator::new("child-master".to_string(), 1, signing_key, metrics);
            let (shutdown_tx, shutdown_rx) = watch::channel(false);
            let (replication_port, _replication_port_lease) = reserve_tcp_port();
            let handle = spawn_master_server(
                HaConfig {
                    replication_port,
                    listen_addr: "127.0.0.1".to_string(),
                    cert: Some(cert),
                    key: Some(key),
                    pinned_slave_fingerprints: vec![fingerprint],
                    ..Default::default()
                },
                coordinator.clone(),
                shutdown_rx,
            );

            let ready = wait_until(Duration::from_secs(2), || {
                let coordinator = coordinator.clone();
                async move { coordinator.readiness().ready }
            })
            .await;
            assert!(
                ready,
                "listener did not become ready after chown: {:?}",
                coordinator.readiness()
            );

            let (ctx, token, dir) =
                create_test_context("master", Some(coordinator), None, None).await;
            let mut cfg = (**ctx.config.load()).clone();
            cfg.ha =
                Some(toml::from_str(&format!("replication_port = {replication_port}")).unwrap());
            ctx.config.store(Arc::new(cfg));
            let app = create_router(ctx);

            let health = get_json(&app, "/health", None).await;
            assert_eq!(health["ha"]["required"], true);
            assert_eq!(
                health["ha"]["ready"], true,
                "public /health must flip to ready after chown: {health}"
            );
            let status = get_json(&app, "/api/v1/ha/status", Some(&token)).await;
            assert_eq!(status["ready"], true);

            let _ = shutdown_tx.send(true);
            let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
            let _ = std::fs::remove_dir_all(dir);
        }
        other => panic!("unknown SITO_HA_CHILD_MODE '{other}'"),
    }
}

/// GETs `path` from the router and decodes a JSON body.
async fn get_json(app: &axum::Router, path: &str, token: Option<&str>) -> serde_json::Value {
    let mut request = Request::builder().uri(path);
    if let Some(token) = token {
        request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    let resp = app
        .clone()
        .oneshot(request.body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "{path}");
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

// ----------------------------------------------------------------------------
// Test 8: List change on master applies to 2 slaves in < 2 seconds
// ----------------------------------------------------------------------------
#[tokio::test]
async fn test_m8_list_change_applied_to_two_slaves_fast() {
    let temp_dir = std::env::temp_dir().join(format!("sito_m8_fast_{}", rand::random::<u64>()));
    tokio::fs::create_dir_all(&temp_dir).await.unwrap();

    let certs = generate_ha_certs(&temp_dir, true, true).unwrap();

    let signing_key = Arc::new(Ed25519SigningKey::generate().unwrap());
    let metrics = MetricsRegistry::new("0.1.0", "test");
    let coordinator = MasterCoordinator::new(
        "master-fast".to_string(),
        1,
        signing_key.clone(),
        metrics.clone(),
    );

    let (replication_port, _replication_port_lease) = reserve_tcp_port();
    let master_ha_cfg = HaConfig {
        replication_port,
        listen_addr: "127.0.0.1".to_string(),
        cert: certs.master_cert_path.clone(),
        key: certs.master_key_path.clone(),
        ca: Some(certs.ca_cert_path.clone()),
        pinned_slave_fingerprints: vec![certs.slave_fingerprint.clone().unwrap()],
        ..Default::default()
    };

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let _server = spawn_master_server(master_ha_cfg, coordinator.clone(), shutdown_rx);
    let master_ready = wait_until(Duration::from_secs(3), || async {
        tokio::net::TcpStream::connect(("127.0.0.1", replication_port))
            .await
            .is_ok()
    })
    .await;
    assert!(master_ready, "master replication listener did not start");

    // Slave 1
    let slave1_tracker = SlaveStatusTracker::new("slave-1".to_string(), 0, None);
    let slave1_cfg = Config::default();
    let slave1_filter = Arc::new(
        HostsFilterEngine::init(slave1_cfg.filtering.clone(), temp_dir.join("slave1")).await,
    );
    let slave1_runtime = Arc::new(sito_runtime::RuntimeState::new(
        Arc::new(ArcSwap::new(Arc::new(slave1_cfg))),
        Arc::new(ArcSwap::new(Arc::new(sito_clients::ClientRegistry::new(
            Default::default(),
        )))),
        Arc::new(ArcSwap::new(Arc::new(sito_rewrites::RewriteTable::new(
            Default::default(),
        )))),
    ));
    let slave1_handles = SlaveAppHandles {
        runtime: slave1_runtime.clone(),
        filter: slave1_filter.clone(),
        metrics: metrics.clone(),
        config_path: None,
        applier: HarnessApplier::arc(slave1_runtime, slave1_filter.clone(), None),
    };
    let slave1_ha_cfg = HaConfig {
        master_url: Some(format!("wss://127.0.0.1:{replication_port}")),
        master_fingerprint: certs.master_fingerprint.clone(),
        master_pubkey: Some(signing_key.public_key_hex()),
        cert: certs.slave_cert_path.clone(),
        key: certs.slave_key_path.clone(),
        ca: Some(certs.ca_cert_path.clone()),
        ..Default::default()
    };
    let (_resync1_tx, resync1_rx) = tokio::sync::mpsc::channel(1);
    let _s1_handle = spawn_slave_worker(
        slave1_ha_cfg,
        slave1_tracker.clone(),
        slave1_handles,
        resync1_rx,
        shutdown_tx.subscribe(),
    );

    // Slave 2
    let slave2_tracker = SlaveStatusTracker::new("slave-2".to_string(), 0, None);
    let slave2_cfg = Config::default();
    let slave2_filter = Arc::new(
        HostsFilterEngine::init(slave2_cfg.filtering.clone(), temp_dir.join("slave2")).await,
    );
    let slave2_runtime = Arc::new(sito_runtime::RuntimeState::new(
        Arc::new(ArcSwap::new(Arc::new(slave2_cfg))),
        Arc::new(ArcSwap::new(Arc::new(sito_clients::ClientRegistry::new(
            Default::default(),
        )))),
        Arc::new(ArcSwap::new(Arc::new(sito_rewrites::RewriteTable::new(
            Default::default(),
        )))),
    ));
    let slave2_handles = SlaveAppHandles {
        runtime: slave2_runtime.clone(),
        filter: slave2_filter.clone(),
        metrics: metrics.clone(),
        config_path: None,
        applier: HarnessApplier::arc(slave2_runtime, slave2_filter.clone(), None),
    };
    let slave2_ha_cfg = HaConfig {
        master_url: Some(format!("wss://127.0.0.1:{replication_port}")),
        master_fingerprint: certs.master_fingerprint.clone(),
        master_pubkey: Some(signing_key.public_key_hex()),
        cert: certs.slave_cert_path.clone(),
        key: certs.slave_key_path.clone(),
        ca: Some(certs.ca_cert_path.clone()),
        ..Default::default()
    };
    let (_resync2_tx, resync2_rx) = tokio::sync::mpsc::channel(1);
    let _s2_handle = spawn_slave_worker(
        slave2_ha_cfg,
        slave2_tracker.clone(),
        slave2_handles,
        resync2_rx,
        shutdown_tx.subscribe(),
    );

    // Wait for both slaves to connect
    let connected = wait_until(Duration::from_secs(3), || {
        let coordinator = coordinator.clone();
        async move { coordinator.connected_slave_count() == 2 }
    })
    .await;
    assert!(connected, "both slaves must connect");
    assert_eq!(coordinator.connected_slave_count(), 2);

    // Now update bundle on master: add a new custom rule
    let bundle = ConfigBundle {
        version: 2,
        term: 0,
        timestamp: 12345,
        config_toml: "config_version = 1\n[server]\nrole = \"slave\"\n".to_string(),
        custom_rules: vec!["||blocked-fast.test^".to_string()],
        rewrites: None,
        clients: None,
        lists: vec![],
    };
    coordinator.update_bundle(bundle).unwrap();

    // Assert both slaves apply the update; strict <2s budget only under
    // SITO_BENCH_TESTS, generous deadline on shared CI runners.
    let sync_deadline = if std::env::var_os("SITO_BENCH_TESTS").is_some() {
        Duration::from_secs(2)
    } else {
        Duration::from_secs(15)
    };
    let both_synced = wait_until(sync_deadline, || {
        let s1 = slave1_tracker.clone();
        let s2 = slave2_tracker.clone();
        async move { s1.get_version() == 2 && s2.get_version() == 2 }
    })
    .await;
    assert!(
        both_synced,
        "Both slaves must apply change before the sync deadline"
    );

    // Assert the filter verdict on both slaves
    let client = ClientContext::new("127.0.0.1".parse().unwrap());
    assert!(
        slave1_filter
            .snapshot()
            .evaluate("blocked-fast.test", RecordType::A, &client)
            .is_blocked()
    );
    assert!(
        slave2_filter
            .snapshot()
            .evaluate("blocked-fast.test", RecordType::A, &client)
            .is_blocked()
    );

    let _ = shutdown_tx.send(true);
    let _ = std::fs::remove_dir_all(&temp_dir);
}

// ----------------------------------------------------------------------------
// Test 8b: D-01 — a push applies every component without a file-watcher event
// ----------------------------------------------------------------------------

/// Records the DNSSEC settings the apply hooks receive and installs a real
/// validator, mirroring the production hook.
struct RecordingDnssecHooks {
    validator: Arc<ArcSwap<sito_dnssec::DnssecValidator>>,
    observed_nta: Arc<Mutex<Vec<String>>>,
}

impl ConfigApplyHooks for RecordingDnssecHooks {
    fn apply<'a>(
        &'a self,
        cfg: &'a Config,
        _clients: &'a sito_clients::ClientsConfig,
    ) -> ApplyFuture<'a> {
        Box::pin(async move {
            *self.observed_nta.lock().unwrap() = cfg.dns.dnssec.nta.clone();
            self.validator
                .store(Arc::new(sito_dnssec::DnssecValidator::from_config(
                    &cfg.dns.dnssec,
                )));
            Ok(())
        })
    }
}

fn filter_compile_count(metrics: &MetricsRegistry) -> u64 {
    metrics
        .render_prometheus()
        .lines()
        .find(|line| line.starts_with("sito_filter_compile_seconds_count "))
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse().ok())
        .expect("filter compile counter must be rendered")
}

#[tokio::test]
async fn test_m8_push_applies_upstream_and_dnssec_without_watcher() {
    let signing_key = Ed25519SigningKey::generate().unwrap();
    let (ctx, _token, temp_dir) = create_test_context("slave", None, None, None).await;
    // The startup compile is recorded by the engine observer; the push must add
    // exactly one more observation.
    let compiles_before_push = filter_compile_count(&ctx.metrics);

    let dnssec_validator = Arc::new(ArcSwap::from_pointee(
        sito_dnssec::DnssecValidator::from_config(&Config::default().dns.dnssec),
    ));
    let observed_nta = Arc::new(Mutex::new(Vec::new()));
    let hooks = Arc::new(RecordingDnssecHooks {
        validator: dnssec_validator.clone(),
        observed_nta: observed_nta.clone(),
    });

    // The production applier: real ServerContext + real apply hooks, no
    // watcher task anywhere in this test.
    let applier = Arc::new(sito::server::HaConfigApplier::new(
        ctx.clone(),
        hooks.clone(),
    ));
    // Listener generation and rate limiters are live in this scenario.
    applier.mark_listeners_ready();

    let tracker = SlaveStatusTracker::new("slave-apply".to_string(), 0, None);
    let handles = SlaveAppHandles {
        runtime: ctx.runtime.clone(),
        filter: ctx.filter.clone(),
        metrics: ctx.metrics.clone(),
        config_path: Some(ctx.config_path.clone()),
        applier,
    };

    let config_toml = r#"
config_version = 1

[server]
role = "slave"
instance_name = "master-value"

[upstream]
servers = ["9.9.9.9"]

[dns.dnssec]
validate = true
mode = "validate"
nta = ["pushed.internal"]
"#;
    let push = build_and_sign_push(
        &ConfigBundle {
            version: 2,
            term: 0,
            timestamp: 1,
            config_toml: config_toml.to_string(),
            custom_rules: vec!["||pushed-d01.test^".to_string()],
            rewrites: None,
            clients: None,
            lists: vec![],
        },
        &signing_key,
    )
    .unwrap();

    let applied =
        sito_ha::apply_config_push(&push, &tracker, &handles, signing_key.public_key().as_ref())
            .await
            .expect("push must apply through the real context");
    assert_eq!(applied, 2);
    assert_eq!(tracker.get_state(), SlaveState::Synced);
    assert_eq!(tracker.get_version(), 2);

    // Runtime snapshot: upstream and filter applied immediately, without the
    // watcher.
    let snapshot = ctx.runtime.snapshot();
    assert_eq!(snapshot.config.upstream.servers, vec!["9.9.9.9"]);
    assert!(
        snapshot
            .config
            .filtering
            .custom_rules
            .iter()
            .any(|rule| rule == "||pushed-d01.test^")
    );
    let statuses = ctx.upstream.statuses().await;
    assert!(
        statuses.iter().any(|(name, _)| name.contains("9.9.9.9")),
        "the upstream manager must be reloaded from the pushed config: {statuses:?}"
    );

    // Hook-owned DNSSEC component applied too.
    assert_eq!(
        *observed_nta.lock().unwrap(),
        vec!["pushed.internal".to_string()]
    );
    assert_eq!(
        dnssec_validator.load().nta_domains.load().as_slice(),
        &["pushed.internal".to_string()][..]
    );

    // Persisted file carries the pushed components.
    let persisted = tokio::fs::read_to_string(&ctx.config_path).await.unwrap();
    assert!(persisted.contains("9.9.9.9"));
    assert!(persisted.contains("pushed.internal"));

    // A watcher notification for the applier's own write must not apply (and
    // reload/download) the configuration a second time.
    let filter_compiles_before = filter_compile_count(&ctx.metrics);
    assert_eq!(
        filter_compiles_before,
        compiles_before_push + 1,
        "the push itself must have compiled the filter exactly once"
    );
    match apply_config_document_event(&ctx, &persisted, FilterApply::Sync, Some(&*hooks)).await {
        ConfigFileApplyOutcome::SelfWriteIgnored => {}
        other => panic!("the applier's own write must be ignored, got {other:?}"),
    }
    assert_eq!(
        filter_compile_count(&ctx.metrics),
        filter_compiles_before,
        "a push must not trigger a second filter download/compile through the watcher"
    );

    // A duplicate watcher event is suppressed because the file still matches
    // the live runtime configuration.
    match apply_config_document_event(&ctx, &persisted, FilterApply::Sync, Some(&*hooks)).await {
        ConfigFileApplyOutcome::SelfWriteIgnored => {}
        other => panic!("a duplicate self-write event must be ignored, got {other:?}"),
    }
    assert_eq!(
        filter_compile_count(&ctx.metrics),
        filter_compiles_before,
        "a duplicate self-write event must not recompile the filter"
    );

    // A changed watcher document is applied normally.
    let mut changed = (**ctx.config.load()).clone();
    changed.upstream.servers = vec!["8.8.8.8".to_string()];
    let changed_document = toml::to_string_pretty(&changed).unwrap();
    tokio::fs::write(&ctx.config_path, &changed_document)
        .await
        .unwrap();
    match apply_config_document_event(&ctx, &changed_document, FilterApply::Sync, Some(&*hooks))
        .await
    {
        ConfigFileApplyOutcome::Applied(_) => {}
        other => panic!("a changed watcher document must be applied, got {other:?}"),
    }
    assert_eq!(
        ctx.runtime.snapshot().config.upstream.servers,
        vec!["8.8.8.8".to_string()]
    );
    assert_eq!(
        filter_compile_count(&ctx.metrics),
        filter_compiles_before + 1
    );

    let _ = std::fs::remove_dir_all(&temp_dir);
}

/// A push that changes a restart-only field must not be acknowledged as fully
/// applied: the live process keeps its previous behavior, so `applied: true`
/// would lie to the master. The push is rejected, the previous live state and
/// the persisted file are kept, and the failure names `restart_required`.
#[tokio::test]
async fn test_m8_push_restart_only_field_is_not_acked_as_applied() {
    let signing_key = Ed25519SigningKey::generate().unwrap();
    let (ctx, _token, temp_dir) = create_test_context("slave", None, None, None).await;

    let hooks = Arc::new(RecordingDnssecHooks {
        validator: Arc::new(ArcSwap::from_pointee(
            sito_dnssec::DnssecValidator::from_config(&Config::default().dns.dnssec),
        )),
        observed_nta: Arc::new(Mutex::new(Vec::new())),
    });
    let applier = Arc::new(sito::server::HaConfigApplier::new(
        ctx.clone(),
        hooks.clone(),
    ));
    applier.mark_listeners_ready();

    let tracker = SlaveStatusTracker::new("slave-restart-only".to_string(), 0, None);
    let handles = SlaveAppHandles {
        runtime: ctx.runtime.clone(),
        filter: ctx.filter.clone(),
        metrics: ctx.metrics.clone(),
        config_path: Some(ctx.config_path.clone()),
        applier,
    };

    let config_before = tokio::fs::read_to_string(&ctx.config_path).await.unwrap();
    let upstream_before = ctx.runtime.snapshot().config.upstream.servers.clone();

    // `server.log_format` is restart-only; the same push also carries a
    // hot-appliable upstream change that must not be applied either, because
    // the push as a whole cannot take effect without a restart.
    let config_toml = r#"
config_version = 1

[server]
role = "slave"
log_format = "pretty"

[upstream]
servers = ["9.9.9.9"]
"#;
    let push = build_and_sign_push(
        &ConfigBundle {
            version: 2,
            term: 0,
            timestamp: 1,
            config_toml: config_toml.to_string(),
            custom_rules: vec![],
            rewrites: None,
            clients: None,
            lists: vec![],
        },
        &signing_key,
    )
    .unwrap();

    let err =
        sito_ha::apply_config_push(&push, &tracker, &handles, signing_key.public_key().as_ref())
            .await
            .expect_err("a restart-only change must not be acknowledged as applied");
    let message = err.to_string();
    assert!(
        message.contains("restart_required"),
        "the rejection must identify the restart-only change: {message}"
    );
    assert!(
        message.contains("server.log_format"),
        "the rejection must name the restart-only field: {message}"
    );
    assert_eq!(tracker.get_state(), SlaveState::Degraded);
    assert_eq!(
        tracker.get_version(),
        0,
        "the watermark must not advance for a push that was not applied"
    );
    assert_eq!(
        ctx.runtime.snapshot().config.upstream.servers,
        upstream_before,
        "hot-appliable fields from a rejected push must not be applied"
    );
    assert_eq!(
        ctx.runtime.snapshot().config.server.log_format,
        "json",
        "the live restart-only setting must be kept"
    );
    assert_eq!(
        tokio::fs::read_to_string(&ctx.config_path).await.unwrap(),
        config_before,
        "the persisted file must be kept"
    );

    let _ = std::fs::remove_dir_all(&temp_dir);
}

/// Regression: an explicit `[auth]` table with the default policy must be
/// equivalent to omitting it. The shipped master example spells the defaults
/// out while the runbook's minimal slave has no `[auth]`; before the fix every
/// such push was rejected with `restart_required: auth`. A genuine policy
/// change must still be rejected.
#[tokio::test]
async fn test_m8_push_default_auth_policy_is_not_rejected() {
    let signing_key = Ed25519SigningKey::generate().unwrap();
    let (ctx, _token, temp_dir) = create_test_context("slave", None, None, None).await;

    let hooks = Arc::new(RecordingDnssecHooks {
        validator: Arc::new(ArcSwap::from_pointee(
            sito_dnssec::DnssecValidator::from_config(&Config::default().dns.dnssec),
        )),
        observed_nta: Arc::new(Mutex::new(Vec::new())),
    });
    let applier = Arc::new(sito::server::HaConfigApplier::new(
        ctx.clone(),
        hooks.clone(),
    ));
    applier.mark_listeners_ready();

    let tracker = SlaveStatusTracker::new("slave-default-auth".to_string(), 0, None);
    let handles = SlaveAppHandles {
        runtime: ctx.runtime.clone(),
        filter: ctx.filter.clone(),
        metrics: ctx.metrics.clone(),
        config_path: Some(ctx.config_path.clone()),
        applier,
    };

    // Master example: explicit `[auth]` with exactly the default values.
    // Slave: no `[auth]` section at all.
    let default_auth_toml = r#"
config_version = 1

[server]
role = "slave"

[filtering]
enabled = false

[auth]
session_ttl_hours = 24
login_rate_limit = 5
session_persist = true
token_default_ttl_days = 90

[upstream]
servers = ["9.9.9.9"]
"#;
    let push = build_and_sign_push(
        &ConfigBundle {
            version: 2,
            term: 0,
            timestamp: 1,
            config_toml: default_auth_toml.to_string(),
            custom_rules: vec![],
            rewrites: None,
            clients: None,
            lists: vec![],
        },
        &signing_key,
    )
    .unwrap();

    let applied =
        sito_ha::apply_config_push(&push, &tracker, &handles, signing_key.public_key().as_ref())
            .await
            .expect("an explicit-default [auth] must not be treated as restart-only");
    assert_eq!(applied, 2);
    assert_eq!(tracker.get_state(), SlaveState::Synced);
    assert_eq!(tracker.get_version(), 2);

    // A real policy change is still a restart-only difference and must not be
    // acknowledged as applied.
    let config_before = tokio::fs::read_to_string(&ctx.config_path).await.unwrap();
    let changed_policy_toml =
        default_auth_toml.replace("session_ttl_hours = 24", "session_ttl_hours = 1");
    let push = build_and_sign_push(
        &ConfigBundle {
            version: 3,
            term: 0,
            timestamp: 2,
            config_toml: changed_policy_toml,
            custom_rules: vec![],
            rewrites: None,
            clients: None,
            lists: vec![],
        },
        &signing_key,
    )
    .unwrap();

    let err =
        sito_ha::apply_config_push(&push, &tracker, &handles, signing_key.public_key().as_ref())
            .await
            .expect_err("a real [auth] policy change must still require a restart");
    let message = err.to_string();
    assert!(
        message.contains("restart_required"),
        "the rejection must identify the restart-only change: {message}"
    );
    assert!(
        message.contains("auth"),
        "the rejection must name the [auth] section: {message}"
    );
    assert_eq!(tracker.get_state(), SlaveState::Degraded);
    assert_eq!(
        tracker.get_version(),
        2,
        "the watermark must not advance for the rejected policy change"
    );
    assert_eq!(
        tokio::fs::read_to_string(&ctx.config_path).await.unwrap(),
        config_before,
        "the persisted file must keep the previously applied policy"
    );

    let _ = std::fs::remove_dir_all(&temp_dir);
}

/// D-01 startup-order regression: a push that arrives before the DNS listener
/// generation and rate limiters exist is refused (so the worker ACKs
/// `applied:false` and retries) instead of being applied and persisted with
/// listener/rate-limit components silently skipped.
#[tokio::test]
async fn test_m8_push_before_listeners_fails_and_retries_after_ready() {
    let signing_key = Ed25519SigningKey::generate().unwrap();
    let (ctx, _token, temp_dir) = create_test_context("slave", None, None, None).await;

    let hooks = Arc::new(RecordingDnssecHooks {
        validator: Arc::new(ArcSwap::from_pointee(
            sito_dnssec::DnssecValidator::from_config(&Config::default().dns.dnssec),
        )),
        observed_nta: Arc::new(Mutex::new(Vec::new())),
    });
    let applier = Arc::new(sito::server::HaConfigApplier::new(
        ctx.clone(),
        hooks.clone(),
    ));
    let tracker = SlaveStatusTracker::new("slave-startup".to_string(), 0, None);
    let handles = SlaveAppHandles {
        runtime: ctx.runtime.clone(),
        filter: ctx.filter.clone(),
        metrics: ctx.metrics.clone(),
        config_path: Some(ctx.config_path.clone()),
        applier: applier.clone(),
    };

    let push = build_and_sign_push(
        &ConfigBundle {
            version: 2,
            term: 0,
            timestamp: 1,
            config_toml: "config_version = 1\n[server]\nrole = \"slave\"\n\n[filtering]\nenabled = false\n\n[upstream]\nservers = [\"9.9.9.9\"]\n".to_string(),
            custom_rules: vec![],
            rewrites: None,
            clients: None,
            lists: vec![],
        },
        &signing_key,
    )
    .unwrap();

    let err =
        sito_ha::apply_config_push(&push, &tracker, &handles, signing_key.public_key().as_ref())
            .await
            .expect_err("a push before listeners exist must not be acknowledged");
    assert!(
        err.to_string().contains("not initialized yet"),
        "the failure must identify the uninitialized listener components: {err}"
    );
    assert_eq!(tracker.get_state(), SlaveState::Degraded);
    assert_eq!(
        tracker.get_version(),
        0,
        "the watermark must not advance before listeners are available"
    );
    assert_eq!(
        ctx.runtime.snapshot().config.upstream.servers,
        Config::default().upstream.servers,
        "the live configuration must be untouched"
    );

    // Once the listener generation and rate limiters are live, the same push
    // applies and the watermark advances.
    applier.mark_listeners_ready();
    let applied =
        sito_ha::apply_config_push(&push, &tracker, &handles, signing_key.public_key().as_ref())
            .await
            .expect("the retry after listener startup must apply");
    assert_eq!(applied, 2);
    assert_eq!(tracker.get_state(), SlaveState::Synced);
    assert_eq!(tracker.get_version(), 2);
    assert_eq!(
        ctx.runtime.snapshot().config.upstream.servers,
        vec!["9.9.9.9".to_string()]
    );
    let persisted = tokio::fs::read_to_string(&ctx.config_path).await.unwrap();
    assert!(persisted.contains("9.9.9.9"));

    let _ = std::fs::remove_dir_all(&temp_dir);
}

// ----------------------------------------------------------------------------
// Test 9: Chaos: Master kill mid-push leaves slave consistent at N or N+1
// ----------------------------------------------------------------------------
#[tokio::test]
async fn test_m8_chaos_master_mid_push_kill() {
    let temp_dir = std::env::temp_dir().join(format!("sito_m8_chaos_{}", rand::random::<u64>()));
    tokio::fs::create_dir_all(&temp_dir).await.unwrap();

    let certs = generate_ha_certs(&temp_dir, true, true).unwrap();

    let signing_key = Arc::new(Ed25519SigningKey::generate().unwrap());
    let metrics = MetricsRegistry::new("0.1.0", "test");
    let coordinator = MasterCoordinator::new(
        "master-chaos".to_string(),
        1,
        signing_key.clone(),
        metrics.clone(),
    );

    let (replication_port, _replication_port_lease) = reserve_tcp_port();
    let master_ha_cfg = HaConfig {
        replication_port,
        listen_addr: "127.0.0.1".to_string(),
        cert: certs.master_cert_path.clone(),
        key: certs.master_key_path.clone(),
        ca: Some(certs.ca_cert_path.clone()),
        pinned_slave_fingerprints: vec![certs.slave_fingerprint.clone().unwrap()],
        ..Default::default()
    };

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let _server = spawn_master_server(master_ha_cfg, coordinator.clone(), shutdown_rx);
    let master_ready = wait_until(Duration::from_secs(3), || async {
        tokio::net::TcpStream::connect(("127.0.0.1", replication_port))
            .await
            .is_ok()
    })
    .await;
    assert!(master_ready, "master replication listener did not start");

    let slave_tracker = SlaveStatusTracker::new("slave-chaos".to_string(), 1, None);
    let slave_cfg = Config::default();
    let slave_filter = Arc::new(
        HostsFilterEngine::init(slave_cfg.filtering.clone(), temp_dir.join("slave")).await,
    );
    let slave_runtime = Arc::new(sito_runtime::RuntimeState::new(
        Arc::new(ArcSwap::new(Arc::new(slave_cfg))),
        Arc::new(ArcSwap::new(Arc::new(sito_clients::ClientRegistry::new(
            Default::default(),
        )))),
        Arc::new(ArcSwap::new(Arc::new(sito_rewrites::RewriteTable::new(
            Default::default(),
        )))),
    ));
    let slave_handles = SlaveAppHandles {
        runtime: slave_runtime.clone(),
        filter: slave_filter.clone(),
        metrics: metrics.clone(),
        config_path: None,
        applier: HarnessApplier::arc(slave_runtime, slave_filter.clone(), None),
    };
    let slave_ha_cfg = HaConfig {
        master_url: Some(format!("wss://127.0.0.1:{replication_port}")),
        master_fingerprint: certs.master_fingerprint.clone(),
        master_pubkey: Some(signing_key.public_key_hex()),
        cert: certs.slave_cert_path.clone(),
        key: certs.slave_key_path.clone(),
        ca: Some(certs.ca_cert_path.clone()),
        ..Default::default()
    };
    let (_resync_tx, resync_rx) = tokio::sync::mpsc::channel(1);
    let worker = spawn_slave_worker(
        slave_ha_cfg,
        slave_tracker.clone(),
        slave_handles,
        resync_rx,
        shutdown_tx.subscribe(),
    );

    let connected = wait_until(Duration::from_secs(3), || {
        let coordinator = coordinator.clone();
        async move { coordinator.connected_slave_count() == 1 }
    })
    .await;
    assert!(connected, "chaos slave must connect");

    // Publish a bundle and kill the master while the push is in flight.
    let bundle = ConfigBundle {
        version: 2,
        term: 0,
        timestamp: 424_242,
        config_toml: "config_version = 1\n[server]\nrole = \"slave\"\n".to_string(),
        custom_rules: vec!["||mid-push.test^".to_string()],
        rewrites: None,
        clients: None,
        lists: vec![],
    };
    coordinator.update_bundle(bundle).unwrap();
    // No coordinator event exposes "WebSocket write in flight". This short
    // bounded delay lets the push leave the master so the test genuinely kills
    // it mid-push; the assertion accepts version 1 or 2, so a slower or faster
    // machine cannot make the test flaky.
    tokio::time::sleep(Duration::from_millis(50)).await;
    let _ = shutdown_tx.send(true);
    let joined = tokio::time::timeout(Duration::from_secs(2), worker)
        .await
        .expect("slave worker must stop after shutdown");
    joined.expect("slave worker task panicked");

    // Assert slave version is strictly 1 (or 2 if finished before kill), never corrupted
    let v = slave_tracker.get_version();
    assert!(
        v == 1 || v == 2,
        "Slave must remain consistent at N (1) or N+1 (2), got {v}"
    );

    let _ = std::fs::remove_dir_all(&temp_dir);
}

// ----------------------------------------------------------------------------
// Test 10: Slave to master promotion runbook procedure execution
// ----------------------------------------------------------------------------
#[tokio::test]
async fn test_m8_slave_to_master_promotion_procedure() {
    let temp_dir =
        std::env::temp_dir().join(format!("sito_m8_promotion_{}", rand::random::<u64>()));
    tokio::fs::create_dir_all(&temp_dir).await.unwrap();

    // 1. Slave running with version 2
    let slave_tracker = SlaveStatusTracker::new("slave-promotee".to_string(), 2, None);
    slave_tracker.set_state(SlaveState::Synced);
    assert_eq!(slave_tracker.get_state(), SlaveState::Synced);

    // 2. Perform promotion per docs/runbook-ha.md:
    // a. Role changed to "master"
    // b. Signing key generated/loaded in data_dir (0600)
    let key_path = temp_dir.join("ha_signing.key");
    let signing_key = Arc::new(Ed25519SigningKey::load_or_create(&key_path).unwrap());
    assert!(key_path.exists());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&key_path).unwrap().permissions();
        assert_eq!(perms.mode() & 0o777, 0o600);
    }

    // c. Initialize MasterCoordinator on promoted node. The operator raised the
    //    cluster term explicitly (section 2 of the runbook).
    let metrics = MetricsRegistry::new("0.1.0", "promoted");
    let promoted_coordinator = MasterCoordinator::new(
        "sito-master-promoted".to_string(),
        2,
        signing_key,
        metrics.clone(),
    )
    .with_term(1);
    assert_eq!(promoted_coordinator.get_current_version(), 2);
    assert_eq!(promoted_coordinator.get_current_term(), 1);

    // d. Promoted master creates and signs new bundle (version 3, term 1)
    let new_bundle = ConfigBundle {
        version: 3,
        term: 1,
        timestamp: 99999,
        config_toml: "config_version = 1\n[server]\nrole = \"slave\"\n".to_string(),
        custom_rules: vec!["||promoted-master-rule.net^".to_string()],
        rewrites: None,
        clients: None,
        lists: vec![],
    };
    promoted_coordinator.update_bundle(new_bundle).unwrap();
    assert_eq!(promoted_coordinator.get_current_version(), 3);

    // A promoted master must never publish a stale/equal version again.
    let stale_bundle = ConfigBundle {
        version: 3,
        term: 1,
        timestamp: 100_000,
        config_toml: "config_version = 1\n[server]\nrole = \"slave\"\n".to_string(),
        custom_rules: vec![],
        rewrites: None,
        clients: None,
        lists: vec![],
    };
    assert!(
        promoted_coordinator.update_bundle(stale_bundle).is_err(),
        "non-monotonic bundle must be rejected after promotion"
    );

    // A stale term-0 master cannot publish a higher version over the promoted
    // epoch.
    let stale_epoch_bundle = ConfigBundle {
        version: 4,
        term: 0,
        timestamp: 100_001,
        config_toml: "config_version = 1\n[server]\nrole = \"slave\"\n".to_string(),
        custom_rules: vec![],
        rewrites: None,
        clients: None,
        lists: vec![],
    };
    let err = promoted_coordinator
        .update_bundle(stale_epoch_bundle)
        .expect_err("an older-term bundle must not publish over the promoted epoch");
    assert!(
        matches!(err, sito_ha::HaError::Validation { ref field, .. } if field == "term"),
        "unexpected error: {err:?}"
    );

    let _ = std::fs::remove_dir_all(&temp_dir);
}

// ----------------------------------------------------------------------------
// Test 11: Master publishes bundle to coordinator on mutating API operation
// ----------------------------------------------------------------------------
#[tokio::test]
async fn test_m8_master_api_mutation_publishes_bundle() {
    let signing_key = Arc::new(Ed25519SigningKey::generate().unwrap());
    let metrics = MetricsRegistry::new("0.1.0", "master-coord-test");
    let coordinator = MasterCoordinator::new("master-pub".to_string(), 1, signing_key, metrics);

    let (ctx, token, temp_dir) =
        create_test_context("master", Some(coordinator.clone()), None, None).await;
    let app = create_router(ctx);

    assert_eq!(coordinator.get_current_version(), 1);

    // Perform mutating request: POST /api/v1/rewrites
    let req = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/rewrites")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            r#"{"domain":"test.local","record_type":"A","answer":"1.2.3.4","exception_clients":[]}"#,
        ))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Coordinator bundle version must have incremented to 2
    assert_eq!(coordinator.get_current_version(), 2);

    let _ = std::fs::remove_dir_all(&temp_dir);
}
