//! `sito-ha`
//!
//! High-availability (HA) master/slave state replication:
//! - Master-driven push replication over secure mTLS WebSocket connections
//! - Ed25519 cryptographic signatures and BLAKE3 checksums on configuration bundles
//! - Versioned state synchronization and rollback safety
//! - Cluster health tracking, heartbeat monitoring, and failover promotion runbooks

pub mod bundle;
pub mod config;
pub mod crypto;
pub mod error;
pub mod master;
pub mod protocol;
pub mod slave;
pub mod transport;

pub use bundle::{
    ConfigBundle, FilterListMetadata, build_and_sign_push, sanitize_config_for_bundle,
    scan_for_secrets, substitute_secrets, verify_and_unpack_push,
};
pub use config::HaConfig;
pub use crypto::{
    Ed25519SigningKey, GeneratedCerts, compute_blake3_fingerprint, compute_blake3_raw_hex,
    generate_ha_certs, parse_public_key, verify_ed25519_signature,
};
pub use error::HaError;
pub use master::{MasterCoordinator, SlaveSummary, spawn_master_server};
pub use protocol::{HaMessage, PROTOCOL_VERSION, UpstreamReport};
pub use slave::{
    SlaveAppHandles, SlaveState, SlaveStatusTracker, apply_config_push, spawn_slave_worker,
};
pub use transport::{
    ExponentialBackoff, PinnedClientCertVerifier, PinnedServerCertVerifier,
    build_client_tls_config, build_server_tls_config,
};

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::sync::watch;

    #[tokio::test]
    async fn test_ha_master_slave_end_to_end_local() {
        // Setup temporary test directory and certificates
        let temp_dir = std::env::temp_dir().join(format!(
            "sito_ha_e2e_test_{}_{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        let certs = generate_ha_certs(&temp_dir, true, true).unwrap();

        let signing_key = Arc::new(Ed25519SigningKey::generate().unwrap());
        let metrics = sito_stats::MetricsRegistry::new("0.1.0", "test");

        // Initialize MasterCoordinator
        let coordinator = MasterCoordinator::new(
            "master-1".to_string(),
            1,
            signing_key.clone(),
            metrics.clone(),
        );

        let replication_port = 18953;
        let master_ha_cfg = HaConfig {
            replication_port,
            listen_addr: "127.0.0.1".to_string(),
            cert: certs.master_cert_path.clone(),
            key: certs.master_key_path.clone(),
            pinned_slave_fingerprints: vec![certs.slave_fingerprint.clone().unwrap()],
            ..Default::default()
        };

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let _server_handle = spawn_master_server(master_ha_cfg, coordinator.clone(), shutdown_rx);

        // Allow listener to bind
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Initialize SlaveTracker and handles
        let slave_tracker = SlaveStatusTracker::new(
            "slave-1".to_string(),
            0,
            Some(format!("wss://127.0.0.1:{replication_port}")),
        );

        let base_config = sito_core::config::Config::default();
        let config_arc = Arc::new(arc_swap::ArcSwap::new(Arc::new(base_config.clone())));
        let filter_engine = Arc::new(
            sito_filter::HostsFilterEngine::init(base_config.filtering.clone(), temp_dir.clone())
                .await,
        );
        let rewrites_arc = Arc::new(arc_swap::ArcSwap::new(Arc::new(
            sito_rewrites::RewriteTable::new(Default::default()),
        )));
        let clients_arc = Arc::new(arc_swap::ArcSwap::new(Arc::new(
            sito_clients::ClientRegistry::new(Default::default()),
        )));

        let handles = SlaveAppHandles {
            config: config_arc.clone(),
            filter: filter_engine.clone(),
            rewrites: rewrites_arc.clone(),
            clients: clients_arc.clone(),
            metrics: metrics.clone(),
            config_path: None,
        };

        let slave_ha_cfg = HaConfig {
            master_url: Some(format!("wss://127.0.0.1:{replication_port}")),
            master_fingerprint: certs.master_fingerprint.clone(),
            master_pubkey: Some(signing_key.public_key_hex()),
            cert: certs.slave_cert_path.clone(),
            key: certs.slave_key_path.clone(),
            ..Default::default()
        };

        // Update bundle on master
        let bundle = ConfigBundle {
            version: 2,
            timestamp: 12345,
            config_toml: "config_version = 1\n[server]\nrole = \"slave\"\n".to_string(),
            custom_rules: vec!["||ha-test-domain.internal^".to_string()],
            rewrites: None,
            clients: None,
            lists: vec![],
        };
        coordinator.update_bundle(bundle).unwrap();

        let (_resync_tx, resync_rx) = tokio::sync::mpsc::channel(1);
        let _worker_handle = spawn_slave_worker(
            slave_ha_cfg,
            slave_tracker.clone(),
            handles,
            resync_rx,
            shutdown_tx.subscribe(),
        );

        // Wait up to 3 seconds for slave to connect, receive push, and sync
        let mut synced = false;
        for _ in 0..30 {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            if slave_tracker.get_version() == 2 && slave_tracker.get_state() == SlaveState::Synced {
                synced = true;
                break;
            }
        }

        assert!(synced, "Slave should synchronize version 2 in < 3s");
        assert_eq!(coordinator.connected_slave_count(), 1);

        let slaves = coordinator.list_slaves();
        assert_eq!(slaves.len(), 1);
        assert_eq!(slaves[0].instance, "slave-1");
        assert_eq!(slaves[0].synced_version, 2);
        assert_eq!(slaves[0].lag, 0);

        let _ = shutdown_tx.send(true);
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_unpinned_tls_rejected_by_default() {
        let mut cfg = HaConfig {
            master_url: Some("wss://127.0.0.1:8953".to_string()),
            master_fingerprint: None,
            allow_unpinned_tls: false,
            ..Default::default()
        };
        assert!(cfg.validate("slave").is_err());

        // Explicitly allowing unpinned TLS passes validation
        cfg.allow_unpinned_tls = true;
        assert!(cfg.validate("slave").is_ok());

        // build_client_tls_config rejects None fingerprint when allow_unpinned_tls is false
        let err = build_client_tls_config(None, None, None, false);
        assert!(err.is_err());
    }

    #[test]
    fn test_insecure_ws_rejected_by_default() {
        let mut cfg = HaConfig {
            master_url: Some("ws://127.0.0.1:8953".to_string()),
            allow_insecure_ws: false,
            ..Default::default()
        };
        assert!(cfg.validate("slave").is_err());

        cfg.allow_insecure_ws = true;
        assert!(cfg.validate("slave").is_ok());
    }

    #[tokio::test]
    async fn test_unauthenticated_slave_rejected_by_master() {
        let temp_dir = std::env::temp_dir().join(format!(
            "sito_ha_auth_test_{}_{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        let certs = generate_ha_certs(&temp_dir, true, true).unwrap();
        let signing_key = Arc::new(Ed25519SigningKey::generate().unwrap());
        let metrics = sito_stats::MetricsRegistry::new("0.1.0", "test");

        let coordinator = MasterCoordinator::new(
            "master-auth".to_string(),
            1,
            signing_key.clone(),
            metrics.clone(),
        )
        .with_token(Some("required-slave-token".to_string()));

        let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);

        let master_ha_cfg = HaConfig {
            replication_port: port,
            listen_addr: "127.0.0.1".to_string(),
            cert: certs.master_cert_path.clone(),
            key: certs.master_key_path.clone(),
            pinned_slave_fingerprints: vec![certs.slave_fingerprint.clone().unwrap()],
            slave_token: Some("required-slave-token".to_string()),
            ..Default::default()
        };

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let _server_handle = spawn_master_server(master_ha_cfg, coordinator.clone(), shutdown_rx);
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let slave_tracker = SlaveStatusTracker::new(
            "unauth-slave".to_string(),
            0,
            Some(format!("wss://127.0.0.1:{port}")),
        );
        let base_config = sito_core::config::Config::default();
        let config_arc = Arc::new(arc_swap::ArcSwap::new(Arc::new(base_config.clone())));
        let filter_engine = Arc::new(
            sito_filter::HostsFilterEngine::init(base_config.filtering.clone(), temp_dir.clone())
                .await,
        );
        let rewrites_arc = Arc::new(arc_swap::ArcSwap::new(Arc::new(
            sito_rewrites::RewriteTable::new(Default::default()),
        )));
        let clients_arc = Arc::new(arc_swap::ArcSwap::new(Arc::new(
            sito_clients::ClientRegistry::new(Default::default()),
        )));

        let handles = SlaveAppHandles {
            config: config_arc,
            filter: filter_engine,
            rewrites: rewrites_arc,
            clients: clients_arc,
            metrics: metrics.clone(),
            config_path: None,
        };

        // Slave with wrong token
        let bad_slave_cfg = HaConfig {
            master_url: Some(format!("wss://127.0.0.1:{port}")),
            master_fingerprint: certs.master_fingerprint.clone(),
            master_pubkey: Some(signing_key.public_key_hex()),
            cert: certs.slave_cert_path.clone(),
            key: certs.slave_key_path.clone(),
            slave_token: Some("wrong-token".to_string()),
            ..Default::default()
        };

        let (_resync_tx, resync_rx) = tokio::sync::mpsc::channel(1);
        let _worker_handle = spawn_slave_worker(
            bad_slave_cfg,
            slave_tracker.clone(),
            handles,
            resync_rx,
            shutdown_tx.subscribe(),
        );

        tokio::time::sleep(std::time::Duration::from_millis(400)).await;
        // Master must refuse unauthenticated slave
        assert_eq!(coordinator.connected_slave_count(), 0);
        assert_ne!(slave_tracker.get_state(), SlaveState::Synced);

        let _ = shutdown_tx.send(true);
        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
