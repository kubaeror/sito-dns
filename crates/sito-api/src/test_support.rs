//! Test-only helpers shared by handler unit tests.

use crate::state::ServerContext;
use arc_swap::ArcSwap;
use sito_core::config::Config;
use std::path::Path;
use std::sync::{Arc, Mutex};

/// Builds an in-memory [`ServerContext`] backed by `temp_dir` for handler
/// tests. The auth manager is a memory-only manager with the default admin
/// account, and the config file is *not* created (handlers that persist must
/// write it).
pub(crate) async fn mock_context(temp_dir: &Path) -> ServerContext {
    let db_path = temp_dir.join("test.db");
    let stats_db = sito_stats::StatsDb::open(&db_path).await.unwrap();
    let querylog_writer = sito_stats::QueryLogWriter::spawn(stats_db.clone(), 100);
    let querylog_sender = querylog_writer.sender();
    let metrics = sito_stats::MetricsRegistry::new("1.2.1", "test");
    let auth_mgr = Arc::new(crate::auth::AuthManager::new());
    let config = Config::default();
    let config_arc = Arc::new(ArcSwap::new(Arc::new(config)));
    let filter = Arc::new(
        sito_filter::HostsFilterEngine::init(Default::default(), temp_dir.to_path_buf()).await,
    );
    let cache = Arc::new(sito_cache::DnsCache::new(Default::default()));
    let bootstrap = sito_upstream::BootstrapResolver::new(
        vec!["127.0.0.1".parse().unwrap()],
        std::time::Duration::from_secs(1),
    );
    let upstream = Arc::new(
        sito_upstream::UpstreamManager::from_config(&Default::default(), &bootstrap)
            .await
            .unwrap(),
    );
    let clients = Arc::new(ArcSwap::new(Arc::new(sito_clients::ClientRegistry::new(
        Default::default(),
    ))));
    let rewrites = Arc::new(ArcSwap::new(Arc::new(sito_rewrites::RewriteTable::new(
        Default::default(),
    ))));
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

    ServerContext {
        config: config_arc,
        runtime,
        runtime_lists,
        config_path: temp_dir.join("config.toml"),
        auth_mgr,
        stats_db,
        querylog_sender,
        metrics,
        filter,
        cache,
        upstream,
        clients,
        rewrites,
        start_time: std::time::Instant::now(),
        restore_tokens: Arc::new(Mutex::new(std::collections::HashMap::new())),
        master_coordinator: None,
        slave_tracker: None,
        resync_sender: None,
        setup_pending: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        dns_starter: None,
    }
}

/// Creates a unique temporary directory for a test.
pub(crate) fn temp_dir(prefix: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("{prefix}_{}", rand::random::<u64>()));
    let _ = std::fs::create_dir_all(&dir);
    dir
}
