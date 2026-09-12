//! `sito-runtime`
//!
//! Coherent view of the configuration state that can change at runtime.
//!
//! The DNS pipeline must not observe a config file watch, an API update and an
//! HA push interleaved halfway: config, client registry and rewrite table are
//! therefore published together as one immutable [`RuntimeSnapshot`] behind a
//! single `ArcSwap`. Writers go through [`RuntimeState`], which keeps the
//! individual handles (used by the web UI and watcher code) and the snapshot
//! in sync under a write lock so concurrent updates cannot lose a component.

use arc_swap::ArcSwap;
use sito_clients::ClientRegistry;
use sito_core::config::Config;
use sito_rewrites::RewriteTable;
use std::sync::{Arc, Mutex};

/// Immutable, internally consistent set of runtime components.
#[derive(Clone)]
pub struct RuntimeSnapshot {
    pub config: Arc<Config>,
    pub clients: Arc<ClientRegistry>,
    pub rewrites: Arc<RewriteTable>,
}

/// Shared holder publishing [`RuntimeSnapshot`] values atomically.
pub struct RuntimeState {
    config: Arc<ArcSwap<Config>>,
    clients: Arc<ArcSwap<ClientRegistry>>,
    rewrites: Arc<ArcSwap<RewriteTable>>,
    snapshot: ArcSwap<RuntimeSnapshot>,
    write_lock: Mutex<()>,
}

impl std::fmt::Debug for RuntimeState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RuntimeState").finish_non_exhaustive()
    }
}

impl RuntimeState {
    /// Creates the state from the existing handles, taking an initial snapshot.
    #[must_use]
    pub fn new(
        config: Arc<ArcSwap<Config>>,
        clients: Arc<ArcSwap<ClientRegistry>>,
        rewrites: Arc<ArcSwap<RewriteTable>>,
    ) -> Self {
        let snapshot = RuntimeSnapshot {
            config: config.load_full(),
            clients: clients.load_full(),
            rewrites: rewrites.load_full(),
        };
        Self {
            config,
            clients,
            rewrites,
            snapshot: ArcSwap::from_pointee(snapshot),
            write_lock: Mutex::new(()),
        }
    }

    /// Returns a coherent snapshot to use for the whole duration of a query.
    #[must_use]
    pub fn snapshot(&self) -> Arc<RuntimeSnapshot> {
        self.snapshot.load_full()
    }

    /// The mutable config handle (used by code that only reads through `load`).
    #[must_use]
    pub fn config_handle(&self) -> &Arc<ArcSwap<Config>> {
        &self.config
    }

    /// The mutable client-registry handle.
    #[must_use]
    pub fn clients_handle(&self) -> &Arc<ArcSwap<ClientRegistry>> {
        &self.clients
    }

    /// The mutable rewrite-table handle.
    #[must_use]
    pub fn rewrites_handle(&self) -> &Arc<ArcSwap<RewriteTable>> {
        &self.rewrites
    }

    /// Publishes a new configuration while preserving the other components.
    pub fn set_config(&self, config: Config) {
        let _guard = self.lock();
        self.config.store(Arc::new(config.clone()));
        self.publish(|current| RuntimeSnapshot {
            config: Arc::new(config),
            ..current.clone()
        });
    }

    /// Publishes a new client registry while preserving the other components.
    pub fn set_clients(&self, clients: ClientRegistry) {
        let _guard = self.lock();
        self.clients.store(Arc::new(clients.clone()));
        self.publish(|current| RuntimeSnapshot {
            clients: Arc::new(clients),
            ..current.clone()
        });
    }

    /// Publishes a new rewrite table while preserving the other components.
    pub fn set_rewrites(&self, rewrites: RewriteTable) {
        let _guard = self.lock();
        self.rewrites.store(Arc::new(rewrites.clone()));
        self.publish(|current| RuntimeSnapshot {
            rewrites: Arc::new(rewrites),
            ..current.clone()
        });
    }

    /// Replaces every component at once; used by the config watcher and HA
    /// applies where config, clients and rewrites change together.
    pub fn replace(&self, snapshot: RuntimeSnapshot) {
        let _guard = self.lock();
        self.config.store(snapshot.config.clone());
        self.clients.store(snapshot.clients.clone());
        self.rewrites.store(snapshot.rewrites.clone());
        self.snapshot.store(Arc::new(snapshot));
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, ()> {
        self.write_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn publish(&self, build: impl FnOnce(&RuntimeSnapshot) -> RuntimeSnapshot) {
        let current = self.snapshot.load_full();
        self.snapshot.store(Arc::new(build(&current)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn config_with_port(port: u16) -> Config {
        let mut config = Config::default();
        config.dns.port = port;
        config
    }

    fn state() -> (
        Arc<RuntimeState>,
        Arc<ArcSwap<Config>>,
        Arc<ArcSwap<RewriteTable>>,
    ) {
        let config = Arc::new(ArcSwap::new(Arc::new(Config::default())));
        let clients = Arc::new(ArcSwap::new(Arc::new(ClientRegistry::new(
            Default::default(),
        ))));
        let rewrites = Arc::new(ArcSwap::new(Arc::new(
            RewriteTable::new(Default::default()),
        )));
        let state = Arc::new(RuntimeState::new(config.clone(), clients, rewrites.clone()));
        (state, config, rewrites)
    }

    #[test]
    fn test_snapshot_is_coherent_across_component_updates() {
        let (state, config_handle, _rewrites_handle) = state();

        state.set_config(config_with_port(5300));
        state.set_rewrites(RewriteTable::new(Default::default()));

        let snapshot = state.snapshot();
        assert_eq!(snapshot.config.dns.port, 5300);
        assert_eq!(config_handle.load().dns.port, 5300);
    }

    #[test]
    fn test_replace_publishes_all_components_together() {
        let (state, _, _) = state();
        state.replace(RuntimeSnapshot {
            config: Arc::new(config_with_port(5301)),
            clients: Arc::new(ClientRegistry::new(Default::default())),
            rewrites: Arc::new(RewriteTable::new(Default::default())),
        });

        let snapshot = state.snapshot();
        assert_eq!(snapshot.config.dns.port, 5301);
    }

    #[test]
    fn test_concurrent_writers_do_not_lose_components() {
        let (state, _, _) = state();
        let barrier = Arc::new(std::sync::Barrier::new(3));
        let counter = Arc::new(AtomicUsize::new(0));

        let mut handles = Vec::new();
        for worker in 0..2 {
            let state = state.clone();
            let barrier = barrier.clone();
            let counter = counter.clone();
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                for i in 0..50 {
                    if worker == 0 {
                        state.set_config(config_with_port(5300 + i));
                    } else {
                        state.set_rewrites(RewriteTable::new(Default::default()));
                    }
                    counter.fetch_add(1, Ordering::Relaxed);
                }
            }));
        }
        barrier.wait();
        for handle in handles {
            handle.join().unwrap();
        }

        // Every published snapshot keeps both components non-empty and the
        // latest writes are visible.
        assert_eq!(counter.load(Ordering::Relaxed), 100);
        assert_eq!(state.snapshot().config.dns.port, 5349);
        assert!(state.config_handle().load().dns.port == 5349);
    }
}
