//! Background slave replication worker and state apply coordinator.

mod apply;
mod config_merge;
mod session;
mod stats;
#[cfg(test)]
mod tests;

use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;

use sito_core::config::Config;
use sito_filter::HostsFilterEngine;
use sito_stats::MetricsRegistry;

pub use apply::apply_config_push;
pub use session::spawn_slave_worker;
#[cfg(test)]
pub(crate) use tests::test_support;

/// Applies and persists a configuration pushed by the master.
///
/// Implemented by the `sito` binary on top of
/// `sito_api::config_apply::apply_and_persist_document`, so every component
/// (upstreams, filter, clients, rewrites, cache, query-log privacy, runtime
/// snapshot and the hook-owned DNSSEC/scoped-upstream/rate-limiter/listener/log
/// level pieces) is applied before a pushed bundle is acknowledged. The trait
/// lives here so `sito-ha` does not depend on `sito-api`.
pub trait SlaveConfigApplier: Send + Sync {
    /// Applies `cfg` to the live server and atomically persists `document`.
    ///
    /// On failure the live components must have been rolled back to the
    /// previous configuration and no document may have been persisted.
    fn apply_and_persist<'a>(
        &'a self,
        cfg: &'a Config,
        document: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>>;
}

/// Active server handles that the slave atomically updates when a new bundle is applied.
///
/// Config/clients/rewrites are published through [`RuntimeState`] so the query
/// pipeline observes them in the same coherent snapshot as the file watcher
/// and API paths do; the individual handles must not be written directly.
/// [`SlaveAppHandles::applier`] is the single apply/persist path.
#[derive(Clone)]
pub struct SlaveAppHandles {
    pub runtime: Arc<sito_runtime::RuntimeState>,
    pub filter: Arc<HostsFilterEngine>,
    pub metrics: MetricsRegistry,
    pub config_path: Option<PathBuf>,
    pub applier: Arc<dyn SlaveConfigApplier>,
}
