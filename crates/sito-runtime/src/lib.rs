//! `sito-runtime`
//!
//! Coherent view of the configuration state that can change at runtime.
//!
//! Every hot-reloadable component that a DNS query reads is part of one
//! immutable [`RuntimeSnapshot`] behind a single `ArcSwap`:
//!
//! * the configuration, client registry and rewrite table;
//! * the compiled filter snapshot (and per-client-group snapshots);
//! * the DNSSEC policy together with the prepared validator;
//! * the cache policy and the transport/listener policy.
//!
//! Writers stage every component first, then call [`RuntimeState::apply`],
//! which validates the candidate, advances the single cache generation and
//! publishes the new snapshot with one `ArcSwap::store`. A failed stage
//! publishes nothing, so queries observe either the complete old generation or
//! the complete new one — never a mixture. The generation counter is owned by
//! `sito-cache` ([`sito_cache::PolicyEpoch`]); the runtime re-exports it as
//! [`RuntimeGeneration`] so there is exactly one epoch in the process.
//! Filter-only refreshes ([`RuntimeState::publish_filter`]) do not advance it:
//! the DNSSEC policy did not change, and a refresh must not invalidate a
//! config generation that a staged apply is checking.
//!
//! The legacy component handles (`config_handle`, `clients_handle`,
//! `rewrites_handle`) are mirrors for the admin UI and HA worker. The DNS query
//! path reads the snapshot, never the mirrors.

use arc_swap::ArcSwap;
use sito_cache::{DnsCache, PolicyEpoch};
use sito_clients::{ClientRegistry, ClientsConfig};
use sito_core::config::{CacheConfig, Config, DnsConfig, DnssecConfig};
use sito_core::error::{ConfigError, UpstreamError};
use sito_dnssec::DnssecValidator;
use sito_filter::{FilterSnapshot, GroupRuleSet, GroupSnapshots};
use sito_rewrites::{RewriteTable, RewritesConfig};
use sito_transport::TlsError;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// Monotonic generation of one runtime configuration.
///
/// This is the cache's [`PolicyEpoch`] under its runtime name: there is one
/// counter, so a query cannot capture a runtime generation from one apply and
/// a cache epoch from another. Config applies advance it; filter-only
/// refreshes do not.
pub type RuntimeGeneration = PolicyEpoch;

/// DNSSEC policy plus the prepared validator that enforces it.
///
/// The validator is built during staging and carried by the snapshot, so a
/// query that reads the policy also reads the exact validator that belongs to
/// it. `config` is retained for callers that compare policies (mode, anchors,
/// NTAs) and for cache re-key decisions.
#[derive(Clone)]
pub struct DnssecPolicy {
    pub config: DnssecConfig,
    pub validator: Arc<DnssecValidator>,
}

impl DnssecPolicy {
    /// Builds a validator for `config` without a shared chain cache.
    #[must_use]
    pub fn from_config(config: &DnssecConfig) -> Self {
        Self {
            config: config.clone(),
            validator: Arc::new(DnssecValidator::from_config(config)),
        }
    }

    /// Uses an already-built validator (for example one sharing the chain
    /// cache across hot reloads).
    #[must_use]
    pub fn from_validator(config: &DnssecConfig, validator: Arc<DnssecValidator>) -> Self {
        Self {
            config: config.clone(),
            validator,
        }
    }

    /// DNSSEC mode currently enforced by the validator.
    #[must_use]
    pub fn mode(&self) -> sito_dnssec::DnssecMode {
        self.validator.mode
    }
}

impl std::fmt::Debug for DnssecPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DnssecPolicy")
            .field("config", &self.config)
            .field("mode", &self.mode())
            .finish_non_exhaustive()
    }
}

/// Listener and admission settings a published generation was built for.
///
/// The listeners are owned by the server binary, but the policy they were
/// derived from travels with the runtime generation so the admin API, the
/// watcher and HA can compare what the running generation expects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportPolicy {
    pub bind: Vec<std::net::IpAddr>,
    pub dns_port: u16,
    pub dot_port: u16,
    pub doh_port: u16,
    pub doq_port: u16,
    pub doh3_port: u16,
    pub max_tcp_connections: usize,
    pub rate_limit_per_ip: u32,
    pub tls: Option<sito_core::config::TlsConfig>,
}

impl From<&DnsConfig> for TransportPolicy {
    fn from(dns: &DnsConfig) -> Self {
        Self {
            bind: dns.bind.clone(),
            dns_port: dns.port,
            dot_port: dns.dot_port,
            doh_port: dns.doh_port,
            doq_port: dns.doq_port,
            doh3_port: dns.doh3_port,
            max_tcp_connections: dns.max_tcp_connections,
            rate_limit_per_ip: dns.rate_limit_per_ip,
            tls: dns.tls.clone(),
        }
    }
}

impl From<&Config> for TransportPolicy {
    fn from(config: &Config) -> Self {
        Self::from(&config.dns)
    }
}

/// Everything a successful apply publishes together.
#[derive(Clone)]
pub struct ApplyPlan {
    pub config: Config,
    pub clients: ClientsConfig,
    pub rewrites: RewritesConfig,
    /// Compiled filter snapshot. Required when `filtering.enabled`.
    pub filter: Option<Arc<FilterSnapshot>>,
    /// Per-client-group compiled snapshots published with the global one.
    pub group_filters: Arc<GroupSnapshots>,
    pub dnssec_policy: DnssecPolicy,
    pub cache_policy: CacheConfig,
    pub transport_policy: TransportPolicy,
}

impl std::fmt::Debug for ApplyPlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApplyPlan")
            .field("config", &self.config)
            .field("filter", &self.filter.as_ref().map(|f| f.rule_count))
            .field("group_filters", &self.group_filters.len())
            .field("dnssec_policy", &self.dnssec_policy)
            .field("cache_policy", &self.cache_policy)
            .field("transport_policy", &self.transport_policy)
            .finish_non_exhaustive()
    }
}

/// Error returned by [`RuntimeState::apply`].
///
/// HA publication is intentionally absent: D8 says a valid local apply is not
/// rolled back when replication fails. An oversized bundle is detected only
/// after the local apply and persist; the apply path then rolls the runtime and
/// the persisted document back to the previous configuration (D8) and reports a
/// normal `ProblemDetails`, so it never reaches this enum.
#[derive(Debug, thiserror::Error)]
pub enum ApplyError {
    #[error(transparent)]
    Validation(#[from] ConfigError),
    #[error(transparent)]
    Filter(#[from] sito_filter::FilterError),
    #[error(transparent)]
    Upstream(#[from] UpstreamError),
    #[error(transparent)]
    Tls(#[from] TlsError),
    #[error("apply hook failed: {0}")]
    Internal(String),
    #[error(
        "runtime generation conflict: expected {expected}, current {actual}; the plan was staged \
         against a generation that is no longer active"
    )]
    GenerationConflict {
        expected: RuntimeGeneration,
        actual: RuntimeGeneration,
    },
}

/// Immutable, internally consistent set of runtime components.
#[derive(Clone)]
pub struct RuntimeSnapshot {
    /// Generation that produced every component below.
    pub generation: RuntimeGeneration,
    pub config: Arc<Config>,
    pub clients: Arc<ClientRegistry>,
    pub rewrites: Arc<RewriteTable>,
    /// Global compiled filter rules. `None` means filtering is disabled for
    /// this generation.
    pub filter: Option<Arc<FilterSnapshot>>,
    /// Per-client-group compiled rules, evaluated with the same generation.
    pub group_filters: Arc<GroupSnapshots>,
    /// DNSSEC policy and the validator prepared for it.
    pub dnssec_policy: DnssecPolicy,
    /// Cache policy the generation was published with.
    pub cache_policy: CacheConfig,
    /// Listener/admission policy the generation was published with.
    pub transport_policy: TransportPolicy,
}

/// Shared holder publishing [`RuntimeSnapshot`] values atomically.
pub struct RuntimeState {
    snapshot: ArcSwap<RuntimeSnapshot>,
    /// The single generation counter. Every config apply advances it and the
    /// cache filters entries and in-flight inserts by it. Filter-only
    /// refreshes flush entries but leave the generation/epoch unchanged.
    cache: Arc<DnsCache>,
    /// Mirrors for the admin UI and HA worker; the query path reads `snapshot`.
    config: Arc<ArcSwap<Config>>,
    clients: Arc<ArcSwap<ClientRegistry>>,
    rewrites: Arc<ArcSwap<RewriteTable>>,
    write_lock: Mutex<()>,
    /// Serializes whole config applies (validation → before-publish commit →
    /// cache re-key → store). A sync `std::sync::Mutex` cannot be held across
    /// the await of a listener/hook commit, so this async mutex owns the
    /// critical section; the snapshot itself still uses `write_lock`.
    apply_mutex: Arc<tokio::sync::Mutex<()>>,
    apply_count: AtomicU64,
    /// Test-only hook invoked immediately before the single `store`, after the
    /// plan is fully staged. Lets the torn-read test hold the writer at the
    /// only point where a reader could observe a partially applied state.
    #[cfg(test)]
    before_publish: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
}

impl std::fmt::Debug for RuntimeState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RuntimeState")
            .field("generation", &self.generation())
            .finish_non_exhaustive()
    }
}

impl RuntimeState {
    /// Creates the state from the existing handles, taking an initial snapshot.
    ///
    /// The initial cache policy comes from the config; call [`Self::with_cache`]
    /// before serving queries so the runtime and the DNS cache share one
    /// generation counter.
    #[must_use]
    pub fn new(
        config: Arc<ArcSwap<Config>>,
        clients: Arc<ArcSwap<ClientRegistry>>,
        rewrites: Arc<ArcSwap<RewriteTable>>,
    ) -> Self {
        let config_snapshot = config.load_full();
        let cache = Arc::new(DnsCache::new(config_snapshot.dns.cache.clone()));
        let transport_policy = TransportPolicy::from(&*config_snapshot);
        let snapshot = RuntimeSnapshot {
            generation: cache.policy_epoch(),
            config: config_snapshot.clone(),
            clients: clients.load_full(),
            rewrites: rewrites.load_full(),
            filter: None,
            group_filters: Arc::new(GroupSnapshots::default()),
            dnssec_policy: DnssecPolicy::from_config(&config_snapshot.dns.dnssec),
            cache_policy: config_snapshot.dns.cache.clone(),
            transport_policy,
        };
        Self {
            snapshot: ArcSwap::from_pointee(snapshot),
            cache,
            config,
            clients,
            rewrites,
            write_lock: Mutex::new(()),
            apply_mutex: Arc::new(tokio::sync::Mutex::new(())),
            apply_count: AtomicU64::new(0),
            #[cfg(test)]
            before_publish: Mutex::new(None),
        }
    }

    /// Shares the process cache so the runtime generation and the cache epoch
    /// are the same counter.
    #[must_use]
    pub fn with_cache(self, cache: Arc<DnsCache>) -> Self {
        let generation = cache.policy_epoch();
        let current = self.snapshot.load_full();
        self.snapshot.store(Arc::new(RuntimeSnapshot {
            generation,
            ..(*current).clone()
        }));
        Self { cache, ..self }
    }

    /// Installs the components that are created outside the config apply path
    /// during startup (filter engine, DNSSEC validator, listener policy).
    ///
    /// This does not advance the generation: it is bootstrap, not an apply.
    pub fn bootstrap_components(
        &self,
        filter: Option<Arc<FilterSnapshot>>,
        group_filters: Arc<GroupSnapshots>,
        dnssec_policy: DnssecPolicy,
        transport_policy: TransportPolicy,
    ) {
        let _guard = self.lock();
        let current = self.snapshot.load_full();
        self.snapshot.store(Arc::new(RuntimeSnapshot {
            filter,
            group_filters,
            dnssec_policy,
            transport_policy,
            ..(*current).clone()
        }));
    }

    /// Returns a coherent snapshot to use for the whole duration of a query.
    #[must_use]
    pub fn snapshot(&self) -> Arc<RuntimeSnapshot> {
        self.snapshot.load_full()
    }

    /// The generation a query or caller is currently observing.
    #[must_use]
    pub fn generation(&self) -> RuntimeGeneration {
        self.snapshot.load().generation
    }

    /// Number of successful [`Self::apply`] calls. Used by the parity tests
    /// that prove API, HA and watcher all execute the same publish function.
    #[must_use]
    pub fn apply_count(&self) -> u64 {
        self.apply_count.load(Ordering::Acquire)
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

    /// Validates, stages and publishes `plan` atomically.
    ///
    /// Nothing visible changes until every check passed: config validation,
    /// cache-policy validation, filter presence (when filtering is enabled),
    /// and the generation check (when the caller supplied one through
    /// [`Self::apply_expecting`]). The cache generation is then advanced and a
    /// single `ArcSwap::store` publishes the new snapshot.
    pub async fn apply(&self, plan: ApplyPlan) -> Result<RuntimeGeneration, ApplyError> {
        self.apply_expecting(plan, None).await
    }

    /// Like [`Self::apply`] but rejects the plan when the config generation
    /// changed since the caller staged it.
    pub async fn apply_expecting(
        &self,
        plan: ApplyPlan,
        expected: Option<RuntimeGeneration>,
    ) -> Result<RuntimeGeneration, ApplyError> {
        self.apply_expecting_with(plan, expected, async { Ok(()) })
            .await
    }

    /// Staged apply with a commit hook.
    ///
    /// `before_publish` runs inside the apply critical section, after the
    /// generation check and before the cache re-key + snapshot store. It is the
    /// only place a component owned by a higher layer (listeners, scoped
    /// upstreams, the global upstream manager) may be swapped. Because every
    /// whole config apply takes `apply_mutex`, a generation conflict cannot be
    /// reported after `before_publish` has run: the check and the commit are one
    /// atomic step. `before_publish` must only mutate components that the new
    /// snapshot supersedes; a failure returns before any runtime publish.
    pub async fn apply_expecting_with<F>(
        &self,
        plan: ApplyPlan,
        expected: Option<RuntimeGeneration>,
        before_publish: F,
    ) -> Result<RuntimeGeneration, ApplyError>
    where
        F: std::future::Future<Output = Result<(), ApplyError>>,
    {
        // 1. Validate before taking the lock: a rejected plan must not delay
        //    readers and must not touch the cache.
        plan.config.validate_full()?;
        plan.cache_policy.validate()?;
        // The typed plan components must be exactly what the candidate config
        // serializes to; a direct caller cannot smuggle a registry/rewrite
        // table that disagrees with the published config.
        let typed_clients: ClientsConfig = match plan.config.clients.as_ref() {
            Some(value) => value.clone().try_into().map_err(|e| {
                ConfigError::validation("clients", format!("invalid [clients] configuration: {e}"))
            })?,
            None => ClientsConfig::default(),
        };
        if typed_clients != plan.clients {
            return Err(ApplyError::Validation(ConfigError::validation(
                "clients",
                "the staged client registry does not match plan.config.clients",
            )));
        }
        let typed_rewrites: RewritesConfig = match plan.config.rewrites.as_ref() {
            Some(value) => value.clone().try_into().map_err(|e| {
                ConfigError::validation(
                    "rewrites",
                    format!("invalid [rewrites] configuration: {e}"),
                )
            })?,
            None => RewritesConfig::default(),
        };
        if typed_rewrites != plan.rewrites {
            return Err(ApplyError::Validation(ConfigError::validation(
                "rewrites",
                "the staged rewrite table does not match plan.config.rewrites",
            )));
        }
        if plan.config.filtering.enabled && plan.filter.is_none() {
            return Err(ApplyError::Filter(
                sito_filter::FilterError::NoUsableRules {
                    details:
                        "a staged apply with filtering enabled requires a compiled filter snapshot"
                            .to_string(),
                },
            ));
        }

        // 2. Enter the whole-apply critical section. Every config apply — API,
        //    HA, watcher, restore — passes through here, so the generation
        //    check cannot be invalidated after it passes.
        let _apply_guard = self.apply_mutex.clone().lock_owned().await;
        let current = self.snapshot.load_full();
        if let Some(expected) = expected
            && expected != current.generation
        {
            return Err(ApplyError::GenerationConflict {
                expected,
                actual: current.generation,
            });
        }

        let registry = ClientRegistry::with_stores(
            plan.clients.clone(),
            current.clients.routeros_leases_store(),
            current.clients.unidentified_store(),
        );
        let rewrites = RewriteTable::new(plan.rewrites.clone());

        // 3. Commit the fallible higher-layer components. This is inside the
        //    same critical section as the generation check, so a conflict
        //    cannot be reported after this point.
        before_publish.await?;

        // 4. Re-key the cache after every fallible stage succeeded. Holding the
        //    apply mutex means no other apply can interleave and leave the live
        //    cache config different from the published snapshot.
        self.cache.update_config(plan.cache_policy.clone()).await;
        let generation = self.cache.advance_policy_epoch();

        // 5. One publish. Queries load either `current` or `next`.
        let next = RuntimeSnapshot {
            generation,
            config: Arc::new(plan.config.clone()),
            clients: Arc::new(registry),
            rewrites: Arc::new(rewrites),
            filter: plan.filter,
            group_filters: plan.group_filters,
            dnssec_policy: plan.dnssec_policy,
            cache_policy: plan.cache_policy,
            transport_policy: plan.transport_policy,
        };
        #[cfg(test)]
        if let Some(hook) = self
            .before_publish
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
        {
            hook();
        }
        self.snapshot.store(Arc::new(next.clone()));

        // 6. Mirror the handles used by the admin UI/HA worker. These stores
        //    are not read by the DNS query path; the coherent value is the
        //    snapshot above.
        self.config.store(next.config.clone());
        self.clients.store(next.clients.clone());
        self.rewrites.store(next.rewrites.clone());

        // Every previous entry belongs to an older generation and is already
        // unservable; reclaim it when the rule set or DNSSEC policy changed.
        if !filter_ptr_eq(current.filter.as_ref(), next.filter.as_ref())
            || current.dnssec_policy.config != next.dnssec_policy.config
        {
            self.cache.flush();
        }

        self.apply_count.fetch_add(1, Ordering::AcqRel);
        Ok(generation)
    }

    /// Publishes a refreshed filter snapshot without changing the config.
    ///
    /// Filter-only publication does **not** advance [`Self::generation`] or the
    /// cache's DNSSEC epoch: the DNSSEC policy did not change, and a refresh
    /// must not invalidate a config generation that a staged apply is checking.
    /// The caller must pass the config generation the refresh was compiled for;
    /// a config apply that landed first makes the publish fail with
    /// [`ApplyError::GenerationConflict`] instead of overwriting the newer
    /// generation's filter with older rules.
    ///
    /// The engine's reload guard must be held across this call and the
    /// subsequent engine publish, so a config apply cannot stage a new filter in
    /// between.
    pub fn publish_filter(
        &self,
        filter: Option<Arc<FilterSnapshot>>,
        group_filters: Arc<GroupSnapshots>,
        expected: RuntimeGeneration,
    ) -> Result<RuntimeGeneration, ApplyError> {
        // A whole apply owns the critical section; a refresh must not publish a
        // filter while it is committing. The caller holds the filter engine
        // guard, so this is normally free rather than contended.
        let Ok(_apply_guard) = self.apply_mutex.try_lock() else {
            let actual = self.generation();
            return Err(ApplyError::GenerationConflict { expected, actual });
        };
        let _guard = self.lock();
        let current = self.snapshot.load_full();
        if current.generation != expected {
            return Err(ApplyError::GenerationConflict {
                expected,
                actual: current.generation,
            });
        }
        let next = RuntimeSnapshot {
            filter,
            group_filters,
            ..(*current).clone()
        };
        self.snapshot.store(Arc::new(next));
        // Cache entries are not tagged with the filter rules, so reclaim them
        // explicitly; the DNSSEC epoch stays unchanged.
        self.cache.flush();
        Ok(current.generation)
    }

    /// Publishes a new configuration while preserving the other components.
    ///
    /// Compatibility helper for startup/test code. Admin writes, the watcher
    /// and HA must use [`Self::apply`].
    pub fn set_config(&self, config: Config) {
        let _guard = self.lock();
        let current = self.snapshot.load_full();
        let config = Arc::new(config);
        self.config.store(config.clone());
        self.snapshot.store(Arc::new(RuntimeSnapshot {
            config,
            ..(*current).clone()
        }));
    }

    /// Publishes a new client registry while preserving the other components.
    pub fn set_clients(&self, clients: ClientRegistry) {
        let _guard = self.lock();
        let current = self.snapshot.load_full();
        let clients = Arc::new(clients);
        self.clients.store(clients.clone());
        self.snapshot.store(Arc::new(RuntimeSnapshot {
            clients,
            ..(*current).clone()
        }));
    }

    /// Publishes a new rewrite table while preserving the other components.
    pub fn set_rewrites(&self, rewrites: RewriteTable) {
        let _guard = self.lock();
        let current = self.snapshot.load_full();
        let rewrites = Arc::new(rewrites);
        self.rewrites.store(rewrites.clone());
        self.snapshot.store(Arc::new(RuntimeSnapshot {
            rewrites,
            ..(*current).clone()
        }));
    }

    /// Replaces every component at once.
    ///
    /// Compatibility helper for test harnesses; production entry points use
    /// [`Self::apply`].
    pub fn replace(&self, snapshot: RuntimeSnapshot) {
        let _guard = self.lock();
        self.config.store(snapshot.config.clone());
        self.clients.store(snapshot.clients.clone());
        self.rewrites.store(snapshot.rewrites.clone());
        self.snapshot.store(Arc::new(snapshot));
    }

    #[cfg(test)]
    fn set_before_publish_hook(&self, hook: Option<Arc<dyn Fn() + Send + Sync>>) {
        *self
            .before_publish
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = hook;
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, ()> {
        self.write_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

fn filter_ptr_eq(a: Option<&Arc<FilterSnapshot>>, b: Option<&Arc<FilterSnapshot>>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(a), Some(b)) => Arc::ptr_eq(a, b),
        _ => false,
    }
}

/// Maps client-group policy onto the filter engine's per-group rule sets.
///
/// Shared by the server startup path and the staged apply so both compile the
/// same groups.
#[must_use]
pub fn group_rule_sets(clients: &ClientsConfig) -> Vec<GroupRuleSet> {
    let mut groups: Vec<GroupRuleSet> = clients
        .groups
        .iter()
        .filter(|(_, group)| !group.lists.is_empty() || !group.custom_rules.is_empty())
        .map(|(name, group)| GroupRuleSet {
            name: name.clone(),
            lists: group.lists.clone(),
            custom_rules: group.custom_rules.clone(),
        })
        .collect();
    groups.sort_by(|a, b| a.name.cmp(&b.name));
    groups
}

#[cfg(test)]
mod tests;
