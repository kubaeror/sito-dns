//! Staged preparation and atomic publish of filter snapshots.

#[allow(clippy::wildcard_imports)]
use super::*;

impl HostsFilterEngine {
    /// Initializes and loads lists immediately (from download or disk cache).
    ///
    /// Failures are logged and reflected in [`HostsFilterEngine::status`];
    /// the engine keeps a `Failed` state instead of silently advertising an
    /// enabled-but-empty filter snapshot.
    pub async fn init(config: FilteringConfig, data_dir: PathBuf) -> Self {
        Self::init_with_observer(config, data_dir, None).await
    }

    /// Initializes and loads lists immediately, reporting the initial compile
    /// duration to `observer` when one is supplied.
    pub async fn init_with_observer(
        config: FilteringConfig,
        data_dir: PathBuf,
        observer: Option<CompileObserver>,
    ) -> Self {
        Self::init_with_observer_and_group_sources(config, data_dir, observer, Vec::new()).await
    }

    /// Initializes and loads lists with the client group rule sets that will
    /// apply before the first reload runs.
    ///
    /// The server loads `[clients]` after the filter engine, so passing the
    /// group definitions here lets the initial reload tell a usable group-only
    /// deployment (global `filtering.lists` empty but at least one group
    /// `custom_rules` entry compiles) from a broken one. The hint is only used
    /// when there is no configured global source; it must never mask a failed
    /// or empty global source.
    pub async fn init_with_observer_and_group_sources(
        config: FilteringConfig,
        data_dir: PathBuf,
        observer: Option<CompileObserver>,
        group_rules: Vec<GroupRuleSet>,
    ) -> Self {
        let engine = Self::new(config, data_dir);
        engine.group_sources_configured.store(
            Self::has_group_custom_rules(&group_rules),
            Ordering::Release,
        );
        engine.group_defs.store(Arc::new(group_rules));
        if let Some(observer) = observer {
            engine.set_compile_observer(observer);
        }
        match engine.reload().await {
            Ok(count) => info!(rule_count = count, "Filter engine initialized"),
            Err(e) => error!(
                error = %e,
                "Initial filter list load failed; no filter rules are active until a later reload succeeds"
            ),
        }
        engine
    }

    /// Returns a full reference to the current active `FilterSnapshot`.
    pub fn snapshot(&self) -> Arc<FilterSnapshot> {
        self.snapshot.load_full()
    }

    /// Per-client-group compiled snapshots for the active generation.
    #[must_use]
    pub fn group_snapshots(&self) -> Arc<FnvHashMap<String, Arc<FilterSnapshot>>> {
        self.group_snapshots.load_full()
    }

    /// Stages a load of `config` without changing the live filter snapshot.
    ///
    /// The candidate is fetched and compiled on a private staging engine that
    /// starts from the live rules, exactly like [`Self::reload_with_config`],
    /// so parse/download/compile failures leave the live state untouched. The
    /// engine's reload lock is held until the returned value is published or
    /// dropped, which makes staging+publish atomic with respect to scheduled
    /// refreshes. Inspect [`PreparedFilterSnapshot::error`] before publishing a
    /// config apply.
    pub async fn prepare(&self, config: &FilteringConfig) -> PreparedFilterSnapshot {
        self.prepare_with_groups(config, None).await
    }

    /// Like [`Self::prepare`] but compiles `groups` as the candidate client
    /// group policy instead of the live group definitions.
    pub async fn prepare_with_groups(
        &self,
        config: &FilteringConfig,
        groups: Option<Vec<GroupRuleSet>>,
    ) -> PreparedFilterSnapshot {
        let guard = self.reload_lock.clone().lock_owned().await;
        let staged = self.staging_engine(groups);
        let result = staged.reload_internal(config, false, None).await;
        if result.is_ok() {
            staged.config.store(Arc::new(config.clone()));
        }

        PreparedFilterSnapshot {
            snapshot: staged.snapshot(),
            group_snapshots: staged.group_snapshots(),
            status: staged.status(),
            config: (*staged.config.load_full()).clone(),
            group_defs: (*staged.group_defs.load_full()).clone(),
            error: result.err(),
            guard,
        }
    }

    /// Stages the current live filter state without compiling anything.
    ///
    /// Used by deferred applies (wizard first boot) where the list fetch is
    /// queued after the request returns; the snapshot still carries a coherent
    /// filter value for the new configuration.
    pub async fn prepare_current(&self) -> PreparedFilterSnapshot {
        self.prepare_current_with_groups(None).await
    }

    /// Like [`Self::prepare_current`] but adopts candidate client-group
    /// definitions for the deferred refresh that follows.
    pub async fn prepare_current_with_groups(
        &self,
        groups: Option<Vec<GroupRuleSet>>,
    ) -> PreparedFilterSnapshot {
        let guard = self.reload_lock.clone().lock_owned().await;
        let mut status = self.status();
        let (group_snapshots, group_defs) = match groups {
            Some(groups) => {
                // Rebuild group snapshots from the already-loaded rules. This
                // is cheap (no downloads) and is required by the Deferred path:
                // a clients/groups save must enforce the new group rules now,
                // not at the next scheduled refresh.
                let staged = self.staging_engine(Some(groups));
                let list_rules = sito_core::sync::lock_or_recover(&staged.list_rules).clone();
                if let Some(degraded) = staged.rebuild_group_snapshots(&list_rules) {
                    status.degraded_groups = degraded;
                }
                (
                    staged.group_snapshots(),
                    (*staged.group_defs.load_full()).clone(),
                )
            }
            None => (
                self.group_snapshots(),
                (*self.group_defs.load_full()).clone(),
            ),
        };
        PreparedFilterSnapshot {
            snapshot: self.snapshot(),
            group_snapshots,
            status,
            config: (*self.config.load_full()).clone(),
            group_defs,
            error: None,
            guard,
        }
    }

    /// Installs a prepared snapshot and returns the compiled rule count.
    ///
    /// A staged failure is published (status/snapshot) and returned as an
    /// error; the live configuration is retained by the staging engine on
    /// failure, so the previous rules stay active.
    pub fn publish_prepared(&self, prepared: PreparedFilterSnapshot) -> Result<usize, FilterError> {
        let PreparedFilterSnapshot {
            snapshot,
            group_snapshots,
            status,
            config,
            group_defs,
            error,
            guard,
        } = prepared;

        self.config.store(Arc::new(config));
        self.group_defs.store(Arc::new(group_defs));
        self.snapshot.store(snapshot);
        self.group_snapshots.store(group_snapshots);
        self.list_generation.fetch_add(1, Ordering::SeqCst);
        let rule_count = status.rule_count;
        self.set_status(status);
        drop(guard);

        match error {
            Some(error) => Err(error),
            None => Ok(rule_count),
        }
    }

    /// Builds a private engine seeded from the live state for staging.
    pub(super) fn staging_engine(&self, groups: Option<Vec<GroupRuleSet>>) -> Self {
        let group_defs = groups.unwrap_or_else(|| (*self.group_defs.load_full()).clone());
        let has_group_sources = Self::has_group_custom_rules(&group_defs);
        Self {
            snapshot: ArcSwap::new(self.snapshot()),
            config: ArcSwap::new(self.config.load_full()),
            data_dir: self.data_dir.clone(),
            list_rules: std::sync::Mutex::new(
                sito_core::sync::lock_or_recover(&self.list_rules).clone(),
            ),
            reload_lock: Arc::new(tokio::sync::Mutex::new(())),
            status: ArcSwap::new(Arc::new(self.status())),
            group_defs: ArcSwap::new(Arc::new(group_defs)),
            group_snapshots: ArcSwap::new(self.group_snapshots()),
            compile_observer: std::sync::RwLock::new(
                sito_core::sync::read_or_recover(&self.compile_observer).clone(),
            ),
            // Staging must not publish metrics/status before the snapshot is
            // committed; the live engine's observer fires in `publish_prepared`.
            status_observer: std::sync::RwLock::new(None),
            snapshot_observer: std::sync::RwLock::new(None),
            list_generation: AtomicU64::new(self.list_generation.load(Ordering::SeqCst)),
            group_sources_configured: AtomicBool::new(has_group_sources),
        }
    }
}
