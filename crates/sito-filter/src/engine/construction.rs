//! HostsFilterEngine construction and observer wiring.

#[allow(clippy::wildcard_imports)]
use super::*;

impl HostsFilterEngine {
    /// Creates a new `HostsFilterEngine` with an empty snapshot.
    pub fn new(config: FilteringConfig, data_dir: PathBuf) -> Self {
        let status = FilterStatus {
            state: if config.enabled {
                FilterState::Loading
            } else {
                FilterState::Disabled
            },
            ..FilterStatus::default()
        };
        Self {
            snapshot: ArcSwap::new(Arc::new(FilterSnapshot::unavailable())),
            config: ArcSwap::new(Arc::new(config)),
            data_dir,
            list_rules: std::sync::Mutex::new(FnvHashMap::default()),
            reload_lock: Arc::new(tokio::sync::Mutex::new(())),
            status: ArcSwap::new(Arc::new(status)),
            group_defs: ArcSwap::new(Arc::new(Vec::new())),
            group_snapshots: ArcSwap::new(Arc::new(FnvHashMap::default())),
            compile_observer: std::sync::RwLock::new(None),
            status_observer: std::sync::RwLock::new(None),
            snapshot_observer: std::sync::RwLock::new(None),
            list_generation: AtomicU64::new(0),
            group_sources_configured: AtomicBool::new(false),
        }
    }

    /// Installs the compile-duration observer (usually the metrics registry).
    ///
    /// Every parse+compile attempt performed by this engine reports its
    /// wall-clock duration, including the initial load and scheduled refreshes.
    pub fn set_compile_observer(&self, observer: CompileObserver) {
        *self
            .compile_observer
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(observer);
    }

    /// Installs the observer that receives rules published by a scheduled or
    /// partial list refresh. Config applies publish through the runtime plan
    /// and do not call it.
    pub fn set_snapshot_observer(&self, observer: SnapshotObserver) {
        *self
            .snapshot_observer
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(observer);
    }

    pub(super) fn observe_snapshot(&self) {
        let observer = self
            .snapshot_observer
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        if let Some(observer) = observer {
            observer(self.snapshot(), self.group_snapshots());
        }
    }

    /// Installs the status observer (usually the metrics registry adapter).
    ///
    /// The observer runs synchronously whenever a new [`FilterStatus`] is
    /// published, so API- and scheduler-driven reloads both update metrics.
    pub fn set_status_observer(&self, observer: StatusObserver) {
        *self
            .status_observer
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(observer);
    }

    pub(super) fn observe_compile(&self, elapsed: Duration) {
        let observer = self
            .compile_observer
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        if let Some(observer) = observer {
            observer(elapsed.as_secs_f64());
        }
    }
}
