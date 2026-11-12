//! Observable engine status and availability queries.

#[allow(clippy::wildcard_imports)]
use super::*;

impl HostsFilterEngine {
    /// Current number of active loaded blocking rules.
    pub fn rule_count(&self) -> usize {
        self.snapshot.load().rule_count
    }

    /// Number of regex/wildcard patterns that could not be compiled into the
    /// current snapshot. A non-zero value means part of the regex class is
    /// inactive and should be surfaced to operators.
    #[must_use]
    pub fn dropped_regex_patterns(&self) -> usize {
        self.snapshot.load().dropped_regex_patterns
    }

    /// True when filtering is enabled with `fail_closed` and no rule snapshot
    /// has ever been compiled (initial load running or failed). Callers
    /// should refuse to resolve rather than silently allow everything.
    pub fn unavailable_for_fail_closed(&self) -> bool {
        let config = self.config.load();
        config.enabled && config.fail_closed && self.snapshot.load().unavailable
    }

    /// Current observable status of the filter engine.
    pub fn status(&self) -> FilterStatus {
        (*self.status.load_full()).clone()
    }

    /// Current lifecycle state of the filter engine.
    pub fn state(&self) -> FilterState {
        self.status.load().state
    }

    pub(super) fn set_status(&self, status: FilterStatus) {
        let observer = sito_core::sync::read_or_recover(&self.status_observer).clone();
        if let Some(observer) = observer {
            observer(&status);
        }
        self.status.store(Arc::new(status));
    }
}
