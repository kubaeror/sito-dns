//! Runtime-refreshable curated lists.
//!
//! The curated parental/service data bundled into the binary is the minimal
//! fallback. Operators can point `[integrations.lists]` at maintained sources;
//! a background task downloads them with the shared subscription downloader
//! (ETag/disk cache/size caps) and swaps the registries without a restart.

use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use tracing::info;

use crate::bundled::BundledListError;
use crate::parental::ParentalRegistry;
use crate::services::ServiceRegistry;

fn default_refresh_hours() -> u64 {
    24
}

/// One curated-category source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListSourceConfig {
    /// Source URL (`https://`, `http://` or `file://`).
    pub url: String,
    /// Per-category refresh interval overriding the section default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_hours: Option<u64>,
    /// SPDX license of the upstream data, for operator reference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub license: Option<String>,
}

/// `[integrations.lists]` configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListCategoriesConfig {
    /// Default refresh interval in hours for categories without an override.
    #[serde(default = "default_refresh_hours")]
    pub refresh_hours: u64,
    /// Category id (e.g. `adult`, `services`) to source definition.
    #[serde(default)]
    pub categories: HashMap<String, ListSourceConfig>,
}

impl Default for ListCategoriesConfig {
    fn default() -> Self {
        Self {
            refresh_hours: default_refresh_hours(),
            categories: HashMap::new(),
        }
    }
}

impl ListCategoriesConfig {
    /// Validates every configured source URL scheme.
    pub fn validate(&self) -> Result<(), String> {
        for (category, source) in &self.categories {
            let allowed = ["https://", "http://", "file://"]
                .iter()
                .any(|scheme| source.url.starts_with(scheme));
            if !allowed {
                return Err(format!(
                    "integrations.lists.categories.{category}.url must use http://, https:// or file://"
                ));
            }
            if source.refresh_hours == Some(0) {
                return Err(format!(
                    "integrations.lists.categories.{category}.refresh_hours must be greater than 0"
                ));
            }
        }
        Ok(())
    }
}

/// Refresh state of one curated category.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeListStatus {
    pub category: String,
    /// Last successfully applied source URL, if the category was refreshed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_url: Option<String>,
    /// Unix timestamp of the last successful refresh.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_refresh_unix: Option<u64>,
    /// Number of entries in the currently active content.
    pub entries: u64,
    /// Whether the active content is the bundled fallback.
    pub bundled: bool,
}

/// Hot-swappable parental and service registries used by the query pipeline.
#[derive(Debug)]
pub struct RuntimeLists {
    parental: ArcSwap<ParentalRegistry>,
    services: ArcSwap<ServiceRegistry>,
    statuses: RwLock<HashMap<String, RuntimeListStatus>>,
    /// Serializes read-modify-write refreshes so two concurrent category
    /// updates cannot publish registries that each miss the other's change.
    apply_lock: std::sync::Mutex<()>,
}

impl RuntimeLists {
    /// Builds the registries from bundled data, returning an error instead of
    /// panicking when embedded content is corrupt.
    pub fn try_new() -> Result<Self, BundledListError> {
        Ok(Self::from_arcs(
            Arc::new(ParentalRegistry::try_bundled()?),
            Arc::new(ServiceRegistry::try_bundled()?),
        ))
    }

    /// Wraps existing registries.
    #[must_use]
    pub fn from_arcs(parental: Arc<ParentalRegistry>, services: Arc<ServiceRegistry>) -> Self {
        let mut statuses = HashMap::new();
        for list in parental.lists() {
            statuses.insert(
                list.id.clone(),
                RuntimeListStatus {
                    category: list.id.clone(),
                    source_url: None,
                    last_refresh_unix: None,
                    entries: list.entries,
                    bundled: true,
                },
            );
        }
        for list in services.lists() {
            statuses.insert(
                list.id.clone(),
                RuntimeListStatus {
                    category: list.id.clone(),
                    source_url: None,
                    last_refresh_unix: None,
                    entries: list.entries,
                    bundled: true,
                },
            );
        }

        let mut bundled: Vec<&str> = statuses
            .values()
            .filter(|status| status.bundled)
            .map(|status| status.category.as_str())
            .collect();
        if !bundled.is_empty() {
            bundled.sort_unstable();
            info!(
                categories = ?bundled,
                "Curated parental/service categories are serving the bundled fallback; \
                 configure [integrations.lists] to refresh them from maintained sources"
            );
        }

        Self {
            parental: ArcSwap::from(parental),
            services: ArcSwap::from(services),
            statuses: RwLock::new(statuses),
            apply_lock: std::sync::Mutex::new(()),
        }
    }
    /// Refresh state of every known category, sorted by id.
    #[must_use]
    pub fn statuses(&self) -> Vec<RuntimeListStatus> {
        let mut statuses: Vec<RuntimeListStatus> = self
            .statuses
            .read()
            .map(|guard| guard.values().cloned().collect())
            .unwrap_or_default();
        statuses.sort_by(|a, b| a.category.cmp(&b.category));
        statuses
    }

    /// Categories still served by the bundled fallback (no successful
    /// external refresh yet), sorted by id.
    ///
    /// This mirrors the filter engine's observable list status: operators and
    /// `/metrics`/status consumers can see that a category is running on the
    /// minimal bundled data instead of a maintained upstream list.
    #[must_use]
    pub fn bundled_fallback_categories(&self) -> Vec<String> {
        self.statuses()
            .into_iter()
            .filter(|status| status.bundled)
            .map(|status| status.category)
            .collect()
    }

    /// Marks a category as refreshed from `source_url` at the current time.
    pub fn mark_refreshed(&self, category: &str, source_url: &str) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        if let Ok(mut statuses) = self.statuses.write() {
            let entry = statuses
                .entry(category.to_string())
                .or_insert_with(|| RuntimeListStatus {
                    category: category.to_string(),
                    source_url: None,
                    last_refresh_unix: None,
                    entries: 0,
                    bundled: false,
                });
            entry.source_url = Some(source_url.to_string());
            entry.last_refresh_unix = Some(now);
            entry.bundled = false;
        }
    }

    /// Current parental registry.
    #[must_use]
    pub fn parental(&self) -> Arc<ParentalRegistry> {
        self.parental.load_full()
    }

    /// Current service registry.
    #[must_use]
    pub fn services(&self) -> Arc<ServiceRegistry> {
        self.services.load_full()
    }

    /// Replaces the registry for one downloaded category.
    ///
    /// The category `services` expects service JSON; every other category is
    /// parsed as a domain list (ABP `||domain^` and hosts syntax accepted) and
    /// replaces the previous content of that parental category.
    ///
    /// Applies a >50% truncation guard: after a category has been refreshed
    /// from an external source, content with fewer than half of the previous
    /// entries is rejected to protect against partial/corrupted downloads.
    /// Use [`RuntimeLists::apply_content_forced`] to accept an intentional
    /// shrink.
    pub fn apply_content(&self, category: &str, content: &str) -> Result<u64, String> {
        self.apply_content_inner(category, content, false)
    }

    /// Like [`RuntimeLists::apply_content`] but bypasses the >50% drop guard.
    pub fn apply_content_forced(&self, category: &str, content: &str) -> Result<u64, String> {
        self.apply_content_inner(category, content, true)
    }

    fn apply_content_inner(
        &self,
        category: &str,
        content: &str,
        force: bool,
    ) -> Result<u64, String> {
        // Serialize the clone-modify-store sequence: concurrent refreshes of
        // different categories would otherwise publish registries missing each
        // other's update (lost update).
        let _apply_guard = self
            .apply_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let (entries, new_parental, new_services) = if category.eq_ignore_ascii_case("services") {
            let registry = ServiceRegistry::from_json(content).map_err(|e| e.to_string())?;
            let entries = registry.service_count() as u64;
            (entries, None, Some(Arc::new(registry)))
        } else {
            let entries = content
                .lines()
                .filter(|line| {
                    let trimmed = line.trim();
                    !trimmed.is_empty() && !trimmed.starts_with('#') && !trimmed.starts_with('!')
                })
                .count() as u64;
            let mut parental = (*self.parental.load_full()).clone();
            parental.set_category_list(category, content);
            (entries, Some(Arc::new(parental)), None)
        };

        // Guard refreshes that replace previously downloaded content; the
        // bundled fallback may legitimately be replaced by a smaller list.
        // An empty response is always rejected while any content is active so
        // a broken first fetch cannot silently disable protection.
        let category_key = category.to_ascii_lowercase();
        let previous_status = self.statuses.read().ok().and_then(|statuses| {
            statuses
                .get(category)
                .or_else(|| statuses.get(&category_key))
                .cloned()
        });
        let previous = previous_status.as_ref().map_or(0, |status| status.entries);
        let was_bundled = previous_status.as_ref().is_none_or(|status| status.bundled);
        let truncating = entries == 0 || entries.saturating_mul(2) < previous;
        if !force && previous > 0 && truncating && (!was_bundled || entries == 0) {
            let detail = if entries == 0 {
                "empty content".to_string()
            } else {
                format!("{entries} entries after {previous} (>50% shrink)")
            };
            return Err(format!(
                "refusing to replace category '{category}' with {detail}; \
                 use a forced refresh to accept the truncation"
            ));
        }

        if let Some(services) = new_services {
            self.services.store(services);
        }
        if let Some(parental) = new_parental {
            self.parental.store(parental);
        }

        if let Ok(mut statuses) = self.statuses.write() {
            let entry = statuses
                .entry(category.to_string())
                .or_insert_with(|| RuntimeListStatus {
                    category: category.to_string(),
                    source_url: None,
                    last_refresh_unix: None,
                    entries: 0,
                    bundled: false,
                });
            entry.entries = entries;
            entry.bundled = false;
        }
        Ok(entries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> RuntimeLists {
        RuntimeLists::from_arcs(
            Arc::new(ParentalRegistry::bundled()),
            Arc::new(ServiceRegistry::bundled()),
        )
    }

    #[test]
    fn test_concurrent_category_updates_do_not_lose_entries() {
        let store = std::sync::Arc::new(store());
        let first = std::sync::Arc::clone(&store);
        let second = std::sync::Arc::clone(&store);

        let t1 = std::thread::spawn(move || first.apply_content("alpha", "alpha-blocked.com\n"));
        let t2 = std::thread::spawn(move || second.apply_content("beta", "beta-blocked.com\n"));
        t1.join().unwrap().unwrap();
        t2.join().unwrap().unwrap();

        let parental = store.parental.load_full();
        assert!(
            parental.matches_category("alpha", "alpha-blocked.com"),
            "concurrent update to `beta` must not drop `alpha`"
        );
        assert!(
            parental.matches_category("beta", "beta-blocked.com"),
            "concurrent update to `alpha` must not drop `beta`"
        );
    }

    #[test]
    fn test_apply_domain_category_replaces_content() {
        let store = store();
        assert!(store.parental().matches_category("adult", "pornhub.com"));

        store
            .apply_content("adult", "refreshed.example\nsub.refreshed.example\n")
            .unwrap();

        let parental = store.parental();
        assert!(parental.matches_category("adult", "refreshed.example"));
        assert!(parental.matches_category("adult", "sub.refreshed.example"));
        assert!(
            !parental.matches_category("adult", "pornhub.com"),
            "refreshed content must replace the bundled list"
        );
        // Other categories stay untouched.
        assert!(parental.matches_category("gambling", "bet365.com"));
    }

    #[test]
    fn test_apply_services_json_replaces_registry() {
        let store = store();
        assert!(store.services().is_service_domain("tiktok", "tiktok.com"));

        store
            .apply_content(
                "services",
                r#"[{"id": "custom", "rules": ["||custom.example^"]}]"#,
            )
            .unwrap();

        let services = store.services();
        assert!(services.is_service_domain("custom", "custom.example"));
        assert!(!services.is_service_domain("tiktok", "tiktok.com"));
    }

    #[test]
    fn test_refresh_status_tracking() {
        let store = store();
        let bundled = store.statuses();
        assert!(bundled.iter().any(|s| s.category == "adult" && s.bundled));
        assert!(
            store
                .bundled_fallback_categories()
                .iter()
                .any(|c| c == "adult"),
            "bundled fallback status must be observable"
        );

        let entries = store
            .apply_content("adult", "a.example\nb.example\n# comment\n")
            .unwrap();
        assert_eq!(entries, 2);
        store.mark_refreshed("adult", "https://lists.example.com/adult.txt");

        let status = store
            .statuses()
            .into_iter()
            .find(|s| s.category == "adult")
            .unwrap();
        assert!(!status.bundled);
        assert_eq!(status.entries, 2);
        assert_eq!(
            status.source_url.as_deref(),
            Some("https://lists.example.com/adult.txt")
        );
        assert!(status.last_refresh_unix.is_some());
        assert!(
            !store
                .bundled_fallback_categories()
                .iter()
                .any(|c| c == "adult"),
            "refreshed categories must no longer report as bundled fallback"
        );
    }

    #[test]
    fn test_invalid_services_json_keeps_previous_registry() {
        let store = store();
        assert!(store.apply_content("services", "not json").is_err());
        assert!(store.services().is_service_domain("tiktok", "tiktok.com"));
    }

    #[test]
    fn test_config_validation_rejects_unknown_scheme() {
        let mut config = ListCategoriesConfig::default();
        config.categories.insert(
            "adult".to_string(),
            ListSourceConfig {
                url: "ftp://example.com/adult.txt".to_string(),
                refresh_hours: None,
                license: None,
            },
        );
        assert!(config.validate().is_err());

        config.categories.get_mut("adult").unwrap().url =
            "https://example.com/adult.txt".to_string();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_drop_guard_rejects_large_shrink_after_refresh() {
        let store = store();
        // First refresh replaces the bundled fallback without a guard.
        store
            .apply_content("adult", "a.example\nb.example\nc.example\nd.example\n")
            .unwrap();

        // A second refresh shrinking to below half is rejected.
        let err = store.apply_content("adult", "only.example\n").unwrap_err();
        assert!(err.contains(">50% shrink"), "unexpected error: {err}");
        assert!(
            store.parental().matches_category("adult", "a.example"),
            "previous content must be retained after a rejected shrink"
        );
        assert!(!store.parental().matches_category("adult", "only.example"));

        // An intentional operator shrink can be forced.
        store
            .apply_content_forced("adult", "only.example\n")
            .unwrap();
        assert!(store.parental().matches_category("adult", "only.example"));
        assert!(!store.parental().matches_category("adult", "a.example"));
    }

    #[test]
    fn test_hosts_format_lines_are_parsed_as_domains() {
        let store = store();
        store
            .apply_content(
                "adult",
                "0.0.0.0 hosts-blocked.example\n127.0.0.1 first.example second.example\n\
                 # comment\n! abp comment\n||abp-blocked.example^\n",
            )
            .unwrap();

        let parental = store.parental();
        assert!(parental.matches_category("adult", "hosts-blocked.example"));
        assert!(parental.matches_category("adult", "first.example"));
        assert!(parental.matches_category("adult", "second.example"));
        assert!(parental.matches_category("adult", "abp-blocked.example"));
        assert!(
            !parental.matches_category("adult", "0.0.0.0"),
            "IP addresses must never be stored as blocking domains"
        );
    }

    #[test]
    fn test_empty_refresh_cannot_wipe_bundled_fallback() {
        let store = store();
        let err = store.apply_content("adult", "\n# nothing\n").unwrap_err();
        assert!(err.contains("empty content"), "unexpected error: {err}");
        assert!(
            store.parental().matches_category("adult", "pornhub.com"),
            "bundled fallback must survive an empty first refresh"
        );
    }

    #[test]
    fn test_try_new_is_non_panicking() {
        let store = RuntimeLists::try_new().expect("bundled data must load");
        assert!(store.parental().matches_category("adult", "pornhub.com"));
    }
}
