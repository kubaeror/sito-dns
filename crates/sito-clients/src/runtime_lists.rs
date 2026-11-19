//! Runtime-refreshable curated lists.
//!
//! The curated parental/service data bundled into the binary is the minimal
//! fallback. Operators can point `[integrations.lists]` at maintained sources;
//! a background task downloads them with the shared subscription downloader
//! (ETag/disk cache/size caps) and swaps the registries without a restart.

use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use tracing::info;

use crate::bundled::BundledListError;
use crate::parental::ParentalRegistry;
use crate::services::ServiceRegistry;

fn default_refresh_hours() -> u64 {
    24
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
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
    /// Validates category keys, every configured source URL scheme and refresh
    /// interval.
    ///
    /// This is the cheap half of validation: it never builds the bundled
    /// registries. Use [`Self::validate_known_categories`] on startup and on
    /// configuration writes to also reject categories the registry cannot
    /// serve.
    pub fn validate(&self) -> Result<(), String> {
        if self.refresh_hours == 0 {
            return Err("integrations.lists.refresh_hours must be greater than 0".to_string());
        }
        if self.refresh_hours > sito_core::config::MAX_REFRESH_HOURS {
            return Err(format!(
                "integrations.lists.refresh_hours must be at most {} hours (one year)",
                sito_core::config::MAX_REFRESH_HOURS
            ));
        }
        let mut seen = HashSet::with_capacity(self.categories.len());
        for (category, source) in &self.categories {
            if category.trim().is_empty() {
                return Err(
                    "integrations.lists.categories keys must not be empty or whitespace"
                        .to_string(),
                );
            }
            if category.trim() != category {
                return Err(format!(
                    "integrations.lists.categories.{category} must not contain leading or trailing whitespace"
                ));
            }
            if !seen.insert(category.to_ascii_lowercase()) {
                return Err(format!(
                    "integrations.lists.categories contains duplicate category '{category}' (category ids are case-insensitive)"
                ));
            }
            let allowed = ["https://", "http://", "file://"]
                .iter()
                .any(|scheme| source.url.starts_with(scheme));
            if !allowed {
                return Err(format!(
                    "integrations.lists.categories.{category}.url must use http://, https:// or file://"
                ));
            }
            if let Some(hours) = source.refresh_hours {
                if hours == 0 {
                    return Err(format!(
                        "integrations.lists.categories.{category}.refresh_hours must be greater than 0"
                    ));
                }
                if hours > sito_core::config::MAX_REFRESH_HOURS {
                    return Err(format!(
                        "integrations.lists.categories.{category}.refresh_hours must be at most {} hours (one year)",
                        sito_core::config::MAX_REFRESH_HOURS
                    ));
                }
            }
        }
        Ok(())
    }

    /// Validates the generic rules plus every category against the registries
    /// bundled into the binary.
    ///
    /// Only categories present in [`RuntimeLists::try_new`] can be refreshed
    /// at runtime; an unknown id would otherwise be downloaded, parsed and
    /// published into a status row the pipeline never reads.
    pub fn validate_known_categories(&self) -> Result<(), String> {
        self.validate()?;
        if self.categories.is_empty() {
            return Ok(());
        }
        let lists = RuntimeLists::try_new()
            .map_err(|e| format!("failed to load bundled curated-list registries: {e}"))?;
        let known: Vec<String> = lists
            .statuses()
            .into_iter()
            .map(|status| status.category)
            .collect();
        let known_set: HashSet<&str> = known.iter().map(String::as_str).collect();
        for category in self.categories.keys() {
            let key = category.to_ascii_lowercase();
            if !known_set.contains(key.as_str()) {
                return Err(format!(
                    "integrations.lists.categories.{category} is not a known curated category (expected one of: {})",
                    known.join(", ")
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
    /// Unix timestamp of the last fetch/apply attempt, successful or not.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_attempt_unix: Option<u64>,
    /// Error from the most recent failed fetch/apply attempt. Cleared by a
    /// successful refresh.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
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
            let category = list.id.to_ascii_lowercase();
            statuses.insert(
                category.clone(),
                RuntimeListStatus {
                    category,
                    source_url: None,
                    last_refresh_unix: None,
                    last_attempt_unix: None,
                    last_error: None,
                    entries: list.entries,
                    bundled: true,
                },
            );
        }
        for list in services.lists() {
            let category = list.id.to_ascii_lowercase();
            statuses.insert(
                category.clone(),
                RuntimeListStatus {
                    category,
                    source_url: None,
                    last_refresh_unix: None,
                    last_attempt_unix: None,
                    last_error: None,
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
            .map(|guard| {
                guard
                    .values()
                    .map(|status| {
                        let mut status = status.clone();
                        status.category = status.category.to_ascii_lowercase();
                        status
                    })
                    .collect()
            })
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

    /// Records a fetch/apply attempt for `category`.
    ///
    /// A start-of-attempt call passes `None` and only updates
    /// `last_attempt_unix`; a previous `last_error` stays visible until the
    /// outcome is known. A failure passes `Some(error)`, which records it. Only
    /// [`Self::mark_refreshed`] clears the error.
    pub fn record_attempt(&self, category: &str, error: Option<String>) {
        let now = unix_now();
        let category = category.to_ascii_lowercase();
        let mut statuses = sito_core::sync::write_or_recover(&self.statuses);
        let entry = statuses
            .entry(category.clone())
            .or_insert_with(|| RuntimeListStatus {
                category: category.clone(),
                source_url: None,
                last_refresh_unix: None,
                last_attempt_unix: None,
                last_error: None,
                entries: 0,
                bundled: false,
            });
        entry.last_attempt_unix = Some(now);
        if let Some(error) = error {
            entry.last_error = Some(error);
        }
    }

    /// Marks a category as refreshed from `source_url` at the current time.
    pub fn mark_refreshed(&self, category: &str, source_url: &str) {
        let now = unix_now();
        let category = category.to_ascii_lowercase();
        let mut statuses = sito_core::sync::write_or_recover(&self.statuses);
        let entry = statuses
            .entry(category.clone())
            .or_insert_with(|| RuntimeListStatus {
                category: category.clone(),
                source_url: None,
                last_refresh_unix: None,
                last_attempt_unix: None,
                last_error: None,
                entries: 0,
                bundled: false,
            });
        entry.source_url = Some(source_url.to_string());
        entry.last_refresh_unix = Some(now);
        entry.last_error = None;
        entry.bundled = false;
    }

    /// Whether the bundled parental registry has `category`.
    #[must_use]
    pub fn has_parental_category(&self, category: &str) -> bool {
        self.parental.load().contains_category(category)
    }

    /// Whether the bundled service registry has `service`.
    #[must_use]
    pub fn has_service(&self, service: &str) -> bool {
        self.services.load().contains_service(service)
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
        let _apply_guard = sito_core::sync::lock_or_recover(&self.apply_lock);

        // Canonical key: `"Adult"` and `"adult"` must update (and clear the
        // bundled flag on) one shared status row.
        let category_key = category.to_ascii_lowercase();
        let (entries, new_parental, new_services) = if category_key == "services" {
            let registry = ServiceRegistry::from_json(content).map_err(|e| e.to_string())?;
            let entries = registry.service_count() as u64;
            (entries, None, Some(Arc::new(registry)))
        } else {
            let mut parental = (*self.parental.load_full()).clone();
            // Count parsed entries, not raw lines: malformed/comment lines must
            // not inflate the reported entry count or the truncation guard.
            let entries = parental.set_category_list(&category_key, content);
            (entries, Some(Arc::new(parental)), None)
        };

        // An empty/zero-entry result is always rejected, even for an explicit
        // force refresh: a broken or empty download must never silently
        // disable protection.
        if entries == 0 {
            return Err(format!(
                "refusing to replace category '{category}' with empty content"
            ));
        }

        // Guard refreshes that replace previously downloaded content; the
        // bundled fallback may legitimately be replaced by a smaller list.
        // Only a non-empty intentional shrink may be forced.
        let previous_status = {
            let statuses = sito_core::sync::read_or_recover(&self.statuses);
            statuses.get(&category_key).cloned()
        };
        let previous = previous_status.as_ref().map_or(0, |status| status.entries);
        let was_bundled = previous_status.as_ref().is_none_or(|status| status.bundled);
        let truncating = entries.saturating_mul(2) < previous;
        if !force && previous > 0 && truncating && !was_bundled {
            return Err(format!(
                "refusing to replace category '{category}' with \
                 {entries} entries after {previous} (>50% shrink); \
                 use a forced refresh to accept the truncation"
            ));
        }

        if let Some(services) = new_services {
            self.services.store(services);
        }
        if let Some(parental) = new_parental {
            self.parental.store(parental);
        }

        let mut statuses = sito_core::sync::write_or_recover(&self.statuses);
        let entry = statuses
            .entry(category_key.clone())
            .or_insert_with(|| RuntimeListStatus {
                category: category_key.clone(),
                source_url: None,
                last_refresh_unix: None,
                last_attempt_unix: None,
                last_error: None,
                entries: 0,
                bundled: false,
            });
        entry.entries = entries;
        entry.bundled = false;
        Ok(entries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> RuntimeLists {
        RuntimeLists::from_arcs(
            Arc::new(ParentalRegistry::try_bundled().expect("bundled parental lists must load")),
            Arc::new(ServiceRegistry::try_bundled().expect("bundled services must load")),
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
    fn test_category_key_case_does_not_duplicate_status() {
        let store = store();
        let before = store.statuses().len();

        // A mixed-case update replaces the bundled rows' content and must
        // clear the bundled flag on the shared lowercase row.
        store
            .apply_content("Adult", "a.example\nb.example\n")
            .unwrap();
        store.mark_refreshed("Adult", "https://lists.example.com/adult.txt");

        let statuses = store.statuses();
        assert_eq!(
            statuses.len(),
            before,
            "case variants must not create a second status row"
        );
        let status = statuses
            .iter()
            .find(|status| status.category == "adult")
            .expect("lowercase adult row");
        assert!(!status.bundled);
        assert_eq!(status.entries, 2);

        // The lowercase spelling updates the same row rather than adding one.
        store
            .apply_content("ADULT", "c.example\nd.example\ne.example\n")
            .unwrap();
        let statuses = store.statuses();
        assert_eq!(statuses.len(), before);
        let status = statuses
            .iter()
            .find(|status| status.category == "adult")
            .expect("lowercase adult row");
        assert_eq!(status.entries, 3);
    }

    #[test]
    fn test_runtime_status_records_attempt_and_error() {
        let store = store();

        store.record_attempt("Adult", None);
        let status = store
            .statuses()
            .into_iter()
            .find(|status| status.category == "adult")
            .expect("adult row");
        assert!(status.last_attempt_unix.is_some());
        assert_eq!(status.last_error, None);

        // A failed fetch/parse attempt is recorded on the same row and does
        // not change the active bundled content.
        store.record_attempt("adult", Some("fetch failed".to_string()));
        let status = store
            .statuses()
            .into_iter()
            .find(|status| status.category == "adult")
            .expect("adult row");
        assert_eq!(status.last_error.as_deref(), Some("fetch failed"));
        assert!(status.last_attempt_unix.is_some());
        assert!(
            status.bundled,
            "a failed refresh keeps the bundled fallback"
        );

        // Starting another attempt must not hide the previous error before the
        // outcome is known; only a success clears it.
        store.record_attempt("adult", None);
        let status = store
            .statuses()
            .into_iter()
            .find(|status| status.category == "adult")
            .expect("adult row");
        assert_eq!(
            status.last_error.as_deref(),
            Some("fetch failed"),
            "an in-flight attempt keeps the prior error visible"
        );
        assert!(status.last_attempt_unix.is_some());

        // A success clears the error and records the refresh.
        store
            .apply_content("adult", "a.example\nb.example\n")
            .unwrap();
        store.mark_refreshed("adult", "https://lists.example.com/adult.txt");
        let status = store
            .statuses()
            .into_iter()
            .find(|status| status.category == "adult")
            .expect("adult row");
        assert_eq!(status.last_error, None);
        assert!(status.last_refresh_unix.is_some());
        assert!(!status.bundled);
    }

    #[test]
    fn test_force_refresh_bypasses_drop_guard_and_updates_status() {
        let store = store();
        store
            .apply_content("adult", "a.example\nb.example\nc.example\nd.example\n")
            .unwrap();

        // The ordinary path rejects the shrink and leaves the row unchanged.
        assert!(store.apply_content("adult", "only.example\n").is_err());
        let before = store
            .statuses()
            .into_iter()
            .find(|status| status.category == "adult")
            .expect("adult row");
        assert_eq!(before.entries, 4);

        // The explicit operator path bypasses the guard and updates the same
        // status row.
        store
            .apply_content_forced("Adult", "only.example\n")
            .unwrap();
        let after = store
            .statuses()
            .into_iter()
            .find(|status| status.category == "adult")
            .expect("adult row");
        assert_eq!(after.entries, 1);
        assert!(!after.bundled);
        assert!(store.parental().matches_category("adult", "only.example"));
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

    fn source(url: &str) -> ListSourceConfig {
        ListSourceConfig {
            url: url.to_string(),
            refresh_hours: None,
            license: None,
        }
    }

    #[test]
    fn test_config_validation_rejects_blank_and_duplicate_category_keys() {
        let mut config = ListCategoriesConfig::default();
        config
            .categories
            .insert("   ".to_string(), source("https://example.com/a.txt"));
        let err = config.validate().unwrap_err();
        assert!(err.contains("must not be empty"), "unexpected error: {err}");

        let mut config = ListCategoriesConfig::default();
        config
            .categories
            .insert("Adult".to_string(), source("https://example.com/a.txt"));
        config
            .categories
            .insert("adult".to_string(), source("https://example.com/b.txt"));
        let err = config.validate().unwrap_err();
        assert!(
            err.contains("duplicate category"),
            "case-insensitive duplicates must be rejected: {err}"
        );

        let mut config = ListCategoriesConfig::default();
        config
            .categories
            .insert(" adult ".to_string(), source("https://example.com/a.txt"));
        assert!(
            config.validate().is_err(),
            "surrounding whitespace is rejected so keys cannot silently miss"
        );
    }

    #[test]
    fn test_config_validation_rejects_unknown_categories_and_accepts_known() {
        let mut config = ListCategoriesConfig::default();
        config
            .categories
            .insert("adult".to_string(), source("https://example.com/a.txt"));
        config
            .categories
            .insert("Gambling".to_string(), source("https://example.com/g.txt"));
        config
            .categories
            .insert("services".to_string(), source("https://example.com/s.json"));
        config
            .validate_known_categories()
            .expect("bundled categories are known case-insensitively");

        config.categories.insert(
            "advertising".to_string(),
            source("https://example.com/ads.txt"),
        );
        let err = config.validate_known_categories().unwrap_err();
        assert!(
            err.contains("not a known curated category") && err.contains("adult"),
            "unknown categories must name the valid ids: {err}"
        );
    }

    #[test]
    fn test_config_validation_caps_refresh_hours() {
        let mut config = ListCategoriesConfig {
            refresh_hours: 0,
            ..ListCategoriesConfig::default()
        };
        assert!(config.validate().is_err(), "global zero must be rejected");
        config.refresh_hours = sito_core::config::MAX_REFRESH_HOURS + 1;
        assert!(
            config.validate().is_err(),
            "global over-cap must be rejected"
        );
        config.refresh_hours = sito_core::config::MAX_REFRESH_HOURS;
        assert!(config.validate().is_ok(), "the global cap itself is valid");

        config.categories.insert(
            "adult".to_string(),
            ListSourceConfig {
                url: "https://example.com/adult.txt".to_string(),
                refresh_hours: Some(sito_core::config::MAX_REFRESH_HOURS + 1),
                license: None,
            },
        );
        assert!(
            config.validate().is_err(),
            "per-category over-cap must be rejected"
        );
        config.categories.get_mut("adult").unwrap().refresh_hours = Some(0);
        assert!(
            config.validate().is_err(),
            "per-category zero must be rejected"
        );
        config.categories.get_mut("adult").unwrap().refresh_hours =
            Some(sito_core::config::MAX_REFRESH_HOURS);
        assert!(config.validate().is_ok(), "the per-category cap is valid");
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
    fn test_drop_guard_counts_parsed_entries_not_raw_lines() {
        let store = store();

        // A first refresh dominated by malformed lines must report the number
        // of parsed domains (1), not the raw line count (1001).
        let mut content = String::new();
        for _ in 0..1_000 {
            content.push_str("not a domain line\n");
        }
        content.push_str("a.example\n");
        let entries = store.apply_content("adult", &content).unwrap();
        assert_eq!(entries, 1, "only the parsed domain may be counted");

        let status = store
            .statuses()
            .into_iter()
            .find(|s| s.category == "adult")
            .unwrap();
        assert_eq!(status.entries, 1);

        // A legitimate later update of the same size must not be rejected as a
        // >50% shrink (which would happen if the malformed lines had inflated
        // the previous count).
        store.apply_content("adult", "b.example\n").unwrap();
        assert!(store.parental().matches_category("adult", "b.example"));
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

        // Even the explicit force path must not accept an empty result.
        let err = store
            .apply_content_forced("adult", "\n# nothing\n")
            .unwrap_err();
        assert!(err.contains("empty content"), "unexpected error: {err}");
        assert!(
            store.parental().matches_category("adult", "pornhub.com"),
            "forced refresh must not wipe protection with empty content"
        );
        let status = store
            .statuses()
            .into_iter()
            .find(|status| status.category == "adult")
            .expect("adult row");
        assert!(
            status.bundled,
            "a rejected empty force keeps the bundled row"
        );
        assert_eq!(status.entries, 40);
    }

    #[test]
    fn test_try_new_is_non_panicking() {
        let store = RuntimeLists::try_new().expect("bundled data must load");
        assert!(store.parental().matches_category("adult", "pornhub.com"));
    }
}
