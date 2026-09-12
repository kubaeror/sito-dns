//! Runtime-refreshable curated lists.
//!
//! The curated parental/service data bundled into the binary is the minimal
//! fallback. Operators can point `[integrations.lists]` at maintained sources;
//! a background task downloads them with the shared subscription downloader
//! (ETag/disk cache/size caps) and swaps the registries without a restart.

use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

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

/// Hot-swappable parental and service registries used by the query pipeline.
#[derive(Debug)]
pub struct RuntimeLists {
    parental: ArcSwap<ParentalRegistry>,
    services: ArcSwap<ServiceRegistry>,
}

impl RuntimeLists {
    /// Wraps existing registries.
    #[must_use]
    pub fn from_arcs(parental: Arc<ParentalRegistry>, services: Arc<ServiceRegistry>) -> Self {
        Self {
            parental: ArcSwap::from(parental),
            services: ArcSwap::from(services),
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
    pub fn apply_content(&self, category: &str, content: &str) -> Result<(), String> {
        if category.eq_ignore_ascii_case("services") {
            let registry = ServiceRegistry::from_json(content).map_err(|e| e.to_string())?;
            self.services.store(Arc::new(registry));
            return Ok(());
        }

        let mut parental = (*self.parental.load_full()).clone();
        parental.set_category_list(category, content);
        self.parental.store(Arc::new(parental));
        Ok(())
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
}
