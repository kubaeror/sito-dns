//! Release-bound catalog of HostlistsRegistry filter and service metadata.
//!
//! The catalog is generated from the AdGuard HostlistsRegistry indexes at
//! release time by `scripts/generate-catalog.py` and committed as
//! `catalog/catalog.json`. It contains only metadata -- filter names,
//! categories, descriptions, homepage/download URLs, list versions and the
//! small blocked-service rules. Filter-list bodies are never embedded; the
//! lists themselves are downloaded at runtime by the selection follow-up when
//! an operator selects them.
//!
//! The embedded data is validated on load so a hand-edited or stale catalog
//! fails loudly instead of silently changing filtering behaviour. There is no
//! network access and no configuration mutation in this module.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use thiserror::Error;

/// Supported embedded catalog schema version.
pub const CATALOG_VERSION: u32 = 1;

/// Upstream filters index the catalog was generated from.
pub const FILTERS_SOURCE_URL: &str =
    "https://adguardteam.github.io/HostlistsRegistry/assets/filters.json";

/// Upstream services index the catalog was generated from.
pub const SERVICES_SOURCE_URL: &str =
    "https://adguardteam.github.io/HostlistsRegistry/assets/services.json";

/// SPDX license of the upstream metadata.
pub const CATALOG_LICENSE: &str = "GPL-3.0-only";

/// The committed catalog, compiled into the binary.
pub const CATALOG_JSON: &str = include_str!("catalog/catalog.json");

/// Provenance of the embedded catalog.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogSource {
    /// Source URL of the filters index.
    pub filters: String,
    /// Source URL of the services index.
    pub services: String,
    /// SPDX license of the upstream metadata.
    pub license: String,
}

/// A filter category (`general`, `other`, `regional`, `security`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogCategory {
    /// Stable category id.
    pub id: String,
    /// Human-readable category name.
    pub name: String,
    /// Display order used by selection UIs.
    pub display_number: u32,
}

/// Metadata for one downloadable filter list.
///
/// Only metadata is stored here. The filter-list body is fetched from
/// [`Self::download_url`] or [`Self::subscription_url`] at runtime by the
/// selection follow-up.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogFilter {
    /// Stable filter id (`filterKey` upstream).
    pub id: String,
    /// Human-readable filter name.
    pub name: String,
    /// Category id, one of [`CatalogCategory::id`].
    pub category: String,
    /// Short description of what the filter blocks.
    pub description: String,
    /// Project homepage.
    pub homepage: String,
    /// Direct download URL for the compiled filter list.
    pub download_url: String,
    /// Subscription URL for the source filter list.
    pub subscription_url: String,
    /// Version of the filter list at catalog generation time.
    pub version: String,
    /// Upstream refresh interval in seconds.
    pub expires_secs: u64,
    /// Display order within the category.
    pub display_number: u32,
    /// Languages the filter targets; empty for language-neutral filters.
    #[serde(default)]
    pub languages: Vec<String>,
    /// Whether upstream marks the filter as deprecated.
    #[serde(default)]
    pub deprecated: bool,
}

/// Metadata and block rules for one blocked service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogService {
    /// Stable service id.
    pub id: String,
    /// Human-readable service name.
    pub name: String,
    /// Service group id, one of [`Catalog::service_groups`].
    pub group: String,
    /// Small DNS block rules (`||domain^`); not a filter-list body.
    pub rules: Vec<String>,
}

/// The embedded filter/service catalog.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Catalog {
    /// Catalog schema version; currently [`CATALOG_VERSION`].
    pub catalog_version: u32,
    /// Source URLs and license.
    pub source: CatalogSource,
    /// Filter categories in display order.
    pub categories: Vec<CatalogCategory>,
    /// Known service group ids.
    pub service_groups: Vec<String>,
    /// Filter metadata, ordered by category and display number.
    pub filters: Vec<CatalogFilter>,
    /// Service metadata, ordered by id.
    pub services: Vec<CatalogService>,
}

/// Errors from loading or validating the embedded catalog.
#[derive(Debug, Error)]
pub enum CatalogError {
    /// The embedded JSON could not be parsed or has unknown fields.
    #[error("catalog is not valid JSON: {0}")]
    Parse(#[from] serde_json::Error),
    /// The catalog version is newer or older than this build supports.
    #[error("unsupported catalog version {0}; this build supports version 1")]
    UnsupportedVersion(u32),
    /// A required catalog section is empty.
    #[error("catalog has no {0}")]
    Empty(&'static str),
    /// A required string field is empty or whitespace-only.
    #[error("{kind} '{id}' has an empty {field}")]
    EmptyField {
        /// Entry kind, for example `filter`.
        kind: &'static str,
        /// Entry id (may be empty when the id itself is invalid).
        id: String,
        /// Field name.
        field: &'static str,
    },
    /// A list entry inside a catalog record is empty.
    #[error("{kind} '{id}' has an empty {field} entry")]
    EmptyEntry {
        /// Entry kind, for example `service`.
        kind: &'static str,
        /// Entry id.
        id: String,
        /// List field name.
        field: &'static str,
    },
    /// Two records share the same id.
    #[error("duplicate {kind} id '{id}'")]
    DuplicateId {
        /// Entry kind, for example `filter`.
        kind: &'static str,
        /// Duplicated id.
        id: String,
    },
    /// A numeric field must be positive.
    #[error("{kind} '{id}' field '{field}' must be positive")]
    NotPositive {
        /// Entry kind.
        kind: &'static str,
        /// Entry id.
        id: String,
        /// Field name.
        field: &'static str,
    },
    /// A filter references a category that is not declared.
    #[error("filter '{filter}' references unknown category '{category}'")]
    UnknownCategory {
        /// Filter id.
        filter: String,
        /// Unknown category id.
        category: String,
    },
    /// A category has no filters, so the category mapping is incomplete.
    #[error("category '{0}' has no filters")]
    EmptyCategory(String),
    /// A service references a group that is not declared.
    #[error("service '{service}' references unknown group '{group}'")]
    UnknownServiceGroup {
        /// Service id.
        service: String,
        /// Unknown group id.
        group: String,
    },
    /// A source URL does not match the generator's pinned URL.
    #[error("catalog source {field} URL '{url}' does not match the pinned upstream URL")]
    UnexpectedSource {
        /// Source field name.
        field: &'static str,
        /// URL found in the catalog.
        url: String,
    },
}

fn require_non_empty(
    kind: &'static str,
    id: &str,
    field: &'static str,
    value: &str,
) -> Result<(), CatalogError> {
    if value.trim().is_empty() {
        return Err(CatalogError::EmptyField {
            kind,
            id: id.to_string(),
            field,
        });
    }
    Ok(())
}

fn require_positive(
    kind: &'static str,
    id: &str,
    field: &'static str,
    value: u64,
) -> Result<(), CatalogError> {
    if value == 0 {
        return Err(CatalogError::NotPositive {
            kind,
            id: id.to_string(),
            field,
        });
    }
    Ok(())
}

impl Catalog {
    /// Parses and validates the catalog embedded in the binary.
    ///
    /// Returns an error instead of panicking so callers can surface a
    /// degraded state at startup.
    pub fn embedded() -> Result<Self, CatalogError> {
        Self::parse(CATALOG_JSON)
    }

    /// Parses and validates a catalog from JSON text.
    pub fn parse(json: &str) -> Result<Self, CatalogError> {
        let catalog: Self = serde_json::from_str(json)?;
        catalog.validate()?;
        Ok(catalog)
    }

    /// Validates catalog schema invariants and cross-references.
    pub fn validate(&self) -> Result<(), CatalogError> {
        if self.catalog_version != CATALOG_VERSION {
            return Err(CatalogError::UnsupportedVersion(self.catalog_version));
        }
        self.validate_source()?;
        self.validate_categories()?;
        self.validate_service_groups()?;
        self.validate_filters()?;
        self.validate_services()
    }

    fn validate_source(&self) -> Result<(), CatalogError> {
        if self.source.filters != FILTERS_SOURCE_URL {
            return Err(CatalogError::UnexpectedSource {
                field: "filters",
                url: self.source.filters.clone(),
            });
        }
        if self.source.services != SERVICES_SOURCE_URL {
            return Err(CatalogError::UnexpectedSource {
                field: "services",
                url: self.source.services.clone(),
            });
        }
        require_non_empty("catalog source", "", "license", &self.source.license)
    }

    fn validate_categories(&self) -> Result<(), CatalogError> {
        if self.categories.is_empty() {
            return Err(CatalogError::Empty("categories"));
        }
        let mut ids = HashSet::with_capacity(self.categories.len());
        for category in &self.categories {
            let id = category.id.as_str();
            require_non_empty("category", id, "id", id)?;
            if !ids.insert(id) {
                return Err(CatalogError::DuplicateId {
                    kind: "category",
                    id: id.to_string(),
                });
            }
            require_non_empty("category", id, "name", &category.name)?;
            require_positive(
                "category",
                id,
                "display_number",
                u64::from(category.display_number),
            )?;
        }
        Ok(())
    }

    fn validate_service_groups(&self) -> Result<(), CatalogError> {
        if self.service_groups.is_empty() {
            return Err(CatalogError::Empty("service groups"));
        }
        let mut ids = HashSet::with_capacity(self.service_groups.len());
        for group in &self.service_groups {
            let group = group.as_str();
            require_non_empty("service group", group, "id", group)?;
            if !ids.insert(group) {
                return Err(CatalogError::DuplicateId {
                    kind: "service group",
                    id: group.to_string(),
                });
            }
        }
        Ok(())
    }

    fn validate_filters(&self) -> Result<(), CatalogError> {
        if self.filters.is_empty() {
            return Err(CatalogError::Empty("filters"));
        }
        let category_ids: HashSet<&str> = self
            .categories
            .iter()
            .map(|category| category.id.as_str())
            .collect();
        let mut filter_ids = HashSet::with_capacity(self.filters.len());
        let mut used_categories: HashSet<&str> = HashSet::new();
        for filter in &self.filters {
            let id = filter.id.as_str();
            require_non_empty("filter", id, "id", id)?;
            if !filter_ids.insert(id) {
                return Err(CatalogError::DuplicateId {
                    kind: "filter",
                    id: id.to_string(),
                });
            }
            require_non_empty("filter", id, "name", &filter.name)?;
            require_non_empty("filter", id, "description", &filter.description)?;
            require_non_empty("filter", id, "homepage", &filter.homepage)?;
            require_non_empty("filter", id, "download_url", &filter.download_url)?;
            require_non_empty("filter", id, "subscription_url", &filter.subscription_url)?;
            require_non_empty("filter", id, "version", &filter.version)?;
            require_positive(
                "filter",
                id,
                "display_number",
                u64::from(filter.display_number),
            )?;
            require_positive("filter", id, "expires_secs", filter.expires_secs)?;

            let category = filter.category.as_str();
            if !category_ids.contains(category) {
                return Err(CatalogError::UnknownCategory {
                    filter: id.to_string(),
                    category: category.to_string(),
                });
            }
            used_categories.insert(category);

            for language in &filter.languages {
                if language.trim().is_empty() {
                    return Err(CatalogError::EmptyEntry {
                        kind: "filter",
                        id: id.to_string(),
                        field: "languages",
                    });
                }
            }
        }

        for category in &self.categories {
            if !used_categories.contains(category.id.as_str()) {
                return Err(CatalogError::EmptyCategory(category.id.clone()));
            }
        }
        Ok(())
    }

    fn validate_services(&self) -> Result<(), CatalogError> {
        if self.services.is_empty() {
            return Err(CatalogError::Empty("services"));
        }
        let group_ids: HashSet<&str> = self.service_groups.iter().map(String::as_str).collect();
        let mut service_ids = HashSet::with_capacity(self.services.len());
        for service in &self.services {
            let id = service.id.as_str();
            require_non_empty("service", id, "id", id)?;
            if !service_ids.insert(id) {
                return Err(CatalogError::DuplicateId {
                    kind: "service",
                    id: id.to_string(),
                });
            }
            require_non_empty("service", id, "name", &service.name)?;
            let group = service.group.as_str();
            if !group_ids.contains(group) {
                return Err(CatalogError::UnknownServiceGroup {
                    service: id.to_string(),
                    group: group.to_string(),
                });
            }
            if service.rules.is_empty() {
                return Err(CatalogError::EmptyEntry {
                    kind: "service",
                    id: id.to_string(),
                    field: "rules",
                });
            }
            for rule in &service.rules {
                if rule.trim().is_empty() {
                    return Err(CatalogError::EmptyEntry {
                        kind: "service",
                        id: id.to_string(),
                        field: "rules",
                    });
                }
            }
        }
        Ok(())
    }

    /// Lists all filter categories.
    pub fn categories(&self) -> impl Iterator<Item = &CatalogCategory> {
        self.categories.iter()
    }

    /// Lists all filters in catalog order.
    pub fn filters(&self) -> impl Iterator<Item = &CatalogFilter> {
        self.filters.iter()
    }

    /// Lists all services in catalog order.
    pub fn services(&self) -> impl Iterator<Item = &CatalogService> {
        self.services.iter()
    }

    /// Lists all known service group ids.
    pub fn service_groups(&self) -> impl Iterator<Item = &str> {
        self.service_groups.iter().map(String::as_str)
    }

    /// Returns the category with the given id.
    #[must_use]
    pub fn category_by_id(&self, id: &str) -> Option<&CatalogCategory> {
        self.categories.iter().find(|category| category.id == id)
    }

    /// Returns the filter with the given id.
    #[must_use]
    pub fn filter_by_id(&self, id: &str) -> Option<&CatalogFilter> {
        self.filters.iter().find(|filter| filter.id == id)
    }

    /// Returns the service with the given id.
    #[must_use]
    pub fn service_by_id(&self, id: &str) -> Option<&CatalogService> {
        self.services.iter().find(|service| service.id == id)
    }

    /// Lists filters in the given category.
    pub fn filters_in_category<'a>(
        &'a self,
        category: &'a str,
    ) -> impl Iterator<Item = &'a CatalogFilter> + 'a {
        self.filters
            .iter()
            .filter(move |filter| filter.category == category)
    }

    /// Counts filters in the given category.
    #[must_use]
    pub fn filter_count_in_category(&self, category: &str) -> usize {
        self.filters_in_category(category).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::path::Path;
    use std::process::Command;

    fn sample_category() -> CatalogCategory {
        CatalogCategory {
            id: "general".to_string(),
            name: "General".to_string(),
            display_number: 1,
        }
    }

    fn sample_filter() -> CatalogFilter {
        CatalogFilter {
            id: "sample_filter".to_string(),
            name: "Sample filter".to_string(),
            category: "general".to_string(),
            description: "A synthetic filter used by unit tests.".to_string(),
            homepage: "https://example.com/filter".to_string(),
            download_url: "https://example.com/filter.txt".to_string(),
            subscription_url: "https://example.com/filter-source.txt".to_string(),
            version: "1.0.0".to_string(),
            expires_secs: 86_400,
            display_number: 1,
            languages: Vec::new(),
            deprecated: false,
        }
    }

    fn sample_service() -> CatalogService {
        CatalogService {
            id: "sample_service".to_string(),
            name: "Sample service".to_string(),
            group: "social_network".to_string(),
            rules: vec!["||example.com^".to_string()],
        }
    }

    fn sample_catalog() -> Catalog {
        Catalog {
            catalog_version: CATALOG_VERSION,
            source: CatalogSource {
                filters: FILTERS_SOURCE_URL.to_string(),
                services: SERVICES_SOURCE_URL.to_string(),
                license: CATALOG_LICENSE.to_string(),
            },
            categories: vec![sample_category()],
            service_groups: vec!["social_network".to_string()],
            filters: vec![sample_filter()],
            services: vec![sample_service()],
        }
    }

    #[test]
    fn embedded_catalog_parses_and_validates() {
        let catalog = Catalog::embedded().expect("embedded catalog must be valid");
        assert_eq!(catalog.catalog_version, CATALOG_VERSION);
        assert_ne!(catalog.filters.len(), 0);
        assert_ne!(catalog.services.len(), 0);
        assert_ne!(catalog.categories.len(), 0);
        assert_ne!(catalog.service_groups.len(), 0);
    }

    #[test]
    fn category_mapping_and_counts_are_non_empty() {
        let catalog = Catalog::embedded().expect("embedded catalog must be valid");
        let expected = ["general", "other", "regional", "security"];
        let actual: HashSet<&str> = catalog
            .categories()
            .map(|category| category.id.as_str())
            .collect();
        assert_eq!(actual, expected.into_iter().collect());

        for category in catalog.categories() {
            assert!(
                catalog.filter_count_in_category(&category.id) > 0,
                "category '{}' must contain filters",
                category.id
            );
            assert!(
                catalog
                    .filters_in_category(&category.id)
                    .all(|filter| filter.category == category.id)
            );
        }

        let first = catalog.filters().next().expect("at least one filter");
        assert_eq!(
            catalog.filter_by_id(&first.id).map(|filter| &filter.name),
            Some(&first.name)
        );
        let service = catalog.services().next().expect("at least one service");
        assert_eq!(
            catalog.service_by_id(&service.id).map(|found| &found.rules),
            Some(&service.rules)
        );
        assert!(
            catalog
                .service_groups()
                .any(|group| group == service.group.as_str())
        );
    }

    #[test]
    fn no_filter_body_or_icon_fields() {
        let catalog: serde_json::Value =
            serde_json::from_str(CATALOG_JSON).expect("catalog JSON must parse");
        let allowed_filter_fields: HashSet<&str> = [
            "id",
            "name",
            "category",
            "description",
            "homepage",
            "download_url",
            "subscription_url",
            "version",
            "expires_secs",
            "display_number",
            "languages",
            "deprecated",
        ]
        .into_iter()
        .collect();
        let forbidden = [
            "body",
            "content",
            "filter_text",
            "list",
            "raw",
            "rules",
            "source_text",
            "text",
            "icon_svg",
        ];

        let filters = catalog["filters"]
            .as_array()
            .expect("filters must be an array");
        assert_ne!(filters.len(), 0);
        for filter in filters {
            let object = filter.as_object().expect("filter must be an object");
            for key in object.keys() {
                assert!(
                    allowed_filter_fields.contains(key.as_str()),
                    "unexpected filter field '{key}'"
                );
                assert!(
                    !forbidden.contains(&key.as_str()),
                    "filter contains body/icon field '{key}'"
                );
            }
        }
        assert!(
            !CATALOG_JSON.contains("\"icon_svg\""),
            "SVG icons are not part of the 2.0 catalog"
        );
    }

    #[test]
    fn duplicate_filter_id_is_rejected() {
        let mut catalog = sample_catalog();
        catalog.filters.push(sample_filter());
        let error = catalog.validate().expect_err("duplicate id must fail");
        assert!(matches!(
            error,
            CatalogError::DuplicateId { kind: "filter", .. }
        ));
    }

    #[test]
    fn duplicate_service_id_is_rejected() {
        let mut catalog = sample_catalog();
        catalog.services.push(sample_service());
        let error = catalog.validate().expect_err("duplicate id must fail");
        assert!(matches!(
            error,
            CatalogError::DuplicateId {
                kind: "service",
                ..
            }
        ));
    }

    #[test]
    fn empty_filter_name_is_rejected() {
        let mut catalog = sample_catalog();
        catalog.filters[0].name = "   ".to_string();
        let error = catalog.validate().expect_err("empty name must fail");
        assert!(matches!(
            error,
            CatalogError::EmptyField {
                kind: "filter",
                field: "name",
                ..
            }
        ));
    }

    #[test]
    fn empty_service_rules_are_rejected() {
        let mut catalog = sample_catalog();
        catalog.services[0].rules.clear();
        let error = catalog.validate().expect_err("empty rules must fail");
        assert!(matches!(
            error,
            CatalogError::EmptyEntry {
                kind: "service",
                field: "rules",
                ..
            }
        ));
    }

    #[test]
    fn unknown_references_are_rejected() {
        let mut catalog = sample_catalog();
        catalog.filters[0].category = "missing".to_string();
        let error = catalog.validate().expect_err("unknown category must fail");
        assert!(matches!(error, CatalogError::UnknownCategory { .. }));

        let mut catalog = sample_catalog();
        catalog.services[0].group = "missing".to_string();
        let error = catalog
            .validate()
            .expect_err("unknown service group must fail");
        assert!(matches!(error, CatalogError::UnknownServiceGroup { .. }));
    }

    #[test]
    fn unsupported_catalog_version_is_rejected() {
        let mut catalog = sample_catalog();
        catalog.catalog_version = CATALOG_VERSION + 1;
        let error = catalog.validate().expect_err("version must fail");
        assert!(matches!(error, CatalogError::UnsupportedVersion(2)));
    }

    #[test]
    fn generator_check_passes_against_committed_catalog() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let script = root.join("scripts/generate-catalog.py");
        let python = std::env::var("PYTHON").unwrap_or_else(|_| "python3".to_string());
        let output = match Command::new(&python).arg(&script).arg("--check").output() {
            Ok(output) => output,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                eprintln!("skipping catalog check: {python} not found");
                return;
            }
            Err(error) => panic!("failed to run {python}: {error}"),
        };
        assert!(
            output.status.success(),
            "generate-catalog.py --check failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
