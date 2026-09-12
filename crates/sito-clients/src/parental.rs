//! Parental control category blocklists (adult, gambling, etc.).

use crate::bundled::{BundledList, BundledManifest, verified_content};
use std::collections::{HashMap, HashSet};

/// Repository of parental category blocklists.
#[derive(Debug, Clone)]
pub struct ParentalRegistry {
    categories: HashMap<String, HashSet<String>>,
    lists: Vec<BundledList>,
}

impl Default for ParentalRegistry {
    fn default() -> Self {
        Self::bundled()
    }
}

impl ParentalRegistry {
    /// Initialize with the bundled category lists after verifying their
    /// manifest checksums.
    ///
    /// # Panics
    /// Panics when the embedded manifest or a bundled file fails its integrity
    /// check; both are covered by unit tests.
    pub fn bundled() -> Self {
        let manifest = BundledManifest::bundled();
        let mut reg = Self {
            categories: HashMap::new(),
            lists: manifest.lists.clone(),
        };
        for list in &manifest.lists {
            if list.kind != "domains" {
                continue;
            }
            let content = verified_content(list)
                .unwrap_or_else(|e| panic!("bundled list integrity check failed: {e}"));
            reg.add_category_list(&list.id, content);
        }
        reg
    }

    /// Metadata (version, source, license, checksum) of the bundled lists.
    #[must_use]
    pub fn lists(&self) -> &[BundledList] {
        &self.lists
    }

    /// Add or append domains from a newline-delimited text list to a category.
    pub fn add_category_list(&mut self, category: &str, content: &str) {
        let cat_set = self
            .categories
            .entry(category.to_ascii_lowercase())
            .or_default();

        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('!') {
                continue;
            }
            let mut domain = trimmed;
            if let Some(stripped) = domain.strip_prefix("||") {
                domain = stripped;
            }
            if let Some(stripped) = domain.strip_suffix('^') {
                domain = stripped;
            }
            cat_set.insert(domain.trim_end_matches('.').to_ascii_lowercase());
        }
    }

    /// Check if a query domain matches a specific category.
    pub fn matches_category(&self, category: &str, query_domain: &str) -> bool {
        let cat_key = category.to_ascii_lowercase();
        let Some(domains) = self.categories.get(&cat_key) else {
            return false;
        };

        let q = query_domain.trim_end_matches('.').to_ascii_lowercase();

        // Check exact match
        if domains.contains(&q) {
            return true;
        }

        // Check suffix subdomains (allocation-free)
        for blocked in domains {
            if sito_core::matches_strict_subdomain(&q, blocked) {
                return true;
            }
        }

        false
    }

    /// Check if a domain matches any of the active categories.
    pub fn matches_any_category<'a>(
        &self,
        categories: impl IntoIterator<Item = &'a str>,
        query_domain: &str,
    ) -> bool {
        for cat in categories {
            if self.matches_category(cat, query_domain) {
                return true;
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parental_bundled_categories() {
        let reg = ParentalRegistry::bundled();

        // Adult matches
        assert!(reg.matches_category("adult", "pornhub.com"));
        assert!(reg.matches_category("adult", "video.pornhub.com"));
        assert!(reg.matches_category("adult", "xvideos.com"));
        assert!(reg.matches_category("adult", "sub.xnxx.com."));
        assert!(!reg.matches_category("adult", "google.com"));

        // Gambling matches
        assert!(reg.matches_category("gambling", "bet365.com"));
        assert!(reg.matches_category("gambling", "pokerstars.com"));
        assert!(reg.matches_category("gambling", "casino.betway.com"));
        assert!(!reg.matches_category("gambling", "pornhub.com"));

        // Any category matching
        let cats = ["adult", "gambling"];
        assert!(reg.matches_any_category(cats, "betfair.com"));
        assert!(reg.matches_any_category(cats, "chaturbate.com"));
        assert!(!reg.matches_any_category(cats, "wikipedia.org"));
    }

    #[test]
    fn test_bundled_list_metadata_exposed() {
        let reg = ParentalRegistry::bundled();
        let adult = reg
            .lists()
            .iter()
            .find(|l| l.id == "adult")
            .expect("adult list metadata");
        assert_eq!(adult.kind, "domains");
        assert!(!adult.version.is_empty());
        assert!(!adult.source.is_empty());
        assert_eq!(adult.license, "CC0-1.0");
        assert_eq!(adult.checksum_blake3.len(), 64);
    }
}
