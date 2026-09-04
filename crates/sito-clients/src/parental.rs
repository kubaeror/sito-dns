//! Parental control category blocklists (adult, gambling, etc.).

use std::collections::{HashMap, HashSet};

const BUNDLED_ADULT: &str = include_str!("bundled/adult.txt");
const BUNDLED_GAMBLING: &str = include_str!("bundled/gambling.txt");

/// Repository of parental category blocklists.
#[derive(Debug, Clone)]
pub struct ParentalRegistry {
    categories: HashMap<String, HashSet<String>>,
}

impl Default for ParentalRegistry {
    fn default() -> Self {
        Self::bundled()
    }
}

impl ParentalRegistry {
    /// Initialize with bundled category lists.
    pub fn bundled() -> Self {
        let mut reg = Self {
            categories: HashMap::new(),
        };
        reg.add_category_list("adult", BUNDLED_ADULT);
        reg.add_category_list("gambling", BUNDLED_GAMBLING);
        reg
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

        // Check suffix subdomains
        for blocked in domains {
            if q.ends_with(&format!(".{blocked}")) {
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
}
