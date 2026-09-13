//! Parental control category blocklists (adult, gambling, etc.).

use crate::bundled::{BundledList, BundledListError, BundledManifest, verified_content};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use tracing::warn;

/// Hostnames present in every hosts file that carry no blocking meaning.
const IGNORED_HOSTNAMES: &[&str] = &[
    "localhost",
    "localhost.localdomain",
    "local",
    "broadcasthost",
    "ip6-localhost",
    "ip6-loopback",
    "ip6-localnet",
    "ip6-mcastprefix",
    "ip6-allnodes",
    "ip6-allrouters",
    "ip6-allhosts",
    "0.0.0.0",
    "::1",
    "::",
];

/// Normalizes a single hosts/ABP token to a lowercase domain, or returns
/// `None` for tokens that are not domains (IPs, regex rules, wildcards).
fn normalize_domain_token(token: &str) -> Option<String> {
    let mut s = token.trim();
    if s.is_empty() {
        return None;
    }
    if let Some(stripped) = s.strip_prefix("||") {
        s = stripped;
    }
    // Drop ABP modifiers (`$important`, ...) before the anchor suffix.
    if let Some(idx) = s.find('$') {
        s = &s[..idx];
    }
    if let Some(stripped) = s.strip_suffix('^') {
        s = stripped;
    }
    s = s.trim_end_matches('.');
    if s.is_empty() || s.len() > 253 {
        return None;
    }
    let lower = s.to_ascii_lowercase();
    for label in lower.split('.') {
        if label.is_empty() || label.len() > 63 {
            return None;
        }
        if !label
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return None;
        }
    }
    Some(lower)
}

/// Parses a newline-delimited category list supporting plain domains, ABP
/// `||domain^` rules and hosts-format lines (`0.0.0.0 domain [domain...]`).
fn parse_domain_lines(content: &str) -> Vec<String> {
    let mut domains = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('!') {
            continue;
        }
        let without_comment = trimmed.split('#').next().unwrap_or(trimmed).trim();
        if without_comment.is_empty() {
            continue;
        }
        let tokens: Vec<&str> = without_comment.split_whitespace().collect();
        if tokens.is_empty() {
            continue;
        }
        // `0.0.0.0 ad.example other.example` lists every following token.
        // Non-hosts lines must be a single ABP/plain token; anything else is
        // malformed and skipped.
        let domain_tokens: &[&str] = if tokens[0].parse::<IpAddr>().is_ok() {
            &tokens[1..]
        } else if tokens.len() == 1 {
            &tokens[..]
        } else {
            warn!(line = %trimmed, "Ignoring malformed parental-control list line");
            continue;
        };
        for token in domain_tokens {
            if IGNORED_HOSTNAMES
                .iter()
                .any(|ignored| token.trim_end_matches('.').eq_ignore_ascii_case(ignored))
            {
                continue;
            }
            if let Some(domain) = normalize_domain_token(token) {
                domains.push(domain);
            } else {
                warn!(token = %token, "Ignoring invalid parental-control list entry");
            }
        }
    }
    domains
}

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
    /// Returns an error instead of panicking when embedded data is corrupt.
    pub fn try_bundled() -> Result<Self, BundledListError> {
        let manifest =
            BundledManifest::try_bundled().map_err(|e| BundledListError::InvalidContent {
                id: "manifest".to_string(),
                reason: e.to_string(),
            })?;
        let mut reg = Self {
            categories: HashMap::new(),
            lists: manifest.lists.clone(),
        };
        for list in &manifest.lists {
            if list.kind != "domains" {
                continue;
            }
            let content = verified_content(list)?;
            reg.add_category_list(&list.id, content);
        }
        Ok(reg)
    }

    /// Initialize with the bundled category lists after verifying their
    /// manifest checksums.
    ///
    /// # Panics
    /// Panics when the embedded manifest or a bundled file fails its integrity
    /// check; both are covered by unit tests. Prefer
    /// [`ParentalRegistry::try_bundled`] on non-fatal paths.
    pub fn bundled() -> Self {
        Self::try_bundled().unwrap_or_else(|e| panic!("bundled list integrity check failed: {e}"))
    }

    /// Metadata (version, source, license, checksum) of the bundled lists.
    #[must_use]
    pub fn lists(&self) -> &[BundledList] {
        &self.lists
    }

    /// Replaces the content of a category with a newline-delimited text list.
    pub fn set_category_list(&mut self, category: &str, content: &str) {
        self.categories.remove(&category.to_ascii_lowercase());
        self.add_category_list(category, content);
    }

    /// Add or append domains from a newline-delimited text list to a category.
    ///
    /// Supports plain domains, ABP `||domain^` rules and hosts-format lines
    /// (`0.0.0.0 domain [domain...]`); invalid entries are skipped with a
    /// warning instead of being stored as bogus domains.
    pub fn add_category_list(&mut self, category: &str, content: &str) {
        let parsed = parse_domain_lines(content);
        let cat_set = self
            .categories
            .entry(category.to_ascii_lowercase())
            .or_default();
        for domain in parsed {
            cat_set.insert(domain);
        }
    }

    /// Check if a query domain matches a specific category.
    ///
    /// Matching walks the query's parent suffixes (`a.b.example.com` ->
    /// `b.example.com` -> `example.com`) and probes the category set once per
    /// label, instead of scanning every blocked domain. This is O(labels)
    /// instead of O(|category|) on the per-query path and preserves the exact
    /// and subdomain semantics of [`sito_core::matches_strict_subdomain`].
    pub fn matches_category(&self, category: &str, query_domain: &str) -> bool {
        let cat_key = category.to_ascii_lowercase();
        let Some(domains) = self.categories.get(&cat_key) else {
            return false;
        };

        let q = query_domain.trim_end_matches('.').to_ascii_lowercase();

        // Exact match.
        if domains.contains(&q) {
            return true;
        }

        // Parent-suffix match (strict subdomain of any blocked domain).
        let mut suffix = q.as_str();
        while let Some((_, parent)) = suffix.split_once('.') {
            if domains.contains(parent) {
                return true;
            }
            suffix = parent;
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

    #[test]
    fn test_try_bundled_is_non_panicking() {
        let reg = ParentalRegistry::try_bundled().expect("bundled parental lists must load");
        assert!(reg.matches_category("adult", "pornhub.com"));
    }

    #[test]
    fn test_parental_suffix_walk_semantics() {
        let mut reg = ParentalRegistry::try_bundled().expect("bundled parental lists must load");
        reg.add_category_list("custom", "example.com\nfoo.bar\nsingle");

        // Exact match.
        assert!(reg.matches_category("custom", "example.com"));
        assert!(reg.matches_category("custom", "foo.bar"));
        assert!(reg.matches_category("custom", "single"));

        // Parent-suffix match at any depth.
        assert!(reg.matches_category("custom", "a.b.example.com"));
        assert!(reg.matches_category("custom", "x.foo.bar."));

        // Label-boundary discipline: no substring or partial-label matches.
        assert!(!reg.matches_category("custom", "notexample.com"));
        assert!(!reg.matches_category("custom", "example.com.evil"));
        assert!(!reg.matches_category("custom", "com"));
        assert!(!reg.matches_category("custom", "bar"));
        assert!(!reg.matches_category("custom", ""));
    }

    #[test]
    fn test_hosts_format_lines_are_not_stored_as_bogus_domains() {
        let mut reg = ParentalRegistry::try_bundled().expect("bundled parental lists must load");
        reg.add_category_list(
            "custom",
            "0.0.0.0 hosts-blocked.example\n127.0.0.1 first.example second.example\n\
             # comment\n! abp comment\n||abp-blocked.example^\nnot a domain\n",
        );

        assert!(reg.matches_category("custom", "hosts-blocked.example"));
        assert!(reg.matches_category("custom", "first.example"));
        assert!(reg.matches_category("custom", "second.example"));
        assert!(reg.matches_category("custom", "abp-blocked.example"));
        assert!(
            !reg.matches_category("custom", "0.0.0.0"),
            "IP addresses must never be stored as blocking domains"
        );
        assert!(
            !reg.matches_category("custom", "domain"),
            "invalid whitespace-containing entries must be skipped"
        );
    }
}
