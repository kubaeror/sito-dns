//! Service blocking engine using bundled `services.json` (compatible with AdGuard format).

use crate::bundled::{BundledList, BundledListError, BundledManifest, verified_content};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use tracing::{error, warn};

/// Service blocking database mapping service IDs to domain patterns.
///
/// Rule patterns are stored as a set per service so a query is matched by
/// probing its parent suffixes (O(labels)) instead of scanning every rule of
/// every active service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceRegistry {
    services: HashMap<String, HashSet<String>>,
    #[serde(skip)]
    lists: Vec<BundledList>,
}

impl Default for ServiceRegistry {
    fn default() -> Self {
        Self::try_bundled().unwrap_or_else(|e| {
            error!(error = %e, "Bundled service list failed to load; continuing with an empty registry");
            Self::empty()
        })
    }
}

#[derive(Deserialize)]
struct ServiceEntry {
    id: String,
    #[serde(default)]
    rules: Vec<String>,
}

impl ServiceRegistry {
    /// An empty registry that matches no services.
    ///
    /// Used as a non-panicking fallback when embedded data cannot be loaded.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            services: HashMap::new(),
            lists: Vec::new(),
        }
    }

    /// Builds the service registry from an already-parsed manifest after
    /// verifying the bundled `services.json` checksum.
    ///
    /// Returns an error instead of panicking when embedded data is corrupt.
    pub fn from_manifest(manifest: &BundledManifest) -> Result<Self, BundledListError> {
        let list = manifest
            .list("services")
            .ok_or_else(|| BundledListError::MissingContent("services".to_string()))?
            .clone();
        let content = verified_content(&list)?;
        let mut registry =
            Self::from_json(content).map_err(|e| BundledListError::InvalidContent {
                id: "services".to_string(),
                reason: e.to_string(),
            })?;
        registry.lists = vec![list];
        Ok(registry)
    }

    /// Load the bundled service definitions after verifying the manifest
    /// checksum.
    ///
    /// Returns an error instead of panicking when embedded data is corrupt.
    pub fn try_bundled() -> Result<Self, BundledListError> {
        let manifest =
            BundledManifest::try_bundled().map_err(|e| BundledListError::InvalidContent {
                id: "manifest".to_string(),
                reason: e.to_string(),
            })?;
        Self::from_manifest(&manifest)
    }

    /// Metadata (version, source, license, checksum) of the loaded bundled list.
    #[must_use]
    pub fn lists(&self) -> &[BundledList] {
        &self.lists
    }

    /// Number of services in the registry.
    #[must_use]
    pub fn service_count(&self) -> usize {
        self.services.len()
    }

    /// Parse service definitions from a JSON string.
    ///
    /// Supports both map format `{"service": ["domain1", "domain2"]}` and
    /// list format `[{"id": "service", "rules": ["domain1"]}]`.
    /// Regex/wildcard rules are rejected with a warning: the matcher works on
    /// literal domain suffixes, so storing `/re/` or `*.x` as a domain would
    /// silently never match.
    pub fn from_json(json_str: &str) -> Result<Self, serde_json::Error> {
        let mut skipped_rules = 0usize;

        // Try map format first
        if let Ok(map) = serde_json::from_str::<HashMap<String, Vec<String>>>(json_str) {
            let mut normalized = HashMap::with_capacity(map.len());
            for (svc, domains) in map {
                let cleaned_domains = domains
                    .into_iter()
                    .filter_map(|d| clean_domain_rule(&d, &svc, &mut skipped_rules))
                    .collect();
                normalized.insert(svc.to_ascii_lowercase(), cleaned_domains);
            }
            log_skipped_rules(skipped_rules);
            return Ok(Self {
                services: normalized,
                lists: Vec::new(),
            });
        }

        let list: Vec<ServiceEntry> = serde_json::from_str(json_str)?;
        let mut services = HashMap::with_capacity(list.len());
        for entry in list {
            let ServiceEntry { id, rules } = entry;
            let cleaned = rules
                .into_iter()
                .filter_map(|r| clean_domain_rule(&r, &id, &mut skipped_rules))
                .collect();
            services.insert(id.to_ascii_lowercase(), cleaned);
        }
        log_skipped_rules(skipped_rules);
        Ok(Self {
            services,
            lists: Vec::new(),
        })
    }

    /// Check if a domain belongs to the given service.
    ///
    /// Probes the query and each of its parent suffixes against the service's
    /// rule set (built once at load time), so a query costs one hash lookup per
    /// label instead of a scan over every rule.
    pub fn is_service_domain(&self, service: &str, query_domain: &str) -> bool {
        let svc_key = service.to_ascii_lowercase();
        let Some(rules) = self.services.get(&svc_key) else {
            return false;
        };

        let q = query_domain.trim_end_matches('.').to_ascii_lowercase();

        if rules.contains(&q) {
            return true;
        }
        let mut suffix = q.as_str();
        while let Some((_, parent)) = suffix.split_once('.') {
            if rules.contains(parent) {
                return true;
            }
            suffix = parent;
        }

        false
    }

    /// Check if any of the given services match the queried domain.
    pub fn matches_any_service<'a>(
        &self,
        services: impl IntoIterator<Item = &'a str>,
        query_domain: &str,
    ) -> Option<&'a str> {
        services
            .into_iter()
            .find(|&svc| self.is_service_domain(svc, query_domain))
    }
}

/// Logs a summary when unsupported service rules were dropped at load time.
fn log_skipped_rules(skipped: usize) {
    if skipped > 0 {
        warn!(
            skipped,
            "Skipped unsupported regex/wildcard or malformed service rules"
        );
    }
}

/// Normalizes a service rule to a literal lowercase domain.
/// Returns `None` (and logs) for rules the suffix matcher cannot represent:
/// regex rules (`/.../`), wildcards (`*`, `?`) and malformed domains. Storing
/// them as domains would silently never match.
fn clean_domain_rule(rule: &str, service: &str, skipped: &mut usize) -> Option<String> {
    let trimmed = rule.trim();
    if trimmed.is_empty() {
        return None;
    }
    if (trimmed.starts_with('/') && trimmed.ends_with('/'))
        || trimmed.contains('*')
        || trimmed.contains('?')
        || trimmed.contains('~')
    {
        warn!(
            service = %service,
            rule = %trimmed,
            "Skipping unsupported regex/wildcard service rule"
        );
        *skipped += 1;
        return None;
    }

    let mut s = trimmed;
    if let Some(stripped) = s.strip_prefix("||") {
        s = stripped;
    }
    if let Some(stripped) = s.strip_suffix('^') {
        s = stripped;
    }
    let s = s.trim_end_matches('.');
    if s.is_empty() || s.len() > 253 {
        *skipped += 1;
        return None;
    }
    let lower = s.to_ascii_lowercase();
    for label in lower.split('.') {
        if label.is_empty()
            || label.len() > 63
            || !label
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            warn!(
                service = %service,
                rule = %trimmed,
                "Skipping malformed service domain rule"
            );
            *skipped += 1;
            return None;
        }
    }
    Some(lower)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bundled_services_loaded() {
        let reg = ServiceRegistry::try_bundled().expect("bundled services must load");
        assert!(reg.is_service_domain("tiktok", "tiktok.com"));
        assert!(reg.is_service_domain("tiktok", "p16-sign.tiktokcdn.com"));
        assert!(reg.is_service_domain("tiktok", "www.musical.ly"));
        assert!(!reg.is_service_domain("tiktok", "google.com"));

        assert!(reg.is_service_domain("youtube", "youtube.com"));
        assert!(reg.is_service_domain("youtube", "googlevideo.com"));
        assert!(reg.is_service_domain("youtube", "r1---sn-4g5edn7k.googlevideo.com"));

        assert!(reg.is_service_domain("steam", "steampowered.com"));
        assert!(reg.is_service_domain("discord", "discord.gg"));
    }

    #[test]
    fn test_matches_any_service() {
        let reg = ServiceRegistry::try_bundled().expect("bundled services must load");
        let blocked = ["tiktok", "steam"];

        assert_eq!(
            reg.matches_any_service(blocked.iter().copied(), "api.tiktokv.com"),
            Some("tiktok")
        );
        assert_eq!(
            reg.matches_any_service(blocked.iter().copied(), "store.steampowered.com"),
            Some("steam")
        );
        assert_eq!(
            reg.matches_any_service(blocked.iter().copied(), "netflix.com"),
            None
        );
    }

    #[test]
    fn test_adguard_list_format() {
        let json_data = r#"[
            { "id": "custom_app", "rules": ["||custom-app.com^", "cdn.custom.net"] }
        ]"#;
        let reg = ServiceRegistry::from_json(json_data).unwrap();
        assert!(reg.is_service_domain("custom_app", "custom-app.com"));
        assert!(reg.is_service_domain("custom_app", "sub.custom-app.com"));
        assert!(reg.is_service_domain("custom_app", "cdn.custom.net"));
        assert!(!reg.is_service_domain("custom_app", "other.custom.net"));

        // Ad-hoc registries carry no bundled metadata.
        assert!(
            reg.lists().is_empty(),
            "ad-hoc registry must not expose bundled lists: {:?}",
            reg.lists()
        );
    }

    #[test]
    fn test_service_suffix_walk_semantics() {
        let json_data = r#"[
            { "id": "custom_app", "rules": ["custom-app.com", "deep.nested.net"] }
        ]"#;
        let reg = ServiceRegistry::from_json(json_data).unwrap();

        assert!(reg.is_service_domain("custom_app", "custom-app.com"));
        assert!(reg.is_service_domain("custom_app", "a.b.custom-app.com"));
        assert!(reg.is_service_domain("custom_app", "x.deep.nested.net"));

        // Label boundaries are respected: no substring/partial-label matches.
        assert!(!reg.is_service_domain("custom_app", "notcustom-app.com"));
        assert!(!reg.is_service_domain("custom_app", "custom-app.com.evil"));
        assert!(!reg.is_service_domain("custom_app", "nested.net"));
        assert!(!reg.is_service_domain("missing", "custom-app.com"));
    }

    #[test]
    fn test_bundled_service_metadata_exposed() {
        let reg = ServiceRegistry::try_bundled().expect("bundled services must load");
        let list = reg.lists().first().expect("services list metadata");
        assert_eq!(list.id, "services");
        assert_eq!(list.kind, "services");
        assert_eq!(list.license, "CC0-1.0");
    }

    #[test]
    fn test_regex_and_wildcard_service_rules_are_rejected() {
        let json_data = r#"[
            { "id": "custom_app", "rules": ["||good.com^", "/re.*/", "*.wild.com", "bad domain", "ok.net"] }
        ]"#;
        let reg = ServiceRegistry::from_json(json_data).unwrap();
        assert!(reg.is_service_domain("custom_app", "good.com"));
        assert!(reg.is_service_domain("custom_app", "ok.net"));
        assert!(!reg.is_service_domain("custom_app", "wild.com"));
        assert!(
            !reg.is_service_domain("custom_app", "re.foo"),
            "regex rules must be dropped, not stored"
        );
    }

    #[test]
    fn test_try_bundled_is_non_panicking() {
        let reg = ServiceRegistry::try_bundled().expect("bundled services must load");
        assert!(reg.is_service_domain("tiktok", "tiktok.com"));
    }

    #[test]
    fn test_corrupt_service_data_degrades_to_error_not_panic() {
        let err = ServiceRegistry::from_json("{ not json").expect_err("corrupt JSON must fail");
        assert_ne!(err.to_string(), "");

        let manifest = BundledManifest::try_bundled().expect("bundled manifest must parse");
        let mut tampered = manifest;
        tampered.lists.retain(|list| list.id == "services");
        tampered.lists[0].checksum_blake3 = "0".repeat(64);
        let err = ServiceRegistry::from_manifest(&tampered)
            .expect_err("a checksum mismatch must be reported");
        assert!(matches!(err, BundledListError::ChecksumMismatch { .. }));

        let empty = ServiceRegistry::empty();
        assert_eq!(empty.service_count(), 0);
        assert!(!empty.is_service_domain("tiktok", "tiktok.com"));
    }
}
