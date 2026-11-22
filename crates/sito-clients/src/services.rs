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
    /// Release-bound catalog service rules, kept as a separate overlay so a
    /// later `[integrations.lists]` refresh can replace the bundled/downloaded
    /// map without discarding the embedded catalog services.
    #[serde(skip)]
    catalog_services: HashMap<String, HashSet<String>>,
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
            catalog_services: HashMap::new(),
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
        // The bundled `services.json` is a minimal fallback; the release-bound
        // catalog carries the full AdGuard service set. Merge it here so the
        // runtime blocking engine, config validation and the UI all see the
        // same service ids.
        registry.attach_catalog_overlay();
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

    /// Number of services in the registry, including catalog overlay services.
    ///
    /// This counts service ids, not blockable rules: a registry whose service
    /// entries all have empty rule arrays has a non-zero service count but
    /// blocks nothing. Use [`Self::rule_count`] for emptiness/truncation
    /// guards.
    #[must_use]
    pub fn service_count(&self) -> usize {
        self.services.len()
            + self
                .catalog_services
                .keys()
                .filter(|id| !self.services.contains_key(*id))
                .count()
    }

    /// Number of usable domain rules across every service, including catalog
    /// overlay rules (same-id rules are counted once).
    ///
    /// This is the effective blocking coverage of the registry: regex/wildcard
    /// rules and malformed domains were dropped at parse time and are not
    /// counted.
    #[must_use]
    pub fn rule_count(&self) -> usize {
        let mut count = self.base_rule_count();
        for (id, rules) in &self.catalog_services {
            count += self
                .services
                .get(id)
                .map_or(rules.len(), |base| rules.difference(base).count());
        }
        count
    }

    /// Number of usable rules in the bundled/downloaded map only, excluding
    /// the catalog overlay. Refresh truncation guards compare this value so the
    /// catalog overlay cannot make a broken download look healthy.
    pub(crate) fn base_rule_count(&self) -> usize {
        self.services.values().map(HashSet::len).sum()
    }

    /// Whether a service id is present in this registry or the catalog overlay.
    #[must_use]
    pub fn contains_service(&self, service: &str) -> bool {
        let key = service.to_ascii_lowercase();
        self.services.contains_key(&key) || self.catalog_services.contains_key(&key)
    }

    /// Adds the release-bound catalog service rules as an overlay.
    ///
    /// Catalog rules pass through the same literal-domain cleaner as bundled
    /// and downloaded service lists: regex/wildcard rules and malformed
    /// domains are dropped with a warning, and `$dnsrewrite=NXDOMAIN` actions
    /// are reduced to their literal domain (the service-blocking engine only
    /// needs the domain). A service whose every rule is unsupported is omitted
    /// from the overlay so it cannot be selected as a silent no-op; the UI and
    /// handler report it as unavailable instead.
    ///
    /// A corrupt catalog is logged and leaves the bundled registry untouched;
    /// startup then continues on the minimal fallback instead of aborting.
    pub(crate) fn attach_catalog_overlay(&mut self) {
        match crate::catalog::Catalog::embedded() {
            Ok(catalog) => self.attach_catalog_overlay_from(&catalog),
            Err(e) => {
                error!(
                    error = %e,
                    "Embedded service catalog is invalid; service registry keeps the bundled fallback only"
                );
            }
        }
    }

    /// Testable core of [`Self::attach_catalog_overlay`].
    pub(crate) fn attach_catalog_overlay_from(&mut self, catalog: &crate::catalog::Catalog) {
        let mut skipped_rules = 0usize;
        let mut overlay: HashMap<String, HashSet<String>> =
            HashMap::with_capacity(catalog.services.len());
        for service in catalog.services() {
            let mut rules = HashSet::new();
            for rule in &service.rules {
                // The catalog is release-bound and validated at build time;
                // cleaning still drops unsupported shapes, but per-rule
                // warnings would repeat on every config validation pass. The
                // summary below reports the count once.
                if let Some(domain) =
                    clean_domain_rule_logged(rule, &service.id, &mut skipped_rules, false)
                {
                    rules.insert(domain);
                }
            }
            if !rules.is_empty() {
                overlay.insert(service.id.to_ascii_lowercase(), rules);
            }
        }
        log_skipped_rules(skipped_rules);
        self.catalog_services = overlay;
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
                catalog_services: HashMap::new(),
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
            catalog_services: HashMap::new(),
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
        let base = self.services.get(&svc_key);
        let overlay = self.catalog_services.get(&svc_key);
        if base.is_none() && overlay.is_none() {
            return false;
        }

        let q = query_domain.trim_end_matches('.').to_ascii_lowercase();
        let matches = |domain: &str| {
            base.is_some_and(|rules| rules.contains(domain))
                || overlay.is_some_and(|rules| rules.contains(domain))
        };

        if matches(&q) {
            return true;
        }
        let mut suffix = q.as_str();
        while let Some((_, parent)) = suffix.split_once('.') {
            if matches(parent) {
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
    clean_domain_rule_logged(rule, service, skipped, true)
}

/// Shared cleaning implementation; `log` controls per-rule warnings so the
/// release-bound catalog overlay can report only an aggregate count.
fn clean_domain_rule_logged(
    rule: &str,
    service: &str,
    skipped: &mut usize,
    log: bool,
) -> Option<String> {
    let mut trimmed = rule.trim();
    if trimmed.is_empty() {
        return None;
    }

    // `$dnsrewrite=NXDOMAIN` is AdGuard's block action for the domain; the
    // service-blocking engine only needs the literal domain, so drop the
    // modifier instead of rejecting the rule as malformed. Other modifiers
    // (`$dnstype`, `$denyallow`, ...) change semantics and stay unsupported.
    if let Some((domain, modifiers)) = trimmed.split_once('$')
        && modifiers
            .to_ascii_lowercase()
            .starts_with("dnsrewrite=nxdomain")
    {
        trimmed = domain.trim();
        if trimmed.is_empty() {
            return None;
        }
    }

    if (trimmed.starts_with('/') && trimmed.ends_with('/'))
        || trimmed.contains('*')
        || trimmed.contains('?')
        || trimmed.contains('~')
    {
        if log {
            warn!(
                service = %service,
                rule = %trimmed,
                "Skipping unsupported regex/wildcard service rule"
            );
        }
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
            if log {
                warn!(
                    service = %service,
                    rule = %trimmed,
                    "Skipping malformed service domain rule"
                );
            }
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
    fn test_catalog_services_are_merged_into_bundled_registry() {
        let catalog = crate::catalog::Catalog::embedded().expect("embedded catalog must be valid");
        let reg = ServiceRegistry::try_bundled().expect("bundled services must load");

        // Every release-bound catalog id resolves and is selectable.
        for service in catalog.services() {
            assert!(
                reg.contains_service(&service.id),
                "catalog service '{}' must be present in the runtime registry",
                service.id
            );
        }

        // A catalog-only service actually blocks matching domains and
        // subdomains through the existing suffix matcher.
        assert!(
            catalog.service_by_id("4chan").is_some(),
            "4chan is catalog-only, not in the bundled services.json"
        );
        assert!(reg.is_service_domain("4chan", "4chan.org"));
        assert!(reg.is_service_domain("4chan", "boards.4chan.org"));
        assert!(!reg.is_service_domain("4chan", "example.com"));

        // The bundled fallback still works, including ids the catalog omits.
        assert!(
            catalog.service_by_id("zoom").is_none(),
            "zoom is a bundled-only fallback service"
        );
        assert!(reg.contains_service("zoom"));
        assert!(reg.is_service_domain("zoom", "zoom.us"));
        assert!(!reg.is_service_domain("zoom", "example.com"));

        // Overlapping bundled/catalog services keep their bundled coverage.
        assert!(reg.is_service_domain("tiktok", "tiktok.com"));
        assert!(reg.is_service_domain("tiktok", "www.musical.ly"));

        let bundled = ServiceRegistry::from_json(crate::bundled::SERVICES_JSON)
            .expect("bundled services JSON must parse");
        let catalog_only = catalog
            .services()
            .filter(|service| !bundled.contains_service(&service.id))
            .count();
        assert_eq!(
            reg.service_count(),
            bundled.service_count() + catalog_only,
            "the merged registry is the union of bundled and catalog service ids"
        );
        assert!(
            reg.rule_count() > bundled.rule_count(),
            "catalog rules must add blocking coverage"
        );
    }

    #[test]
    fn test_catalog_dnsrewrite_nxdomain_rules_are_literal_domains() {
        let reg = ServiceRegistry::try_bundled().expect("bundled services must load");
        assert!(reg.contains_service("icloud_private_relay"));
        for domain in [
            "mask.icloud.com",
            "mask-h2.icloud.com",
            "mask-canary.icloud.com",
        ] {
            assert!(
                reg.is_service_domain("icloud_private_relay", domain),
                "{domain} must be blocked by the catalog rule"
            );
            assert!(
                reg.is_service_domain("icloud_private_relay", &format!("sub.{domain}")),
                "subdomains of {domain} must be blocked"
            );
        }
        assert!(!reg.is_service_domain("icloud_private_relay", "icloud.com"));
    }

    #[test]
    fn test_catalog_overlay_omits_services_with_no_usable_rules() {
        use crate::catalog::CatalogService;

        let mut catalog = crate::catalog::Catalog::embedded().expect("embedded catalog");
        let group = catalog.service_groups[0].clone();
        catalog.services.push(CatalogService {
            id: "zero_rule_service".to_string(),
            name: "Zero rule service".to_string(),
            group: group.clone(),
            rules: vec![
                "/regex.*/".to_string(),
                "*.wild.example".to_string(),
                "||mask.example^$dnsrewrite=NOERROR;;".to_string(),
            ],
        });
        catalog.services.push(CatalogService {
            id: "partial_rule_service".to_string(),
            name: "Partial rule service".to_string(),
            group,
            rules: vec![
                "||good.example^".to_string(),
                "*.dropped.example".to_string(),
            ],
        });

        let mut reg = ServiceRegistry::from_json("{}").expect("empty service map");
        reg.attach_catalog_overlay_from(&catalog);

        assert!(
            !reg.contains_service("zero_rule_service"),
            "a service with no usable rules must not resolve"
        );
        assert!(reg.contains_service("partial_rule_service"));
        assert!(reg.is_service_domain("partial_rule_service", "good.example"));
        assert!(!reg.is_service_domain("partial_rule_service", "x.dropped.example"));
        assert!(
            reg.is_service_domain("4chan", "4chan.org"),
            "real catalog services must still be merged"
        );
    }

    #[test]
    fn test_catalog_overlay_cleans_unsupported_rule_shapes() {
        let reg = ServiceRegistry::try_bundled().expect("bundled services must load");

        // The tiktok catalog entry contains wildcard rules that the literal
        // suffix matcher cannot represent. They are dropped with a warning,
        // while its simple `||domain^` rules still block.
        assert!(reg.is_service_domain("tiktok", "tiktok.com"));
        assert!(reg.is_service_domain("tiktok", "tiktokv.com"));
        assert!(
            !reg.is_service_domain("tiktok", "p16-tiktok-abc.ibyteimg.com"),
            "wildcard-only catalog rules must not be stored as literal domains"
        );

        // Amazon has a `$dnstype` modifier and wildcard rules; the literal
        // rules remain usable after the same cleaning path.
        assert!(reg.is_service_domain("amazon", "amazon.com"));
        assert!(!reg.is_service_domain("amazon", "awsdns-12.com"));
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
