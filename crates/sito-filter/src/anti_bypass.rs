//! Anti-DoH bypass registry with bundled dataset of known public resolvers.
//!
//! Blocks encrypted DNS queries attempting to bypass sito by contacting known
//! public DoH/DoT providers (Cloudflare, Google, Quad9, AdGuard, NextDNS, etc.).

use serde::{Deserialize, Serialize};
use sito_core::domain::NormalizedDomain;
use std::collections::HashSet;
use std::net::IpAddr;
use std::str::FromStr;
use tracing::error;

/// Embedded metadata header describing the bundled DoH resolver dataset.
pub const METADATA_JSON: &str = include_str!("../data/doh_resolvers.meta.json");

/// Known public resolver dataset entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DohResolverEntry {
    pub name: String,
    pub domains: Vec<String>,
    pub ips: Vec<String>,
}

/// Metadata header for the bundled DoH resolver dataset.
///
/// Counts describe the raw dataset (before de-duplication): exact domains,
/// wildcard domains and IP addresses. Tests compare them against the loaded
/// registry so the header cannot drift from the data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AntiBypassMetadata {
    pub format_version: u32,
    pub version: String,
    pub generated: String,
    pub source: String,
    pub license: String,
    /// Number of exact (non-wildcard) domain entries.
    pub exact_domains: u64,
    /// Number of wildcard (`*.example.com`) domain entries.
    pub wildcard_domains: u64,
    /// Number of IP address entries.
    pub ips: u64,
}

impl AntiBypassMetadata {
    /// Parses metadata from a JSON string.
    pub fn parse(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Parses the embedded metadata header.
    pub fn try_bundled() -> Result<Self, serde_json::Error> {
        Self::parse(METADATA_JSON)
    }
}

/// Registry of known public encrypted DNS resolvers used for anti-bypass filtering.
#[derive(Debug, Clone)]
pub struct AntiBypassRegistry {
    exact_domains: HashSet<String>,
    wildcard_domains: HashSet<String>,
    suffix_domains: Vec<NormalizedDomain>,
    ips: HashSet<IpAddr>,
}

impl Default for AntiBypassRegistry {
    fn default() -> Self {
        Self::try_bundled().unwrap_or_else(|e| {
            error!(error = %e, "Bundled DoH resolver list failed to load; continuing with an empty registry");
            Self::empty()
        })
    }
}

impl AntiBypassRegistry {
    /// An empty registry that matches no resolvers.
    ///
    /// Used as a non-panicking fallback when the embedded dataset is corrupt.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            exact_domains: HashSet::new(),
            wildcard_domains: HashSet::new(),
            suffix_domains: Vec::new(),
            ips: HashSet::new(),
        }
    }

    /// Parses resolver entries from a JSON string.
    ///
    /// Returns an error instead of silently ignoring corrupt data.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        let entries: Vec<DohResolverEntry> = serde_json::from_str(json)?;
        let mut registry = Self::empty();
        for entry in entries {
            registry.add_entry(&entry);
        }
        Ok(registry)
    }

    /// Create registry from the bundled dataset.
    ///
    /// Returns an error instead of panicking when the embedded JSON is corrupt.
    pub fn try_bundled() -> Result<Self, serde_json::Error> {
        Self::from_json(include_str!("../data/doh_resolvers.json"))
    }

    /// Add an entry to the registry.
    pub fn add_entry(&mut self, entry: &DohResolverEntry) {
        for domain in &entry.domains {
            let normalized = match NormalizedDomain::parse(domain.trim()) {
                Ok(normalized) => normalized,
                Err(error) => {
                    error!(
                        domain = %domain,
                        %error,
                        "Skipping invalid anti-bypass resolver domain"
                    );
                    continue;
                }
            };
            if let Some(rest) = normalized.as_str().strip_prefix("*.") {
                match NormalizedDomain::parse(rest) {
                    Ok(suffix) => {
                        self.wildcard_domains.insert(suffix.as_str().to_string());
                        self.suffix_domains.push(suffix);
                    }
                    Err(error) => error!(
                        domain = %domain,
                        %error,
                        "Skipping invalid anti-bypass wildcard domain"
                    ),
                }
            } else {
                self.exact_domains.insert(normalized.as_str().to_string());
                self.suffix_domains.push(normalized);
            }
        }
        for ip_str in &entry.ips {
            if let Ok(ip) = IpAddr::from_str(ip_str.trim()) {
                self.ips.insert(ip);
            }
        }
    }

    /// Check if a domain matches any known public DoH/DoT resolver.
    pub fn matches_domain(&self, domain: &str) -> bool {
        let Ok(domain) = NormalizedDomain::parse(domain) else {
            return false;
        };
        if self.exact_domains.contains(domain.as_str()) {
            return true;
        }
        self.suffix_domains
            .iter()
            .any(|suffix| domain.is_strict_subdomain_of(suffix))
    }

    /// Check if an IP address matches any known public DoH/DoT resolver.
    pub fn matches_ip(&self, ip: &IpAddr) -> bool {
        self.ips.contains(ip)
    }

    /// Total count of known unique resolver domains (exact plus wildcard).
    pub fn domain_count(&self) -> usize {
        self.exact_domains.len() + self.wildcard_domains.len()
    }

    /// Total count of known unique resolver IPs.
    pub fn ip_count(&self) -> usize {
        self.ips.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bundled_registry_matches() {
        let reg = AntiBypassRegistry::try_bundled().expect("bundled DoH resolver list must load");
        assert!(reg.domain_count() > 0);
        assert!(reg.ip_count() > 0);

        // Cloudflare
        assert!(reg.matches_domain("cloudflare-dns.com"));
        assert!(reg.matches_domain("one.one.one.one."));
        assert!(reg.matches_domain("1.1.1.1.cloudflare-dns.com"));
        assert!(reg.matches_ip(&"1.1.1.1".parse().unwrap()));
        assert!(reg.matches_ip(&"1.0.0.1".parse().unwrap()));

        // Google
        assert!(reg.matches_domain("dns.google"));
        assert!(reg.matches_domain("dns.google.com"));
        assert!(reg.matches_ip(&"8.8.8.8".parse().unwrap()));
        assert!(reg.matches_ip(&"8.8.4.4".parse().unwrap()));

        // Quad9
        assert!(reg.matches_domain("dns.quad9.net"));
        assert!(reg.matches_ip(&"9.9.9.9".parse().unwrap()));

        // AdGuard
        assert!(reg.matches_domain("dns.adguard-dns.com"));
        assert!(reg.matches_ip(&"94.140.14.14".parse().unwrap()));

        // NextDNS
        assert!(reg.matches_domain("dns.nextdns.io"));
        assert!(reg.matches_domain("my-id.dns.nextdns.io"));

        // ControlD
        assert!(reg.matches_domain("dns.controld.com"));
        assert!(reg.matches_ip(&"76.76.2.0".parse().unwrap()));

        // Mullvad
        assert!(reg.matches_domain("dns.mullvad.net"));
        assert!(reg.matches_ip(&"194.242.2.2".parse().unwrap()));

        // Non-matching legitimate domains
        assert!(!reg.matches_domain("example.com"));
        assert!(!reg.matches_domain("google.com"));
        assert!(!reg.matches_domain("github.com"));
        assert!(!reg.matches_ip(&"192.168.1.1".parse().unwrap()));
    }

    #[test]
    fn test_bundled_metadata_parses_and_matches_counts() {
        let metadata = AntiBypassMetadata::try_bundled().expect("bundled DoH metadata must parse");
        assert_eq!(metadata.format_version, 1);
        assert!(
            !metadata.version.is_empty(),
            "metadata must record a version"
        );
        assert!(!metadata.source.is_empty(), "metadata must record a source");
        assert!(
            !metadata.license.is_empty(),
            "metadata must record a license"
        );
        assert!(
            !metadata.generated.is_empty(),
            "metadata must record a generation date"
        );

        let registry =
            AntiBypassRegistry::try_bundled().expect("bundled DoH resolver list must load");
        assert_eq!(
            registry.domain_count() as u64,
            metadata.exact_domains + metadata.wildcard_domains,
            "metadata domain counts must match the bundled dataset"
        );
        assert_eq!(
            registry.ip_count() as u64,
            metadata.ips,
            "metadata IP count must match the bundled dataset"
        );
        assert_eq!(metadata.exact_domains, 29);
        assert_eq!(metadata.wildcard_domains, 1);
        assert_eq!(metadata.ips, 70);
    }

    #[test]
    fn test_wildcard_domains_counted() {
        let registry = AntiBypassRegistry::from_json(
            r#"[{"name":"test","domains":["example.com","*.example.com","*.example.com"],"ips":[]}]"#,
        )
        .expect("valid resolver JSON must parse");
        // One exact domain plus one unique wildcard (duplicate wildcard ignored).
        assert_eq!(registry.domain_count(), 2);
    }

    #[test]
    fn test_corrupt_anti_bypass_data_degrades_to_error_not_panic() {
        let err = AntiBypassRegistry::from_json("{ not json").expect_err("corrupt JSON must fail");
        assert_ne!(err.to_string(), "");

        let empty = AntiBypassRegistry::empty();
        assert_eq!(empty.domain_count(), 0);
        assert_eq!(empty.ip_count(), 0);
        assert!(!empty.matches_domain("cloudflare-dns.com"));
        assert!(!empty.matches_ip(&"1.1.1.1".parse().unwrap()));
    }
}
