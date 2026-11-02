//! Anti-DoH bypass registry with bundled dataset of known public resolvers.
//!
//! Blocks encrypted DNS queries attempting to bypass sito by contacting known
//! public DoH/DoT providers (Cloudflare, Google, Quad9, AdGuard, NextDNS, etc.).

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::IpAddr;
use std::str::FromStr;
use tracing::error;

/// Known public resolver dataset entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DohResolverEntry {
    pub name: String,
    pub domains: Vec<String>,
    pub ips: Vec<String>,
}

/// Registry of known public encrypted DNS resolvers used for anti-bypass filtering.
#[derive(Debug, Clone)]
pub struct AntiBypassRegistry {
    exact_domains: HashSet<String>,
    suffix_domains: Vec<String>,
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
            let d = domain.trim().trim_end_matches('.').to_ascii_lowercase();
            if let Some(suffix) = d.strip_prefix("*.") {
                self.suffix_domains.push(format!(".{suffix}"));
            } else {
                self.exact_domains.insert(d.clone());
                self.suffix_domains.push(format!(".{d}"));
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
        let d = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        if self.exact_domains.contains(&d) {
            return true;
        }
        for suffix in &self.suffix_domains {
            if d.ends_with(suffix) {
                return true;
            }
        }
        false
    }

    /// Check if an IP address matches any known public DoH/DoT resolver.
    pub fn matches_ip(&self, ip: &IpAddr) -> bool {
        self.ips.contains(ip)
    }

    /// Total count of known unique resolver domains.
    pub fn domain_count(&self) -> usize {
        self.exact_domains.len()
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
