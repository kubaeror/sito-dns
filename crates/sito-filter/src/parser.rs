//! Hosts-format blocklist parser.

use sito_proto::normalize_domain;
use std::collections::HashSet;
use std::hash::BuildHasher;
use std::net::IpAddr;

/// List of standard loopback / system hostnames to ignore in hosts files.
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

/// Parses a hosts-format list or plain domain list into a set of normalized domains.
///
/// Features:
/// - Handles `0.0.0.0 domain`, `127.0.0.1 domain`, `::1 domain` and plain domain lists.
/// - Supports multiple domains per line (e.g. `0.0.0.0 d1.com d2.com`).
/// - Strips `#` and `!` comments (both whole-line and inline).
/// - Filters out loopback and broadcast names (e.g. `localhost`, `broadcasthost`).
/// - Normalizes all domain names (lowercase, strips trailing dot, verifies valid characters).
pub fn parse_hosts<S: BuildHasher>(content: &str, set: &mut HashSet<String, S>) -> usize {
    let mut added = 0;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('!') {
            continue;
        }

        // Strip inline comments starting with '#' or '!'
        let clean_line = if let Some(idx) = trimmed.find(['#', '!']) {
            trimmed[..idx].trim()
        } else {
            trimmed
        };

        if clean_line.is_empty() {
            continue;
        }

        let tokens: Vec<&str> = clean_line.split_whitespace().collect();
        if tokens.is_empty() {
            continue;
        }

        // Determine if token 0 is an IP address
        let domain_tokens: &[&str] = if tokens[0].parse::<IpAddr>().is_ok() {
            &tokens[1..]
        } else {
            &tokens[..]
        };

        for &raw_domain in domain_tokens {
            let lower = raw_domain.to_ascii_lowercase();
            let stripped = lower.strip_suffix('.').unwrap_or(&lower);

            if IGNORED_HOSTNAMES.contains(&stripped) {
                continue;
            }

            if let Ok(normalized) = normalize_domain(raw_domain) {
                if set.insert(normalized) {
                    added += 1;
                }
            }
        }
    }

    added
}

#[cfg(test)]
mod tests {
    use super::*;
    use fnv::FnvHashSet;

    #[test]
    fn test_parse_hosts_basic() {
        let content = r#"
# Standard hosts file comment
127.0.0.1 localhost
::1 localhost ip6-localhost
0.0.0.0 ads.example.com
127.0.0.1 tracking.example.org bad.domain.net # inline comment
! ABP style comment
plain-ad.com
"#;
        let mut set = FnvHashSet::default();
        let count = parse_hosts(content, &mut set);

        assert_eq!(count, 4);
        assert!(set.contains("ads.example.com"));
        assert!(set.contains("tracking.example.org"));
        assert!(set.contains("bad.domain.net"));
        assert!(set.contains("plain-ad.com"));
        assert!(!set.contains("localhost"));
        assert!(!set.contains("ip6-localhost"));
    }

    #[test]
    fn test_parse_hosts_normalization() {
        let content = "0.0.0.0 ADS.EXAMPLE.COM.\n127.0.0.1 Tracker.Org.";
        let mut set = FnvHashSet::default();
        parse_hosts(content, &mut set);

        assert!(set.contains("ads.example.com"));
        assert!(set.contains("tracker.org"));
    }

    #[test]
    fn test_parse_hosts_malformed_ignored() {
        let content = "0.0.0.0 invalid@domain.com\n0.0.0.0 valid.com\n# just a comment\n\n";
        let mut set = FnvHashSet::default();
        parse_hosts(content, &mut set);

        assert!(set.contains("valid.com"));
        assert_eq!(set.len(), 1);
    }
}
