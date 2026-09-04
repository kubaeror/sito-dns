//! Local network MAC address resolution and caching (60-second TTL).

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

const CACHE_TTL: Duration = Duration::from_secs(60);

/// Normalizes a MAC address string into standard lowercase `aa:bb:cc:dd:ee:ff`.
pub fn normalize_mac(s: &str) -> Option<String> {
    let clean: String = s
        .chars()
        .filter(char::is_ascii_hexdigit)
        .map(|c| c.to_ascii_lowercase())
        .collect();

    if clean.len() != 12 {
        return None;
    }

    let mut formatted = String::with_capacity(17);
    for (i, ch) in clean.chars().enumerate() {
        if i > 0 && i % 2 == 0 {
            formatted.push(':');
        }
        formatted.push(ch);
    }

    Some(formatted)
}

/// Cache entry for a resolved MAC address.
#[derive(Clone, Debug)]
struct CachedMac {
    mac: String,
    expires_at: Instant,
}

/// Resolver for MAC addresses with 60-second cache and injectable provider.
#[derive(Clone, Default)]
pub struct MacResolver {
    cache: Arc<RwLock<HashMap<IpAddr, CachedMac>>>,
    mock_arp: Arc<RwLock<Option<HashMap<IpAddr, String>>>>,
}

impl MacResolver {
    pub fn new() -> Self {
        Self {
            cache: Arc::new(RwLock::new(HashMap::new())),
            mock_arp: Arc::new(RwLock::new(None)),
        }
    }

    /// Sets mock ARP entries for testing purposes.
    pub fn set_mock_arp(&self, table: HashMap<IpAddr, String>) {
        let mut normalized_table = HashMap::with_capacity(table.len());
        for (ip, mac) in table {
            if let Some(norm) = normalize_mac(&mac) {
                normalized_table.insert(ip, norm);
            }
        }
        *self.mock_arp.write().unwrap() = Some(normalized_table);
    }

    /// Resolves the MAC address for a given IP address.
    pub fn resolve_mac(&self, ip: IpAddr) -> Option<String> {
        let now = Instant::now();

        // 1. Check cache
        {
            let cache = self.cache.read().unwrap();
            if let Some(entry) = cache.get(&ip) {
                if entry.expires_at > now {
                    return Some(entry.mac.clone());
                }
            }
        }

        // 2. Query ARP table (mock or /proc/net/arp)
        let resolved = self.lookup_arp(ip)?;

        // 3. Update cache
        {
            let mut cache = self.cache.write().unwrap();
            cache.insert(
                ip,
                CachedMac {
                    mac: resolved.clone(),
                    expires_at: now + CACHE_TTL,
                },
            );
        }

        Some(resolved)
    }

    fn lookup_arp(&self, ip: IpAddr) -> Option<String> {
        // Check mock ARP table first
        if let Some(mock) = self.mock_arp.read().unwrap().as_ref() {
            return mock.get(&ip).cloned();
        }

        // Query system ARP table
        read_system_arp().get(&ip).cloned()
    }
}

/// Reads the system ARP table from `/proc/net/arp` (Linux).
fn read_system_arp() -> HashMap<IpAddr, String> {
    let mut map = HashMap::new();

    let Ok(content) = std::fs::read_to_string("/proc/net/arp") else {
        return map;
    };

    // Format:
    // IP address       HW type     Flags       HW address            Mask     Device
    // 192.168.1.1      0x1         0x2         00:11:22:33:44:55     *        eth0
    for line in content.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() >= 4 {
            if let Ok(ip) = fields[0].parse::<IpAddr>() {
                if let Some(norm) = normalize_mac(fields[3]) {
                    if norm != "00:00:00:00:00:00" {
                        map.insert(ip, norm);
                    }
                }
            }
        }
    }

    map
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_mac_normalization() {
        assert_eq!(
            normalize_mac("AA:BB:CC:DD:EE:FF"),
            Some("aa:bb:cc:dd:ee:ff".to_string())
        );
        assert_eq!(
            normalize_mac("aa-bb-cc-dd-ee-ff"),
            Some("aa:bb:cc:dd:ee:ff".to_string())
        );
        assert_eq!(
            normalize_mac("aabb.ccdd.eeff"),
            Some("aa:bb:cc:dd:ee:ff".to_string())
        );
        assert_eq!(
            normalize_mac("aabbccddeeff"),
            Some("aa:bb:cc:dd:ee:ff".to_string())
        );
        assert_eq!(normalize_mac("invalid"), None);
    }

    #[test]
    fn test_mac_resolver_caching_and_mock() {
        let resolver = MacResolver::new();
        let ip = IpAddr::from_str("192.168.1.50").unwrap();

        assert_eq!(resolver.resolve_mac(ip), None);

        let mut mock = HashMap::new();
        mock.insert(ip, "AA:BB:CC:DD:EE:FF".to_string());
        resolver.set_mock_arp(mock);

        let mac = resolver.resolve_mac(ip).unwrap();
        assert_eq!(mac, "aa:bb:cc:dd:ee:ff");

        // Should return from cache even if mock table is cleared
        resolver.set_mock_arp(HashMap::new());
        assert_eq!(
            resolver.resolve_mac(ip),
            Some("aa:bb:cc:dd:ee:ff".to_string())
        );
    }
}
