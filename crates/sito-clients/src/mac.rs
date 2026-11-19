//! Local network MAC address resolution and caching.
//!
//! The Linux ARP table (`/proc/net/arp`) is read only by a background refresh
//! task, never on the query path. Lookups are answered from an in-memory
//! snapshot with a bounded positive cache (60 s TTL) and a short negative
//! cache (5 s TTL), so a burst of queries for unknown addresses cannot cause
//! filesystem IO or unbounded memory growth.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock, RwLock};
use std::time::{Duration, Instant};

pub use sito_core::net::{normalize_mac, normalize_mac_id};

/// ARP table path (Linux only).
const ARP_TABLE_PATH: &str = "/proc/net/arp";

/// How often the background task refreshes the ARP snapshot.
pub const ARP_REFRESH_INTERVAL: Duration = Duration::from_secs(2);

/// How long a resolved MAC address stays cached.
const CACHE_TTL: Duration = Duration::from_secs(60);

/// How long a failed lookup stays negatively cached.
const NEGATIVE_CACHE_TTL: Duration = Duration::from_secs(5);

/// Upper bound on positive and negative cache entries.
const MAX_CACHE_ENTRIES: usize = 4096;

/// Upper bound on entries taken from the ARP table.
const MAX_ARP_ENTRIES: usize = 4096;

/// Counts filesystem reads of the ARP table (test-only probe).
#[cfg(test)]
static ARP_FILE_READS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Cache entry for a resolved MAC address.
#[derive(Clone, Debug)]
struct CachedMac {
    mac: String,
    expires_at: Instant,
    epoch: u64,
}

/// Cache entry for a failed lookup.
#[derive(Clone, Copy, Debug)]
struct CachedNegative {
    expires_at: Instant,
    epoch: u64,
}

/// Resolver for MAC addresses backed by a background-refreshed ARP snapshot.
///
/// [`MacResolver::resolve_mac`] never touches the filesystem: it answers from
/// the bounded positive/negative caches and the in-memory snapshot installed
/// by the background task (or by [`MacResolver::set_mock_arp`] in tests).
#[derive(Clone)]
pub struct MacResolver {
    cache: Arc<RwLock<HashMap<IpAddr, CachedMac>>>,
    negative: Arc<RwLock<HashMap<IpAddr, CachedNegative>>>,
    snapshot: Arc<RwLock<HashMap<IpAddr, String>>>,
    /// Incremented whenever a different ARP snapshot is installed. Cache
    /// entries from an older generation are ignored even if a concurrent
    /// resolve races with the invalidation.
    epoch: Arc<AtomicU64>,
    mock_arp: Arc<RwLock<Option<HashMap<IpAddr, String>>>>,
    refresh_started: Arc<OnceLock<()>>,
    cache_ttl: Duration,
    negative_ttl: Duration,
}

impl Default for MacResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl MacResolver {
    #[must_use]
    pub fn new() -> Self {
        Self::with_ttls(CACHE_TTL, NEGATIVE_CACHE_TTL)
    }

    fn with_ttls(cache_ttl: Duration, negative_ttl: Duration) -> Self {
        Self {
            cache: Arc::new(RwLock::new(HashMap::new())),
            negative: Arc::new(RwLock::new(HashMap::new())),
            snapshot: Arc::new(RwLock::new(HashMap::new())),
            epoch: Arc::new(AtomicU64::new(0)),
            mock_arp: Arc::new(RwLock::new(None)),
            refresh_started: Arc::new(OnceLock::new()),
            cache_ttl,
            negative_ttl,
        }
    }

    /// Starts the background `/proc/net/arp` refresher (idempotent).
    ///
    /// Returns `true` when the refresher is running or already started and
    /// `false` when no Tokio runtime is current (a later call from inside a
    /// runtime retries). The task holds weak references, so it exits on its
    /// next tick once every resolver sharing the snapshot has been dropped.
    pub fn start_background_refresh(&self) -> bool {
        if self.refresh_started.get().is_some() {
            return true;
        }
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return false;
        };
        if self.refresh_started.set(()).is_err() {
            // Another caller won the race and spawned the task.
            return true;
        }

        let snapshot = Arc::downgrade(&self.snapshot);
        let cache = Arc::downgrade(&self.cache);
        let negative = Arc::downgrade(&self.negative);
        let epoch = Arc::downgrade(&self.epoch);
        let mock_arp = Arc::downgrade(&self.mock_arp);
        handle.spawn(async move {
            loop {
                tokio::time::sleep(ARP_REFRESH_INTERVAL).await;
                let (Some(snapshot), Some(cache), Some(negative), Some(epoch), Some(mock_arp)) = (
                    snapshot.upgrade(),
                    cache.upgrade(),
                    negative.upgrade(),
                    epoch.upgrade(),
                    mock_arp.upgrade(),
                ) else {
                    break;
                };
                let mocked = mock_arp.read().is_ok_and(|mock| mock.is_some());
                if mocked {
                    continue;
                }
                let table = tokio::task::spawn_blocking(read_system_arp)
                    .await
                    .unwrap_or_default();
                install_arp_snapshot(&snapshot, &cache, &negative, &epoch, table);
            }
        });
        true
    }

    /// Sets mock ARP entries for testing purposes.
    ///
    /// While a mock table is installed the background refresher leaves the
    /// snapshot untouched. Installing a different table invalidates both the
    /// positive and negative caches, exactly like a background refresh.
    pub fn set_mock_arp(&self, table: HashMap<IpAddr, String>) {
        let mut normalized_table = HashMap::with_capacity(table.len());
        for (ip, mac) in table {
            if let Some(norm) = normalize_mac(&mac) {
                normalized_table.insert(ip, norm);
            }
        }
        if let Ok(mut mock) = self.mock_arp.write() {
            *mock = Some(normalized_table.clone());
        }
        self.install_snapshot(normalized_table);
    }

    /// Resolves the MAC address for a given IP address.
    ///
    /// This never performs filesystem IO: misses are answered `None` and
    /// negatively cached for a short TTL.
    pub fn resolve_mac(&self, ip: IpAddr) -> Option<String> {
        // Registries constructed outside a Tokio runtime start the refresher
        // lazily from the first query that needs MAC resolution.
        let _ = self.start_background_refresh();

        let now = Instant::now();
        let epoch = self.epoch.load(Ordering::SeqCst);

        let cached = {
            let cache = sito_core::sync::read_or_recover(&self.cache);
            cache
                .get(&ip)
                .filter(|entry| entry.expires_at > now && entry.epoch == epoch)
                .map(|entry| entry.mac.clone())
        };
        if let Some(mac) = cached {
            return Some(mac);
        }

        let negatively_cached = {
            let negative = sito_core::sync::read_or_recover(&self.negative);
            negative
                .get(&ip)
                .is_some_and(|entry| entry.expires_at > now && entry.epoch == epoch)
        };
        if negatively_cached {
            return None;
        }

        // Snapshot lookup only; the snapshot is maintained off the query path.
        let resolved = {
            let snapshot = sito_core::sync::read_or_recover(&self.snapshot);
            snapshot.get(&ip).cloned()
        };

        if let Some(mac) = resolved {
            sito_core::sync::write_or_recover(&self.negative).remove(&ip);
            self.store_positive(ip, mac.clone(), now, epoch);
            Some(mac)
        } else {
            self.store_negative(ip, now, epoch);
            None
        }
    }

    fn store_positive(&self, ip: IpAddr, mac: String, now: Instant, epoch: u64) {
        let mut cache = sito_core::sync::write_or_recover(&self.cache);
        if cache.len() >= MAX_CACHE_ENTRIES {
            cache.retain(|_, entry| entry.expires_at > now);
            if cache.len() >= MAX_CACHE_ENTRIES
                && let Some(oldest) = cache
                    .iter()
                    .min_by_key(|(_, entry)| entry.expires_at)
                    .map(|(ip, _)| *ip)
            {
                cache.remove(&oldest);
            }
        }
        cache.insert(
            ip,
            CachedMac {
                mac,
                expires_at: now + self.cache_ttl,
                epoch,
            },
        );
    }

    fn store_negative(&self, ip: IpAddr, now: Instant, epoch: u64) {
        let mut negative = sito_core::sync::write_or_recover(&self.negative);
        if negative.len() >= MAX_CACHE_ENTRIES {
            negative.retain(|_, entry| entry.expires_at > now);
            if negative.len() >= MAX_CACHE_ENTRIES
                && let Some(oldest) = negative
                    .iter()
                    .min_by_key(|(_, entry)| entry.expires_at)
                    .map(|(ip, _)| *ip)
            {
                negative.remove(&oldest);
            }
        }
        negative.insert(
            ip,
            CachedNegative {
                expires_at: now + self.negative_ttl,
                epoch,
            },
        );
    }

    fn install_snapshot(&self, table: HashMap<IpAddr, String>) {
        install_arp_snapshot(
            &self.snapshot,
            &self.cache,
            &self.negative,
            &self.epoch,
            table,
        );
    }

    /// Reads the ARP table and installs it as the new snapshot.
    ///
    /// Synchronous IO; used by the background refresher (`spawn_blocking`)
    /// and by tests. The query path never calls this.
    #[cfg(test)]
    pub(crate) fn refresh_arp_now(&self) -> usize {
        let table = read_system_arp();
        let entries = table.len();
        self.install_snapshot(table);
        entries
    }
}

/// Installs an ARP snapshot and invalidates both caches when it changed.
///
/// The snapshot is compared before replacement so a periodic refresh that
/// returns identical data keeps the positive cache warm. A changed snapshot
/// increments the generation and drops every positive and negative entry.
fn install_arp_snapshot(
    snapshot: &RwLock<HashMap<IpAddr, String>>,
    cache: &RwLock<HashMap<IpAddr, CachedMac>>,
    negative: &RwLock<HashMap<IpAddr, CachedNegative>>,
    epoch: &AtomicU64,
    table: HashMap<IpAddr, String>,
) {
    let changed = {
        let mut snapshot = sito_core::sync::write_or_recover(snapshot);
        if *snapshot == table {
            false
        } else {
            *snapshot = table;
            epoch.fetch_add(1, Ordering::SeqCst);
            true
        }
    };

    if changed {
        // A new snapshot can turn a previous positive answer stale or make a
        // previously missing address resolvable.
        sito_core::sync::write_or_recover(cache).clear();
        sito_core::sync::write_or_recover(negative).clear();
    }
}

/// Reads the system ARP table from `/proc/net/arp` (Linux).
fn read_system_arp() -> HashMap<IpAddr, String> {
    #[cfg(test)]
    ARP_FILE_READS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);

    let Ok(content) = std::fs::read_to_string(ARP_TABLE_PATH) else {
        return HashMap::new();
    };
    parse_arp_table(&content)
}

/// Parses `/proc/net/arp` content into an IP -> MAC map (bounded).
fn parse_arp_table(content: &str) -> HashMap<IpAddr, String> {
    let mut map = HashMap::new();

    // Format:
    // IP address       HW type     Flags       HW address            Mask     Device
    // 192.168.1.1      0x1         0x2         00:11:22:33:44:55     *        eth0
    for line in content.lines().skip(1) {
        if map.len() >= MAX_ARP_ENTRIES {
            break;
        }
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() >= 4
            && let Ok(ip) = fields[0].parse::<IpAddr>()
            && let Some(norm) = normalize_mac(fields[3])
            && norm != "00:00:00:00:00:00"
        {
            map.insert(ip, norm);
        }
    }

    map
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn arp_line(ip: &str, mac: &str) -> String {
        format!("{ip} 0x1 0x2 {mac} * eth0\n")
    }

    #[test]
    fn test_mac_normalization_accepts_strict_and_bare_forms() {
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
        // Trusted ARP/RouterOS values may be bare hex.
        assert_eq!(
            normalize_mac("aabbccddeeff"),
            Some("aa:bb:cc:dd:ee:ff".to_string())
        );
        assert_eq!(normalize_mac("invalid"), None);
    }

    #[test]
    fn test_mac_normalization_rejects_non_mac_shapes() {
        for value in [
            "aa:bb:cc:dd:ee",
            "aa:bb:cc:dd:ee:ff:00",
            "aa:bb-cc:dd:ee:ff",
            "aa.bb.cc.dd.ee.ff",
            "aabb.cdddeeff",
            "::aa:bb:cc:dd:ee:ff",
            "2001:db8::1",
            "192.168.1.1",
            "10.0.0.0/8",
            "aa:bb:cc:dd:ee:ff/24",
            "janes-phone",
            "abc-def-123456",
        ] {
            assert_eq!(normalize_mac(value), None, "{value} must not be a MAC");
        }
    }

    #[test]
    fn test_mac_id_requires_strict_or_explicit_mac_format() {
        // Separators or the `mac:` prefix make the intent explicit.
        assert_eq!(
            normalize_mac_id("AA:BB:CC:DD:EE:FF"),
            Some("aa:bb:cc:dd:ee:ff".to_string())
        );
        assert_eq!(
            normalize_mac_id("aa-bb-cc-dd-ee-ff"),
            Some("aa:bb:cc:dd:ee:ff".to_string())
        );
        assert_eq!(
            normalize_mac_id("aabb.ccdd.eeff"),
            Some("aa:bb:cc:dd:ee:ff".to_string())
        );
        // The historical explicit marker allows a bare hex MAC.
        assert_eq!(
            normalize_mac_id("mac:aabbccddeeff"),
            Some("aa:bb:cc:dd:ee:ff".to_string())
        );
        assert_eq!(
            normalize_mac_id("MAC:AA-BB-CC-DD-EE-FF"),
            Some("aa:bb:cc:dd:ee:ff".to_string())
        );
        // A bare 12-hex string is a hostname/client name, not a MAC.
        for value in [
            "aabbccddeeff",
            "deadbeefcafe",
            "janes-phone",
            "abc-def-123456",
            "::aa:bb:cc:dd:ee:ff",
            "10.0.0.0/8",
            "192.168.1.1",
            "aa:bb-cc:dd:ee:ff",
        ] {
            assert_eq!(
                normalize_mac_id(value),
                None,
                "{value} must not be a MAC identity"
            );
        }
    }

    #[test]
    fn test_mac_resolver_caching_and_mock() {
        let resolver = MacResolver::new();
        let ip = IpAddr::from_str("192.168.1.50").unwrap();

        assert_eq!(resolver.resolve_mac(ip), None);

        let mut mock = HashMap::new();
        mock.insert(ip, "AA:BB:CC:DD:EE:FF".to_string());
        resolver.set_mock_arp(mock.clone());

        let mac = resolver.resolve_mac(ip).unwrap();
        assert_eq!(mac, "aa:bb:cc:dd:ee:ff");

        // Re-installing the same snapshot keeps the positive cache warm.
        resolver.set_mock_arp(mock);
        assert_eq!(
            resolver.resolve_mac(ip),
            Some("aa:bb:cc:dd:ee:ff".to_string())
        );

        // Changing the snapshot invalidates it; a stale MAC must not survive.
        resolver.set_mock_arp(HashMap::new());
        assert_eq!(resolver.resolve_mac(ip), None);
    }

    #[test]
    fn test_arp_snapshot_change_invalidates_positive_cache() {
        let resolver = MacResolver::new();
        let ip = IpAddr::from_str("192.168.1.52").unwrap();

        let mut first = HashMap::new();
        first.insert(ip, "AA:BB:CC:DD:EE:01".to_string());
        resolver.set_mock_arp(first);
        assert_eq!(
            resolver.resolve_mac(ip).as_deref(),
            Some("aa:bb:cc:dd:ee:01")
        );

        // A refresh installs a different MAC for the same address.
        let mut second = HashMap::new();
        second.insert(ip, "aa:bb:cc:dd:ee:02".to_string());
        resolver.install_snapshot(second);
        assert_eq!(
            resolver.resolve_mac(ip).as_deref(),
            Some("aa:bb:cc:dd:ee:02"),
            "the cached positive answer must be invalidated by the new snapshot"
        );
    }

    #[test]
    fn test_arp_snapshot_change_invalidates_negative_cache() {
        let resolver = MacResolver::new();
        let ip = IpAddr::from_str("192.168.1.53").unwrap();
        resolver.set_mock_arp(HashMap::new());
        assert_eq!(resolver.resolve_mac(ip), None);

        let mut table = HashMap::new();
        table.insert(ip, "aa:bb:cc:dd:ee:03".to_string());
        resolver.install_snapshot(table);
        assert_eq!(
            resolver.resolve_mac(ip).as_deref(),
            Some("aa:bb:cc:dd:ee:03"),
            "a new snapshot entry must not be suppressed by a stale negative entry"
        );
    }

    /// Serializes tests that assert on the process-global ARP read counter;
    /// another test's background refresher could otherwise bump it mid-assert.
    static ARP_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn test_query_path_never_reads_proc_net_arp() {
        let _guard = ARP_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let before = ARP_FILE_READS.load(std::sync::atomic::Ordering::SeqCst);

        let resolver = MacResolver::new();
        let ip = IpAddr::from_str("192.168.1.50").unwrap();
        let mut mock = HashMap::new();
        mock.insert(ip, "AA:BB:CC:DD:EE:FF".to_string());
        resolver.set_mock_arp(mock);

        for _ in 0..1_000 {
            assert_eq!(
                resolver.resolve_mac(ip).as_deref(),
                Some("aa:bb:cc:dd:ee:ff")
            );
        }
        // Misses stay in memory too (negative cache).
        let missing = IpAddr::from_str("10.99.99.99").unwrap();
        for _ in 0..1_000 {
            assert_eq!(resolver.resolve_mac(missing), None);
        }

        assert_eq!(
            ARP_FILE_READS.load(std::sync::atomic::Ordering::SeqCst),
            before,
            "the query hot path must never read /proc/net/arp"
        );
    }

    #[test]
    fn test_arp_snapshot_refresh_is_the_only_reader() {
        let _guard = ARP_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let before = ARP_FILE_READS.load(std::sync::atomic::Ordering::SeqCst);
        let resolver = MacResolver::new();
        let _ = resolver.refresh_arp_now();
        assert_eq!(
            ARP_FILE_READS.load(std::sync::atomic::Ordering::SeqCst),
            before + 1,
            "refreshing the snapshot is the only path that reads /proc/net/arp"
        );
    }

    #[test]
    fn test_negative_cache_expiry_allows_fresh_snapshot_entry() {
        let resolver = MacResolver::with_ttls(Duration::from_secs(60), Duration::ZERO);
        let ip = IpAddr::from_str("192.168.1.51").unwrap();

        resolver.set_mock_arp(HashMap::new());
        assert_eq!(resolver.resolve_mac(ip), None);

        // Simulate the address appearing in the snapshot without an
        // install-time invalidation (for example a concurrent refresh). An
        // expired negative entry must not suppress the fresh value.
        resolver
            .snapshot
            .write()
            .unwrap()
            .insert(ip, "aa:bb:cc:dd:ee:01".to_string());
        assert_eq!(
            resolver.resolve_mac(ip).as_deref(),
            Some("aa:bb:cc:dd:ee:01"),
            "an expired negative entry must not suppress a fresh snapshot entry"
        );
    }

    #[test]
    fn test_mac_caches_are_bounded() {
        let resolver = MacResolver::new();
        let mut table = HashMap::new();
        for i in 0..(MAX_CACHE_ENTRIES + 64) {
            let ip = IpAddr::V4(std::net::Ipv4Addr::from(0x0a00_0000 + i as u32));
            table.insert(ip, "aa:bb:cc:dd:ee:ff".to_string());
        }
        resolver.set_mock_arp(table);

        for i in 0..(MAX_CACHE_ENTRIES + 64) {
            let ip = IpAddr::V4(std::net::Ipv4Addr::from(0x0a00_0000 + i as u32));
            assert!(resolver.resolve_mac(ip).is_some());
        }
        let missing = IpAddr::from_str("10.99.99.99").unwrap();
        for _ in 0..(MAX_CACHE_ENTRIES + 64) {
            assert_eq!(resolver.resolve_mac(missing), None);
        }

        assert!(resolver.cache.read().unwrap().len() <= MAX_CACHE_ENTRIES);
        assert!(resolver.negative.read().unwrap().len() <= MAX_CACHE_ENTRIES);
    }

    #[test]
    fn test_parse_arp_table_skips_invalid_and_zero_macs() {
        let content = format!(
            "IP address       HW type     Flags       HW address            Mask     Device\n\
             {}\
             {}\
             {}\
             {}",
            arp_line("192.168.1.1", "00:11:22:33:44:55"),
            arp_line("192.168.1.2", "00:00:00:00:00:00"),
            arp_line("not-an-ip", "aa:bb:cc:dd:ee:ff"),
            arp_line("192.168.1.3", "gg:hh:ii:jj:kk:ll"),
        );
        let table = parse_arp_table(&content);
        assert_eq!(table.len(), 1);
        assert_eq!(
            table.get(&IpAddr::from_str("192.168.1.1").unwrap()),
            Some(&"00:11:22:33:44:55".to_string())
        );
    }
}
