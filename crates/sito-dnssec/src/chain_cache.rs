//! Persistent DNSSEC chain/negative-DS cache.
//!
//! The cache records zones for which the delegation probe has established an
//! *authenticated* status: a signed delegation (DS present and validly signed
//! by the parent) or an unsigned delegation (authenticated DS denial). It never
//! records \`Unknown\` or network failures, so a transient resolver outage cannot
//! turn into a persistent downgrade.
//!
//! Entries are bounded and expire. The on-disk file is advisory: a missing,
//! corrupt or unreadable file starts an empty cache instead of failing startup.

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use dashmap::DashMap;
use hickory_proto::rr::{LowerName, Name};
use serde::{Deserialize, Serialize};
use tracing::warn;

/// Hard bound on persisted entries. Zones are re-discoverable, so eviction is
/// safe; dropping the cache never changes a validation decision on its own.
pub const CHAIN_CACHE_MAX_ENTRIES: usize = 8192;

/// Authenticated status of a zone/delegation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ZoneStatus {
    /// A DS RRset for the zone was authenticated: the zone must be signed.
    Signed,
    /// A DS denial for the zone was authenticated: the delegation is unsigned.
    Unsigned,
}

/// One authenticated chain-cache record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainEntry {
    pub status: ZoneStatus,
    /// UNIX timestamp after which the entry must be re-probed.
    pub expires_at: u32,
    /// UNIX timestamp when the entry was established.
    pub validated_at: u32,
}

/// Bounded, optionally persistent map of authenticated zone statuses.
///
/// The query path only touches the in-memory map. Disk I/O happens in
/// [`ChainCache::load`] (startup) and [`ChainCache::flush`] (background task or
/// shutdown); neither is called while validating a response.
pub struct ChainCache {
    entries: DashMap<LowerName, ChainEntry>,
    dirty: AtomicBool,
    path: Option<PathBuf>,
    max_entries: usize,
    /// Trust-anchor/NTA policy the entries were authenticated under. A change
    /// clears the cache so a stale `Unsigned` cannot override a new anchor.
    policy: Mutex<Option<String>>,
    /// Serializes disk flushes so the shutdown flush and the periodic flush
    /// task cannot write the same temporary file concurrently.
    flush_lock: Mutex<()>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct PersistedCache {
    #[serde(default)]
    entries: Vec<PersistedEntry>,
    #[serde(default)]
    policy: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct PersistedEntry {
    name: String,
    status: ZoneStatus,
    #[serde(default)]
    expires_at: u32,
    #[serde(default)]
    validated_at: u32,
}

impl ChainCache {
    /// Creates an empty cache. A `None` path keeps it purely in memory.
    #[must_use]
    pub fn new(path: Option<PathBuf>) -> Self {
        Self::with_max_entries(path, CHAIN_CACHE_MAX_ENTRIES)
    }

    /// Creates an empty cache with an explicit entry bound (test/diagnostics).
    #[must_use]
    pub fn with_max_entries(path: Option<PathBuf>, max_entries: usize) -> Self {
        Self {
            entries: DashMap::new(),
            dirty: AtomicBool::new(false),
            path,
            max_entries: max_entries.max(1),
            policy: Mutex::new(None),
            flush_lock: Mutex::new(()),
        }
    }

    /// Ensures the cache belongs to the trust-anchor/NTA policy identified by
    /// `fingerprint`, clearing every entry when it changed.
    ///
    /// Returns `true` when entries were dropped (or the policy was recorded for
    /// the first time), so the caller can log the invalidation.
    pub fn ensure_policy(&self, fingerprint: String) -> bool {
        // Serialize against `flush`: a flush must not snapshot entries and then
        // read a policy that was replaced in between (which would persist
        // pre-clear entries tagged with the new fingerprint).
        let _flush_guard = self
            .flush_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut policy = self
            .policy
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if policy.as_deref() == Some(fingerprint.as_str()) {
            return false;
        }
        let changed = !self.entries.is_empty() || policy.is_some();
        if changed {
            self.entries.clear();
            warn!(
                previous = ?policy.as_deref(),
                "DNSSEC chain cache policy changed; dropping cached delegation statuses"
            );
        }
        *policy = Some(fingerprint);
        self.dirty.store(true, Ordering::Release);
        changed
    }

    /// Removes `Unsigned` entries that the newly configured `anchor`
    /// contradicts: entries whose zone is at or above the anchor (the cached
    /// zone is an ancestor of, or equal to, the anchor).
    ///
    /// A legitimate unsigned child below the anchor is not contradicted and is
    /// deliberately kept. Signed entries remain valid: a new anchor never makes
    /// signed evidence weaker.
    pub fn invalidate_unsigned_at_or_above(&self, anchor: &LowerName) -> usize {
        // Serialize with `flush`: a flush snapshots the map under this lock, so
        // taking it here guarantees an entry invalidated now cannot be picked
        // up by a flush that starts afterwards. (A flush already in progress
        // completes before the removal; the dirty flag then makes the next
        // flush persist the invalidated view.)
        let _flush_guard = self
            .flush_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let stale: Vec<LowerName> = self
            .entries
            .iter()
            .filter(|entry| {
                entry.value().status == ZoneStatus::Unsigned && entry.key().zone_of(anchor)
            })
            .map(|entry| entry.key().clone())
            .collect();
        let removed = stale.len();
        for name in stale {
            self.entries.remove(&name);
        }
        if removed > 0 {
            self.dirty.store(true, Ordering::Release);
        }
        removed
    }

    /// Path of the backing file, if any.
    #[must_use]
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// Whether the cache has changes that have not been written yet.
    #[must_use]
    pub fn is_dirty(&self) -> bool {
        self.dirty.load(Ordering::Acquire)
    }

    /// Number of in-memory entries (including expired ones not yet pruned).
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the cache holds no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Loads the backing file, if present.
    ///
    /// Missing files are normal. Corrupt or unreadable files are ignored with a
    /// path-only warning; expired entries are dropped. This function never
    /// panics and never marks the cache dirty.
    pub fn load(&self, now: u32) {
        let Some(path) = self.path.as_deref() else {
            return;
        };
        let content = match std::fs::read_to_string(path) {
            Ok(content) => content,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
            Err(error) => {
                warn!(
                    path = %path.display(),
                    error = %error,
                    "Ignoring unreadable DNSSEC chain cache"
                );
                return;
            }
        };
        let Ok(persisted) = toml::from_str::<PersistedCache>(&content) else {
            warn!(
                path = %path.display(),
                "Ignoring corrupt DNSSEC chain cache"
            );
            return;
        };

        if let Some(policy) = persisted.policy {
            *self
                .policy
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(policy);
        }

        let mut expired = 0usize;
        for entry in persisted.entries {
            if entry.expires_at < now {
                expired += 1;
                continue;
            }
            let Ok(name) = Name::from_ascii(&entry.name) else {
                continue;
            };
            let lower = LowerName::from(&name);
            let loaded = ChainEntry {
                status: entry.status,
                expires_at: entry.expires_at,
                validated_at: entry.validated_at,
            };
            let replace = self
                .entries
                .get(&lower)
                .is_none_or(|existing| loaded.validated_at >= existing.validated_at);
            if replace {
                self.entries.insert(lower, loaded);
            }
        }
        if expired > 0 {
            warn!(
                path = %path.display(),
                expired,
                "Dropped expired DNSSEC chain-cache entries"
            );
        }
        self.enforce_bounds(now);
    }

    /// Returns the entry for `name` when it is still valid at `now`.
    #[must_use]
    pub fn get(&self, name: &LowerName, now: u32) -> Option<ChainEntry> {
        self.entries
            .get(name)
            .filter(|entry| entry.expires_at >= now)
            .map(|entry| entry.value().clone())
    }

    /// Records an authenticated status. Older evidence never overwrites newer
    /// evidence; the write is in memory only and marks the cache dirty.
    pub fn insert(&self, name: LowerName, status: ZoneStatus, expires_at: u32, now: u32) {
        if let Some(mut existing) = self.entries.get_mut(&name) {
            if now < existing.validated_at {
                return;
            }
            existing.status = status;
            existing.expires_at = expires_at;
            existing.validated_at = now;
        } else {
            self.entries.insert(
                name,
                ChainEntry {
                    status,
                    expires_at,
                    validated_at: now,
                },
            );
        }
        self.dirty.store(true, Ordering::Release);
        self.enforce_bounds(now);
    }

    /// Drops expired entries and returns how many were removed.
    pub fn retain(&self, now: u32) -> usize {
        let before = self.entries.len();
        self.entries.retain(|_, entry| entry.expires_at >= now);
        before.saturating_sub(self.entries.len())
    }

    /// The closest cached `Signed` zone covering `name` (including `name`).
    #[must_use]
    pub fn closest_signed(&self, name: &LowerName, now: u32) -> Option<(LowerName, u32)> {
        match self.deepest_entry(name, now) {
            Some((zone, entry)) if entry.status == ZoneStatus::Signed => {
                Some((zone, entry.expires_at))
            }
            _ => None,
        }
    }

    /// The closest cached `Unsigned` zone covering `name`, if the deepest known
    /// status for the name is an authenticated DS denial.
    #[must_use]
    pub fn covers_unsigned(&self, name: &LowerName, now: u32) -> Option<(LowerName, u32)> {
        match self.deepest_entry(name, now) {
            Some((zone, entry)) if entry.status == ZoneStatus::Unsigned => {
                Some((zone, entry.expires_at))
            }
            _ => None,
        }
    }

    fn deepest_entry(&self, name: &LowerName, now: u32) -> Option<(LowerName, ChainEntry)> {
        // Walk the ancestor chain instead of scanning the map: the closest
        // entry is exactly the deepest matching suffix, and this is O(labels).
        let mut current = name.clone();
        loop {
            if let Some(entry) = self.entries.get(&current)
                && entry.expires_at >= now
            {
                return Some((current, entry.value().clone()));
            }
            if current.is_root() {
                return None;
            }
            let base = current.base_name();
            if base == current {
                return None;
            }
            current = base;
        }
    }

    /// Prunes expired entries and, if still over the bound, evicts the oldest
    /// evidence first. The map is never cleared wholesale.
    fn enforce_bounds(&self, now: u32) {
        if self.entries.len() <= self.max_entries {
            return;
        }
        self.retain(now);
        if self.entries.len() <= self.max_entries {
            return;
        }
        let mut by_age: Vec<(LowerName, u32)> = self
            .entries
            .iter()
            .map(|entry| (entry.key().clone(), entry.validated_at))
            .collect();
        by_age.sort_by_key(|(_, validated_at)| *validated_at);
        let excess = self.entries.len().saturating_sub(self.max_entries);
        for (name, _) in by_age.into_iter().take(excess) {
            self.entries.remove(&name);
        }
        self.dirty.store(true, Ordering::Release);
    }

    /// Writes the cache atomically (temporary file + rename, mode 0600).
    ///
    /// Returns `Ok(())` when there is nothing to write or the write succeeded.
    /// On failure the dirty flag is restored so a later attempt retries.
    pub fn flush(&self) -> std::io::Result<()> {
        let Some(path) = self.path.as_deref() else {
            self.dirty.store(false, Ordering::Release);
            return Ok(());
        };
        // A shutdown flush can race the periodic flush task. Serialize the
        // whole write (including the shared `.tmp` path and rename).
        let _flush_guard = self
            .flush_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !self.dirty.swap(false, Ordering::AcqRel) {
            return Ok(());
        }

        let now = system_now();
        self.retain(now);
        let entries: Vec<PersistedEntry> = self
            .entries
            .iter()
            .map(|entry| PersistedEntry {
                name: entry.key().to_string(),
                status: entry.value().status,
                expires_at: entry.value().expires_at,
                validated_at: entry.value().validated_at,
            })
            .collect();
        let policy = self
            .policy
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let serialized = match toml::to_string(&PersistedCache { entries, policy }) {
            Ok(serialized) => serialized,
            Err(error) => {
                self.dirty.store(true, Ordering::Release);
                return Err(std::io::Error::other(error.to_string()));
            }
        };

        let tmp = tmp_path(path);
        let result = (|| {
            if let Some(parent) = path.parent()
                && !parent.as_os_str().is_empty()
            {
                std::fs::create_dir_all(parent)?;
            }
            write_private(&tmp, serialized.as_bytes())?;
            std::fs::rename(&tmp, path)
        })();
        if let Err(error) = &result {
            self.dirty.store(true, Ordering::Release);
            let _ = std::fs::remove_file(&tmp);
            warn!(
                path = %path.display(),
                error = %error,
                "Failed to flush DNSSEC chain cache"
            );
        }
        result
    }
}

fn tmp_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().map_or_else(
        || std::ffi::OsString::from("dnssec-chain-cache.toml"),
        std::ffi::OsStr::to_os_string,
    );
    name.push(".tmp");
    path.with_file_name(name)
}

#[cfg(unix)]
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    // `mode` only applies when the file is created; enforce it for a stale tmp.
    file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    file.write_all(bytes)?;
    file.sync_all()
}

#[cfg(not(unix))]
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

fn system_now() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn temp_path(tag: &str) -> PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "sito_chain_cache_{}_{}_{}",
            std::process::id(),
            tag,
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).expect("temp dir");
        dir.join("dnssec-chain-cache.toml")
    }

    fn name(name: &str) -> LowerName {
        LowerName::from(&Name::from_ascii(name).expect("name"))
    }

    #[test]
    fn test_cache_is_bounded_and_prunes_expired() {
        let cache = ChainCache::with_max_entries(None, 3);
        let now = system_now();
        cache.insert(
            name("expired.example."),
            ZoneStatus::Signed,
            now - 1,
            now - 2,
        );
        for index in 0..10 {
            cache.insert(
                name(&format!("z{index}.example.")),
                ZoneStatus::Signed,
                now + 3600,
                now + index,
            );
        }

        assert_eq!(cache.len(), 3, "the cache must stay within its bound");
        assert!(
            cache.get(&name("expired.example."), now).is_none(),
            "expired entries must be pruned"
        );
        // Oldest evidence is evicted first; the newest three survive.
        assert!(cache.get(&name("z9.example."), now).is_some());
        assert!(cache.get(&name("z8.example."), now).is_some());
        assert!(cache.get(&name("z7.example."), now).is_some());
        assert!(cache.get(&name("z0.example."), now).is_none());
    }

    #[test]
    fn test_dirty_flush_is_atomic() {
        let path = temp_path("flush");
        let cache = ChainCache::new(Some(path.clone()));
        let now = system_now();
        cache.insert(name("signed.example."), ZoneStatus::Signed, now + 600, now);

        assert!(cache.is_dirty());
        cache.flush().expect("flush");
        assert!(!cache.is_dirty(), "a successful flush clears dirty");
        assert!(path.exists(), "the cache file must exist after flush");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path)
                .expect("metadata")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "the cache must be private (0600)");
        }

        let tmp = tmp_path(&path);
        assert!(!tmp.exists(), "the temporary file must be renamed away");

        let reloaded = ChainCache::new(Some(path.clone()));
        reloaded.load(now);
        assert_eq!(
            reloaded.get(&name("signed.example."), now),
            Some(ChainEntry {
                status: ZoneStatus::Signed,
                expires_at: now + 600,
                validated_at: now,
            })
        );
        let _ = std::fs::remove_dir_all(path.parent().expect("parent"));
    }

    /// Minor: the periodic flush and the shutdown flush can run at the same
    /// time. Serialized flushes must leave one valid file, not a torn write.
    #[test]
    fn test_concurrent_flushes_leave_a_valid_file() {
        use std::sync::Arc;

        let path = temp_path("concurrent_flush");
        let cache = Arc::new(ChainCache::new(Some(path.clone())));
        let now = system_now();
        for index in 0..64 {
            cache.insert(
                name(&format!("z{index}.example.")),
                ZoneStatus::Signed,
                now + 600,
                now + index,
            );
        }

        let mut handles = Vec::new();
        for _ in 0..4 {
            let worker = cache.clone();
            handles.push(std::thread::spawn(move || {
                for _ in 0..8 {
                    worker.flush().expect("concurrent flush");
                }
            }));
        }
        for handle in handles {
            handle.join().expect("flush thread");
        }
        cache.flush().expect("final flush");

        let reloaded = ChainCache::new(Some(path.clone()));
        reloaded.load(now);
        assert_eq!(reloaded.len(), 64, "the final file must be intact");
        let _ = std::fs::remove_dir_all(path.parent().expect("parent"));
    }

    #[test]
    fn test_corrupt_file_is_ignored() {
        let path = temp_path("corrupt");
        std::fs::write(&path, "not = [ valid toml").expect("write corrupt file");
        let cache = ChainCache::new(Some(path.clone()));
        cache.load(system_now());
        assert!(cache.is_empty(), "a corrupt file must load as empty");
        let _ = std::fs::remove_dir_all(path.parent().expect("parent"));
    }

    /// An unsigned entry invalidated before a flush must not be persisted by
    /// that flush; signed evidence below the anchor survives.
    #[test]
    fn test_invalidated_unsigned_entries_are_not_persisted() {
        let path = temp_path("invalidate");
        let cache = ChainCache::new(Some(path.clone()));
        let now = system_now();
        cache.insert(name("corp."), ZoneStatus::Unsigned, now + 600, now);
        cache.insert(name("signed.corp."), ZoneStatus::Signed, now + 600, now + 1);

        assert_eq!(cache.invalidate_unsigned_at_or_above(&name("corp.")), 1);
        cache.flush().expect("flush");

        let reloaded = ChainCache::new(Some(path.clone()));
        reloaded.load(now);
        assert!(
            reloaded.get(&name("corp."), now).is_none(),
            "the invalidated unsigned entry must not reach disk"
        );
        assert!(
            reloaded.get(&name("signed.corp."), now).is_some(),
            "signed evidence below the anchor must survive"
        );

        let _ = std::fs::remove_dir_all(path.parent().expect("parent"));
    }

    /// I1: a trust-anchor/NTA policy change must drop cached `Unsigned`
    /// evidence, and the same policy must keep it.
    #[test]
    fn test_policy_change_clears_cached_statuses() {
        let cache = ChainCache::new(None);
        let now = system_now();
        assert!(
            !cache.ensure_policy("v1-aaaa".to_string()),
            "recording the initial policy with an empty cache is not a change"
        );
        cache.insert(name("corp."), ZoneStatus::Unsigned, now + 600, now);
        assert!(
            !cache.ensure_policy("v1-aaaa".to_string()),
            "the unchanged policy must preserve entries"
        );
        assert!(cache.get(&name("corp."), now).is_some());

        assert!(
            cache.ensure_policy("v1-bbbb".to_string()),
            "a changed policy must invalidate the cache"
        );
        assert!(cache.is_empty());
    }

    #[test]
    fn test_unsigned_coverage_uses_deepest_entry() {
        let cache = ChainCache::new(None);
        let now = system_now();
        cache.insert(name("example."), ZoneStatus::Unsigned, now + 60, now);
        cache.insert(
            name("signed.example."),
            ZoneStatus::Signed,
            now + 60,
            now + 1,
        );

        assert_eq!(
            cache.covers_unsigned(&name("www.example."), now),
            Some((name("example."), now + 60))
        );
        assert_eq!(
            cache.covers_unsigned(&name("www.signed.example."), now),
            None,
            "a deeper signed zone overrides an unsigned ancestor"
        );
        assert_eq!(
            cache.closest_signed(&name("www.signed.example."), now),
            Some((name("signed.example."), now + 60))
        );
    }
}
