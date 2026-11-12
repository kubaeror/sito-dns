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

/// On-disk format version. Bumped whenever previously persisted evidence is no
/// longer safe to trust. Version 1 (implicit: files without a version field)
/// could contain `Signed` root/TLD entries recorded from fetched chain-helper
/// RRSIGs, which made unrelated names look like stripped downgrades.
const CHAIN_CACHE_FORMAT_VERSION: u32 = 2;

/// Authenticated status of a zone/delegation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ZoneStatus {
    /// A DS RRset for the zone was authenticated: the zone must be signed.
    Signed,
    /// A DS denial for the zone was authenticated: the delegation is unsigned.
    Unsigned,
}

/// Trust-anchor/NTA policy under which cached statuses were authenticated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyState {
    /// Stable fingerprint of the full trust-anchor/NTA configuration.
    pub fingerprint: String,
    /// Configured anchor zone names, normalized and sorted.
    pub anchors: Vec<String>,
    /// Configured negative trust anchor names, normalized and sorted.
    pub ntas: Vec<String>,
}

/// Internal policy record: the public state plus whether the anchor/NTA lists
/// came from a format that explicitly persisted them. A legacy fingerprint
/// without metadata must full-clear on any policy change, while a new-format
/// policy with genuinely empty lists can still diff/target additions.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PolicyRecord {
    state: PolicyState,
    metadata_known: bool,
    /// Monotonic policy generation. Incremented on every effective policy
    /// change. Validators carry the generation they were built under, and an
    /// insert from an older generation is rejected: this closes the hot-reload
    /// race where an in-flight query validates under the old policy after
    /// `ensure_policy` flushed the cache.
    generation: u64,
}

/// Effect of [`ChainCache::ensure_policy`] on the cached entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyChange {
    /// The policy fingerprint is unchanged; nothing was touched.
    None,
    /// The policy cannot be diffed safely; every entry was dropped.
    FullClear,
    /// Only these anchors were added; affected cached `Unsigned` zones were
    /// invalidated and every other entry was preserved.
    AddedAnchors(Vec<LowerName>),
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
    /// Trust-anchor/NTA policy the entries were authenticated under. This lock
    /// also serializes entry snapshots during a flush: a flush must never
    /// combine entries from one policy with the metadata of another.
    policy: Mutex<Option<PolicyRecord>>,
    /// Serializes the whole flush (snapshot, serialization, temp-file write,
    /// rename and parent fsync) so a shutdown flush and the periodic flush
    /// task cannot interleave and an older snapshot cannot overwrite a newer
    /// one. Policy changes never take this lock, so a slow disk write cannot
    /// block them.
    flush_lock: Mutex<()>,
    /// Test-only hook invoked after the snapshot is released and before the
    /// disk write, used to prove policy changes are not blocked by I/O.
    #[cfg(test)]
    flush_hook: Mutex<Option<Box<dyn Fn() + Send + Sync>>>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct PersistedCache {
    /// Format version. `0` (missing) marks files written before versioning was
    /// introduced; their entries were produced by the buggy zone-evidence
    /// rules and are migrated on load.
    #[serde(default)]
    format_version: u32,
    #[serde(default)]
    entries: Vec<PersistedEntry>,
    #[serde(default)]
    policy: Option<String>,
    /// Anchor zones in force when the entries were authenticated. `None` in
    /// files written before 1.9.1, which forces a safe full clear on the first
    /// policy change. `Some(empty)` is a new-format policy that genuinely has
    /// no configured non-root anchors.
    #[serde(default)]
    policy_anchors: Option<Vec<String>>,
    /// Negative trust anchors in force when the entries were authenticated.
    /// `None` marks legacy files exactly like `policy_anchors`.
    #[serde(default)]
    policy_ntas: Option<Vec<String>>,
    /// Monotonic policy generation that produced the entries. Absent in older
    /// files (treated as generation 0).
    #[serde(default)]
    policy_generation: u64,
}

/// Counters collected while loading a persisted cache (used for diagnostics
/// and tests; malformed entries are skipped, never trusted).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct LoadStats {
    expired: usize,
    malformed: usize,
    /// Unsafe legacy root/TLD `Signed` entries dropped by the format upgrade.
    migrated: usize,
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
            #[cfg(test)]
            flush_hook: Mutex::new(None),
        }
    }

    /// Ensures the cache belongs to the trust-anchor/NTA policy identified by
    /// `fingerprint` and described by `anchors`/`ntas`.
    ///
    /// An unchanged fingerprint is a no-op. A changed policy that cannot be
    /// diffed safely (missing metadata or an NTA change) drops every entry.
    /// Adding anchors only invalidates cached `Unsigned` zones at or above the
    /// added anchors, so legitimate unsigned children below an unchanged
    /// anchor survive a reload. Any removal or non-additive fingerprint change
    /// (for example anchor key material) also full-clears: evidence must never
    /// survive an anchor removal.
    pub fn ensure_policy(
        &self,
        fingerprint: String,
        anchors: Vec<String>,
        ntas: Vec<String>,
    ) -> PolicyChange {
        let anchors = normalize_policy_names(anchors);
        let ntas = normalize_policy_names(ntas);
        let mut policy = sito_core::sync::lock_or_recover(&self.policy);

        let Some(previous) = policy.clone() else {
            // A legacy file can contain entries with no policy at all. Those
            // entries were never authenticated under the current policy, so
            // they must not be adopted by the first `ensure_policy` call.
            if !self.entries.is_empty() {
                warn!(
                    removed = self.entries.len(),
                    "DNSSEC chain cache had entries without policy metadata; dropping cached delegation statuses"
                );
                self.entries.clear();
            }
            *policy = Some(PolicyRecord {
                state: PolicyState {
                    fingerprint,
                    anchors,
                    ntas,
                },
                metadata_known: true,
                generation: 1,
            });
            self.dirty.store(true, Ordering::Release);
            return PolicyChange::FullClear;
        };

        if previous.state.fingerprint == fingerprint {
            return PolicyChange::None;
        }
        let next_generation = previous.generation.saturating_add(1);

        // Files written before 1.9.1 carry a fingerprint but no anchor/NTA
        // metadata. We cannot prove which cached `Unsigned` zones are
        // legitimate under the new policy, so clear rather than risk a stale
        // fail-open.
        if !previous.metadata_known {
            self.entries.clear();
            warn!(
                previous = ?previous.state.fingerprint,
                "DNSSEC chain cache policy changed without anchor metadata; dropping cached delegation statuses"
            );
            *policy = Some(PolicyRecord {
                state: PolicyState {
                    fingerprint,
                    anchors,
                    ntas,
                },
                metadata_known: true,
                generation: next_generation,
            });
            self.dirty.store(true, Ordering::Release);
            return PolicyChange::FullClear;
        }

        if previous.state.ntas != ntas {
            self.entries.clear();
            warn!(
                previous = ?previous.state.fingerprint,
                "DNSSEC chain cache NTA policy changed; dropping cached delegation statuses"
            );
            *policy = Some(PolicyRecord {
                state: PolicyState {
                    fingerprint,
                    anchors,
                    ntas,
                },
                metadata_known: true,
                generation: next_generation,
            });
            self.dirty.store(true, Ordering::Release);
            return PolicyChange::FullClear;
        }

        let removed_any = previous
            .state
            .anchors
            .iter()
            .any(|anchor| !anchors.contains(anchor));
        let added: Vec<LowerName> = anchors
            .iter()
            .filter(|anchor| !previous.state.anchors.contains(anchor))
            .filter_map(|anchor| {
                Name::from_ascii(anchor)
                    .ok()
                    .map(|name| LowerName::from(&name))
            })
            .collect();
        // Only a genuine addition may keep evidence. An anchor removal (or a
        // fingerprint-only change such as new key material for the same zone)
        // invalidates signed and unsigned evidence alike, so fail closed with
        // a full clear instead of returning an empty targeted change.
        if removed_any || added.is_empty() {
            self.entries.clear();
            warn!(
                previous = ?previous.state.fingerprint,
                "DNSSEC chain cache trust-anchor policy changed without new anchors; dropping cached delegation statuses"
            );
            *policy = Some(PolicyRecord {
                state: PolicyState {
                    fingerprint,
                    anchors,
                    ntas,
                },
                metadata_known: true,
                generation: next_generation,
            });
            self.dirty.store(true, Ordering::Release);
            return PolicyChange::FullClear;
        }

        let mut removed = 0usize;
        for anchor in &added {
            removed += self.remove_unsigned_at_or_above_locked(anchor);
        }
        if removed > 0 {
            warn!(
                removed,
                added = added.len(),
                "DNSSEC trust-anchor policy added anchors; dropped contradicted unsigned cache entries"
            );
        }
        *policy = Some(PolicyRecord {
            state: PolicyState {
                fingerprint,
                anchors,
                ntas,
            },
            metadata_known: true,
            generation: next_generation,
        });
        // The metadata (at least the fingerprint) changed even when no entry
        // was invalidated, so the next flush must persist it.
        self.dirty.store(true, Ordering::Release);
        PolicyChange::AddedAnchors(added)
    }

    /// Removes `Unsigned` entries that the newly configured `anchor`
    /// contradicts: entries whose zone is at or above the anchor (the cached
    /// zone is an ancestor of, or equal to, the anchor).
    ///
    /// A legitimate unsigned child below the anchor is not contradicted and is
    /// deliberately kept. Signed entries remain valid: a new anchor never makes
    /// signed evidence weaker.
    pub fn invalidate_unsigned_at_or_above(&self, anchor: &LowerName) -> usize {
        // This is the state lock, not `flush_lock`: invalidating memory must
        // never wait for an in-progress disk write. A flush snapshots entries
        // under the same lock, so it observes either the pre- or post-clear
        // view consistently with the policy metadata.
        let _policy_guard = sito_core::sync::lock_or_recover(&self.policy);
        let removed = self.remove_unsigned_at_or_above_locked(anchor);
        if removed > 0 {
            self.dirty.store(true, Ordering::Release);
        }
        removed
    }

    /// Caller must hold the `policy` state lock.
    fn remove_unsigned_at_or_above_locked(&self, anchor: &LowerName) -> usize {
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
    /// path-only warning; expired entries and malformed individual entries are
    /// dropped. This function never panics. A legacy-format file may mark the
    /// cache dirty so the migrated view is persisted by the next flush.
    pub fn load(&self, now: u32) {
        let _ = self.load_with_stats(now);
    }

    /// [`Self::load`] with counters for diagnostics/tests.
    fn load_with_stats(&self, now: u32) -> LoadStats {
        let mut stats = LoadStats::default();
        let Some(path) = self.path.as_deref() else {
            return stats;
        };
        let content = match std::fs::read_to_string(path) {
            Ok(content) => content,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return stats,
            Err(error) => {
                warn!(
                    path = %path.display(),
                    error = %error,
                    "Ignoring unreadable DNSSEC chain cache"
                );
                return stats;
            }
        };
        let Ok(persisted) = toml::from_str::<PersistedCache>(&content) else {
            warn!(
                path = %path.display(),
                "Ignoring corrupt DNSSEC chain cache"
            );
            return stats;
        };

        let PersistedCache {
            format_version,
            entries,
            policy,
            policy_anchors,
            policy_ntas,
            policy_generation,
        } = persisted;
        // Older formats recorded root/TLD `Signed` evidence from fetched
        // chain-helper RRSIGs. Such an entry covers every descendant and would
        // otherwise turn the first new signed zone after an upgrade into a
        // false SERVFAIL, so prune it even when the policy fingerprint is
        // unchanged. Deeper `Signed` entries came from a zone that actually
        // signed data and remain valid; `Unsigned` entries only cause a
        // re-probe and are safe to keep.
        let legacy_format = format_version < CHAIN_CACHE_FORMAT_VERSION;

        if let Some(fingerprint) = policy {
            let metadata_known = policy_anchors.is_some() && policy_ntas.is_some();
            *sito_core::sync::lock_or_recover(&self.policy) = Some(PolicyRecord {
                state: PolicyState {
                    fingerprint,
                    anchors: normalize_policy_names(policy_anchors.unwrap_or_default()),
                    ntas: normalize_policy_names(policy_ntas.unwrap_or_default()),
                },
                metadata_known,
                generation: policy_generation,
            });
        }

        for entry in entries {
            if entry.expires_at < now {
                stats.expired += 1;
                continue;
            }
            let Ok(name) = Name::from_ascii(&entry.name) else {
                // Path-only diagnostics: the malformed name is untrusted input
                // and must not be echoed into logs.
                stats.malformed += 1;
                continue;
            };
            let lower = LowerName::from(&name);
            if legacy_format && entry.status == ZoneStatus::Signed && lower.num_labels() <= 1 {
                stats.migrated += 1;
                continue;
            }
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
        if stats.expired > 0 {
            warn!(
                path = %path.display(),
                expired = stats.expired,
                "Dropped expired DNSSEC chain-cache entries"
            );
        }
        if stats.malformed > 0 {
            warn!(
                path = %path.display(),
                malformed = stats.malformed,
                "Skipped malformed DNSSEC chain-cache entries"
            );
        }
        if stats.migrated > 0 {
            warn!(
                path = %path.display(),
                dropped = stats.migrated,
                "Dropped unsafe legacy root/TLD signed DNSSEC chain-cache entries"
            );
            // Persist the migrated view so the unsafe entries cannot come back
            // if the process exits before the next policy change.
            self.dirty.store(true, Ordering::Release);
        }
        self.enforce_bounds(now);
        stats
    }

    /// Returns the entry for `name` when it is still valid at `now`.
    #[must_use]
    pub fn get(&self, name: &LowerName, now: u32) -> Option<ChainEntry> {
        self.entries
            .get(name)
            .filter(|entry| entry.expires_at >= now)
            .map(|entry| entry.value().clone())
    }

    /// Current monotonic policy generation (0 before the first
    /// [`Self::ensure_policy`]).
    #[must_use]
    pub fn policy_generation(&self) -> u64 {
        sito_core::sync::lock_or_recover(&self.policy)
            .as_ref()
            .map_or(0, |record| record.generation)
    }

    /// Records an authenticated status under the cache's current policy
    /// generation. Convenience for tests and non-validator callers.
    ///
    /// Production validation uses [`Self::insert_for_generation`] so an
    /// in-flight query built under an older policy cannot write after a reload.
    pub fn insert(&self, name: LowerName, status: ZoneStatus, expires_at: u32, now: u32) {
        let _policy_guard = sito_core::sync::lock_or_recover(&self.policy);
        self.insert_locked(name, status, expires_at, now);
    }

    /// Records an authenticated status only when `generation` matches the
    /// cache's current policy generation. Returns `false` when the policy
    /// changed after the validator was built (the insert is rejected).
    pub fn insert_for_generation(
        &self,
        name: LowerName,
        status: ZoneStatus,
        expires_at: u32,
        now: u32,
        generation: u64,
    ) -> bool {
        // Hold the policy lock across the generation check and the insert:
        // `ensure_policy` takes the same lock, so an in-flight insert either
        // completes before the flush or observes the new generation and is
        // rejected. It can never land between the flush and the metadata swap.
        let policy = sito_core::sync::lock_or_recover(&self.policy);
        let current = policy.as_ref().map_or(0, |record| record.generation);
        if current != generation {
            return false;
        }
        self.insert_locked(name, status, expires_at, now);
        true
    }

    /// Caller must hold the `policy` lock. Older evidence never overwrites
    /// newer evidence; the write is in memory only and marks the cache dirty.
    fn insert_locked(&self, name: LowerName, status: ZoneStatus, expires_at: u32, now: u32) {
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

    /// Writes the cache atomically (temporary file + rename + parent fsync,
    /// mode 0600).
    ///
    /// The state lock is held only while snapshotting entries and policy; the
    /// disk write uses `flush_lock` alone so a slow filesystem cannot block a
    /// policy change. (`flush_lock` still spans the whole flush to serialize
    /// snapshots and prevent an older write from overwriting a newer one.)
    /// Returns `Ok(())` when there is nothing to write or the write succeeded.
    /// On failure the dirty flag is restored so a later attempt retries.
    pub fn flush(&self) -> std::io::Result<()> {
        let Some(path) = self.path.as_deref() else {
            self.dirty.store(false, Ordering::Release);
            return Ok(());
        };
        // A shutdown flush can race the periodic flush task. Serialize the
        // whole flush so an older snapshot can never overwrite a newer one.
        // Policy operations never take this lock.
        let _flush_guard = sito_core::sync::lock_or_recover(&self.flush_lock);
        let now = system_now();
        let persisted = {
            let policy = sito_core::sync::lock_or_recover(&self.policy);
            if !self.dirty.swap(false, Ordering::AcqRel) {
                return Ok(());
            }
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
            match policy.as_ref() {
                Some(record) => PersistedCache {
                    format_version: CHAIN_CACHE_FORMAT_VERSION,
                    entries,
                    policy: Some(record.state.fingerprint.clone()),
                    policy_anchors: record.metadata_known.then(|| record.state.anchors.clone()),
                    policy_ntas: record.metadata_known.then(|| record.state.ntas.clone()),
                    policy_generation: record.generation,
                },
                None => PersistedCache {
                    format_version: CHAIN_CACHE_FORMAT_VERSION,
                    entries,
                    policy: None,
                    policy_anchors: None,
                    policy_ntas: None,
                    policy_generation: 0,
                },
            }
        };
        let serialized = match toml::to_string(&persisted) {
            Ok(serialized) => serialized,
            Err(error) => {
                self.dirty.store(true, Ordering::Release);
                return Err(std::io::Error::other(error.to_string()));
            }
        };

        #[cfg(test)]
        {
            let hook = sito_core::sync::lock_or_recover(&self.flush_hook);
            if let Some(hook) = hook.as_ref() {
                hook();
            }
        }

        let tmp = tmp_path(path);
        let result = (|| {
            if let Some(parent) = path.parent()
                && !parent.as_os_str().is_empty()
            {
                std::fs::create_dir_all(parent)?;
            }
            write_private(&tmp, serialized.as_bytes())?;
            std::fs::rename(&tmp, path)?;
            sync_parent_dir(path)
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

    #[cfg(test)]
    fn set_flush_hook(&self, hook: Option<Box<dyn Fn() + Send + Sync>>) {
        *sito_core::sync::lock_or_recover(&self.flush_hook) = hook;
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

/// Normalizes policy domain lists to lowercase dotted names, sorted and
/// deduplicated, so equivalent configurations compare equal.
fn normalize_policy_names<I, S>(values: I) -> Vec<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut names: Vec<String> = values
        .into_iter()
        .map(|value| {
            let trimmed = value.as_ref().trim().to_ascii_lowercase();
            if trimmed.is_empty() || trimmed.ends_with('.') {
                trimmed
            } else {
                format!("{trimmed}.")
            }
        })
        .filter(|value| !value.is_empty())
        .collect();
    names.sort_unstable();
    names.dedup();
    names
}

/// fsyncs the directory containing `path` so the rename is durable.
fn sync_parent_dir(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        std::fs::File::open(parent)?.sync_all()
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
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

    /// A failed write must restore the dirty flag so the next flush retries.
    #[test]
    fn test_failed_flush_restores_dirty_flag() {
        let path = temp_path("flush_failure");
        let parent = path.parent().expect("parent");
        let blocker = parent.join("blocker");
        std::fs::write(&blocker, b"not a directory").expect("write blocker");
        let unwritable = blocker.join("dnssec-chain-cache.toml");
        let cache = ChainCache::new(Some(unwritable));
        let now = system_now();
        cache.insert(name("signed.example."), ZoneStatus::Signed, now + 600, now);

        assert!(cache.is_dirty());
        assert!(
            cache.flush().is_err(),
            "writing through a non-directory parent must fail"
        );
        assert!(
            cache.is_dirty(),
            "a failed flush must restore the dirty flag"
        );

        let _ = std::fs::remove_dir_all(parent);
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
        assert_eq!(
            cache.ensure_policy("v1-aaaa".to_string(), Vec::new(), Vec::new()),
            PolicyChange::FullClear,
            "recording the initial policy is a safe migration clear"
        );
        cache.insert(name("corp."), ZoneStatus::Unsigned, now + 600, now);
        assert_eq!(
            cache.ensure_policy("v1-aaaa".to_string(), Vec::new(), Vec::new()),
            PolicyChange::None,
            "the unchanged policy must preserve entries"
        );
        assert!(cache.get(&name("corp."), now).is_some());

        assert_eq!(
            cache.ensure_policy("v1-bbbb".to_string(), Vec::new(), Vec::new()),
            PolicyChange::FullClear,
            "a fingerprint change without an anchor addition must clear safely"
        );
        assert!(cache.is_empty());
    }

    /// Adding an unrelated anchor must not evict a legitimate unsigned child
    /// under an anchor that was already configured.
    #[test]
    fn test_unrelated_anchor_preserves_unsigned_child() {
        let cache = ChainCache::new(None);
        let now = system_now();
        assert_eq!(
            cache.ensure_policy(
                "fp-1".to_string(),
                vec!["signed.example.".to_string()],
                Vec::new()
            ),
            PolicyChange::FullClear
        );
        let child = name("unsigned.signed.example.");
        cache.insert(child.clone(), ZoneStatus::Unsigned, now + 600, now);

        let change = cache.ensure_policy(
            "fp-2".to_string(),
            vec![
                "signed.example.".to_string(),
                "unrelated.example.".to_string(),
            ],
            Vec::new(),
        );
        assert_eq!(
            change,
            PolicyChange::AddedAnchors(vec![name("unrelated.example.")])
        );
        assert!(
            cache.get(&child, now).is_some(),
            "an unrelated added anchor must not evict a legitimate unsigned child"
        );
    }

    /// A new-format policy that genuinely has no configured anchors/NTAs must
    /// still support targeted additions. The old empty-list sentinel treated
    /// this as legacy metadata and full-cleared an unrelated unsigned child.
    #[test]
    fn test_empty_new_format_policy_preserves_unrelated_unsigned_child() {
        let path = temp_path("empty_policy_restart");
        let now = system_now();
        let cache = ChainCache::new(Some(path.clone()));
        assert_eq!(
            cache.ensure_policy("fp-1".to_string(), Vec::new(), Vec::new()),
            PolicyChange::FullClear
        );
        let child = name("unsigned.signed.example.");
        cache.insert(child.clone(), ZoneStatus::Unsigned, now + 600, now);
        cache.flush().expect("flush");

        // Reload proves the empty-but-present lists were persisted explicitly,
        // not mistaken for legacy missing metadata.
        let reloaded = ChainCache::new(Some(path.clone()));
        reloaded.load(now);
        assert_eq!(
            reloaded.ensure_policy(
                "fp-2".to_string(),
                vec!["unrelated.example.".to_string()],
                Vec::new()
            ),
            PolicyChange::AddedAnchors(vec![name("unrelated.example.")]),
            "adding an unrelated anchor to an empty new-format policy is targeted"
        );
        assert!(
            reloaded.get(&child, now).is_some(),
            "an unrelated addition must preserve an existing unsigned child"
        );

        let _ = std::fs::remove_dir_all(path.parent().expect("parent"));
    }

    /// An added anchor at or above a cached unsigned zone contradicts that
    /// cached denial and must evict it.
    #[test]
    fn test_anchor_at_or_above_unsigned_zone_invalidates() {
        let cache = ChainCache::new(None);
        let now = system_now();
        assert_eq!(
            cache.ensure_policy(
                "fp-1".to_string(),
                vec!["parent.example.".to_string()],
                Vec::new()
            ),
            PolicyChange::FullClear
        );

        let corp = name("corp.");
        cache.insert(corp.clone(), ZoneStatus::Unsigned, now + 600, now);
        assert_eq!(
            cache.ensure_policy(
                "fp-2".to_string(),
                vec!["parent.example.".to_string(), "corp.".to_string(),],
                Vec::new()
            ),
            PolicyChange::AddedAnchors(vec![corp.clone()])
        );
        assert!(
            cache.get(&corp, now).is_none(),
            "an anchor equal to the cached unsigned zone must invalidate it"
        );

        // Re-seed and add a deeper anchor: the cached zone is an ancestor of
        // the anchor and must still be invalidated.
        cache.insert(corp.clone(), ZoneStatus::Unsigned, now + 600, now);
        assert_eq!(
            cache.ensure_policy(
                "fp-3".to_string(),
                vec![
                    "parent.example.".to_string(),
                    "corp.".to_string(),
                    "sub.corp.".to_string(),
                ],
                Vec::new()
            ),
            PolicyChange::AddedAnchors(vec![name("sub.corp.")])
        );
        assert!(
            cache.get(&corp, now).is_none(),
            "an anchor below the cached unsigned zone must invalidate the ancestor"
        );
    }

    /// Removing an anchor (or any non-additive fingerprint change) must clear
    /// all evidence, including `Signed`, rather than return an empty targeted
    /// change that could let old trust survive.
    #[test]
    fn test_anchor_removal_full_clears_cache() {
        let cache = ChainCache::new(None);
        let now = system_now();
        assert_eq!(
            cache.ensure_policy(
                "fp-1".to_string(),
                vec!["a.example.".to_string(), "b.example.".to_string()],
                Vec::new()
            ),
            PolicyChange::FullClear
        );
        cache.insert(
            name("unsigned.a.example."),
            ZoneStatus::Unsigned,
            now + 600,
            now,
        );
        cache.insert(
            name("signed.b.example."),
            ZoneStatus::Signed,
            now + 600,
            now + 1,
        );

        assert_eq!(
            cache.ensure_policy(
                "fp-2".to_string(),
                vec!["a.example.".to_string()],
                Vec::new()
            ),
            PolicyChange::FullClear,
            "anchor removal must full-clear cached evidence"
        );
        assert!(cache.is_empty());
    }

    /// Any NTA change makes previously authenticated classifications unsafe.
    #[test]
    fn test_nta_change_clears_cache() {
        let cache = ChainCache::new(None);
        let now = system_now();
        assert_eq!(
            cache.ensure_policy(
                "fp-1".to_string(),
                vec!["signed.example.".to_string()],
                vec!["nta-one.example.".to_string()]
            ),
            PolicyChange::FullClear
        );
        cache.insert(
            name("unsigned.signed.example."),
            ZoneStatus::Unsigned,
            now + 600,
            now,
        );

        assert_eq!(
            cache.ensure_policy(
                "fp-2".to_string(),
                vec!["signed.example.".to_string()],
                vec!["nta-two.example.".to_string()]
            ),
            PolicyChange::FullClear,
            "an NTA diff must return FullClear"
        );
        assert!(cache.is_empty(), "an NTA diff must empty the cache");
    }

    /// Policy metadata and entries survive a flush/reload cycle; an unchanged
    /// fingerprint after reload is a no-op.
    #[test]
    fn test_policy_anchors_survive_restart() {
        let path = temp_path("policy_restart");
        let now = system_now();
        let cache = ChainCache::new(Some(path.clone()));
        assert_eq!(
            cache.ensure_policy(
                "fp-1".to_string(),
                vec!["signed.example.".to_string(), "corp.".to_string(),],
                vec!["nta.example.".to_string()]
            ),
            PolicyChange::FullClear
        );
        let child = name("unsigned.signed.example.");
        cache.insert(child.clone(), ZoneStatus::Unsigned, now + 600, now);
        cache.flush().expect("flush");

        let reloaded = ChainCache::new(Some(path.clone()));
        reloaded.load(now);
        let record = reloaded
            .policy
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
            .expect("policy metadata must survive restart");
        assert!(record.metadata_known);
        let state = record.state;
        assert_eq!(state.fingerprint, "fp-1");
        assert_eq!(
            state.anchors,
            vec!["corp.".to_string(), "signed.example.".to_string()]
        );
        assert_eq!(state.ntas, vec!["nta.example.".to_string()]);
        assert!(
            reloaded.get(&child, now).is_some(),
            "entries must survive restart with intact policy metadata"
        );
        assert_eq!(
            reloaded.ensure_policy(
                "fp-1".to_string(),
                vec!["corp.".to_string(), "signed.example.".to_string(),],
                vec!["nta.example.".to_string()]
            ),
            PolicyChange::None,
            "an unchanged policy after reload must be a no-op"
        );
        assert!(reloaded.get(&child, now).is_some());

        let _ = std::fs::remove_dir_all(path.parent().expect("parent"));
    }

    /// A legacy file with a fingerprint but no `policy_anchors`/`policy_ntas`
    /// must full-clear when the policy changes, because the old anchors are
    /// unknown and a stale `Unsigned` could otherwise become a fail-open.
    #[test]
    fn test_legacy_policy_file_without_anchor_metadata_full_clears_on_change() {
        let path = temp_path("legacy_policy_metadata");
        let now = system_now();
        let cache = ChainCache::new(Some(path.clone()));
        std::fs::write(
            &path,
            format!(
                "policy = \"v1-legacy\"\n\n[[entries]]\nname = \"unsigned.signed.example.\"\nstatus = \"unsigned\"\nexpires_at = {}\nvalidated_at = {}\n",
                now + 600,
                now
            ),
        )
        .expect("write legacy cache");

        cache.load(now);
        let stale = name("unsigned.signed.example.");
        assert!(
            cache.get(&stale, now).is_some(),
            "the legacy entry itself must still load"
        );
        assert_eq!(
            cache.ensure_policy(
                "v1-new".to_string(),
                vec!["signed.example.".to_string()],
                Vec::new()
            ),
            PolicyChange::FullClear,
            "missing anchor metadata must force a safe full clear"
        );
        assert!(
            cache.is_empty(),
            "no entry may survive a legacy-metadata policy change"
        );

        let _ = std::fs::remove_dir_all(path.parent().expect("parent"));
    }

    /// A legacy file without even a policy fingerprint can still load entries,
    /// but the first `ensure_policy` must not adopt them.
    #[test]
    fn test_legacy_file_without_policy_full_clears_on_first_policy() {
        let path = temp_path("legacy_no_policy");
        let now = system_now();
        let cache = ChainCache::new(Some(path.clone()));
        std::fs::write(
            &path,
            format!(
                "[[entries]]\nname = \"unsigned.signed.example.\"\nstatus = \"unsigned\"\nexpires_at = {}\nvalidated_at = {}\n",
                now + 600,
                now
            ),
        )
        .expect("write legacy cache");

        cache.load(now);
        let stale = name("unsigned.signed.example.");
        assert!(
            cache.get(&stale, now).is_some(),
            "the legacy entry itself must still load"
        );
        assert_eq!(
            cache.ensure_policy("v1-new".to_string(), Vec::new(), Vec::new()),
            PolicyChange::FullClear
        );
        assert!(
            cache.is_empty(),
            "entries with no prior policy must not be adopted"
        );

        let _ = std::fs::remove_dir_all(path.parent().expect("parent"));
    }

    /// A flush blocked in disk I/O must not prevent a policy change from
    /// completing: the state lock is released before the write.
    #[test]
    fn test_flush_does_not_block_policy_change() {
        use std::sync::{Arc, Condvar, Mutex};

        let path = temp_path("slow_flush");
        let cache = Arc::new(ChainCache::new(Some(path.clone())));
        let now = system_now();
        assert_eq!(
            cache.ensure_policy(
                "fp-1".to_string(),
                vec!["base.example.".to_string()],
                Vec::new()
            ),
            PolicyChange::FullClear
        );
        cache.insert(name("corp."), ZoneStatus::Unsigned, now + 600, now);

        let entered = Arc::new((Mutex::new(false), Condvar::new()));
        let release = Arc::new((Mutex::new(false), Condvar::new()));
        {
            let entered = entered.clone();
            let release = release.clone();
            cache.set_flush_hook(Some(Box::new(move || {
                let (lock, condvar) = &*entered;
                *lock
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = true;
                condvar.notify_all();
                let (lock, condvar) = &*release;
                let mut released = lock
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                while !*released {
                    released = condvar
                        .wait(released)
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                }
            })));
        }

        let flush_cache = cache.clone();
        let flush = std::thread::spawn(move || flush_cache.flush().expect("flush"));
        {
            let (lock, condvar) = &*entered;
            let mut flag = lock
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            while !*flag {
                flag = condvar
                    .wait(flag)
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
            }
        }

        let policy_cache = cache.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        let policy = std::thread::spawn(move || {
            let change = policy_cache.ensure_policy(
                "fp-2".to_string(),
                vec!["base.example.".to_string(), "corp.".to_string()],
                Vec::new(),
            );
            let _ = tx.send(change);
        });
        let change = rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("a policy change must not block on a slow flush");
        assert_eq!(change, PolicyChange::AddedAnchors(vec![name("corp.")]));

        {
            let (lock, condvar) = &*release;
            *lock
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = true;
            condvar.notify_all();
        }
        flush.join().expect("flush thread");
        policy.join().expect("policy thread");
        cache.set_flush_hook(None);
        let _ = std::fs::remove_dir_all(path.parent().expect("parent"));
    }

    /// A concurrent flush and invalidate must leave a valid TOML file, and an
    /// invalidation that happens while a flush is in flight must mark the cache
    /// dirty so the invalidated view is persisted by the next flush.
    #[test]
    fn test_concurrent_flush_and_invalidate_leave_valid_file() {
        use std::sync::{Arc, Condvar, Mutex};

        let path = temp_path("concurrent_invalidate");
        let cache = Arc::new(ChainCache::new(Some(path.clone())));
        let now = system_now();
        assert_eq!(
            cache.ensure_policy(
                "fp-1".to_string(),
                vec!["base.example.".to_string()],
                Vec::new()
            ),
            PolicyChange::FullClear
        );
        for index in 0..32 {
            cache.insert(
                name(&format!("z{index}.example.")),
                ZoneStatus::Signed,
                now + 600,
                now + index,
            );
        }
        let corp = name("corp.");
        cache.insert(corp.clone(), ZoneStatus::Unsigned, now + 600, now);

        // Block the flush after it has snapshotted (and cleared dirty) but
        // before it writes, so the invalidation is genuinely concurrent with
        // an in-flight disk write.
        let entered = Arc::new((Mutex::new(false), Condvar::new()));
        let release = Arc::new((Mutex::new(false), Condvar::new()));
        {
            let entered = entered.clone();
            let release = release.clone();
            cache.set_flush_hook(Some(Box::new(move || {
                let (lock, condvar) = &*entered;
                *lock
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = true;
                condvar.notify_all();
                let (lock, condvar) = &*release;
                let mut released = lock
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                while !*released {
                    released = condvar
                        .wait(released)
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                }
            })));
        }

        let flush_cache = cache.clone();
        let flush = std::thread::spawn(move || flush_cache.flush().expect("concurrent flush"));
        {
            let (lock, condvar) = &*entered;
            let mut flag = lock
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            while !*flag {
                flag = condvar
                    .wait(flag)
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
            }
        }

        // The flush has cleared dirty for its snapshot; invalidation must set
        // it again so the stale snapshot is not the final state.
        let removed = cache.invalidate_unsigned_at_or_above(&corp);
        assert_eq!(removed, 1, "the unsigned entry must be invalidated");
        assert!(
            cache.is_dirty(),
            "an invalidation during an in-flight flush must mark the cache dirty"
        );

        {
            let (lock, condvar) = &*release;
            *lock
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = true;
            condvar.notify_all();
        }
        flush.join().expect("flush thread");
        cache.set_flush_hook(None);

        // The in-flight flush wrote its pre-invalidation snapshot. It must
        // still be a complete, parseable file (never a torn write).
        let content = std::fs::read_to_string(&path).expect("read in-flight cache file");
        let in_flight: PersistedCache =
            toml::from_str(&content).expect("the in-flight flush must leave valid TOML");
        assert!(
            in_flight.entries.len() >= 32,
            "the in-flight snapshot must contain the signed entries"
        );

        // The dirty mark from the invalidation must make the final flush
        // persist the invalidated view.
        assert!(cache.is_dirty(), "the invalidation must still be pending");
        cache.flush().expect("final flush");
        assert!(!cache.is_dirty());
        let content = std::fs::read_to_string(&path).expect("read final cache file");
        let persisted: PersistedCache = toml::from_str(&content).expect("valid TOML cache");
        assert!(
            !persisted
                .entries
                .iter()
                .any(|entry| entry.name == "corp." && entry.status == ZoneStatus::Unsigned),
            "the invalidated unsigned entry must never be in the final file"
        );
        assert!(
            persisted.entries.len() >= 32,
            "the signed entries must still be present"
        );
        let _ = std::fs::remove_dir_all(path.parent().expect("parent"));
    }

    /// A malformed individual entry is skipped and counted instead of being
    /// silently accepted; the warning remains path-only.
    #[test]
    fn test_malformed_cache_entry_is_skipped_with_warning() {
        let path = temp_path("malformed_entry");
        let now = system_now();
        let valid = name("valid.example.");
        let persisted = PersistedCache {
            format_version: CHAIN_CACHE_FORMAT_VERSION,
            entries: vec![
                PersistedEntry {
                    name: valid.to_string(),
                    status: ZoneStatus::Signed,
                    expires_at: now + 600,
                    validated_at: now,
                },
                PersistedEntry {
                    name: "not a valid dns name".to_string(),
                    status: ZoneStatus::Unsigned,
                    expires_at: now + 600,
                    validated_at: now,
                },
            ],
            policy: Some("fp-1".to_string()),
            policy_anchors: Some(Vec::new()),
            policy_ntas: Some(Vec::new()),
            policy_generation: 1,
        };
        std::fs::write(
            &path,
            toml::to_string(&persisted).expect("serialize malformed fixture"),
        )
        .expect("write cache file");

        let cache = ChainCache::new(Some(path.clone()));
        let stats = cache.load_with_stats(now);
        assert_eq!(stats.malformed, 1, "the malformed entry must be counted");
        assert_eq!(stats.expired, 0);
        assert_eq!(cache.len(), 1, "only the valid entry may be loaded");
        assert!(cache.get(&valid, now).is_some());

        let _ = std::fs::remove_dir_all(path.parent().expect("parent"));
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

    /// Format migration: files written before the helper-RRSIG fix can contain
    /// `Signed` root/TLD entries recorded from fetched chain-helper signatures.
    /// Those entries would suppress validation for every descendant after an
    /// upgrade, so a legacy-format load must drop them while keeping genuine
    /// delegation evidence.
    #[test]
    fn test_legacy_format_drops_root_and_tld_signed_entries() {
        let path = temp_path("legacy_format");
        let now = system_now();
        std::fs::write(
            &path,
            format!(
                "[[entries]]\n\
                 name = \".\"\nstatus = \"signed\"\nexpires_at = {}\nvalidated_at = {}\n\
                 \n[[entries]]\n\
                 name = \"com.\"\nstatus = \"signed\"\nexpires_at = {}\nvalidated_at = {}\n\
                 \n[[entries]]\n\
                 name = \"signed.example.com.\"\nstatus = \"signed\"\nexpires_at = {}\nvalidated_at = {}\n\
                 \n[[entries]]\n\
                 name = \"corp.\"\nstatus = \"unsigned\"\nexpires_at = {}\nvalidated_at = {}\n",
                now + 600,
                now,
                now + 600,
                now,
                now + 600,
                now,
                now + 600,
                now,
            ),
        )
        .expect("write legacy cache");

        let cache = ChainCache::new(Some(path.clone()));
        cache.load(now);

        assert!(
            cache.get(&name("."), now).is_none(),
            "a legacy root Signed entry must not survive the format upgrade"
        );
        assert!(
            cache.get(&name("com."), now).is_none(),
            "a legacy TLD Signed entry must not survive the format upgrade"
        );
        assert!(
            cache.get(&name("signed.example.com."), now).is_some(),
            "genuine deeper signed evidence must survive"
        );
        assert!(
            cache.get(&name("corp."), now).is_some(),
            "legacy unsigned delegation evidence must survive (it only causes a re-probe)"
        );

        cache.flush().expect("flush migrated cache");
        let content = std::fs::read_to_string(&path).expect("read migrated cache");
        let persisted: PersistedCache = toml::from_str(&content).expect("valid migrated TOML");
        assert_eq!(
            persisted.format_version, CHAIN_CACHE_FORMAT_VERSION,
            "the migrated file must carry the current format version"
        );
        assert!(
            !persisted.entries.iter().any(|entry| {
                entry.status == ZoneStatus::Signed && (entry.name == "." || entry.name == "com.")
            }),
            "root/TLD signed entries must not be re-persisted"
        );

        let _ = std::fs::remove_dir_all(path.parent().expect("parent"));
    }

    /// An in-flight validation built under the old policy must not insert after
    /// a reload's `ensure_policy` flushed the cache.
    #[test]
    fn test_in_flight_insert_from_old_policy_generation_is_rejected() {
        let cache = ChainCache::new(None);
        let now = system_now();
        assert_eq!(
            cache.ensure_policy("v1-old".to_string(), Vec::new(), Vec::new()),
            PolicyChange::FullClear
        );
        let old_generation = cache.policy_generation();
        assert_eq!(old_generation, 1);
        assert!(cache.insert_for_generation(
            name("old.example."),
            ZoneStatus::Unsigned,
            now + 600,
            now,
            old_generation,
        ));

        // Reload: the shared cache adopts the new policy and generation.
        assert_eq!(
            cache.ensure_policy("v1-new".to_string(), Vec::new(), Vec::new()),
            PolicyChange::FullClear
        );
        let new_generation = cache.policy_generation();
        assert!(new_generation > old_generation);

        // Late write from the validator that was built under the old policy.
        assert!(
            !cache.insert_for_generation(
                name("stale.example."),
                ZoneStatus::Unsigned,
                now + 600,
                now,
                old_generation,
            ),
            "an old-generation insert must be rejected"
        );
        assert!(
            cache.get(&name("stale.example."), now).is_none(),
            "the rejected entry must not be visible"
        );

        // The reloaded validator can still insert under the new generation.
        assert!(cache.insert_for_generation(
            name("fresh.example."),
            ZoneStatus::Signed,
            now + 600,
            now,
            new_generation,
        ));
        assert!(cache.get(&name("fresh.example."), now).is_some());
    }

    /// The generation is part of the persisted policy record, so a restart
    /// cannot silently reuse a validator's old generation.
    #[test]
    fn test_policy_generation_survives_flush_and_load() {
        let path = temp_path("generation");
        let now = system_now();
        let cache = ChainCache::new(Some(path.clone()));
        let _ = cache.ensure_policy("v1-old".to_string(), Vec::new(), Vec::new());
        let _ = cache.ensure_policy("v1-new".to_string(), Vec::new(), Vec::new());
        let generation = cache.policy_generation();
        assert!(generation > 1);
        cache.flush().expect("flush generation");

        let reloaded = ChainCache::new(Some(path.clone()));
        reloaded.load(now);
        assert_eq!(
            reloaded.policy_generation(),
            generation,
            "the policy generation must survive a restart"
        );

        let _ = std::fs::remove_dir_all(path.parent().expect("parent"));
    }
}
