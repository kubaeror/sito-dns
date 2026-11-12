//! In-memory validated DNSKEY cache.

#[allow(clippy::wildcard_imports)]
use super::*;

/// Cache for validated DNSKEY records.
///
/// Entries track whether the key was linked to a trust anchor (directly, via a
/// DS record or via a validated DNSKEY RRset). Only validated entries may be
/// used to mark a response `Secure`; unvalidated keys from response processing
/// are never inserted, and an existing unexpired validated entry is never
/// overwritten by an unvalidated one.
#[derive(Default)]
pub struct KeyCache {
    pub(super) keys: DashMap<(LowerName, u16), (DNSKEY, u32, bool)>,
}

impl KeyCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns any cached key, validated or not (used for signature checks).
    pub fn get(&self, name: &LowerName, key_tag: u16, now: u32) -> Option<DNSKEY> {
        if let Some(entry) = self.keys.get(&(name.clone(), key_tag)) {
            let (key, expires_at, _) = entry.value();
            if now <= *expires_at {
                return Some(key.clone());
            }
        }
        None
    }

    /// Returns a cached key only when it is part of a validated chain.
    pub fn get_validated(&self, name: &LowerName, key_tag: u16, now: u32) -> Option<DNSKEY> {
        if let Some(entry) = self.keys.get(&(name.clone(), key_tag)) {
            let (key, expires_at, validated) = entry.value();
            if *validated && now <= *expires_at {
                return Some(key.clone());
            }
        }
        None
    }

    /// Whether `key` itself (not just some key with the same tag) is a cached
    /// validated key. Trust must never be granted from the tag alone: a key
    /// tag collision would otherwise let a forged DNSKEY inherit an anchored
    /// key's trust.
    #[must_use]
    pub fn is_validated(&self, name: &LowerName, key_tag: u16, key: &DNSKEY, now: u32) -> bool {
        self.keys
            .get(&(name.clone(), key_tag))
            .is_some_and(|entry| {
                let (cached, expires_at, validated) = entry.value();
                *validated && now <= *expires_at && same_public_key(cached, key)
            })
    }

    /// Stores a key that has not (yet) been linked to a trust anchor.
    ///
    /// An existing unexpired validated entry is never downgraded. Primarily a
    /// test/diagnostics helper: response processing must use
    /// [`Self::insert_validated`].
    pub fn insert(&self, name: LowerName, key_tag: u16, key: DNSKEY, expires_at: u32) {
        self.insert_with_now(name, key_tag, key, expires_at, Self::system_now());
    }

    /// Stores a key that has been linked to a trust anchor by the chain walk.
    pub fn insert_validated(&self, name: LowerName, key_tag: u16, key: DNSKEY, expires_at: u32) {
        self.insert_validated_with_now(name, key_tag, key, expires_at, Self::system_now());
    }

    /// [`Self::insert`] with an explicit `now` for deterministic callers.
    pub fn insert_with_now(
        &self,
        name: LowerName,
        key_tag: u16,
        key: DNSKEY,
        expires_at: u32,
        now: u32,
    ) {
        let keep_existing = self
            .keys
            .get(&(name.clone(), key_tag))
            .is_some_and(|entry| {
                let (_, existing_expiry, existing_validated) = entry.value();
                *existing_validated && now <= *existing_expiry
            });
        if keep_existing {
            return;
        }
        self.keys.insert((name, key_tag), (key, expires_at, false));
        self.enforce_bounds(now);
    }

    /// [`Self::insert_validated`] with an explicit `now` for deterministic
    /// callers.
    ///
    /// An existing unexpired validated entry with the same tag but different
    /// key material is never overwritten: otherwise a forged key that shares a
    /// tag with a validated key could inherit its trust.
    pub fn insert_validated_with_now(
        &self,
        name: LowerName,
        key_tag: u16,
        key: DNSKEY,
        expires_at: u32,
        now: u32,
    ) {
        if let Some(existing) = self.keys.get(&(name.clone(), key_tag)) {
            let (cached, existing_expiry, existing_validated) = existing.value();
            if *existing_validated && now <= *existing_expiry && !same_public_key(cached, &key) {
                // Keep the original validated key; the different key is either
                // a forgery or a rollover that must be re-validated from
                // scratch.
                return;
            }
        }
        self.keys.insert((name, key_tag), (key, expires_at, true));
        self.enforce_bounds(now);
    }

    /// Current UNIX timestamp truncated to the DNSSEC serial-number width.
    pub(super) fn system_now() -> u32 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as u32
    }

    /// Removes entries that are not valid at `now`; returns the number purged.
    pub fn purge_expired(&self, now: u32) -> usize {
        let before = self.keys.len();
        self.keys.retain(|_, (_, expires_at, _)| *expires_at >= now);
        // Concurrent inserts between the two `len()` calls can make the
        // difference negative; the count is informational.
        before.saturating_sub(self.keys.len())
    }

    /// Keeps the cache bounded: purge expired entries first and, if the cache
    /// is still oversized, clear it (keys are re-discoverable).
    pub(super) fn enforce_bounds(&self, now: u32) {
        self.purge_expired(now);
        if self.keys.len() > KEY_CACHE_MAX_ENTRIES {
            self.keys.clear();
        }
    }

    /// Number of cached keys (validated and unvalidated). Test/diagnostics helper.
    #[must_use]
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Whether the cache holds no keys.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// All unexpired validated keys cached for `name` (any key tag).
    #[must_use]
    pub fn validated_keys(&self, name: &LowerName, now: u32) -> Vec<DNSKEY> {
        self.keys
            .iter()
            .filter(|entry| entry.key().0 == *name)
            .filter_map(|entry| {
                let (key, expires_at, validated) = entry.value();
                (*validated && now <= *expires_at).then(|| key.clone())
            })
            .collect()
    }
}
