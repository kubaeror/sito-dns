//! Metadata and integrity checks for the curated lists bundled into the binary.
//!
//! Every bundled list is described in `bundled/manifest.json` with its version,
//! source URL, license and BLAKE3 checksum. Registries verify the checksum when
//! loading so a corrupted or accidentally edited data file fails loudly instead
//! of silently weakening protection. The manifest marks these lists as the
//! minimal built-in fallback until curated updates are fetched by the
//! subscription downloader.

use serde::{Deserialize, Serialize};

pub const MANIFEST_JSON: &str = include_str!("bundled/manifest.json");
pub const ADULT_TXT: &str = include_str!("bundled/adult.txt");
pub const GAMBLING_TXT: &str = include_str!("bundled/gambling.txt");
pub const SERVICES_JSON: &str = include_str!("bundled/services.json");

/// Versioned description of one bundled list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundledList {
    /// Stable identifier (also the parental category for `kind = "domains"`).
    pub id: String,
    /// List type: `"domains"` (one domain per line, ABP `||domain^` accepted)
    /// or `"services"` (JSON map/service list).
    pub kind: String,
    /// File name relative to `bundled/`.
    pub file: String,
    /// Curated content version (updated when the data file changes).
    pub version: String,
    /// Upstream source or repository path for provenance.
    pub source: String,
    /// SPDX license identifier of the data.
    pub license: String,
    /// Number of entries (domains or services) in the list.
    #[serde(default)]
    pub entries: u64,
    /// BLAKE3 checksum of the raw file content.
    pub checksum_blake3: String,
}

/// Manifest describing all bundled lists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundledManifest {
    pub format_version: u32,
    pub generated: String,
    pub lists: Vec<BundledList>,
}

impl BundledManifest {
    /// Parses a manifest from JSON.
    pub fn parse(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Parses the embedded manifest.
    ///
    /// Returns an error instead of panicking so callers can degrade to a
    /// loaded/error state at runtime.
    pub fn try_bundled() -> Result<Self, serde_json::Error> {
        Self::parse(MANIFEST_JSON)
    }

    /// Parses the embedded manifest.
    ///
    /// # Panics
    /// Panics when the embedded manifest is invalid; this is a build-time
    /// invariant covered by unit tests. Prefer [`BundledManifest::try_bundled`]
    /// on non-fatal paths.
    #[must_use]
    pub fn bundled() -> Self {
        Self::try_bundled().expect("embedded bundled manifest must be valid JSON")
    }

    /// Returns the list with the given id.
    #[must_use]
    pub fn list(&self, id: &str) -> Option<&BundledList> {
        self.lists.iter().find(|list| list.id == id)
    }
}

/// Errors from bundled list integrity checks.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BundledListError {
    /// The manifest references a file that is not embedded in the binary.
    #[error("bundled list '{0}' has no embedded content")]
    MissingContent(String),
    /// The content checksum does not match the manifest.
    #[error(
        "bundled list '{id}' checksum mismatch: expected {expected}, got {actual}; \
         update the data file and its manifest entry together"
    )]
    ChecksumMismatch {
        id: String,
        expected: String,
        actual: String,
    },
    /// The bundled content could not be parsed.
    #[error("bundled list '{id}' content is invalid: {reason}")]
    InvalidContent { id: String, reason: String },
}

/// Returns the embedded content for a manifest entry, if known.
#[must_use]
pub fn content_for(list: &BundledList) -> Option<&'static str> {
    match list.file.as_str() {
        "adult.txt" => Some(ADULT_TXT),
        "gambling.txt" => Some(GAMBLING_TXT),
        "services.json" => Some(SERVICES_JSON),
        _ => None,
    }
}

/// Verifies the BLAKE3 checksum of `content` against the manifest entry.
pub fn verify(list: &BundledList, content: &str) -> Result<(), BundledListError> {
    let actual = blake3::hash(content.as_bytes()).to_hex().to_string();
    if actual.eq_ignore_ascii_case(&list.checksum_blake3) {
        Ok(())
    } else {
        Err(BundledListError::ChecksumMismatch {
            id: list.id.clone(),
            expected: list.checksum_blake3.clone(),
            actual,
        })
    }
}

/// Loads and verifies the content of the given manifest entry.
pub fn verified_content(list: &BundledList) -> Result<&'static str, BundledListError> {
    let content =
        content_for(list).ok_or_else(|| BundledListError::MissingContent(list.id.clone()))?;
    verify(list, content)?;
    Ok(content)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_manifest_is_valid_and_unique() {
        let manifest = BundledManifest::bundled();
        assert_eq!(manifest.format_version, 1);
        assert!(!manifest.generated.is_empty());

        let mut ids: Vec<&str> = manifest.lists.iter().map(|l| l.id.as_str()).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), manifest.lists.len(), "list ids must be unique");
        assert!(manifest.lists.len() >= 3);
    }

    #[test]
    fn test_bundled_checksums_verify() {
        let manifest = BundledManifest::bundled();
        for list in &manifest.lists {
            let content = verified_content(list).unwrap_or_else(|e| panic!("{e}"));
            assert!(!content.trim().is_empty(), "list {} is empty", list.id);
            assert!(
                !list.source.is_empty() && !list.license.is_empty(),
                "list {} must document source and license",
                list.id
            );
        }
    }

    #[test]
    fn test_tampered_content_is_rejected() {
        let manifest = BundledManifest::bundled();
        let adult = manifest.list("adult").unwrap();
        let err = verify(adult, "evil.example\n").unwrap_err();
        assert!(matches!(err, BundledListError::ChecksumMismatch { .. }));

        let missing = BundledList {
            file: "does-not-exist.txt".to_string(),
            ..adult.clone()
        };
        assert_eq!(
            content_for(&missing),
            None,
            "unknown files must not resolve to embedded content"
        );
    }
}
