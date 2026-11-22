//! Canonical BLAKE3 hash parsing for HA wire and configuration values.
//!
//! ADR-0010 normalizes every bundle hash (`bundle_hash`, `have_bundle_hash`,
//! `published_hash` and the witness certificate pin) to 64 lowercase
//! hexadecimal characters. A `blake3:` prefix is accepted on input and stripped,
//! so `blake3:<hex>` and bare `<hex>` are equivalent. The literal `"none"`
//! represents "no published bundle" and is valid only at version 0.

use thiserror::Error;

/// A malformed BLAKE3 hash value.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum BundleHashError {
    /// The value is not 64 hexadecimal characters.
    #[error("'{0}' is not a 64-character hexadecimal BLAKE3 hash")]
    NotAHash(String),
    /// A zero version requires exactly `"none"`.
    #[error("version 0 requires bundle_hash \"none\"")]
    VersionZeroRequiresNone,
    /// `"none"` is a sentinel, not a real hash.
    #[error("bundle_hash \"none\" is only valid for version 0")]
    NoneRequiresVersionZero,
}

/// Normalizes a BLAKE3 hash to 64 lowercase hexadecimal characters.
///
/// A `blake3:` prefix is accepted and stripped. Anything else (wrong length,
/// non-hex characters, an empty value) is rejected.
pub fn normalize_blake3_hash(input: &str) -> Result<String, BundleHashError> {
    let trimmed = input.trim();
    let hex = if trimmed
        .as_bytes()
        .get(..7)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"blake3:"))
    {
        &trimmed[7..]
    } else {
        trimmed
    };
    if hex.len() != 64 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(BundleHashError::NotAHash(trimmed.to_string()));
    }
    Ok(hex.to_ascii_lowercase())
}

/// Normalizes a `(version, bundle_hash)` pair.
///
/// `version == 0` requires exactly `"none"`; a positive version requires a
/// valid BLAKE3 hash and rejects `"none"`.
pub fn normalize_bundle_hash(version: u64, input: &str) -> Result<String, BundleHashError> {
    if version == 0 {
        if input.trim() == "none" {
            return Ok("none".to_string());
        }
        return Err(BundleHashError::VersionZeroRequiresNone);
    }
    if input.trim() == "none" {
        return Err(BundleHashError::NoneRequiresVersionZero);
    }
    normalize_blake3_hash(input)
}

/// Normalizes an optional hash field carried on the wire.
///
/// A missing field is `None` (unknown/old peer). The literal `"none"` also
/// normalizes to `None`: it means "no published bundle", not a hash. A present
/// malformed value is rejected rather than treated as unknown, because a
/// promotion must not overwrite a possible fork when the hash is ambiguous.
pub fn normalize_optional_hash(input: &str) -> Result<Option<String>, BundleHashError> {
    if input.trim().eq_ignore_ascii_case("none") {
        return Ok(None);
    }
    normalize_blake3_hash(input).map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(byte: u8) -> String {
        format!("{byte:02x}").repeat(32)
    }

    #[test]
    fn hashes_accept_bare_and_prefixed_uppercase_forms() {
        let bare = hash(0xab);
        assert_eq!(normalize_blake3_hash(&bare).unwrap(), bare);
        assert_eq!(
            normalize_blake3_hash(&format!("blake3:{}", bare.to_uppercase())).unwrap(),
            bare
        );
        assert_eq!(
            normalize_blake3_hash(&format!("BLAKE3:{bare}")).unwrap(),
            bare
        );
        assert_eq!(
            normalize_blake3_hash(&format!("BlAkE3:{bare}")).unwrap(),
            bare
        );
        assert_eq!(normalize_blake3_hash(&format!("  {bare}  ")).unwrap(), bare);
    }

    #[test]
    fn malformed_hashes_are_rejected() {
        for value in ["", "abc", &hash(1)[..63], &format!("{}g", &hash(1)[..63])] {
            assert!(normalize_blake3_hash(value).is_err(), "{value:?}");
        }
        assert!(normalize_blake3_hash("none").is_err());
    }

    #[test]
    fn none_is_only_valid_at_version_zero() {
        assert_eq!(normalize_bundle_hash(0, "none").unwrap(), "none");
        assert_eq!(normalize_bundle_hash(0, " none ").unwrap(), "none");
        assert!(matches!(
            normalize_bundle_hash(0, &hash(1)),
            Err(BundleHashError::VersionZeroRequiresNone)
        ));
        assert!(matches!(
            normalize_bundle_hash(7, "none"),
            Err(BundleHashError::NoneRequiresVersionZero)
        ));
        assert_eq!(
            normalize_bundle_hash(7, &format!("blake3:{}", hash(1).to_uppercase())).unwrap(),
            hash(1)
        );
    }

    #[test]
    fn optional_hashes_treat_none_as_unknown_but_reject_garbage() {
        assert_eq!(normalize_optional_hash("none").unwrap(), None);
        assert_eq!(normalize_optional_hash("NONE").unwrap(), None);
        assert_eq!(
            normalize_optional_hash(&format!("blake3:{}", hash(3))).unwrap(),
            Some(hash(3))
        );
        assert!(normalize_optional_hash("not-a-hash").is_err());
    }
}
