//! Ed25519 signing key generation, persistence, and signature verification.

use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use ring::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};
use std::path::Path;
use tracing::warn;

use crate::error::HaError;

/// An Ed25519 signing key used by the master node to sign configuration bundles.
pub struct Ed25519SigningKey {
    key_pair: Ed25519KeyPair,
    pkcs8_bytes: Vec<u8>,
}

impl Ed25519SigningKey {
    /// Generates a new random Ed25519 keypair.
    pub fn generate() -> Result<Self, HaError> {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8_doc = Ed25519KeyPair::generate_pkcs8(&rng)
            .map_err(|e| HaError::Crypto(format!("Failed to generate Ed25519 keypair: {e}")))?;
        let pkcs8_bytes = pkcs8_doc.as_ref().to_vec();
        let key_pair = Ed25519KeyPair::from_pkcs8(&pkcs8_bytes).map_err(|e| {
            HaError::Crypto(format!("Failed to parse generated Ed25519 keypair: {e}"))
        })?;
        Ok(Self {
            key_pair,
            pkcs8_bytes,
        })
    }

    /// Loads an Ed25519 keypair from PKCS#8 DER bytes.
    pub fn from_pkcs8(bytes: &[u8]) -> Result<Self, HaError> {
        let key_pair = Ed25519KeyPair::from_pkcs8(bytes)
            .map_err(|e| HaError::Crypto(format!("Failed to parse PKCS#8 Ed25519 key: {e}")))?;
        Ok(Self {
            key_pair,
            pkcs8_bytes: bytes.to_vec(),
        })
    }

    /// Loads the signing key from `path`, or generates a new one if it does not exist.
    ///
    /// Strict file permissions (0600 on Unix) are enforced: the key is created
    /// with mode 0600 atomically (`O_CREAT|O_EXCL`, so it is never briefly
    /// world-readable) and an existing key with wider permissions is repaired
    /// in place.
    pub fn load_or_create(path: &Path) -> Result<Self, HaError> {
        if let Ok(bytes) = std::fs::read(path) {
            let key = Self::from_pkcs8(&bytes)?;
            enforce_private_permissions(path)?;
            return Ok(key);
        }

        let key = Self::generate()?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        match write_private_exclusive(path, key.pkcs8_bytes()) {
            Ok(()) => Ok(key),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                // Racing creator won; use its key rather than clobbering it.
                let bytes = std::fs::read(path)?;
                let existing = Self::from_pkcs8(&bytes)?;
                enforce_private_permissions(path)?;
                Ok(existing)
            }
            Err(e) => Err(HaError::Io(std::io::Error::new(
                e.kind(),
                format!("Failed to write Ed25519 key file '{}': {e}", path.display()),
            ))),
        }
    }

    /// Returns the raw PKCS#8 bytes of the key.
    pub fn pkcs8_bytes(&self) -> &[u8] {
        &self.pkcs8_bytes
    }

    /// Signs the given data slice using Ed25519, returning a 64-byte signature.
    pub fn sign(&self, data: &[u8]) -> [u8; 64] {
        let sig = self.key_pair.sign(data);
        let mut out = [0u8; 64];
        out.copy_from_slice(sig.as_ref());
        out
    }

    /// Returns the 32-byte Ed25519 public key.
    pub fn public_key(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(self.key_pair.public_key().as_ref());
        out
    }

    /// Returns the Ed25519 public key formatted as lowercase hex (64 chars).
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.public_key())
    }

    /// Returns the Ed25519 public key formatted as standard Base64.
    pub fn public_key_b64(&self) -> String {
        BASE64_STANDARD.encode(self.public_key())
    }
}

/// Creates `path` with mode 0600 and writes `bytes`, failing if it already
/// exists. On Unix the file is never observable with wider permissions (the
/// mode is applied at creation time).
fn write_private_exclusive(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt as _;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        if path.exists() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "signing key already exists",
            ));
        }
        std::fs::write(path, bytes)
    }
}

/// Ensures an existing key file is readable only by its owner (0600).
fn enforce_private_permissions(path: &Path) -> Result<(), HaError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = std::fs::metadata(path)?;
        let mode = metadata.permissions().mode() & 0o777;
        if mode != 0o600 {
            warn!(
                path = %path.display(),
                mode = format!("{mode:o}"),
                "HA signing key has insecure permissions; tightening to 0600"
            );
            let mut perms = metadata.permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(path, perms)?;
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

/// Parses an Ed25519 public key from either 64-char hex or 44-char base64 string.
pub fn parse_public_key(input: &str) -> Result<[u8; 32], HaError> {
    let trimmed = input.trim();
    if trimmed.len() == 64 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        let decoded = hex::decode(trimmed)
            .map_err(|e| HaError::Crypto(format!("Invalid hex public key: {e}")))?;
        let mut out = [0u8; 32];
        out.copy_from_slice(&decoded);
        return Ok(out);
    }

    if let Ok(decoded) = BASE64_STANDARD.decode(trimmed)
        && decoded.len() == 32
    {
        let mut out = [0u8; 32];
        out.copy_from_slice(&decoded);
        return Ok(out);
    }

    Err(HaError::Crypto(format!(
        "Invalid Ed25519 public key format (expected 32-byte hex or base64): '{trimmed}'"
    )))
}

/// Verifies an Ed25519 signature over `data` using the given 32-byte public key.
pub fn verify_ed25519_signature(
    pubkey: &[u8],
    data: &[u8],
    signature: &[u8],
) -> Result<(), HaError> {
    if pubkey.len() != 32 {
        return Err(HaError::Crypto(format!(
            "Invalid public key length {}, expected 32 bytes",
            pubkey.len()
        )));
    }
    if signature.len() != 64 {
        return Err(HaError::Crypto(format!(
            "Invalid signature length {}, expected 64 bytes",
            signature.len()
        )));
    }

    let peer_key = UnparsedPublicKey::new(&ED25519, pubkey);
    peer_key.verify(data, signature).map_err(|_| {
        HaError::SignatureVerification("Ed25519 signature verification failed".to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signing_key_lifecycle() {
        let temp_dir = std::env::temp_dir().join(format!(
            "sito_ha_signing_test_{}_{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        std::fs::create_dir_all(&temp_dir).unwrap();
        let key_path = temp_dir.join("ha_signing.key");

        let key1 = Ed25519SigningKey::load_or_create(&key_path).unwrap();
        let pubkey_hex = key1.public_key_hex();
        let pubkey_b64 = key1.public_key_b64();

        // Permissions test on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let meta = std::fs::metadata(&key_path).unwrap();
            assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        }

        // Parsing tests
        assert_eq!(parse_public_key(&pubkey_hex).unwrap(), key1.public_key());
        assert_eq!(parse_public_key(&pubkey_b64).unwrap(), key1.public_key());

        // Reload existing
        let key2 = Ed25519SigningKey::load_or_create(&key_path).unwrap();
        assert_eq!(key1.public_key(), key2.public_key());

        // An existing key with wider permissions is repaired on load (a
        // pre-existing 0644 file must not stay group/world-readable).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o644)).unwrap();
            let key3 = Ed25519SigningKey::load_or_create(&key_path).unwrap();
            assert_eq!(key1.public_key(), key3.public_key());
            let meta = std::fs::metadata(&key_path).unwrap();
            assert_eq!(
                meta.permissions().mode() & 0o777,
                0o600,
                "load_or_create must repair an insecure key file"
            );
        }

        // Sign and verify
        let message = b"sito-ha-config-bundle-v1";
        let sig = key1.sign(message);
        assert!(verify_ed25519_signature(&key1.public_key(), message, &sig).is_ok());

        // Rejection of tampered message
        assert!(verify_ed25519_signature(&key1.public_key(), b"tampered-message", &sig).is_err());
    }
}
