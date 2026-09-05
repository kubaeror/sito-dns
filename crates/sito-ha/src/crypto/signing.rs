//! Ed25519 signing key generation, persistence, and signature verification.

use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use ring::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};
use std::path::Path;

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
    /// Strict file permissions (0600 on Unix) are enforced on the key file.
    pub fn load_or_create(path: &Path) -> Result<Self, HaError> {
        if path.exists() {
            let bytes = std::fs::read(path).map_err(|e| {
                HaError::Io(std::io::Error::new(
                    e.kind(),
                    format!("Failed to read Ed25519 key file '{}': {e}", path.display()),
                ))
            })?;
            Self::from_pkcs8(&bytes)
        } else {
            let key = Self::generate()?;
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(path, key.pkcs8_bytes())?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mut perms = std::fs::metadata(path)?.permissions();
                perms.set_mode(0o600);
                std::fs::set_permissions(path, perms)?;
            }
            Ok(key)
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

    if let Ok(decoded) = BASE64_STANDARD.decode(trimmed) {
        if decoded.len() == 32 {
            let mut out = [0u8; 32];
            out.copy_from_slice(&decoded);
            return Ok(out);
        }
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

        // Sign and verify
        let message = b"sito-ha-config-bundle-v1";
        let sig = key1.sign(message);
        assert!(verify_ed25519_signature(&key1.public_key(), message, &sig).is_ok());

        // Rejection of tampered message
        assert!(verify_ed25519_signature(&key1.public_key(), b"tampered-message", &sig).is_err());
    }
}
