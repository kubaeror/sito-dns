//! Encryption-at-rest for TOTP secrets.
//!
//! TOTP secrets are sealed with AES-256-GCM using a per-deployment key stored
//! in `<data_dir>/totp.key` (0600). Each value is self-describing:
//!
//! ```text
//! enc:v1:<base64(12-byte nonce || ciphertext || 16-byte tag)>
//! ```
//!
//! The username is authenticated as additional data (`sito-totp-v1:<user>`), so
//! a ciphertext copied from another account fails to open. The key file is a
//! credential: losing it makes every stored TOTP secret unreadable, which is
//! why [`super::manager::AuthManager`] refuses to start rather than silently
//! dropping 2FA.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use rand::RngExt as _;
use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Encrypted TOTP secrets are prefixed with a format/version tag so a future
/// release can rotate the key or algorithm without guessing at the contents.
pub const ENC_PREFIX: &str = "enc:v1:";
/// Prefix shared by every encrypted value, including unsupported versions.
const ENC_ANY_PREFIX: &str = "enc:";
/// Additional-data prefix binding a ciphertext to one account.
const AAD_PREFIX: &str = "sito-totp-v1:";
const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

/// Errors produced while sealing or opening a TOTP secret. Messages never
/// contain secret material.
#[derive(Debug, thiserror::Error)]
pub enum TotpSecretError {
    #[error("value is not an encrypted TOTP secret")]
    NotEncrypted,
    #[error("unsupported encrypted TOTP secret version")]
    UnsupportedVersion,
    #[error("malformed encrypted TOTP secret")]
    Malformed,
    #[error("TOTP secret encryption failed")]
    Encrypt,
    #[error("TOTP secret authentication failed")]
    Decrypt,
}

/// AES-256-GCM key used to encrypt TOTP secrets in `users.toml`.
///
/// The key lives in an [`Arc`] so the surrounding [`super::manager::AuthManager`]
/// can be cloned cheaply; the `Debug` implementation is redacted.
#[derive(Clone)]
pub struct TotpSecretStore {
    key: Arc<LessSafeKey>,
    key_path: PathBuf,
}

impl std::fmt::Debug for TotpSecretStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TotpSecretStore")
            .field("key_path", &self.key_path)
            .field("key", &"<redacted>")
            .finish()
    }
}

impl TotpSecretStore {
    /// Loads the key from `path`, creating it (0600, `create_new`) when absent.
    ///
    /// An existing key with wider permissions is repaired in place. Creation is
    /// atomic and exclusive: if another process wins the race, its key is used
    /// rather than overwritten.
    pub fn load_or_create(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let path = path.as_ref();
        match std::fs::read(path) {
            Ok(bytes) => Self::from_bytes(path, &bytes),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if let Some(parent) = path.parent()
                    && !parent.as_os_str().is_empty()
                {
                    std::fs::create_dir_all(parent)?;
                }

                let mut bytes = [0u8; KEY_LEN];
                rand::rng().fill(&mut bytes);
                match write_private_exclusive(path, &bytes) {
                    Ok(()) => Self::from_bytes(path, &bytes),
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                        // Racing creator won; use its key rather than clobbering it.
                        let existing = std::fs::read(path)?;
                        Self::from_bytes(path, &existing)
                    }
                    Err(e) => Err(e),
                }
            }
            Err(e) => Err(e),
        }
    }

    /// Loads an existing key, failing when the file is missing.
    pub fn load_existing(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let path = path.as_ref();
        let bytes = std::fs::read(path)?;
        Self::from_bytes(path, &bytes)
    }

    /// Path of the key backing this store (used in diagnostics, never logged
    /// with key material).
    #[must_use]
    pub fn key_path(&self) -> &Path {
        &self.key_path
    }

    /// True for any value carrying an `enc:` version prefix. Unknown versions
    /// are intentionally treated as encrypted so they fail closed instead of
    /// being mistaken for legacy plaintext.
    #[must_use]
    pub fn is_encrypted(value: &str) -> bool {
        value.starts_with(ENC_ANY_PREFIX)
    }

    /// Encrypts a TOTP secret bound to `username`.
    pub fn seal(&self, username: &str, secret: &str) -> Result<String, TotpSecretError> {
        let mut nonce_bytes = [0u8; NONCE_LEN];
        rand::rng().fill(&mut nonce_bytes);
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);

        let aad_value = format!("{AAD_PREFIX}{username}");
        let aad = Aad::from(aad_value.as_bytes());

        let mut in_out = secret.as_bytes().to_vec();
        self.key
            .seal_in_place_append_tag(nonce, aad, &mut in_out)
            .map_err(|_| TotpSecretError::Encrypt)?;

        let mut encoded = Vec::with_capacity(NONCE_LEN + in_out.len());
        encoded.extend_from_slice(&nonce_bytes);
        encoded.extend_from_slice(&in_out);
        Ok(format!("{ENC_PREFIX}{}", BASE64_STANDARD.encode(encoded)))
    }

    /// Decrypts a TOTP secret bound to `username`.
    pub fn open(&self, username: &str, ciphertext: &str) -> Result<String, TotpSecretError> {
        let Some(encoded) = ciphertext.strip_prefix(ENC_PREFIX) else {
            return if TotpSecretStore::is_encrypted(ciphertext) {
                Err(TotpSecretError::UnsupportedVersion)
            } else {
                Err(TotpSecretError::NotEncrypted)
            };
        };

        let decoded = BASE64_STANDARD
            .decode(encoded)
            .map_err(|_| TotpSecretError::Malformed)?;
        if decoded.len() < NONCE_LEN + TAG_LEN {
            return Err(TotpSecretError::Malformed);
        }
        let (nonce_bytes, encrypted) = decoded.split_at(NONCE_LEN);
        let mut nonce_array = [0u8; NONCE_LEN];
        nonce_array.copy_from_slice(nonce_bytes);
        let nonce = Nonce::assume_unique_for_key(nonce_array);

        let aad_value = format!("{AAD_PREFIX}{username}");
        let aad = Aad::from(aad_value.as_bytes());

        let mut in_out = encrypted.to_vec();
        let plaintext = self
            .key
            .open_in_place(nonce, aad, &mut in_out)
            .map_err(|_| TotpSecretError::Decrypt)?;
        String::from_utf8(plaintext.to_vec()).map_err(|_| TotpSecretError::Malformed)
    }

    fn from_bytes(path: &Path, bytes: &[u8]) -> std::io::Result<Self> {
        enforce_private_permissions(path)?;
        let key_bytes: [u8; KEY_LEN] = bytes.try_into().map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "TOTP key file '{}' must contain exactly {KEY_LEN} bytes",
                    path.display()
                ),
            )
        })?;
        let unbound = UnboundKey::new(&AES_256_GCM, &key_bytes).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid AES-256-GCM key in '{}'", path.display()),
            )
        })?;
        Ok(Self {
            key: Arc::new(LessSafeKey::new(unbound)),
            key_path: path.to_path_buf(),
        })
    }
}

/// Creates `path` with mode 0600 and writes `bytes`, failing if it already
/// exists. On Unix the mode is applied at creation time, so the key is never
/// observable with wider permissions.
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
                "TOTP key already exists",
            ));
        }
        std::fs::write(path, bytes)
    }
}

/// Ensures an existing key file is readable only by its owner (0600).
fn enforce_private_permissions(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = std::fs::metadata(path)?;
        let mode = metadata.permissions().mode() & 0o777;
        if mode != 0o600 {
            tracing::warn!(
                path = %path.display(),
                mode = format!("{mode:o}"),
                "TOTP key file has insecure permissions; tightening to 0600"
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

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    fn temp_dir(label: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("sito_totp_store_{label}_{}", rand::random::<u64>()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[cfg(unix)]
    fn mode(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn test_key_file_created_0600_and_repaired() {
        let dir = temp_dir("perms");
        let path = dir.join("totp.key");
        let _store = TotpSecretStore::load_or_create(&path).unwrap();
        assert!(path.exists(), "key file must be created");
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 32);

        #[cfg(unix)]
        {
            assert_eq!(mode(&path), 0o600);
            let mut perms = std::fs::metadata(&path).unwrap().permissions();
            perms.set_mode(0o644);
            std::fs::set_permissions(&path, perms).unwrap();
            assert_eq!(mode(&path), 0o644);

            let _reloaded = TotpSecretStore::load_existing(&path).unwrap();
            assert_eq!(mode(&path), 0o600, "wider permissions must be repaired");
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_seal_open_round_trip_and_aad_binding() {
        let dir = temp_dir("roundtrip");
        let store = TotpSecretStore::load_or_create(dir.join("totp.key")).unwrap();
        let secret = "JBSWY3DPEHPK3PXP";

        let sealed = store.seal("admin", secret).unwrap();
        assert!(sealed.starts_with(ENC_PREFIX), "{sealed}");
        assert!(!sealed.contains(secret));
        assert_eq!(store.open("admin", &sealed).unwrap(), secret);

        assert!(
            store.open("other-user", &sealed).is_err(),
            "the username must be bound as AAD"
        );

        // Flip one ciphertext bit: authentication must fail.
        let mut raw = BASE64_STANDARD
            .decode(sealed.strip_prefix(ENC_PREFIX).unwrap())
            .unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 0x01;
        let tampered = format!("{ENC_PREFIX}{}", BASE64_STANDARD.encode(raw));
        assert!(store.open("admin", &tampered).is_err());

        // A future/unknown version is refused rather than treated as plaintext.
        assert!(TotpSecretStore::is_encrypted("enc:v2:abc"));
        assert!(store.open("admin", "enc:v2:abc").is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_wrong_key_fails_closed() {
        let dir_a = temp_dir("wrongkey_a");
        let dir_b = temp_dir("wrongkey_b");
        let a = TotpSecretStore::load_or_create(dir_a.join("totp.key")).unwrap();
        let b = TotpSecretStore::load_or_create(dir_b.join("totp.key")).unwrap();

        let sealed = a.seal("admin", "JBSWY3DPEHPK3PXP").unwrap();
        assert!(b.open("admin", &sealed).is_err());

        let _ = std::fs::remove_dir_all(&dir_a);
        let _ = std::fs::remove_dir_all(&dir_b);
    }

    #[test]
    fn test_nonce_is_unique_for_repeated_seals() {
        let dir = temp_dir("nonce");
        let store = TotpSecretStore::load_or_create(dir.join("totp.key")).unwrap();

        let first = store.seal("admin", "JBSWY3DPEHPK3PXP").unwrap();
        let second = store.seal("admin", "JBSWY3DPEHPK3PXP").unwrap();
        assert_ne!(first, second, "a fresh 12-byte nonce is required per seal");
        assert_eq!(store.open("admin", &first).unwrap(), "JBSWY3DPEHPK3PXP");
        assert_eq!(store.open("admin", &second).unwrap(), "JBSWY3DPEHPK3PXP");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
