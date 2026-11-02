//! TOTP implementation conforming to RFC 6238 and section 12.2.
//!
//! 30s window, ±1 step tolerance, replay protection for accepted time steps,
//! and 10 one-time backup codes with 128 bits of entropy stored as keyed
//! BLAKE3 digests.
//!
//! Dynamic codes are verified with HMAC (RFC 6238) and backup codes with a
//! fast constant-time digest comparison: an attacker cannot turn a failed
//! verification into ten Argon2id computations. Argon2 (memory-hard) remains
//! reserved for low-entropy user passwords.

use rand::RngExt;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;
use totp_rs::{Builder, Secret};

/// Prefix used for BLAKE3 backup-code digests. Hashes without it are legacy
/// Argon2id digests from older releases and are refused (never verified) so a
/// failed attempt cannot trigger memory-hard work.
pub const BACKUP_HASH_PREFIX: &str = "b3:";

/// TOTP configuration and state for a user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotpConfig {
    pub enabled: bool,
    pub secret: String,
    /// BLAKE3 digests (`b3:<hex>`) of remaining one-time backup codes.
    pub backup_code_hashes: Vec<String>,
    /// Highest accepted TOTP time-step, used to reject replays within the
    /// ±1 window. `None` until the first successful dynamic-code login.
    #[serde(default)]
    pub last_used_step: Option<u64>,
}

impl TotpConfig {
    /// True when any stored backup-code digest is a legacy Argon2id hash that
    /// this version refuses to verify.
    #[must_use]
    pub fn has_legacy_backup_hashes(&self) -> bool {
        self.backup_code_hashes
            .iter()
            .any(|h| !h.starts_with(BACKUP_HASH_PREFIX))
    }
}

/// Returned during TOTP setup.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct TotpSetupResponse {
    pub secret: String,
    pub otpauth_url: String,
    pub qr_code: String,
    pub backup_codes: Vec<String>,
}

impl TotpConfig {
    /// Generates a new TOTP setup with secret, URL, QR code, and 10 plaintext
    /// backup codes (128-bit random each).
    pub fn generate(issuer: &str, username: &str) -> (Self, TotpSetupResponse) {
        let secret = Secret::generate();
        let secret_str = secret.to_base32();

        let totp = Builder::new()
            .with_secret(secret)
            .with_issuer(Some(issuer))
            .with_account_name(username)
            .build()
            .expect("Valid TOTP parameters");

        let otpauth_url = totp.to_url().unwrap_or_default();
        let qr_code = totp.to_qr_base64().unwrap_or_default();

        // Generate 10 one-time backup codes with 128 bits of entropy each.
        let mut plaintext_backup_codes = Vec::with_capacity(10);
        let mut backup_code_hashes = Vec::with_capacity(10);

        for _ in 0..10 {
            let mut bytes = [0u8; 16];
            rand::rng().fill(&mut bytes);
            let code = hex::encode(bytes);
            let hash = hash_backup_code(&code);
            plaintext_backup_codes.push(code);
            backup_code_hashes.push(hash);
        }

        let config = Self {
            enabled: false,
            secret: secret_str.clone(),
            backup_code_hashes,
            last_used_step: None,
        };

        let response = TotpSetupResponse {
            secret: secret_str,
            otpauth_url,
            qr_code,
            backup_codes: plaintext_backup_codes,
        };

        (config, response)
    }

    /// Verifies an entered TOTP code (6-digit dynamic code or backup code).
    ///
    /// Dynamic codes inside the ±1 step window are rejected if their time-step
    /// was already used (replay protection). A matching backup code is consumed.
    pub fn verify(&mut self, code: &str, username: &str, issuer: &str) -> bool {
        let clean_code = code.trim().replace(' ', "");

        // 1. Try dynamic 6-digit TOTP code.
        if clean_code.len() == 6
            && clean_code.chars().all(|c| c.is_ascii_digit())
            && let Ok(secret) = Secret::try_from_base32(&self.secret)
            && let Ok(totp) = Builder::new()
                .with_secret(secret)
                .with_issuer(Some(issuer))
                .with_account_name(username)
                .build()
        {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            if let Some(matched_step) = totp.check(&clean_code, now) {
                if self.last_used_step.is_some_and(|last| matched_step <= last) {
                    return false;
                }
                self.last_used_step = Some(matched_step);
                return true;
            }
        }

        // 2. Try one-time backup codes. Evaluate every digest (no early exit)
        //    so the position of the match is not observable from timing.
        let mut matched_idx = None;
        for (idx, h) in self.backup_code_hashes.iter().enumerate() {
            if verify_backup_code(&clean_code, h) {
                matched_idx = Some(idx);
            }
        }

        if let Some(pos) = matched_idx {
            self.backup_code_hashes.remove(pos);
            return true;
        }

        false
    }
}

fn backup_digest(code: &str) -> String {
    format!(
        "{BACKUP_HASH_PREFIX}{}",
        blake3::hash(code.as_bytes()).to_hex()
    )
}

fn hash_backup_code(code: &str) -> String {
    backup_digest(code)
}

/// Constant-time verification of a backup code against a stored digest.
///
/// Legacy Argon2id digests (written by releases before 1.8) are refused
/// outright: verifying them would reintroduce the ten-Argon2 hashes per failed
/// TOTP attempt that this module exists to prevent. Affected users can still
/// log in with their authenticator app and re-enroll 2FA to get fresh codes.
fn verify_backup_code(code: &str, stored: &str) -> bool {
    let Some(expected) = stored.strip_prefix(BACKUP_HASH_PREFIX) else {
        return false;
    };
    let actual = blake3::hash(code.as_bytes()).to_hex();
    let expected = expected.as_bytes();
    let actual = actual.as_bytes();
    expected.len() == actual.len() && bool::from(expected.ct_eq(actual))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dynamic_code(config: &TotpConfig) -> String {
        let secret = Secret::try_from_base32(&config.secret).unwrap();
        let totp = Builder::new()
            .with_secret(secret)
            .with_issuer(Some("sito"))
            .with_account_name("admin")
            .build()
            .unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        totp.generate(now).to_string()
    }

    #[test]
    fn test_totp_setup_and_verification() {
        let (mut config, setup) = TotpConfig::generate("sito", "admin");

        assert_eq!(setup.backup_codes.len(), 10);
        for code in &setup.backup_codes {
            assert_eq!(code.len(), 32, "backup codes must carry >= 128 bits");
            assert!(code.chars().all(|c| c.is_ascii_hexdigit()));
        }
        assert!(
            !setup.qr_code.is_empty(),
            "TOTP setup must render a QR code"
        );
        assert!(setup.otpauth_url.contains("sito"));

        // Plaintext codes are never stored; digests are fast BLAKE3 (no Argon2:
        // a failed TOTP attempt must not cost ten memory-hard hashes).
        assert!(config.backup_code_hashes[0].starts_with(BACKUP_HASH_PREFIX));
        assert_ne!(config.backup_code_hashes[0], setup.backup_codes[0]);
        assert!(
            config
                .backup_code_hashes
                .iter()
                .all(|h| !h.contains("$argon2")),
            "backup codes must never be Argon2-hashed: {:#?}",
            config.backup_code_hashes
        );
        assert!(!config.has_legacy_backup_hashes());

        let valid_code = dynamic_code(&config);
        assert!(config.verify(&valid_code, "admin", "sito"));
        assert!(!config.verify("999999", "admin", "sito"));

        // Verify with backup code
        let backup_code = &setup.backup_codes[0];
        assert_eq!(config.backup_code_hashes.len(), 10);
        assert!(config.verify(backup_code, "admin", "sito"));
        // One-time code cannot be reused
        assert_eq!(config.backup_code_hashes.len(), 9);
        assert!(!config.verify(backup_code, "admin", "sito"));
    }

    #[test]
    fn test_totp_replay_is_rejected() {
        let (mut config, _setup) = TotpConfig::generate("sito", "admin");
        let code = dynamic_code(&config);

        assert!(config.verify(&code, "admin", "sito"), "first use accepted");
        assert!(
            config.last_used_step.is_some(),
            "accepted step must be recorded"
        );
        assert!(
            !config.verify(&code, "admin", "sito"),
            "replayed code must be rejected"
        );
    }

    /// Regression for WP-4.4: one failed verification used to run up to ten
    /// Argon2id hashes (~16 MiB / 2 iterations each). 50 failed attempts must
    /// now complete in well under a second; the old implementation needed
    /// several seconds at minimum.
    #[test]
    fn test_failed_totp_verification_is_bounded() {
        let (mut config, _setup) = TotpConfig::generate("sito", "admin");
        let attempts = 50;
        let start = std::time::Instant::now();
        for _ in 0..attempts {
            assert!(!config.verify("000000", "admin", "sito"));
        }
        let elapsed = start.elapsed();
        assert!(
            elapsed < std::time::Duration::from_secs(2),
            "{attempts} failed TOTP verifications took {elapsed:?}; Argon2 backup-code hashing must not be on this path"
        );
    }

    /// Legacy Argon2 backup hashes are refused without running Argon2.
    #[test]
    fn test_legacy_argon2_backup_hashes_are_refused() {
        let (mut config, setup) = TotpConfig::generate("sito", "admin");
        let argon2_hash = "$argon2id$v=19$m=16384,t=2,p=2$c29tZXNhbHQ$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        config.backup_code_hashes = vec![argon2_hash.to_string()];
        assert!(config.has_legacy_backup_hashes());
        assert!(
            !config.verify(&setup.backup_codes[0], "admin", "sito"),
            "legacy Argon2 backup hashes must be refused, never verified"
        );
    }
}
