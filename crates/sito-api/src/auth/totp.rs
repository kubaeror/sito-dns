//! TOTP implementation conforming to RFC 6238 and section 12.2.
//!
//! 30s window, ±1 step tolerance, replay protection for accepted time steps,
//! and 10 one-time backup codes with 128 bits of entropy stored as Argon2id
//! hashes (never as unsalted fast hashes).

use argon2::password_hash::phc::PasswordHash;
use argon2::password_hash::{PasswordHasher, PasswordVerifier};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngExt;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use totp_rs::{Builder, Secret};

/// Backup-code Argon2 memory cost in KiB (16 MiB; codes are already high-entropy).
const BACKUP_ARGON2_M_COST: u32 = 16_384;
const BACKUP_ARGON2_T_COST: u32 = 2;
const BACKUP_ARGON2_P_COST: u32 = 2;

/// TOTP configuration and state for a user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotpConfig {
    pub enabled: bool,
    pub secret: String,
    /// Argon2id hashes of remaining one-time backup codes.
    pub backup_code_hashes: Vec<String>,
    /// Highest accepted TOTP time-step, used to reject replays within the
    /// ±1 window. `None` until the first successful dynamic-code login.
    #[serde(default)]
    pub last_used_step: Option<u64>,
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

        // 2. Try one-time backup codes. Evaluate every hash (no early exit) so
        //    the position of the match is not observable from timing.
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

fn backup_argon2() -> Argon2<'static> {
    let params = Params::new(
        BACKUP_ARGON2_M_COST,
        BACKUP_ARGON2_T_COST,
        BACKUP_ARGON2_P_COST,
        None,
    )
    .expect("valid backup-code Argon2 parameters");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

fn hash_backup_code(code: &str) -> String {
    backup_argon2()
        .hash_password(code.as_bytes())
        .map(|hash| hash.to_string())
        .expect("backup-code hashing cannot fail")
}

fn verify_backup_code(code: &str, hash_str: &str) -> bool {
    let Ok(parsed_hash) = PasswordHash::new(hash_str) else {
        return false;
    };
    backup_argon2()
        .verify_password(code.as_bytes(), &parsed_hash)
        .is_ok()
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
        assert!(!setup.qr_code.is_empty());
        assert!(setup.otpauth_url.contains("sito"));

        // Plaintext codes are never stored; hashes are Argon2id.
        assert!(config.backup_code_hashes[0].starts_with("$argon2id$"));
        assert_ne!(config.backup_code_hashes[0], setup.backup_codes[0]);

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
}
