//! TOTP implementation conforming to RFC 6238 and section 12.2.
//!
//! 30s window, ±1 step tolerance, 10 one-time backup codes stored hashed.

use blake3::Hash;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use totp_rs::{Algorithm, Secret, TOTP};

/// TOTP configuration and state for a user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotpConfig {
    pub enabled: bool,
    pub secret: String,
    /// Hashes of remaining one-time backup codes.
    pub backup_code_hashes: Vec<String>,
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
    /// Generates a new TOTP setup with secret, URL, QR code, and 10 plaintext backup codes.
    pub fn generate(issuer: &str, username: &str) -> (Self, TotpSetupResponse) {
        let secret = Secret::generate_secret();
        let secret_str = secret.to_encoded().to_string();

        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1, // ±1 step tolerance
            30,
            secret.to_bytes().unwrap_or_default(),
            Some(issuer.to_string()),
            username.to_string(),
        )
        .expect("Valid TOTP parameters");

        let otpauth_url = totp.get_url();
        let qr_code = totp.get_qr_base64().unwrap_or_default();

        // Generate 10 one-time 8-character backup codes
        let mut plaintext_backup_codes = Vec::with_capacity(10);
        let mut backup_code_hashes = Vec::with_capacity(10);

        for _ in 0..10 {
            let code = format!("{:08x}", rand::random::<u32>());
            let hash = hash_backup_code(&code);
            plaintext_backup_codes.push(code);
            backup_code_hashes.push(hash);
        }

        let config = Self {
            enabled: false,
            secret: secret_str.clone(),
            backup_code_hashes: backup_code_hashes.clone(),
        };

        let response = TotpSetupResponse {
            secret: secret_str,
            otpauth_url,
            qr_code,
            backup_codes: plaintext_backup_codes,
        };

        (config, response)
    }

    /// Verifies an entered TOTP code (either 6-digit dynamic code or 8-char backup code).
    ///
    /// If a backup code matches, it is consumed (removed from remaining hashes).
    pub fn verify(&mut self, code: &str, username: &str, issuer: &str) -> bool {
        let clean_code = code.trim().replace(' ', "");

        // 1. Try dynamic 6-digit TOTP code
        if clean_code.len() == 6 && clean_code.chars().all(|c| c.is_ascii_digit()) {
            if let Ok(secret) = Secret::Encoded(self.secret.clone()).to_bytes() {
                if let Ok(totp) = TOTP::new(
                    Algorithm::SHA1,
                    6,
                    1, // ±1 step window
                    30,
                    secret,
                    Some(issuer.to_string()),
                    username.to_string(),
                ) {
                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    if totp.check(&clean_code, now) {
                        return true;
                    }
                }
            }
        }

        // 2. Try one-time backup codes
        let entered_hash = hash_backup_code(&clean_code);
        if let Some(pos) = self
            .backup_code_hashes
            .iter()
            .position(|h| h == &entered_hash)
        {
            self.backup_code_hashes.remove(pos);
            return true;
        }

        false
    }
}

fn hash_backup_code(code: &str) -> String {
    let hash: Hash = blake3::hash(code.as_bytes());
    hash.to_hex().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_totp_setup_and_verification() {
        let (mut config, setup) = TotpConfig::generate("sito", "admin");

        assert_eq!(setup.backup_codes.len(), 10);
        assert!(!setup.qr_code.is_empty());
        assert!(setup.otpauth_url.contains("sito"));

        // Generate valid 6-digit code
        let secret = Secret::Encoded(config.secret.clone()).to_bytes().unwrap();
        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            secret,
            Some("sito".to_string()),
            "admin".to_string(),
        )
        .unwrap();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let valid_code = totp.generate(now);

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
}
