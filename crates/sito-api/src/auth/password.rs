//! Password hashing using Argon2id with strict parameters per section 12.2.
//!
//! Parameters: m = 64 MiB (65536 KiB), t = 3 iterations, p = 4 lanes.

use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Argon2, Params, Version};

/// Memory cost in KiB (64 MiB).
pub const ARGON2_M_COST: u32 = 65536;
/// Time cost in iterations.
pub const ARGON2_T_COST: u32 = 3;
/// Parallelism cost in lanes.
pub const ARGON2_P_COST: u32 = 4;

/// Hashes a plaintext password using Argon2id with production parameters.
pub fn hash_password(password: &str) -> Result<String, String> {
    let params = Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, None)
        .map_err(|e| format!("Invalid Argon2 parameters: {e}"))?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, params);
    let salt = SaltString::generate(&mut OsRng);

    argon2
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|e| format!("Failed to hash password: {e}"))
}

/// Verifies a plaintext password against an Argon2 hash.
pub fn verify_password(password: &str, hash_str: &str) -> bool {
    let Ok(parsed_hash) = PasswordHash::new(hash_str) else {
        return false;
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_hash_and_verification() {
        let password = "SuperSecretPassword123!";
        let hash = hash_password(password).expect("hash failed");

        assert!(hash.starts_with("$argon2id$"));
        assert!(verify_password(password, &hash));
        assert!(!verify_password("WrongPassword!", &hash));
    }
}
