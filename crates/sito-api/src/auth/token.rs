//! API token management per section 12.1 and 12.2.
//!
//! Format: `sito_<random-256-bit>`, only Blake3 hashes stored persistently.
//! Scopes: `admin`, `operator`, `viewer`.

use rand::RngExt;
use serde::{Deserialize, Serialize};
use std::fmt;
use utoipa::ToSchema;

/// RBAC role hierarchy: Admin > Operator > Viewer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Viewer = 1,
    Operator = 2,
    Admin = 3,
}

impl Role {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Viewer => "viewer",
            Self::Operator => "operator",
            Self::Admin => "admin",
        }
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::str::FromStr for Role {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "viewer" => Ok(Self::Viewer),
            "operator" => Ok(Self::Operator),
            "admin" => Ok(Self::Admin),
            other => Err(format!("Unknown role: {other}")),
        }
    }
}

/// Stored metadata for an API token (the plaintext token is never stored).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ApiTokenMeta {
    pub id: String,
    pub name: String,
    pub hash: String,
    pub scope: Role,
    pub created_at: i64,
    pub last_used: Option<i64>,
}

/// Response returned when creating an API token.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CreateTokenResponse {
    pub id: String,
    pub name: String,
    pub scope: Role,
    /// The plaintext token. Only displayed once upon creation.
    pub token: String,
}

/// Hashes an API token using Blake3.
pub fn hash_token(token: &str) -> String {
    blake3::hash(token.as_bytes()).to_hex().to_string()
}

/// Generates a new cryptographically secure API token formatted as `sito_<256-bit hex>`.
pub fn generate_token(name: &str, scope: Role) -> (ApiTokenMeta, CreateTokenResponse) {
    let mut bytes = [0u8; 32];
    rand::rng().fill(&mut bytes);
    let token = format!("sito_{}", hex::encode(bytes));
    let hash = hash_token(&token);
    let id = format!("tok_{}", &hash[..12]);
    let now = chrono::Utc::now().timestamp_millis();

    let meta = ApiTokenMeta {
        id: id.clone(),
        name: name.to_string(),
        hash,
        scope,
        created_at: now,
        last_used: None,
    };

    let response = CreateTokenResponse {
        id,
        name: name.to_string(),
        scope,
        token,
    };

    (meta, response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_generation_and_hashing() {
        let (meta, resp) = generate_token("ci-deploy", Role::Operator);

        assert!(resp.token.starts_with("sito_"));
        assert_eq!(resp.token.len(), 5 + 64);
        assert_eq!(meta.hash, hash_token(&resp.token));
        assert_eq!(meta.scope, Role::Operator);
        assert_eq!(meta.name, "ci-deploy");
    }

    #[test]
    fn test_role_ordering() {
        assert!(Role::Admin > Role::Operator);
        assert!(Role::Operator > Role::Viewer);
        assert!(Role::Admin >= Role::Admin);
    }
}
