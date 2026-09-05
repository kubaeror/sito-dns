//! Error types for High Availability (HA) replication.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum HaError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Crypto error: {0}")]
    Crypto(String),

    #[error("TLS configuration error: {0}")]
    Tls(String),

    #[error("Protocol error: {0}")]
    Protocol(String),

    #[error("Validation error for field '{field}': {reason}")]
    Validation { field: String, reason: String },

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Signature verification failed: {0}")]
    SignatureVerification(String),

    #[error("Secret leak detected: bundle contains raw secret '{secret_name}'")]
    SecretLeak { secret_name: String },

    #[error("Configuration rollback error: {0}")]
    Rollback(String),

    #[error("Slave degraded: {0}")]
    Degraded(String),

    #[error("Connection error: {0}")]
    Connection(String),

    #[error("Timeout error: {0}")]
    Timeout(String),
}
