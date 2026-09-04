//! Protocol errors for wire format handling and name normalization.

use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ProtoError {
    #[error("Domain name contains non-ASCII characters (raw IDN not allowed): '{0}'")]
    InvalidIdn(String),

    #[error("Domain name contains invalid character '{character}' in '{domain}'")]
    InvalidCharacter { domain: String, character: char },

    #[error("Invalid domain length ({length} bytes, max 253): '{domain}'")]
    DomainTooLong { domain: String, length: usize },

    #[error("Invalid label length ({length} bytes, max 63) in '{domain}'")]
    LabelTooLong { domain: String, length: usize },

    #[error("Empty label or domain name: '{0}'")]
    EmptyLabel(String),

    #[error("Invalid punycode in label '{label}': {reason}")]
    InvalidPunycode { label: String, reason: String },

    #[error("Wire decode error: {0}")]
    DecodeError(String),

    #[error("Wire encode error: {0}")]
    EncodeError(String),
}
