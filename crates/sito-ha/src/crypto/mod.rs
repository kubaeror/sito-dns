//! Cryptographic utilities for HA mutual TLS and Ed25519 bundle signing.

pub mod certs;
pub mod signing;

pub use certs::{
    GeneratedCerts, compute_blake3_fingerprint, compute_blake3_raw_hex, generate_ha_certs,
    generate_ha_certs_with_sans,
};
pub use signing::{Ed25519SigningKey, parse_public_key, verify_ed25519_signature};
