//! Client-side foundation for opt-in HA automatic promotion.
//!
//! ADR-0010 separates the promotion feature into a lease client (this module,
//! C3b2a), the promotion state machine/quiesce/reconciliation/fencing
//! (C3b2b), and status/metrics/CLI confirmation (C3b2c). Only the transport
//! foundation lives here: configuration is in `sito-ha-types`, and this module
//! provides the TLS/bearer witness client.

pub mod witness_client;

#[cfg(test)]
mod tests;

pub use witness_client::{WITNESS_REQUEST_TIMEOUT, WitnessClient, WitnessClientError};
