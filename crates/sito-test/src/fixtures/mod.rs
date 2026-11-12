//! Shared, test-only fixtures (WP-1.8).
//!
//! Nothing in this module is linked into the production `sito` binary: it
//! lives in the `sito-test` crate, which only integration tests depend on.

pub mod acme;
pub mod dnssec;
pub mod ha;
pub mod net;
pub mod tls;
