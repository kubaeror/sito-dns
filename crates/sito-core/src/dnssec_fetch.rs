//! Key-resolution interface used by DNSSEC chain validation.
//!
//! The validator can only walk DS/DNSKEY links that are present in the
//! response. When a signed answer references a key that is not anchored and
//! not included, the validator asks a [`DnssecKeyFetcher`] for the missing
//! DNSKEY/DS records. Production code wires this to the upstream manager;
//! tests use deterministic in-memory fetchers.

use async_trait::async_trait;
use hickory_proto::op::Message;
use hickory_proto::rr::{Name, RecordType};

use crate::error::UpstreamError;

/// Fetches DNSKEY/DS records needed to extend a DNSSEC trust chain.
#[async_trait]
pub trait DnssecKeyFetcher: Send + Sync {
    /// Resolves a single question (`name`, `rtype`) and returns the message.
    async fn query(&self, name: &Name, rtype: RecordType) -> Result<Message, UpstreamError>;
}
