//! DNSSEC key fetcher backed by the upstream manager.

use std::sync::Arc;

use async_trait::async_trait;
use sito_core::DnssecKeyFetcher;
use sito_core::error::UpstreamError;
use sito_proto::{Edns, Message, MessageType, Name, OpCode, Query, RecordType};

use crate::manager::UpstreamManager;

/// Fetches DNSKEY/DS records through the same upstreams used for queries.
pub struct UpstreamKeyFetcher {
    manager: Arc<UpstreamManager>,
}

impl UpstreamKeyFetcher {
    /// Creates a fetcher over the given upstream manager.
    #[must_use]
    pub fn new(manager: Arc<UpstreamManager>) -> Self {
        Self { manager }
    }
}

/// Builds the DS/DNSKEY query used for chain construction.
pub(crate) fn key_query(name: &Name, rtype: RecordType) -> Message {
    let mut message = Message::new(0, MessageType::Query, OpCode::Query);
    message.metadata.recursion_desired = true;
    message.queries.push(Query::query(name.clone(), rtype));
    // DNSSEC OK: without it a validating upstream strips the RRSIGs that bind
    // the fetched DS/DNSKEY RRsets, breaking chain construction.
    let mut edns = Edns::new();
    edns.set_dnssec_ok(true);
    message.set_edns(edns);
    message
}

#[async_trait]
impl DnssecKeyFetcher for UpstreamKeyFetcher {
    async fn query(&self, name: &Name, rtype: RecordType) -> Result<Message, UpstreamError> {
        self.manager.resolve(&key_query(name, rtype)).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_key_query_sets_dnssec_ok() {
        let name = Name::from_str("example.com.").unwrap();
        let message = key_query(&name, RecordType::DNSKEY);
        assert!(
            message.edns.as_ref().is_some_and(|e| e.flags().dnssec_ok),
            "key fetches must set the DO bit"
        );
    }
}
