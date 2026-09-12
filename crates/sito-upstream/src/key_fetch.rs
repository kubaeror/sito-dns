//! DNSSEC key fetcher backed by the upstream manager.

use std::sync::Arc;

use async_trait::async_trait;
use sito_core::DnssecKeyFetcher;
use sito_core::error::UpstreamError;
use sito_proto::{Message, MessageType, Name, OpCode, Query, RecordType};

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

#[async_trait]
impl DnssecKeyFetcher for UpstreamKeyFetcher {
    async fn query(&self, name: &Name, rtype: RecordType) -> Result<Message, UpstreamError> {
        let mut message = Message::new(0, MessageType::Query, OpCode::Query);
        message.metadata.recursion_desired = true;
        message.queries.push(Query::query(name.clone(), rtype));
        self.manager.resolve(&message).await
    }
}
