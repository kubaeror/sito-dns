//! Core Upstream trait definition.

use async_trait::async_trait;
use sito_core::error::UpstreamError;
use sito_proto::Message;

/// Trait implemented by DNS upstream resolvers.
#[async_trait]
pub trait Upstream: Send + Sync {
    /// Resolve a DNS query against the upstream.
    async fn resolve(&self, msg: &Message) -> Result<Message, UpstreamError>;
}
