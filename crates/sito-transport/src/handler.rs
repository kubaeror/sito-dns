//! Query handler trait implemented by the pipeline.

use sito_core::client::ClientContext;
use sito_proto::Message;
use std::future::Future;

/// Trait implemented by components that process DNS queries.
pub trait QueryHandler: Send + Sync + 'static {
    /// Handle an incoming DNS query from a given client context.
    /// Returns the DNS response message, or None if no response should be sent.
    fn handle(
        &self,
        query: Message,
        client: ClientContext,
    ) -> impl Future<Output = Option<Message>> + Send;
}

impl<F, Fut> QueryHandler for F
where
    F: Fn(Message, ClientContext) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Option<Message>> + Send + 'static,
{
    fn handle(
        &self,
        query: Message,
        client: ClientContext,
    ) -> impl Future<Output = Option<Message>> + Send {
        (self)(query, client)
    }
}
