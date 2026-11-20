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
    async fn query(
        &self,
        name: &Name,
        rtype: RecordType,
        deadline: std::time::Instant,
    ) -> Result<Message, UpstreamError> {
        // The deadline is shared by every fetch for one client query, so a
        // black-holed DS/DNSKEY lookup cannot outlive the query's budget.
        match tokio::time::timeout_at(
            deadline.into(),
            self.manager.resolve(&key_query(name, rtype)),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => Err(UpstreamError::Timeout),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plain::PlainUpstream;
    use crate::upstream::Upstream;
    use sito_core::config::UpstreamStrategy;
    use std::str::FromStr;
    use std::time::{Duration, Instant};

    #[test]
    fn test_key_query_sets_dnssec_ok() {
        let name = Name::from_str("example.com.").unwrap();
        let message = key_query(&name, RecordType::DNSKEY);
        assert!(
            message.metadata.recursion_desired,
            "key fetches must ask the upstream for recursion (RD=1)"
        );
        assert!(
            message.edns.as_ref().is_some_and(|e| e.flags().dnssec_ok),
            "key fetches must set the DO bit"
        );
    }

    #[tokio::test]
    async fn test_upstream_key_fetcher_maps_deadline_to_timeout() {
        // Bind a local UDP socket but never read from it: every datagram is
        // black-holed. The manager and upstream timeouts are long, so only the
        // fetcher's own deadline can end the lookup.
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind black-hole socket");
        let addr = socket.local_addr().expect("black-hole address");
        let manager = Arc::new(UpstreamManager::with_upstreams(
            vec![(
                "black-hole".to_string(),
                Arc::new(PlainUpstream::new(addr, Duration::from_secs(30))),
            )],
            UpstreamStrategy::Failover,
            Duration::from_secs(30),
        ));
        let fetcher = UpstreamKeyFetcher::new(manager);
        let name = Name::from_str("example.com.").expect("name");
        let deadline = Instant::now() + Duration::from_millis(20);

        let result = fetcher.query(&name, RecordType::DNSKEY, deadline).await;

        assert!(
            matches!(result, Err(UpstreamError::Timeout)),
            "the fetcher deadline must surface as Timeout, got {result:?}"
        );
        drop(socket);
    }

    /// An upstream that always refuses the query.
    struct RefusedUpstream;

    #[async_trait::async_trait]
    impl Upstream for RefusedUpstream {
        async fn resolve(&self, _msg: &Message) -> Result<Message, UpstreamError> {
            Err(UpstreamError::Refused)
        }
    }

    #[tokio::test]
    async fn test_upstream_key_fetcher_preserves_refused_error() {
        let manager = Arc::new(UpstreamManager::with_upstreams(
            vec![("refused".to_string(), Arc::new(RefusedUpstream))],
            UpstreamStrategy::Failover,
            Duration::from_secs(5),
        ));
        let fetcher = UpstreamKeyFetcher::new(manager);
        let name = Name::from_str("example.com.").expect("name");

        let result = fetcher
            .query(
                &name,
                RecordType::DNSKEY,
                Instant::now() + Duration::from_secs(5),
            )
            .await;

        assert!(
            matches!(result, Err(UpstreamError::Refused)),
            "the fetcher must preserve a non-timeout upstream error, got {result:?}"
        );
    }
}
