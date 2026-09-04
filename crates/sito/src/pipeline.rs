//! DNS query execution pipeline.

use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::RData;
use sito_cache::DnsCache;
use sito_core::client::ClientContext;
use sito_core::config::Config;
use sito_core::engine::FilterEngine;
use sito_filter::HostsFilterEngine;
use sito_proto::synthesize_blocked_response;
use sito_transport::QueryHandler;
use sito_upstream::UpstreamManager;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tracing::{Instrument, debug, info, trace, warn};

/// Tracks in-flight queries using RAII.
struct InFlightGuard(Arc<AtomicUsize>);

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// The core DNS query resolution pipeline.
pub struct DnsPipeline {
    config: Arc<Config>,
    filter: Arc<HostsFilterEngine>,
    cache: Arc<DnsCache>,
    upstream: Arc<UpstreamManager>,
    in_flight: Arc<AtomicUsize>,
}

impl DnsPipeline {
    pub fn new(
        config: Arc<Config>,
        filter: Arc<HostsFilterEngine>,
        cache: Arc<DnsCache>,
        upstream: Arc<UpstreamManager>,
        in_flight: Arc<AtomicUsize>,
    ) -> Self {
        Self {
            config,
            filter,
            cache,
            upstream,
            in_flight,
        }
    }
}

impl QueryHandler for DnsPipeline {
    async fn handle(&self, query: Message, client: ClientContext) -> Option<Message> {
        self.in_flight.fetch_add(1, Ordering::SeqCst);
        let _guard = InFlightGuard(Arc::clone(&self.in_flight));

        let query_id = query.metadata.id;
        let request_id = rand::random::<u64>();

        let span = tracing::info_span!(
            "query",
            request_id = request_id,
            client_ip = %client.ip,
            query_id = query_id
        );

        async {
            let Some(first_query) = query.queries.first() else {
                let mut err_resp = Message::new(query_id, MessageType::Response, OpCode::Query);
                err_resp.metadata.response_code = ResponseCode::FormErr;
                return Some(err_resp);
            };

            let qname = first_query.name();
            let qtype = first_query.query_type();
            let qclass = first_query.query_class();

            trace!(qname = %qname, qtype = ?qtype, "Processing DNS query");

            // 1. Filtering engine evaluation
            let verdict = self.filter.evaluate(qname, qtype, &client);
            if verdict.is_blocked() {
                info!(
                    qname = %qname,
                    qtype = ?qtype,
                    verdict = ?verdict,
                    "Query blocked by filter"
                );
                let mut blocked_resp = synthesize_blocked_response(
                    &query,
                    &self.config.filtering.blocking_mode,
                    self.config.filtering.blocking_ttl,
                );
                blocked_resp.metadata.id = query_id;
                return Some(blocked_resp);
            }

            // 2. Cache lookup
            if self.config.dns.cache.enabled {
                if let Some(mut cached_resp) = self.cache.get(qname, qtype, qclass).await {
                    info!(qname = %qname, qtype = ?qtype, "Cache hit");
                    cached_resp.metadata.id = query_id;
                    return Some(cached_resp);
                }
                debug!(qname = %qname, qtype = ?qtype, "Cache miss");
            }

            // 3. Upstream resolution
            match self.upstream.resolve(&query).await {
                Ok(mut upstream_resp) => {
                    upstream_resp.metadata.id = query_id;

                    // 4. CNAME uncloaking: inspect any CNAME targets against FilterEngine
                    if self.config.filtering.enabled && self.config.filtering.cname_cloaking {
                        for record in &upstream_resp.answers {
                            if let RData::CNAME(cname) = &record.data {
                                let cname_target = &cname.0;
                                let verdict = self.filter.evaluate(cname_target, qtype, &client);
                                if verdict.is_blocked() {
                                    info!(
                                        qname = %qname,
                                        cname_target = %cname_target,
                                        verdict = ?verdict,
                                        via_cname = true,
                                        "Query blocked via CNAME uncloaking"
                                    );
                                    let mut blocked_resp = synthesize_blocked_response(
                                        &query,
                                        &self.config.filtering.blocking_mode,
                                        self.config.filtering.blocking_ttl,
                                    );
                                    blocked_resp.metadata.id = query_id;
                                    return Some(blocked_resp);
                                }
                            }
                        }
                    }

                    if self.config.dns.cache.enabled {
                        self.cache.insert(&query, &upstream_resp).await;
                    }
                    Some(upstream_resp)
                }
                Err(e) => {
                    warn!(
                        qname = %qname,
                        qtype = ?qtype,
                        error = %e,
                        "Upstream resolution failed"
                    );
                    let mut err_resp = Message::new(query_id, MessageType::Response, OpCode::Query);
                    err_resp.metadata.response_code = ResponseCode::ServFail;
                    err_resp.metadata.recursion_desired = query.metadata.recursion_desired;
                    err_resp.metadata.recursion_available = true;
                    err_resp.queries.clone_from(&query.queries);
                    Some(err_resp)
                }
            }
        }
        .instrument(span)
        .await
    }
}
