//! DNS query execution pipeline.

use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::{Name, RData};
use sito_cache::DnsCache;
use sito_clients::{ClientRegistry, ParentalRegistry, ServiceRegistry, match_safe_search};
use sito_core::FilterEngine;
use sito_core::client::ClientContext;
use sito_core::config::Config;
use sito_dnssec::DnssecValidator;
use sito_filter::HostsFilterEngine;
use sito_proto::synthesize_blocked_response;
use sito_proto::wire::{synthesize_cname_response, synthesize_records_response};
use sito_rewrites::RewriteTable;
use sito_transport::QueryHandler;
use sito_upstream::UpstreamManager;
use std::str::FromStr;
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
    dnssec: Arc<DnssecValidator>,
    clients: Arc<ClientRegistry>,
    parental: Arc<ParentalRegistry>,
    services: Arc<ServiceRegistry>,
    rewrites: Arc<RewriteTable>,
    in_flight: Arc<AtomicUsize>,
}

impl DnsPipeline {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        config: Arc<Config>,
        filter: Arc<HostsFilterEngine>,
        cache: Arc<DnsCache>,
        upstream: Arc<UpstreamManager>,
        dnssec: Arc<DnssecValidator>,
        clients: Arc<ClientRegistry>,
        parental: Arc<ParentalRegistry>,
        services: Arc<ServiceRegistry>,
        rewrites: Arc<RewriteTable>,
        in_flight: Arc<AtomicUsize>,
    ) -> Self {
        Self {
            config,
            filter,
            cache,
            upstream,
            dnssec,
            clients,
            parental,
            services,
            rewrites,
            in_flight,
        }
    }
}

impl QueryHandler for DnsPipeline {
    async fn handle(&self, query: Message, client: ClientContext) -> Option<Message> {
        self.in_flight.fetch_add(1, Ordering::SeqCst);
        let _guard = InFlightGuard(Arc::clone(&self.in_flight));

        let mut client = client;
        let now = chrono::Utc::now();
        let policy = self.clients.resolve(&mut client, now);

        let query_id = query.metadata.id;
        let request_id = rand::random::<u64>();

        let span = tracing::info_span!(
            "query",
            request_id = request_id,
            client_ip = %client.ip,
            client_name = ?client.client_name,
            group = %policy.group_name,
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

            // ADR-0007 Stage 1: $important filter rules (takes precedence over local rewrites)
            if policy.is_filtering_enabled {
                if let Some(verdict) = self.filter.evaluate_important(qname, qtype, &client) {
                    if verdict.is_blocked() {
                        info!(
                            qname = %qname,
                            qtype = ?qtype,
                            verdict = ?verdict,
                            "Query blocked by $important filter rule"
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

            // ADR-0007 Stage 2: Local DNS rewrites and auto-PTR
            if let Some(records) = self.rewrites.lookup(qname, qtype, &client) {
                trace!(
                    qname = %qname,
                    qtype = ?qtype,
                    count = records.len(),
                    "Resolved via local rewrite table"
                );
                let mut rewrite_resp = synthesize_records_response(&query, records);
                rewrite_resp.metadata.id = query_id;
                return Some(rewrite_resp);
            }

            let domain_str = qname.to_utf8();

            // ADR-0007 Stage 3: Standard filtering, Parental Control, and Service Blocking
            if policy.is_filtering_enabled {
                // 3a. Parental Control categories (adult, gambling)
                if policy.parental
                    && self.parental.matches_any_category(
                        policy.parental_categories.iter().map(String::as_str),
                        &domain_str,
                    )
                {
                    info!(
                        qname = %qname,
                        qtype = ?qtype,
                        "Query blocked by parental control category"
                    );
                    let mut blocked_resp = synthesize_blocked_response(
                        &query,
                        &self.config.filtering.blocking_mode,
                        self.config.filtering.blocking_ttl,
                    );
                    blocked_resp.metadata.id = query_id;
                    return Some(blocked_resp);
                }

                // 3b. Blocked services (e.g. TikTok, YouTube, etc.)
                if !policy.active_blocked_services.is_empty()
                    && self
                        .services
                        .matches_any_service(
                            policy.active_blocked_services.iter().map(String::as_str),
                            &domain_str,
                        )
                        .is_some()
                {
                    info!(
                        qname = %qname,
                        qtype = ?qtype,
                        "Query blocked by service blocking policy"
                    );
                    let mut blocked_resp = synthesize_blocked_response(
                        &query,
                        &self.config.filtering.blocking_mode,
                        self.config.filtering.blocking_ttl,
                    );
                    blocked_resp.metadata.id = query_id;
                    return Some(blocked_resp);
                }

                // 3c. Standard filter rules
                let verdict = self.filter.evaluate_standard(qname, qtype, &client);
                if verdict.is_blocked() {
                    info!(
                        qname = %qname,
                        qtype = ?qtype,
                        verdict = ?verdict,
                        "Query blocked by standard filter"
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

            // ADR-0007 Stage 4: Safe Search CNAME rewrites (Google, Bing, YouTube, DuckDuckGo)
            if policy.safe_search {
                if let Some(target) = match_safe_search(&domain_str, policy.safe_search_youtube) {
                    if let Ok(cname_target) = Name::from_str(target) {
                        info!(
                            qname = %qname,
                            target = %target,
                            "Enforcing safe search CNAME rewrite"
                        );
                        let mut ss_resp = synthesize_cname_response(&query, &cname_target, 300);
                        ss_resp.metadata.id = query_id;
                        return Some(ss_resp);
                    }
                }
            }

            // 5. Cache lookup
            if self.config.dns.cache.enabled {
                if let Some(mut cached_resp) = self.cache.get(qname, qtype, qclass).await {
                    info!(qname = %qname, qtype = ?qtype, "Cache hit");
                    cached_resp.metadata.id = query_id;
                    return Some(cached_resp);
                }
                debug!(qname = %qname, qtype = ?qtype, "Cache miss");
            }

            // 6. Upstream resolution
            match self.upstream.resolve(&query).await {
                Ok(mut upstream_resp) => {
                    upstream_resp.metadata.id = query_id;

                    // 7. CNAME uncloaking: inspect any CNAME targets against FilterEngine
                    if self.config.filtering.enabled
                        && self.config.filtering.cname_cloaking
                        && policy.is_filtering_enabled
                    {
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

                    // 8. DNSSEC validation
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs() as u32;
                    let _outcome = self.dnssec.validate_response(&mut upstream_resp, None, now);

                    if self.config.dns.cache.enabled
                        && upstream_resp.metadata.response_code == ResponseCode::NoError
                    {
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
