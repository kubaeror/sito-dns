//! DNS query execution pipeline.

use arc_swap::ArcSwap;
use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::{Name, RData, RecordType};
use sito_cache::DnsCache;
use sito_clients::{ClientRegistry, ParentalRegistry, ServiceRegistry, match_safe_search};
use sito_core::FilterEngine;
use sito_core::client::ClientContext;
use sito_core::config::Config;
use sito_dnssec::DnssecValidator;
use sito_filter::{AntiBypassRegistry, HostsFilterEngine};
use sito_proto::synthesize_blocked_response;
use sito_proto::wire::{synthesize_cname_response, synthesize_records_response};
use sito_rewrites::RewriteTable;
use sito_transport::QueryHandler;
use sito_upstream::UpstreamManager;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tracing::{Instrument, debug, info, trace, warn};

/// Helper trait to accept either `Arc<T>` or `Arc<ArcSwap<T>>`.
pub trait IntoArcSwap<T> {
    fn into_arc_swap(self) -> Arc<ArcSwap<T>>;
}

impl<T> IntoArcSwap<T> for Arc<ArcSwap<T>> {
    fn into_arc_swap(self) -> Arc<ArcSwap<T>> {
        self
    }
}

impl<T> IntoArcSwap<T> for Arc<T> {
    fn into_arc_swap(self) -> Arc<ArcSwap<T>> {
        Arc::new(ArcSwap::new(self))
    }
}

/// Tracks in-flight queries using RAII.
struct InFlightGuard(Arc<AtomicUsize>);

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Outcome of executing a query through the DNS pipeline.
struct QueryOutcome {
    response: Option<Message>,
    verdict: &'static str,
    rule: Option<String>,
    source: Option<String>,
    upstream: Option<String>,
    from_cache: bool,
    domain_str: String,
    qtype: RecordType,
    dnssec: Option<String>,
}

impl QueryOutcome {
    fn blocked(
        response: Message,
        rule: Option<String>,
        source: Option<String>,
        domain_str: String,
        qtype: RecordType,
    ) -> Self {
        Self {
            response: Some(response),
            verdict: "blocked",
            rule,
            source,
            upstream: None,
            from_cache: false,
            domain_str,
            qtype,
            dnssec: None,
        }
    }

    fn anti_doh_blocked(response: Message, domain_str: String, qtype: RecordType) -> Self {
        Self::blocked(
            response,
            Some("anti_doh_bypass".to_string()),
            Some("anti_doh_bypass".to_string()),
            domain_str,
            qtype,
        )
    }

    fn rewritten(response: Message, domain_str: String, qtype: RecordType) -> Self {
        Self {
            response: Some(response),
            verdict: "rewritten",
            rule: None,
            source: None,
            upstream: None,
            from_cache: false,
            domain_str,
            qtype,
            dnssec: None,
        }
    }

    fn formerr(query_id: u16) -> Self {
        let mut err_resp = Message::new(query_id, MessageType::Response, OpCode::Query);
        err_resp.metadata.response_code = ResponseCode::FormErr;
        Self {
            response: Some(err_resp),
            verdict: "formerr",
            rule: None,
            source: None,
            upstream: None,
            from_cache: false,
            domain_str: String::new(),
            qtype: RecordType::A,
            dnssec: None,
        }
    }

    fn servfail(query_id: u16, query: &Message, domain_str: String, qtype: RecordType) -> Self {
        let mut err_resp = Message::new(query_id, MessageType::Response, OpCode::Query);
        err_resp.metadata.response_code = ResponseCode::ServFail;
        err_resp.metadata.recursion_desired = query.metadata.recursion_desired;
        err_resp.metadata.recursion_available = true;
        err_resp.queries.clone_from(&query.queries);
        Self {
            response: Some(err_resp),
            verdict: "servfail",
            rule: None,
            source: None,
            upstream: None,
            from_cache: false,
            domain_str,
            qtype,
            dnssec: None,
        }
    }
}

fn make_blocked_response(
    query: &Message,
    blocking_mode: &sito_core::BlockingMode,
    blocking_ttl: u32,
    query_id: u16,
) -> Message {
    let mut blocked_resp = synthesize_blocked_response(query, blocking_mode, blocking_ttl);
    blocked_resp.metadata.id = query_id;
    blocked_resp
}

fn answers_contain_bypass_ip(
    anti_bypass: &AntiBypassRegistry,
    answers: &[hickory_proto::rr::Record],
) -> bool {
    answers.iter().any(|rec| match &rec.data {
        RData::A(a) => anti_bypass.matches_ip(&IpAddr::V4(a.0)),
        RData::AAAA(aaaa) => anti_bypass.matches_ip(&IpAddr::V6(aaaa.0)),
        _ => false,
    })
}

/// The core DNS query resolution pipeline.
pub struct DnsPipeline {
    config: Arc<ArcSwap<Config>>,
    filter: Arc<HostsFilterEngine>,
    anti_bypass: Arc<AntiBypassRegistry>,
    cache: Arc<DnsCache>,
    upstream: Arc<UpstreamManager>,
    dnssec: Arc<DnssecValidator>,
    clients: Arc<ArcSwap<ClientRegistry>>,
    parental: Arc<ParentalRegistry>,
    services: Arc<ServiceRegistry>,
    rewrites: Arc<ArcSwap<RewriteTable>>,
    in_flight: Arc<AtomicUsize>,
    prefetch_semaphore: Arc<tokio::sync::Semaphore>,
    querylog: Option<sito_stats::QueryLogSender>,
    metrics: Option<sito_stats::MetricsRegistry>,
}

impl DnsPipeline {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        config: impl IntoArcSwap<Config>,
        filter: Arc<HostsFilterEngine>,
        cache: Arc<DnsCache>,
        upstream: Arc<UpstreamManager>,
        dnssec: Arc<DnssecValidator>,
        clients: impl IntoArcSwap<ClientRegistry>,
        parental: Arc<ParentalRegistry>,
        services: Arc<ServiceRegistry>,
        rewrites: impl IntoArcSwap<RewriteTable>,
        in_flight: Arc<AtomicUsize>,
    ) -> Self {
        Self {
            config: config.into_arc_swap(),
            filter,
            anti_bypass: Arc::new(AntiBypassRegistry::bundled()),
            cache,
            upstream,
            dnssec,
            clients: clients.into_arc_swap(),
            parental,
            services,
            rewrites: rewrites.into_arc_swap(),
            in_flight,
            prefetch_semaphore: Arc::new(tokio::sync::Semaphore::new(64)),
            querylog: None,
            metrics: None,
        }
    }

    #[must_use]
    pub fn with_anti_bypass(mut self, anti_bypass: Arc<AntiBypassRegistry>) -> Self {
        self.anti_bypass = anti_bypass;
        self
    }

    #[must_use]
    pub fn with_stats(
        mut self,
        querylog: sito_stats::QueryLogSender,
        metrics: sito_stats::MetricsRegistry,
    ) -> Self {
        self.querylog = Some(querylog);
        self.metrics = Some(metrics);
        self
    }
}

impl QueryHandler for DnsPipeline {
    async fn handle(&self, query: Message, client: ClientContext) -> Option<Message> {
        self.in_flight.fetch_add(1, Ordering::SeqCst);
        let _guard = InFlightGuard(Arc::clone(&self.in_flight));

        let config = self.config.load();
        let clients = self.clients.load();
        let rewrites = self.rewrites.load();

        let mut client = client;
        let now = chrono::Utc::now();
        let policy = clients.resolve(&mut client, now);

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

        let start = std::time::Instant::now();

        let outcome = async {
            let Some(first_query) = query.queries.first() else {
                return QueryOutcome::formerr(query_id);
            };

            let qname = first_query.name();
            let qtype = first_query.query_type();
            let qclass = first_query.query_class();
            let domain_str = qname.to_utf8();

            trace!(qname = %qname, qtype = ?qtype, "Processing DNS query");

            let bypass_check_needed = match config.filtering.anti_doh_bypass.as_str() {
                "block_all" => true,
                "block_except_trusted" => !policy.trusted,
                _ => false,
            };

            // Anti-DoH bypass: check if domain matches known public resolver
            if bypass_check_needed && self.anti_bypass.matches_domain(&domain_str) {
                info!(
                    qname = %qname,
                    "Query blocked by Anti-DoH bypass rule (resolver domain)"
                );
                if let Some(ref m) = self.metrics {
                    m.inc_doh_bypass_blocked();
                }
                let resp = make_blocked_response(
                    &query,
                    &config.filtering.blocking_mode,
                    config.filtering.blocking_ttl,
                    query_id,
                );
                return QueryOutcome::anti_doh_blocked(resp, domain_str, qtype);
            }

            // ADR-0007 Stage 1: $important filter rules (takes precedence over local rewrites)
            if policy.is_filtering_enabled
                && let Some(verdict) = self.filter.evaluate_important(qname, qtype, &client)
                && verdict.is_blocked()
            {
                info!(
                    qname = %qname,
                    qtype = ?qtype,
                    verdict = ?verdict,
                    "Query blocked by $important filter rule"
                );
                let resp = make_blocked_response(
                    &query,
                    &config.filtering.blocking_mode,
                    config.filtering.blocking_ttl,
                    query_id,
                );
                return QueryOutcome::blocked(resp, None, None, domain_str, qtype);
            }

            // ADR-0007 Stage 2: Local DNS rewrites and auto-PTR
            if let Some(records) = rewrites.lookup(qname, qtype, &client) {
                trace!(
                    qname = %qname,
                    qtype = ?qtype,
                    count = records.len(),
                    "Resolved via local rewrite table"
                );
                let mut rewrite_resp = synthesize_records_response(&query, records);
                rewrite_resp.metadata.id = query_id;
                return QueryOutcome::rewritten(rewrite_resp, domain_str, qtype);
            }

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
                    let resp = make_blocked_response(
                        &query,
                        &config.filtering.blocking_mode,
                        config.filtering.blocking_ttl,
                        query_id,
                    );
                    return QueryOutcome::blocked(
                        resp,
                        Some("parental".to_string()),
                        None,
                        domain_str,
                        qtype,
                    );
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
                    let resp = make_blocked_response(
                        &query,
                        &config.filtering.blocking_mode,
                        config.filtering.blocking_ttl,
                        query_id,
                    );
                    return QueryOutcome::blocked(
                        resp,
                        Some("service".to_string()),
                        None,
                        domain_str,
                        qtype,
                    );
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
                    let resp = make_blocked_response(
                        &query,
                        &config.filtering.blocking_mode,
                        config.filtering.blocking_ttl,
                        query_id,
                    );
                    return QueryOutcome::blocked(resp, None, None, domain_str, qtype);
                }
            }

            // ADR-0007 Stage 4: Safe Search CNAME rewrites (Google, Bing, YouTube, DuckDuckGo)
            if policy.safe_search
                && let Some(target) = match_safe_search(&domain_str, policy.safe_search_youtube)
                && let Ok(cname_target) =
                    Name::from_str(&format!("{}.", target.trim_end_matches('.')))
            {
                info!(
                    qname = %qname,
                    target = %target,
                    "Enforcing safe search CNAME rewrite"
                );
                let mut ss_resp = synthesize_cname_response(&query, &cname_target, 300);
                ss_resp.metadata.id = query_id;
                return QueryOutcome::rewritten(ss_resp, domain_str, qtype);
            }

            // 5. Cache lookup
            if config.dns.cache.enabled {
                if let Some(mut cached_resp) = self.cache.get(qname, qtype, qclass).await {
                    if bypass_check_needed
                        && answers_contain_bypass_ip(&self.anti_bypass, &cached_resp.answers)
                    {
                        info!(
                            qname = %qname,
                            "Cached query blocked by Anti-DoH bypass (resolved IP)"
                        );
                        if let Some(ref m) = self.metrics {
                            m.inc_doh_bypass_blocked();
                        }
                        let resp = make_blocked_response(
                            &query,
                            &config.filtering.blocking_mode,
                            config.filtering.blocking_ttl,
                            query_id,
                        );
                        return QueryOutcome::anti_doh_blocked(resp, domain_str, qtype);
                    }

                    info!(qname = %qname, qtype = ?qtype, "Cache hit");
                    if self.cache.should_prefetch(qname, qtype, qclass).await
                        && let Ok(permit) = Arc::clone(&self.prefetch_semaphore).try_acquire_owned()
                    {
                        let bg_upstream = Arc::clone(&self.upstream);
                        let bg_cache = Arc::clone(&self.cache);
                        let bg_query = query.clone();
                        tokio::spawn(async move {
                            let _permit = permit;
                            if let Ok(resp) = bg_upstream.resolve(&bg_query).await
                                && (resp.metadata.response_code == ResponseCode::NoError
                                    || resp.metadata.response_code == ResponseCode::NXDomain)
                            {
                                bg_cache.insert(&bg_query, &resp).await;
                            }
                        });
                    }
                    cached_resp.metadata.id = query_id;
                    let cached_dnssec = if self.dnssec.mode == sito_dnssec::DnssecMode::Disabled
                        || !cached_resp.metadata.authentic_data
                    {
                        None
                    } else {
                        Some("secure".to_string())
                    };
                    return QueryOutcome {
                        response: Some(cached_resp),
                        verdict: "allowed",
                        rule: Some("cache".to_string()),
                        source: None,
                        upstream: None,
                        from_cache: true,
                        domain_str,
                        qtype,
                        dnssec: cached_dnssec,
                    };
                }
                debug!(qname = %qname, qtype = ?qtype, "Cache miss");
                if let Some(ref m) = self.metrics {
                    m.inc_cache_misses();
                }
            }

            // 6. Upstream resolution
            match self.upstream.resolve_with_upstream(&query).await {
                Ok((mut upstream_resp, upstream_name)) => {
                    upstream_resp.metadata.id = query_id;

                    // Anti-DoH bypass: inspect resolved A and AAAA records for known resolver IPs
                    if bypass_check_needed
                        && answers_contain_bypass_ip(&self.anti_bypass, &upstream_resp.answers)
                    {
                        info!(
                            qname = %qname,
                            "Upstream query blocked by Anti-DoH bypass (resolved IP)"
                        );
                        if let Some(ref m) = self.metrics {
                            m.inc_doh_bypass_blocked();
                        }
                        let resp = make_blocked_response(
                            &query,
                            &config.filtering.blocking_mode,
                            config.filtering.blocking_ttl,
                            query_id,
                        );
                        return QueryOutcome::anti_doh_blocked(resp, domain_str, qtype);
                    }

                    // 7. CNAME uncloaking: inspect any CNAME targets against FilterEngine
                    if config.filtering.enabled
                        && config.filtering.cname_cloaking
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
                                    let resp = make_blocked_response(
                                        &query,
                                        &config.filtering.blocking_mode,
                                        config.filtering.blocking_ttl,
                                        query_id,
                                    );
                                    return QueryOutcome::blocked(
                                        resp,
                                        Some("cname_uncloaking".to_string()),
                                        None,
                                        domain_str,
                                        qtype,
                                    );
                                }
                            }
                        }
                    }

                    // 8. DNSSEC validation
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs() as u32;
                    let dnssec_outcome =
                        self.dnssec.validate_response(&mut upstream_resp, None, now);
                    let dnssec_str = if self.dnssec.mode == sito_dnssec::DnssecMode::Disabled {
                        None
                    } else {
                        Some(dnssec_outcome.as_str().to_string())
                    };

                    if config.dns.cache.enabled
                        && (upstream_resp.metadata.response_code == ResponseCode::NoError
                            || upstream_resp.metadata.response_code == ResponseCode::NXDomain)
                    {
                        self.cache.insert(&query, &upstream_resp).await;
                        if let Some(ref m) = self.metrics {
                            m.set_cache_size_bytes(
                                i64::try_from(self.cache.weighted_size()).unwrap_or(i64::MAX),
                            );
                        }
                    }
                    QueryOutcome {
                        response: Some(upstream_resp),
                        verdict: "allowed",
                        rule: None,
                        source: None,
                        upstream: Some(upstream_name),
                        from_cache: false,
                        domain_str,
                        qtype,
                        dnssec: dnssec_str,
                    }
                }
                Err(e) => {
                    warn!(
                        qname = %qname,
                        qtype = ?qtype,
                        error = %e,
                        "Upstream resolution failed"
                    );

                    if config.dns.cache.enabled
                        && config.dns.cache.serve_stale_hours > 0
                        && let Some(mut stale_resp) =
                            self.cache.get_stale(qname, qtype, qclass).await
                    {
                        info!(
                            qname = %qname,
                            "Upstream failed, serving stale cached response (RFC 8767)"
                        );
                        stale_resp.metadata.id = query_id;
                        return QueryOutcome {
                            response: Some(stale_resp),
                            verdict: "allowed",
                            rule: Some("stale_cache".to_string()),
                            source: None,
                            upstream: None,
                            from_cache: true,
                            domain_str,
                            qtype,
                            dnssec: None,
                        };
                    }

                    QueryOutcome::servfail(query_id, &query, domain_str, qtype)
                }
            }
        }
        .instrument(span)
        .await;

        let elapsed = start.elapsed();
        let elapsed_us = elapsed.as_micros() as i64;
        let elapsed_secs = elapsed.as_secs_f64();
        let qtype_num = u16::from(outcome.qtype);

        if let Some(ref m) = self.metrics {
            m.inc_queries(&client.proto, qtype_num, outcome.verdict);
            m.observe_query_duration(outcome.verdict, elapsed_secs);
            if outcome.from_cache {
                m.inc_cache_hits();
            }
        }

        if !policy.ignore_query_log
            && !outcome.domain_str.is_empty()
            && let Some(ref ql) = self.querylog
        {
            let rcode = outcome
                .response
                .as_ref()
                .map(|r| u16::from(r.metadata.response_code) as u8);
            let entry = sito_stats::QueryLogEntry {
                id: None,
                ts: chrono::Utc::now().timestamp_millis(),
                client_ip: client.ip.to_string(),
                client_name: client.client_name.clone(),
                qname: outcome.domain_str.trim_end_matches('.').to_string(),
                qtype: qtype_num,
                rcode,
                verdict: outcome.verdict.to_string(),
                rule: outcome.rule,
                list_source: outcome.source,
                upstream: outcome.upstream,
                elapsed_us: Some(elapsed_us),
                dnssec: outcome.dnssec,
                proto: client.proto.clone(),
            };
            let _ = ql.try_send(entry);
        }

        outcome.response
    }
}
