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
                let mut err_resp = Message::new(query_id, MessageType::Response, OpCode::Query);
                err_resp.metadata.response_code = ResponseCode::FormErr;
                return (
                    Some(err_resp),
                    "formerr",
                    None,
                    None,
                    None,
                    false,
                    String::new(),
                    RecordType::A,
                    None,
                );
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
                let mut blocked_resp = synthesize_blocked_response(
                    &query,
                    &config.filtering.blocking_mode,
                    config.filtering.blocking_ttl,
                );
                blocked_resp.metadata.id = query_id;
                return (
                    Some(blocked_resp),
                    "blocked",
                    Some("anti_doh_bypass".to_string()),
                    Some("anti_doh_bypass".to_string()),
                    None,
                    false,
                    domain_str,
                    qtype,
                    None,
                );
            }

            // ADR-0007 Stage 1: $important filter rules (takes precedence over local rewrites)
            if policy.is_filtering_enabled
                && let Some(verdict) = self.filter.evaluate_important(qname, qtype, &client)
                    && verdict.is_blocked() {
                        info!(
                            qname = %qname,
                            qtype = ?qtype,
                            verdict = ?verdict,
                            "Query blocked by $important filter rule"
                        );
                        let mut blocked_resp = synthesize_blocked_response(
                            &query,
                            &config.filtering.blocking_mode,
                            config.filtering.blocking_ttl,
                        );
                        blocked_resp.metadata.id = query_id;
                        return (
                            Some(blocked_resp),
                            "blocked",
                            None,
                            None,
                            None,
                            false,
                            domain_str,
                            qtype,
                            None,
                        );
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
                return (
                    Some(rewrite_resp),
                    "rewritten",
                    None,
                    None,
                    None,
                    false,
                    domain_str,
                    qtype,
                    None,
                );
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
                    let mut blocked_resp = synthesize_blocked_response(
                        &query,
                        &config.filtering.blocking_mode,
                        config.filtering.blocking_ttl,
                    );
                    blocked_resp.metadata.id = query_id;
                    return (
                        Some(blocked_resp),
                        "blocked",
                        Some("parental".to_string()),
                        None,
                        None,
                        false,
                        domain_str,
                        qtype,
                        None,
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
                    let mut blocked_resp = synthesize_blocked_response(
                        &query,
                        &config.filtering.blocking_mode,
                        config.filtering.blocking_ttl,
                    );
                    blocked_resp.metadata.id = query_id;
                    return (
                        Some(blocked_resp),
                        "blocked",
                        Some("service".to_string()),
                        None,
                        None,
                        false,
                        domain_str,
                        qtype,
                        None,
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
                    let mut blocked_resp = synthesize_blocked_response(
                        &query,
                        &config.filtering.blocking_mode,
                        config.filtering.blocking_ttl,
                    );
                    blocked_resp.metadata.id = query_id;
                    return (
                        Some(blocked_resp),
                        "blocked",
                        None,
                        None,
                        None,
                        false,
                        domain_str,
                        qtype,
                        None,
                    );
                }
            }

            // ADR-0007 Stage 4: Safe Search CNAME rewrites (Google, Bing, YouTube, DuckDuckGo)
            if policy.safe_search
                && let Some(target) = match_safe_search(&domain_str, policy.safe_search_youtube)
                && let Ok(cname_target) = Name::from_str(&format!("{}.", target.trim_end_matches('.'))) {
                        info!(
                            qname = %qname,
                            target = %target,
                            "Enforcing safe search CNAME rewrite"
                        );
                        let mut ss_resp = synthesize_cname_response(&query, &cname_target, 300);
                        ss_resp.metadata.id = query_id;
                        return (
                            Some(ss_resp),
                            "rewritten",
                            None,
                            None,
                            None,
                            false,
                            domain_str,
                            qtype,
                            None,
                        );
                    }

            // 5. Cache lookup
            if config.dns.cache.enabled {
                if let Some(mut cached_resp) = self.cache.get(qname, qtype, qclass).await {
                    if bypass_check_needed {
                        let has_bypass_ip = cached_resp.answers.iter().any(|rec| match &rec.data {
                            RData::A(a) => self.anti_bypass.matches_ip(&IpAddr::V4(a.0)),
                            RData::AAAA(aaaa) => self.anti_bypass.matches_ip(&IpAddr::V6(aaaa.0)),
                            _ => false,
                        });
                        if has_bypass_ip {
                            info!(qname = %qname, "Cached query blocked by Anti-DoH bypass (resolved IP)");
                            if let Some(ref m) = self.metrics {
                                m.inc_doh_bypass_blocked();
                            }
                            let mut blocked_resp = synthesize_blocked_response(
                                &query,
                                &config.filtering.blocking_mode,
                                config.filtering.blocking_ttl,
                            );
                            blocked_resp.metadata.id = query_id;
                            return (
                                Some(blocked_resp),
                                "blocked",
                                Some("anti_doh_bypass".to_string()),
                                Some("anti_doh_bypass".to_string()),
                                None,
                                false,
                                domain_str,
                                qtype,
                                None,
                            );
                        }
                    }

                    info!(qname = %qname, qtype = ?qtype, "Cache hit");
                    if self.cache.should_prefetch(qname, qtype, qclass).await {
                        let bg_upstream = Arc::clone(&self.upstream);
                        let bg_cache = Arc::clone(&self.cache);
                        let bg_query = query.clone();
                        tokio::spawn(async move {
                            if let Ok(resp) = bg_upstream.resolve(&bg_query).await
                                && resp.metadata.response_code == ResponseCode::NoError
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
                    return (
                        Some(cached_resp),
                        "allowed",
                        Some("cache".to_string()),
                        None,
                        None,
                        true,
                        domain_str,
                        qtype,
                        cached_dnssec,
                    );
                }
                debug!(qname = %qname, qtype = ?qtype, "Cache miss");
                if let Some(ref m) = self.metrics {
                    m.inc_cache_misses();
                }
            }

            // 6. Upstream resolution
            match self.upstream.resolve(&query).await {
                Ok(mut upstream_resp) => {
                    upstream_resp.metadata.id = query_id;

                    // Anti-DoH bypass: inspect resolved A and AAAA records for known resolver IPs
                    if bypass_check_needed {
                        let has_bypass_ip = upstream_resp.answers.iter().any(|rec| match &rec.data {
                            RData::A(a) => self.anti_bypass.matches_ip(&IpAddr::V4(a.0)),
                            RData::AAAA(aaaa) => self.anti_bypass.matches_ip(&IpAddr::V6(aaaa.0)),
                            _ => false,
                        });
                        if has_bypass_ip {
                            info!(
                                qname = %qname,
                                "Upstream query blocked by Anti-DoH bypass (resolved IP)"
                            );
                            if let Some(ref m) = self.metrics {
                                m.inc_doh_bypass_blocked();
                            }
                            let mut blocked_resp = synthesize_blocked_response(
                                &query,
                                &config.filtering.blocking_mode,
                                config.filtering.blocking_ttl,
                            );
                            blocked_resp.metadata.id = query_id;
                            return (
                                Some(blocked_resp),
                                "blocked",
                                Some("anti_doh_bypass".to_string()),
                                Some("anti_doh_bypass".to_string()),
                                None,
                                false,
                                domain_str,
                                qtype,
                                None,
                            );
                        }
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
                                    let mut blocked_resp = synthesize_blocked_response(
                                        &query,
                                        &config.filtering.blocking_mode,
                                        config.filtering.blocking_ttl,
                                    );
                                    blocked_resp.metadata.id = query_id;
                                    return (
                                        Some(blocked_resp),
                                        "blocked",
                                        Some("cname_uncloaking".to_string()),
                                        None,
                                        None,
                                        false,
                                        domain_str,
                                        qtype,
                                        None,
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
                    let dnssec_outcome = self.dnssec.validate_response(&mut upstream_resp, None, now);
                    let dnssec_str = if self.dnssec.mode == sito_dnssec::DnssecMode::Disabled {
                        None
                    } else {
                        Some(dnssec_outcome.as_str().to_string())
                    };

                    if config.dns.cache.enabled
                        && upstream_resp.metadata.response_code == ResponseCode::NoError
                    {
                        self.cache.insert(&query, &upstream_resp).await;
                    }
                    (
                        Some(upstream_resp),
                        "allowed",
                        None,
                        None,
                        Some("upstream".to_string()),
                        false,
                        domain_str,
                        qtype,
                        dnssec_str,
                    )
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
                        return (
                            Some(stale_resp),
                            "allowed",
                            Some("stale_cache".to_string()),
                            None,
                            None,
                            true,
                            domain_str,
                            qtype,
                            None,
                        );
                    }

                    let mut err_resp = Message::new(query_id, MessageType::Response, OpCode::Query);
                    err_resp.metadata.response_code = ResponseCode::ServFail;
                    err_resp.metadata.recursion_desired = query.metadata.recursion_desired;
                    err_resp.metadata.recursion_available = true;
                    err_resp.queries.clone_from(&query.queries);
                    (
                        Some(err_resp),
                        "servfail",
                        None,
                        None,
                        None,
                        false,
                        domain_str,
                        qtype,
                        None,
                    )
                }
            }
        }
        .instrument(span)
        .await;

        let (
            resp,
            verdict_str,
            rule_opt,
            source_opt,
            upstream_opt,
            from_cache,
            domain_str,
            qtype,
            dnssec_opt,
        ) = outcome;

        let elapsed = start.elapsed();
        let elapsed_us = elapsed.as_micros() as i64;
        let elapsed_secs = elapsed.as_secs_f64();
        let qtype_num = u16::from(qtype);

        if let Some(ref m) = self.metrics {
            m.inc_queries(&client.proto, qtype_num, verdict_str);
            m.observe_query_duration(verdict_str, elapsed_secs);
            if from_cache {
                m.inc_cache_hits();
            }
        }

        if !policy.ignore_query_log
            && !domain_str.is_empty()
            && let Some(ref ql) = self.querylog
        {
            let rcode = resp
                .as_ref()
                .map(|r| u16::from(r.metadata.response_code) as u8);
            let entry = sito_stats::QueryLogEntry {
                id: None,
                ts: chrono::Utc::now().timestamp_millis(),
                client_ip: client.ip.to_string(),
                client_name: client.client_name.clone(),
                qname: domain_str.trim_end_matches('.').to_string(),
                qtype: qtype_num,
                rcode,
                verdict: verdict_str.to_string(),
                rule: rule_opt,
                list_source: source_opt,
                upstream: upstream_opt,
                elapsed_us: Some(elapsed_us),
                dnssec: dnssec_opt,
                proto: client.proto.clone(),
            };
            let _ = ql.try_send(entry);
        }

        resp
    }
}
