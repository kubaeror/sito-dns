//! DNS query execution pipeline.

use arc_swap::ArcSwap;
use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA, CNAME};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use sito_cache::DnsCache;
use sito_clients::{
    ClientRegistry, EffectivePolicy, ParentalRegistry, ServiceRegistry, match_safe_search,
};
use sito_core::FilterEngine;
use sito_core::client::ClientContext;
use sito_core::config::Config;
use sito_core::verdict::{RewriteAction, Verdict};
use sito_dnssec::DnssecValidator;
use sito_filter::{AntiBypassRegistry, HostsFilterEngine};
use sito_proto::synthesize_blocked_response;
use sito_proto::wire::{synthesize_cname_response, synthesize_records_response};
use sito_rewrites::RewriteTable;
use sito_runtime::RuntimeState;
use sito_transport::QueryHandler;
use sito_upstream::UpstreamManager;
use std::collections::HashMap;
use std::net::IpAddr;
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

/// Builds a synthesized response for an ABP `$dnsrewrite` action.
fn make_rewrite_response(query: &Message, action: &RewriteAction, query_id: u16) -> Message {
    let RewriteAction::DnsRewrite {
        rcode,
        rtype,
        value,
    } = action
    else {
        // `SynthesizeAnswer` is not emitted by the current filter engine; return
        // a plain NOERROR response for the query instead.
        let mut resp = Message::new(query_id, MessageType::Response, OpCode::Query);
        resp.metadata.recursion_desired = query.metadata.recursion_desired;
        resp.metadata.recursion_available = true;
        resp.queries.clone_from(&query.queries);
        return resp;
    };

    let mut resp = Message::new(query_id, MessageType::Response, OpCode::Query);
    resp.metadata.recursion_desired = query.metadata.recursion_desired;
    resp.metadata.recursion_available = true;
    resp.queries.clone_from(&query.queries);

    resp.metadata.response_code = match rcode.to_ascii_uppercase().as_str() {
        "NXDOMAIN" => ResponseCode::NXDomain,
        "REFUSED" => ResponseCode::Refused,
        "SERVFAIL" => ResponseCode::ServFail,
        "FORMERR" => ResponseCode::FormErr,
        "NOTIMP" => ResponseCode::NotImp,
        _ => ResponseCode::NoError,
    };

    if resp.metadata.response_code == ResponseCode::NoError
        && let (Some(rtype), Some(value)) = (rtype.as_deref(), value.as_deref())
        && let Some(question) = query.queries.first()
    {
        let rtype = rtype.to_ascii_uppercase();
        let rdata = match rtype.as_str() {
            "A" => value
                .parse::<std::net::Ipv4Addr>()
                .ok()
                .map(|ip| RData::A(A(ip))),
            "AAAA" => value
                .parse::<std::net::Ipv6Addr>()
                .ok()
                .map(|ip| RData::AAAA(AAAA(ip))),
            "CNAME" => Name::from_str(value.trim_end_matches('.'))
                .ok()
                .map(|name| RData::CNAME(CNAME(name))),
            _ => None,
        };
        if let Some(rdata) = rdata {
            let record = Record::from_rdata(question.name().clone(), 60, rdata);
            resp.answers.push(record);
        }
    }

    resp
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
    runtime: Arc<RuntimeState>,
    filter: Arc<HostsFilterEngine>,
    anti_bypass: Arc<AntiBypassRegistry>,
    cache: Arc<DnsCache>,
    upstream: Arc<UpstreamManager>,
    dnssec: Arc<DnssecValidator>,
    parental: Arc<ParentalRegistry>,
    services: Arc<ServiceRegistry>,
    in_flight: Arc<AtomicUsize>,
    prefetch_semaphore: Arc<tokio::sync::Semaphore>,
    querylog: Option<sito_stats::QueryLogSender>,
    metrics: Option<sito_stats::MetricsRegistry>,
    /// Per-client upstream managers keyed by `servers.join(",")`.
    scoped_upstreams: Arc<HashMap<String, Arc<UpstreamManager>>>,
}

impl DnsPipeline {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        config: Arc<ArcSwap<Config>>,
        filter: Arc<HostsFilterEngine>,
        cache: Arc<DnsCache>,
        upstream: Arc<UpstreamManager>,
        dnssec: Arc<DnssecValidator>,
        clients: Arc<ArcSwap<ClientRegistry>>,
        parental: Arc<ParentalRegistry>,
        services: Arc<ServiceRegistry>,
        rewrites: Arc<ArcSwap<RewriteTable>>,
        in_flight: Arc<AtomicUsize>,
    ) -> Self {
        let runtime = Arc::new(RuntimeState::new(config, clients, rewrites));
        Self {
            runtime,
            filter,
            anti_bypass: Arc::new(AntiBypassRegistry::bundled()),
            cache,
            upstream,
            dnssec,
            parental,
            services,
            in_flight,
            prefetch_semaphore: Arc::new(tokio::sync::Semaphore::new(64)),
            querylog: None,
            metrics: None,
            scoped_upstreams: Arc::new(HashMap::new()),
        }
    }

    /// The runtime snapshot holder in use by this pipeline.
    #[must_use]
    pub fn runtime(&self) -> &Arc<RuntimeState> {
        &self.runtime
    }

    /// Shares a runtime snapshot holder with the server so config, clients and
    /// rewrites are observed atomically by each query.
    #[must_use]
    pub fn with_runtime(mut self, runtime: Arc<RuntimeState>) -> Self {
        self.runtime = runtime;
        self
    }

    /// Registers per-client upstream managers used when a client opts out of
    /// the global upstreams (`use_global_upstreams = false`).
    #[must_use]
    pub fn with_scoped_upstreams(
        mut self,
        scoped: Arc<HashMap<String, Arc<UpstreamManager>>>,
    ) -> Self {
        self.scoped_upstreams = scoped;
        self
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

impl DnsPipeline {
    /// Builds a blocked response for the configured blocking mode.
    fn blocked_outcome(
        query: &Message,
        config: &Config,
        query_id: u16,
        domain_str: &str,
        qtype: RecordType,
        rule: Option<&str>,
        source: Option<&str>,
    ) -> QueryOutcome {
        let resp = make_blocked_response(
            query,
            &config.filtering.blocking_mode,
            config.filtering.blocking_ttl,
            query_id,
        );
        QueryOutcome::blocked(
            resp,
            rule.map(str::to_string),
            source.map(str::to_string),
            domain_str.to_string(),
            qtype,
        )
    }

    /// Anti-DoH bypass check by requested domain name.
    fn anti_doh_blocked_by_domain(
        &self,
        query: &Message,
        config: &Config,
        query_id: u16,
        domain_str: &str,
        qtype: RecordType,
    ) -> Option<QueryOutcome> {
        if !self.anti_bypass.matches_domain(domain_str) {
            return None;
        }
        info!(
            qname = %domain_str,
            "Query blocked by Anti-DoH bypass rule (resolver domain)"
        );
        if let Some(ref m) = self.metrics {
            m.inc_doh_bypass_blocked();
        }
        Some(Self::blocked_outcome(
            query,
            config,
            query_id,
            domain_str,
            qtype,
            Some("anti_doh_bypass"),
            Some("anti_doh_bypass"),
        ))
    }

    /// Anti-DoH bypass check by resolved A/AAAA addresses.
    #[allow(clippy::too_many_arguments)]
    fn anti_doh_blocked_by_answers(
        &self,
        query: &Message,
        config: &Config,
        answers: &[Record],
        query_id: u16,
        domain_str: &str,
        qtype: RecordType,
        origin: &'static str,
    ) -> Option<QueryOutcome> {
        if !answers_contain_bypass_ip(&self.anti_bypass, answers) {
            return None;
        }
        info!(
            qname = %domain_str,
            origin,
            "Query blocked by Anti-DoH bypass (resolved IP)"
        );
        if let Some(ref m) = self.metrics {
            m.inc_doh_bypass_blocked();
        }
        Some(Self::blocked_outcome(
            query,
            config,
            query_id,
            domain_str,
            qtype,
            Some("anti_doh_bypass"),
            Some("anti_doh_bypass"),
        ))
    }

    /// Parental, service and standard filter stages (ADR-0007 stage 3).
    #[allow(clippy::too_many_arguments)]
    fn evaluate_filter_stages(
        &self,
        query: &Message,
        config: &Config,
        client: &ClientContext,
        policy: &EffectivePolicy,
        domain_str: &str,
        qtype: RecordType,
        query_id: u16,
    ) -> Option<QueryOutcome> {
        if policy.parental
            && self.parental.matches_any_category(
                policy.parental_categories.iter().map(String::as_str),
                domain_str,
            )
        {
            info!(
                qname = %domain_str,
                qtype = ?qtype,
                "Query blocked by parental control category"
            );
            return Some(Self::blocked_outcome(
                query,
                config,
                query_id,
                domain_str,
                qtype,
                Some("parental"),
                None,
            ));
        }

        if !policy.active_blocked_services.is_empty()
            && self
                .services
                .matches_any_service(
                    policy.active_blocked_services.iter().map(String::as_str),
                    domain_str,
                )
                .is_some()
        {
            info!(
                qname = %domain_str,
                qtype = ?qtype,
                "Query blocked by service blocking policy"
            );
            return Some(Self::blocked_outcome(
                query,
                config,
                query_id,
                domain_str,
                qtype,
                Some("service"),
                None,
            ));
        }

        let qname = Name::from_str(domain_str).ok()?;
        match self.filter.evaluate_standard(&qname, qtype, client) {
            Verdict::Block(verdict) => {
                info!(
                    qname = %domain_str,
                    qtype = ?qtype,
                    verdict = ?verdict,
                    "Query blocked by standard filter"
                );
                Some(Self::blocked_outcome(
                    query, config, query_id, domain_str, qtype, None, None,
                ))
            }
            Verdict::Rewrite(action) => {
                debug!(qname = %domain_str, "Query rewritten by standard filter rule");
                let resp = make_rewrite_response(query, &action, query_id);
                Some(QueryOutcome::rewritten(resp, domain_str.to_string(), qtype))
            }
            Verdict::Allow(_) => None,
        }
    }
}

impl QueryHandler for DnsPipeline {
    async fn handle(&self, query: Message, client: ClientContext) -> Option<Message> {
        self.in_flight.fetch_add(1, Ordering::SeqCst);
        let _guard = InFlightGuard(Arc::clone(&self.in_flight));

        // One snapshot per query: config, clients and rewrites cannot be torn
        // apart by a concurrent hot reload.
        let runtime_snapshot = self.runtime.snapshot();
        let config = &runtime_snapshot.config;
        let clients = &runtime_snapshot.clients;
        let rewrites = &runtime_snapshot.rewrites;

        let mut client = client;
        let now = chrono::Utc::now();
        let policy = clients.resolve(&mut client, now);

        // Per-client upstream scope (falls back to the global manager).
        let scoped_upstream = if policy.use_global_upstreams {
            None
        } else {
            policy
                .upstreams
                .as_ref()
                .and_then(|servers| self.scoped_upstreams.get(&servers.join(",")).cloned())
        };
        let effective_upstream = scoped_upstream
            .clone()
            .unwrap_or_else(|| Arc::clone(&self.upstream));
        // Answers from per-client upstreams must not be shared via the global cache.
        let cache_enabled = config.dns.cache.enabled && scoped_upstream.is_none();

        if let Some(ref m) = self.metrics {
            m.inc_clients_identified(if client.client_name.is_some() {
                "identified"
            } else {
                "ip"
            });
        }

        let query_id = query.metadata.id;
        let request_id = rand::random::<u64>();

        let span = tracing::debug_span!(
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
            let client_wants_dnssec = query
                .edns
                .as_ref()
                .is_some_and(|edns| edns.flags().dnssec_ok);

            trace!(qname = %qname, qtype = ?qtype, "Processing DNS query");

            let bypass_check_needed = match config.filtering.anti_doh_bypass.as_str() {
                "block_all" => true,
                "block_except_trusted" => !policy.trusted,
                _ => false,
            };

            // Anti-DoH bypass: check if domain matches known public resolver
            if bypass_check_needed
                && let Some(outcome) =
                    self.anti_doh_blocked_by_domain(&query, config, query_id, &domain_str, qtype)
            {
                return outcome;
            }

            // ADR-0007 Stage 1: $important filter rules (takes precedence over local rewrites)
            let mut important_allowed = false;
            if policy.is_filtering_enabled
                && let Some(verdict) = self.filter.evaluate_important(qname, qtype, &client)
            {
                match verdict {
                    Verdict::Block(_) => {
                        info!(
                            qname = %qname,
                            qtype = ?qtype,
                            verdict = ?verdict,
                            "Query blocked by $important filter rule"
                        );
                        return Self::blocked_outcome(
                            &query,
                            config,
                            query_id,
                            &domain_str,
                            qtype,
                            None,
                            None,
                        );
                    }
                    Verdict::Rewrite(action) => {
                        debug!(qname = %qname, "Query rewritten by $important rule");
                        let resp = make_rewrite_response(&query, &action, query_id);
                        return QueryOutcome::rewritten(resp, domain_str, qtype);
                    }
                    Verdict::Allow(_) => {
                        // $important allow overrides rewrites and all standard blocks.
                        important_allowed = true;
                    }
                }
            }

            // ADR-0007 Stage 2: Local DNS rewrites and auto-PTR
            if !important_allowed && let Some(records) = rewrites.lookup(qname, qtype, &client) {
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
            if policy.is_filtering_enabled
                && !important_allowed
                && let Some(outcome) = self.evaluate_filter_stages(
                    &query,
                    config,
                    &client,
                    &policy,
                    &domain_str,
                    qtype,
                    query_id,
                )
            {
                return outcome;
            }

            // ADR-0007 Stage 4: Safe Search CNAME rewrites (Google, Bing, YouTube, DuckDuckGo)
            if !important_allowed
                && policy.safe_search
                && let Some(target) = match_safe_search(&domain_str, policy.safe_search_youtube)
                && let Ok(cname_target) =
                    Name::from_str(&format!("{}.", target.trim_end_matches('.')))
            {
                debug!(
                    qname = %qname,
                    target = %target,
                    "Enforcing safe search CNAME rewrite"
                );
                let mut ss_resp = synthesize_cname_response(&query, &cname_target, 300);
                ss_resp.metadata.id = query_id;
                return QueryOutcome::rewritten(ss_resp, domain_str, qtype);
            }

            // 5. Cache lookup
            if cache_enabled {
                // Never serve an unvalidated cached answer to a DNSSEC-aware
                // client while validation is enabled: force an upstream lookup.
                let cached = match self.cache.get(qname, qtype, qclass).await {
                    Some(resp)
                        if client_wants_dnssec
                            && self.dnssec.mode != sito_dnssec::DnssecMode::Disabled
                            && !resp.metadata.authentic_data =>
                    {
                        debug!(
                            qname = %qname,
                            "Ignoring non-validated cache entry for DNSSEC-aware client"
                        );
                        None
                    }
                    other => other,
                };
                if let Some(mut cached_resp) = cached {
                    if bypass_check_needed
                        && let Some(outcome) = self.anti_doh_blocked_by_answers(
                            &query,
                            config,
                            &cached_resp.answers,
                            query_id,
                            &domain_str,
                            qtype,
                            "cache",
                        )
                    {
                        return outcome;
                    }

                    debug!(qname = %qname, qtype = ?qtype, "Cache hit");
                    if self.cache.should_prefetch(qname, qtype, qclass).await
                        && let Ok(permit) = Arc::clone(&self.prefetch_semaphore).try_acquire_owned()
                    {
                        let bg_upstream = Arc::clone(&effective_upstream);
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
            // Force the DNSSEC OK bit when validation is enabled so upstreams
            // return RRSIGs even for non-DO clients.
            let upstream_query = if self.dnssec.mode == sito_dnssec::DnssecMode::Disabled {
                query.clone()
            } else {
                let mut q = query.clone();
                let mut edns = q.edns.clone().unwrap_or_default();
                edns.set_dnssec_ok(true);
                edns.set_max_payload(config.dns.edns_udp_size.max(1232));
                q.set_edns(edns);
                q
            };
            let upstream_start = std::time::Instant::now();
            match effective_upstream
                .resolve_with_upstream(&upstream_query)
                .await
            {
                Ok((mut upstream_resp, upstream_name)) => {
                    if let Some(ref m) = self.metrics {
                        m.observe_upstream_rtt(
                            &upstream_name,
                            upstream_start.elapsed().as_secs_f64(),
                        );
                        m.set_upstream_health(&upstream_name, 1.0);
                    }
                    upstream_resp.metadata.id = query_id;

                    // Anti-DoH bypass: inspect resolved A and AAAA records for known resolver IPs
                    if bypass_check_needed
                        && let Some(outcome) = self.anti_doh_blocked_by_answers(
                            &query,
                            config,
                            &upstream_resp.answers,
                            query_id,
                            &domain_str,
                            qtype,
                            "upstream",
                        )
                    {
                        return outcome;
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
                                    return Self::blocked_outcome(
                                        &query,
                                        config,
                                        query_id,
                                        &domain_str,
                                        qtype,
                                        Some("cname_uncloaking"),
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
                    let dnssec_outcome = self.dnssec.validate_response(
                        &mut upstream_resp,
                        Some(upstream_name.as_str()),
                        now,
                    );
                    if let Some(ref m) = self.metrics
                        && matches!(dnssec_outcome, sito_dnssec::ValidationOutcome::Bogus { .. })
                    {
                        m.inc_dnssec_bogus(&upstream_name);
                    }
                    let dnssec_str = if self.dnssec.mode == sito_dnssec::DnssecMode::Disabled {
                        None
                    } else {
                        Some(dnssec_outcome.as_str().to_string())
                    };

                    if cache_enabled
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
                    if let Some(ref m) = self.metrics {
                        m.inc_upstream_errors("all", &e.to_string());
                    }

                    if cache_enabled
                        && config.dns.cache.serve_stale_hours > 0
                        && let Some(mut stale_resp) =
                            self.cache.get_stale(qname, qtype, qclass).await
                    {
                        debug!(
                            qname = %qname,
                            "Upstream failed, serving stale cached response (RFC 8767)"
                        );
                        if let Some(ref m) = self.metrics {
                            m.inc_cache_stale_served();
                        }
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

        if let Some(ref m) = self.metrics
            && !policy.ignore_stats
        {
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
