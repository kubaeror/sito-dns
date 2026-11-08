//! DNS query execution pipeline.

use arc_swap::ArcSwap;
use hickory_proto::op::{Edns, Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::opt::{ClientSubnet, EdnsCode, EdnsOption};
use hickory_proto::rr::rdata::{A, AAAA, CNAME, PTR, TXT};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use sito_cache::{DnsCache, ValidationStatus};
use sito_clients::{
    ClientRegistry, EffectivePolicy, ParentalRegistry, RuntimeLists, ServiceRegistry,
    match_safe_search,
};
use sito_core::client::ClientContext;
use sito_core::config::{Config, UpstreamEcs};
use sito_core::verdict::Verdict;
use sito_dnssec::DnssecValidator;
use sito_filter::{AntiBypassRegistry, DnsRewriteRule, FilterSnapshot, HostsFilterEngine};
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
use tracing::{Instrument, debug, error, info, trace, warn};

/// Tracks in-flight queries using RAII.
struct InFlightGuard(Arc<AtomicUsize>);

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Whether a query carried the DNSSEC OK (DO) bit.
fn query_has_do(query: &Message) -> bool {
    query
        .edns
        .as_ref()
        .is_some_and(|edns| edns.flags().dnssec_ok)
}

/// Maximum wall-clock time the pipeline spends on DNSSEC validation and its
/// DNSKEY/DS chain fetches for one query.
///
/// The fetcher performs network I/O and an upstream can stall a response (or
/// an attacker can black-hole DS/DNSKEY queries). A bound here keeps one query
/// from pinning a worker for the upstream timeout times the chain depth.
const DNSSEC_VALIDATION_DEADLINE: std::time::Duration = std::time::Duration::from_secs(5);

/// Validates a response under a hard wall-clock deadline.
///
/// On timeout strict (`Validate`) mode fails closed with SERVFAIL (never an
/// unvalidated answer), while `LogOnly` keeps the response without AD, and
/// `Disabled` never calls this helper.
async fn validate_dnssec_with_deadline(
    validator: &DnssecValidator,
    response: &mut Message,
    upstream: Option<&str>,
    now: u32,
    fetcher: &dyn sito_core::DnssecKeyFetcher,
    deadline: std::time::Duration,
) -> sito_dnssec::ValidationOutcome {
    use sito_dnssec::{DnssecMode, ValidationOutcome};

    // The chain walk appends fetched DNSKEY/DS helpers to the response. If the
    // future is cancelled on timeout, drop anything it already appended so
    // unvalidated helper records cannot leak to the client (or into a log-only
    // cached response).
    let original_additionals = response.additionals.len();
    if let Ok(outcome) = tokio::time::timeout(
        deadline,
        validator.validate_with_key_fetcher(response, upstream, now, fetcher),
    )
    .await
    {
        return outcome;
    }
    response.additionals.truncate(original_additionals);

    response.metadata.authentic_data = false;
    if validator.mode == DnssecMode::Validate {
        response.metadata.response_code = ResponseCode::ServFail;
        response.answers.clear();
        sito_dnssec::apply_ede(
            response,
            sito_dnssec::EDE_DNSSEC_BOGUS,
            "DNSSEC validation timed out",
        );
        let outcome = ValidationOutcome::Bogus {
            reason: "DNSSEC validation timed out".to_string(),
            ede_code: sito_dnssec::EDE_DNSSEC_BOGUS,
        };
        validator.metrics.record_validation(&outcome);
        outcome
    } else {
        let outcome = ValidationOutcome::Indeterminate;
        validator.metrics.record_validation(&outcome);
        outcome
    }
}

/// Copies the query-derived metadata (ID/opcode are set by the caller) that
/// every synthesized or error response must echo: RD, CD, the question and a
/// minimal OPT record with the client's DO bit.
fn copy_query_response_flags(response: &mut Message, query: &Message) {
    response.metadata.recursion_desired = query.metadata.recursion_desired;
    response.metadata.recursion_available = true;
    response.metadata.checking_disabled = query.metadata.checking_disabled;
    response.queries.clone_from(&query.queries);
    if let Some(client_edns) = &query.edns {
        let mut edns = Edns::new();
        edns.set_max_payload(client_edns.max_payload());
        edns.set_dnssec_ok(client_edns.flags().dnssec_ok);
        response.set_edns(edns);
    }
}

/// Builds an error/synthesized response that preserves the query's opcode,
/// question, CD bit and EDNS/DO signalling.
fn error_response(query: &Message, response_code: ResponseCode) -> Message {
    let mut response = Message::new(
        query.metadata.id,
        MessageType::Response,
        query.metadata.op_code,
    );
    response.metadata.response_code = response_code;
    copy_query_response_flags(&mut response, query);
    response
}

/// Strips DNSSEC records and DO-dependent EDNS options from a response.
///
/// RFC 3225: clients that did not set DO must not receive RRSIG/NSEC/NSEC3/
/// DNSKEY material. The same shaping is applied before such a response is
/// cached so a DO=0 cache entry never carries DNSSEC data.
fn strip_dnssec_records(response: &mut Message) {
    let is_dnssec_type = |record: &Record| {
        matches!(
            record.record_type(),
            RecordType::RRSIG | RecordType::NSEC | RecordType::NSEC3 | RecordType::DNSKEY
        )
    };
    response.answers.retain(|record| !is_dnssec_type(record));
    response
        .authorities
        .retain(|record| !is_dnssec_type(record));
    response
        .additionals
        .retain(|record| !is_dnssec_type(record));
    if let Some(edns) = response.edns.as_mut() {
        // DAU/DHU/N3U only make sense for DNSSEC-aware clients.
        edns.options_mut().remove(EdnsCode::DAU);
        edns.options_mut().remove(EdnsCode::DHU);
        edns.options_mut().remove(EdnsCode::N3U);
    }
}

/// Masks the host bits of an address so the cache key and the forwarded ECS
/// option describe the same network prefix.
fn truncate_ip(addr: IpAddr, prefix: u8) -> IpAddr {
    match addr {
        IpAddr::V4(v4) if prefix < 32 => {
            let mask = u32::MAX << (32 - u32::from(prefix));
            IpAddr::V4((u32::from(v4) & mask).into())
        }
        IpAddr::V6(v6) if prefix < 128 => {
            let mask = u128::MAX << (128 - u32::from(prefix));
            IpAddr::V6((u128::from(v6) & mask).into())
        }
        other => other,
    }
}

/// Applies the configured ECS policy to an outbound/cache query.
///
/// `off` removes the client's ECS option entirely (privacy-preserving and
/// cache-friendly); `forward` validates the prefix, clamps it to /24 (IPv4)
/// or /56 (IPv6), clears the scope and zeroes host bits. A zero-length source
/// prefix (RFC 7871 opt-out) is never forwarded.
fn apply_ecs_policy(query: &mut Message, policy: UpstreamEcs) {
    let Some(edns) = query.edns.as_mut() else {
        return;
    };
    let subnet = match edns.option(EdnsCode::Subnet).cloned() {
        Some(EdnsOption::Subnet(subnet)) => Some(subnet),
        _ => None,
    };
    edns.options_mut().remove(EdnsCode::Subnet);
    if policy == UpstreamEcs::Off {
        return;
    }
    let Some(subnet) = subnet else {
        return;
    };
    if subnet.source_prefix() == 0 {
        return;
    }
    let (max_prefix, bits) = match subnet.addr() {
        IpAddr::V4(_) => (24u8, 32u8),
        IpAddr::V6(_) => (56u8, 128u8),
    };
    let prefix = subnet.source_prefix().min(max_prefix).min(bits);
    if prefix == 0 {
        return;
    }
    let clamped = ClientSubnet::new(truncate_ip(subnet.addr(), prefix), prefix, 0);
    edns.options_mut().insert(EdnsOption::Subnet(clamped));
}

/// Builds the query used for cache lookups/inserts: the client's DO/CD/opcode
/// flags plus the ECS actually forwarded upstream (`off` deduplicates keys,
/// `forward` keys on the clamped subnet).
fn build_cache_query(query: &Message, config: &Config) -> Message {
    let mut cache_query = query.clone();
    apply_ecs_policy(&mut cache_query, config.upstream.ecs);
    cache_query
}

/// Builds the query sent upstream, optionally forcing DO so validation has
/// signatures to check.
fn build_upstream_query(query: &Message, config: &Config, force_dnssec: bool) -> Message {
    let mut upstream_query = query.clone();
    if force_dnssec {
        let mut edns = upstream_query.edns.clone().unwrap_or_default();
        edns.set_dnssec_ok(true);
        edns.set_max_payload(config.dns.edns_udp_size.max(1232));
        upstream_query.set_edns(edns);
    }
    apply_ecs_policy(&mut upstream_query, config.upstream.ecs);
    upstream_query
}

/// Maps a DNSSEC validation outcome onto the status stored in the cache.
fn validation_status(outcome: Option<&sito_dnssec::ValidationOutcome>) -> ValidationStatus {
    match outcome {
        Some(sito_dnssec::ValidationOutcome::Secure) => ValidationStatus::Secure,
        Some(
            sito_dnssec::ValidationOutcome::Insecure | sito_dnssec::ValidationOutcome::NtaBypass,
        ) => ValidationStatus::Insecure,
        Some(
            sito_dnssec::ValidationOutcome::Indeterminate
            | sito_dnssec::ValidationOutcome::Bogus { .. },
        ) => ValidationStatus::Indeterminate,
        None => ValidationStatus::Unchecked,
    }
}

/// Whether a cached entry may be served while local validation is active.
///
/// `Unchecked` entries (CD=1 / validation disabled) must never be served when
/// a CD=0 query expects the resolver to have validated the answer. Insecure
/// and Indeterminate entries are legitimate but are always served with AD=0.
fn cache_entry_servable(status: ValidationStatus, validation_active: bool) -> bool {
    !validation_active || status != ValidationStatus::Unchecked
}

/// Whether a *stale* (RFC 8767) entry may be served while local validation is
/// active.
///
/// Stale answers are not revalidated, so only authenticated cache decisions
/// (`Secure`/`Insecure`) may be served. An `Indeterminate` entry is
/// inconclusive by definition — in log-only mode even Bogus data is recorded
/// that way — and `Unchecked` means no local validation ran at all. Neither
/// may be handed to a CD=0 client that relies on the resolver. Stale answers
/// are always sanitized to AD=0 before they leave the cache.
fn stale_cache_entry_servable(status: ValidationStatus, validation_active: bool) -> bool {
    !validation_active
        || matches!(
            status,
            ValidationStatus::Secure | ValidationStatus::Insecure
        )
}

/// Outcome of executing a query through the DNS pipeline.
struct QueryOutcome {
    response: Option<Message>,
    verdict: &'static str,
    /// Matched rule/list identifiers: static labels use `Cow::Borrowed` and
    /// matched filter rules carry their rule text and list name via `Cow::Owned`.
    rule: Option<std::borrow::Cow<'static, str>>,
    source: Option<std::borrow::Cow<'static, str>>,
    upstream: Option<String>,
    from_cache: bool,
    domain_str: String,
    qtype: RecordType,
    dnssec: Option<&'static str>,
}

fn block_reason_labels(
    reason: &sito_core::verdict::BlockReason,
) -> (
    Option<std::borrow::Cow<'static, str>>,
    Option<std::borrow::Cow<'static, str>>,
) {
    use std::borrow::Cow;
    match reason {
        sito_core::verdict::BlockReason::Rule(rule_ref) => (
            Some(Cow::Owned(rule_ref.rule_text.clone())),
            rule_ref.list_name.clone().map(Cow::Owned),
        ),
        sito_core::verdict::BlockReason::Parental => (Some(Cow::Borrowed("parental")), None),
        sito_core::verdict::BlockReason::Service(svc) => (
            Some(Cow::Borrowed("service")),
            Some(Cow::Owned(svc.clone())),
        ),
        sito_core::verdict::BlockReason::AntiDohBypass => (
            Some(Cow::Borrowed("anti_doh_bypass")),
            Some(Cow::Borrowed("anti_doh_bypass")),
        ),
        sito_core::verdict::BlockReason::FilterUnavailable => {
            (Some(Cow::Borrowed("filter_unavailable")), None)
        }
    }
}

impl QueryOutcome {
    fn blocked(
        response: Message,
        rule: Option<std::borrow::Cow<'static, str>>,
        source: Option<std::borrow::Cow<'static, str>>,
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

    fn formerr(query: &Message) -> Self {
        Self::error(
            query,
            ResponseCode::FormErr,
            "formerr",
            String::new(),
            RecordType::A,
        )
    }

    fn notimp(query: &Message, domain_str: String, qtype: RecordType) -> Self {
        Self::error(query, ResponseCode::NotImp, "notimp", domain_str, qtype)
    }

    fn badvers(query: &Message, domain_str: String, qtype: RecordType) -> Self {
        Self::error(query, ResponseCode::BADVERS, "badvers", domain_str, qtype)
    }

    fn error(
        query: &Message,
        response_code: ResponseCode,
        verdict: &'static str,
        domain_str: String,
        qtype: RecordType,
    ) -> Self {
        Self {
            response: Some(error_response(query, response_code)),
            verdict,
            rule: None,
            source: None,
            upstream: None,
            from_cache: false,
            domain_str,
            qtype,
            dnssec: None,
        }
    }

    fn servfail(query: &Message, domain_str: String, qtype: RecordType) -> Self {
        Self::error(query, ResponseCode::ServFail, "servfail", domain_str, qtype)
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

/// Splits TXT data into the 255-byte character-strings a DNS TXT record allows.
fn txt_chunks(value: &str) -> Vec<String> {
    let mut chunks = Vec::new();
    let mut start = 0;
    while start < value.len() {
        let mut end = (start + 255).min(value.len());
        while end > start && !value.is_char_boundary(end) {
            end -= 1;
        }
        chunks.push(value[start..end].to_string());
        start = end;
    }
    if chunks.is_empty() {
        chunks.push(String::new());
    }
    chunks
}

/// Whether a `$dnsrewrite` record type can answer the given question type.
///
/// DNS applies exact record-type matching, except that a CNAME answers any
/// query type. Unsupported types are rejected by the parser; they fall through
/// so the synthesis path can still warn about programmatically built rules.
fn rewrite_applies_to_qtype(rtype: &str, qtype: RecordType) -> bool {
    if rtype == "CNAME" {
        return true;
    }
    match rtype {
        "A" => qtype == RecordType::A,
        "AAAA" => qtype == RecordType::AAAA,
        "PTR" => qtype == RecordType::PTR,
        "TXT" => qtype == RecordType::TXT,
        _ => true,
    }
}

/// Builds a synthesized response for all matching ABP `$dnsrewrite` rules.
///
/// AdGuard aggregates every matching rewrite for an owner: two `A` rewrites
/// produce two answer records. Records are filtered by the question type
/// (`A`/`AAAA`/`PTR`/`TXT` exact match, `CNAME` answers any type); when no
/// matching value applies the result is NOERROR/NODATA, never an upstream
/// fallback. A non-`NOERROR` rcode is exclusive and wins over any record
/// synthesis.
fn make_rewrite_response(query: &Message, rules: &[DnsRewriteRule], query_id: u16) -> Message {
    let mut resp = Message::new(query_id, MessageType::Response, query.metadata.op_code);
    copy_query_response_flags(&mut resp, query);

    let rcode = rules
        .iter()
        .map(|rule| rule.rcode.trim())
        .find(|rcode| !rcode.is_empty() && !rcode.eq_ignore_ascii_case("NOERROR"));
    resp.metadata.response_code = match rcode.map(str::to_ascii_uppercase).as_deref() {
        Some("NXDOMAIN") => ResponseCode::NXDomain,
        Some("REFUSED") => ResponseCode::Refused,
        Some("SERVFAIL") => ResponseCode::ServFail,
        Some("FORMERR") => ResponseCode::FormErr,
        Some("NOTIMP") => ResponseCode::NotImp,
        _ => ResponseCode::NoError,
    };

    if resp.metadata.response_code == ResponseCode::NoError
        && let Some(question) = query.queries.first()
    {
        for rule in rules {
            let (Some(rtype), Some(value)) = (rule.rtype.as_deref(), rule.value.as_deref()) else {
                continue;
            };
            let rtype = rtype.to_ascii_uppercase();
            if !rewrite_applies_to_qtype(&rtype, question.query_type()) {
                continue;
            }
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
                "PTR" => Name::from_str(value.trim_end_matches('.'))
                    .ok()
                    .map(|name| RData::PTR(PTR(name))),
                "TXT" => Some(RData::TXT(TXT::new(txt_chunks(value)))),
                other => {
                    // The parser rejects unsupported `$dnsrewrite` types; this
                    // only guards programmatically constructed rules.
                    warn!(
                        record_type = other,
                        "Unsupported $dnsrewrite record type; omitting record"
                    );
                    None
                }
            };
            if let Some(rdata) = rdata {
                let record = Record::from_rdata(question.name().clone(), 60, rdata);
                resp.answers.push(record);
            }
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

/// Candidate rule ids collected once per query and shared by the `$important`
/// (stage 1) and standard (stage 3) filter passes.
///
/// ADR-0007 requires local rewrites between the two passes, so a single
/// combined `evaluate` call cannot be used; collecting the candidates once
/// keeps the compiled structures from being walked twice without changing
/// precedence.
#[derive(Default)]
struct FilterCandidates {
    allow: Vec<u32>,
    block: Vec<u32>,
}

/// Combines the global and per-group standard verdicts.
///
/// Allow rules from either set win over block rules from the other set;
/// rewrites apply when no allow matched; blocks from the global set take
/// precedence in the returned reason.
fn combine_standard_verdicts(global: Verdict, group: Option<Verdict>) -> Verdict {
    let allow_rule_matched = |verdict: &Verdict| matches!(verdict, Verdict::Allow(Some(_)));
    let global_allowed = allow_rule_matched(&global);
    let group_allowed = group.as_ref().is_some_and(allow_rule_matched);
    if global_allowed || group_allowed {
        return Verdict::Allow(None);
    }
    if let Some(Verdict::Rewrite(action)) = group {
        return Verdict::Rewrite(action);
    }
    if let Verdict::Rewrite(action) = global {
        return Verdict::Rewrite(action);
    }
    if let Verdict::Block(_) = global {
        return global;
    }
    if let Some(block @ Verdict::Block(_)) = group {
        return block;
    }
    Verdict::Allow(None)
}

/// Aggregates all matching `$dnsrewrite` rules from the global and per-group
/// snapshots and applies their `@@...$dnsrewrite` exceptions.
///
/// Rewrites and cancellations from every applicable set are merged before
/// cancellation so a group exception can disable a global rewrite (and vice
/// versa), matching AdGuard's "all lists are one rule set" model.
fn effective_rewrites(
    sets: &[(&FilterSnapshot, &FilterCandidates)],
    domain: &str,
    qtype: RecordType,
    client: &ClientContext,
    important: bool,
) -> Vec<DnsRewriteRule> {
    let mut rules = Vec::new();
    let mut cancellations = Vec::new();
    // An `$important` cancellation outranks standard rewrite rules, so the
    // standard tier must also consult important exceptions. The important tier
    // only honours important cancellations (a standard exception cannot
    // override an important rewrite).
    let cancellation_tiers: &[bool] = if important { &[true] } else { &[false, true] };
    for (snapshot, candidates) in sets {
        rules.extend(snapshot.collect_rewrite_rules(
            domain,
            qtype,
            client,
            &candidates.block,
            important,
        ));
        for &tier in cancellation_tiers {
            cancellations.extend(snapshot.collect_rewrite_cancellations(
                domain,
                qtype,
                client,
                &candidates.allow,
                tier,
            ));
        }
    }
    sito_filter::apply_rewrite_cancellations(&mut rules, &cancellations);
    rules
}

/// Normalizes a query name to its ASCII/punycode, lowercased form.
///
/// Mirrors `sito_filter`'s private `normalized_query_domain` exactly so the
/// candidate lists collected here address the same compiled structures as the
/// engine's own `evaluate*` methods, including the malformed-punycode fallback.
fn normalized_query_domain(qname: &Name) -> String {
    let ascii = qname.to_ascii();
    sito_proto::normalize_domain(&ascii).unwrap_or_else(|_| {
        let fallback = ascii.trim_end_matches('.').to_ascii_lowercase();
        if fallback.is_empty() {
            // Root: keep a non-empty placeholder so substring/regex rules
            // cannot accidentally match the empty string.
            ".".to_string()
        } else {
            fallback
        }
    })
}

/// The core DNS query resolution pipeline.
pub struct DnsPipeline {
    runtime: Arc<RuntimeState>,
    filter: Arc<HostsFilterEngine>,
    anti_bypass: Arc<AntiBypassRegistry>,
    cache: Arc<DnsCache>,
    upstream: Arc<UpstreamManager>,
    /// Swappable so DNSSEC settings (mode, anchors, NTAs) hot-reload.
    dnssec: Arc<ArcSwap<DnssecValidator>>,
    lists: Arc<RuntimeLists>,
    in_flight: Arc<AtomicUsize>,
    prefetch_semaphore: Arc<tokio::sync::Semaphore>,
    querylog: Option<sito_stats::QueryLogSender>,
    metrics: Option<sito_stats::MetricsRegistry>,
    /// Per-client upstream managers keyed by `servers.join(",")`; swappable so
    /// client upstream changes hot-reload.
    scoped_upstreams: Arc<ArcSwap<HashMap<String, Arc<UpstreamManager>>>>,
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
        let lists = Arc::new(RuntimeLists::from_arcs(parental, services));
        Self {
            runtime,
            filter,
            anti_bypass: Arc::new(AntiBypassRegistry::try_bundled().unwrap_or_else(|e| {
                error!(
                    error = %e,
                    "Bundled DoH resolver list failed to load; anti-bypass domain/IP matching is disabled"
                );
                AntiBypassRegistry::empty()
            })),
            cache,
            upstream,
            dnssec: Arc::new(ArcSwap::from(dnssec)),
            lists,
            in_flight,
            prefetch_semaphore: Arc::new(tokio::sync::Semaphore::new(64)),
            querylog: None,
            metrics: None,
            scoped_upstreams: Arc::new(ArcSwap::from(Arc::new(HashMap::new()))),
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

    /// Shares runtime-refreshable parental/service registries with the server.
    #[must_use]
    pub fn with_runtime_lists(mut self, lists: Arc<RuntimeLists>) -> Self {
        self.lists = lists;
        self
    }

    /// Registers per-client upstream managers used when a client opts out of
    /// the global upstreams (`use_global_upstreams = false`).
    #[must_use]
    pub fn with_scoped_upstreams(
        mut self,
        scoped: Arc<HashMap<String, Arc<UpstreamManager>>>,
    ) -> Self {
        self.scoped_upstreams = Arc::new(ArcSwap::from(scoped));
        self
    }

    /// Shares the swappable DNSSEC validator handle with the server so config
    /// changes can replace it without a restart.
    #[must_use]
    pub fn with_shared_dnssec(mut self, dnssec: Arc<ArcSwap<DnssecValidator>>) -> Self {
        self.dnssec = dnssec;
        self
    }

    /// Shares the swappable per-client upstream map with the server.
    #[must_use]
    pub fn with_shared_scoped_upstreams(
        mut self,
        scoped: Arc<ArcSwap<HashMap<String, Arc<UpstreamManager>>>>,
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
        rule: Option<std::borrow::Cow<'static, str>>,
        source: Option<std::borrow::Cow<'static, str>>,
    ) -> QueryOutcome {
        let resp = make_blocked_response(
            query,
            &config.filtering.blocking_mode,
            config.filtering.blocking_ttl,
            query_id,
        );
        QueryOutcome::blocked(resp, rule, source, domain_str.to_string(), qtype)
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
            Some(std::borrow::Cow::Borrowed("anti_doh_bypass")),
            Some(std::borrow::Cow::Borrowed("anti_doh_bypass")),
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
            Some(std::borrow::Cow::Borrowed("anti_doh_bypass")),
            Some(std::borrow::Cow::Borrowed("anti_doh_bypass")),
        ))
    }

    /// Parental, service and standard filter stages (ADR-0007 stage 3).
    ///
    /// `snapshot` and `candidates` are collected once per query by the caller
    /// so the standard pass reuses the candidate walk already performed for the
    /// `$important` pass; the local `qname` is also no longer re-parsed from
    /// the human-readable domain string.
    #[allow(clippy::too_many_arguments)]
    fn evaluate_filter_stages(
        &self,
        query: &Message,
        config: &Config,
        client: &ClientContext,
        policy: &EffectivePolicy,
        domain_str: &str,
        normalized_domain: &str,
        snapshot: &sito_filter::FilterSnapshot,
        candidates: &FilterCandidates,
        group: Option<(&sito_filter::FilterSnapshot, &FilterCandidates)>,
        qtype: RecordType,
        query_id: u16,
    ) -> Option<QueryOutcome> {
        let parental = self.lists.parental();
        if policy.parental
            && parental.matches_any_category(
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
                Some(std::borrow::Cow::Borrowed("parental")),
                None,
            ));
        }

        let services = self.lists.services();
        if !policy.active_blocked_services.is_empty()
            && let Some(service_name) = services.matches_any_service(
                policy.active_blocked_services.iter().map(String::as_str),
                domain_str,
            )
        {
            info!(
                qname = %domain_str,
                qtype = ?qtype,
                service = %service_name,
                "Query blocked by service blocking policy"
            );
            return Some(Self::blocked_outcome(
                query,
                config,
                query_id,
                domain_str,
                qtype,
                Some(std::borrow::Cow::Borrowed("service")),
                Some(std::borrow::Cow::Owned(service_name.to_string())),
            ));
        }

        // A per-group standard allow rule may unblock a global block, and a
        // per-group block applies to group members even when the global set
        // does not match.
        let group_verdict = group.map(|(group_snapshot, group_candidates)| {
            group_snapshot.evaluate_standard_candidates(
                normalized_domain,
                qtype,
                client,
                &group_candidates.allow,
                &group_candidates.block,
            )
        });
        let global_verdict = snapshot.evaluate_standard_candidates(
            normalized_domain,
            qtype,
            client,
            &candidates.allow,
            &candidates.block,
        );
        let combined = combine_standard_verdicts(global_verdict, group_verdict);

        match combined {
            Verdict::Block(verdict) => {
                info!(
                    qname = %domain_str,
                    qtype = ?qtype,
                    verdict = ?verdict,
                    "Query blocked by standard filter"
                );
                let (rule, source) = block_reason_labels(&verdict);
                Some(Self::blocked_outcome(
                    query, config, query_id, domain_str, qtype, rule, source,
                ))
            }
            Verdict::Rewrite(_) => {
                // Aggregate every matching rewrite for this owner (AdGuard
                // returns all A/AAAA values) and let `@@...$dnsrewrite`
                // exceptions cancel them. A fully cancelled rewrite falls
                // through to normal resolution.
                let mut sets: Vec<(&FilterSnapshot, &FilterCandidates)> =
                    vec![(snapshot, candidates)];
                if let Some((group_snapshot, group_candidates)) = group {
                    sets.push((group_snapshot, group_candidates));
                }
                let rewrites = effective_rewrites(&sets, normalized_domain, qtype, client, false);
                if rewrites.is_empty() {
                    debug!(
                        qname = %domain_str,
                        "DNS rewrite cancelled by an exception rule"
                    );
                    return None;
                }
                debug!(qname = %domain_str, count = rewrites.len(), "Query rewritten by standard filter rule");
                let resp = make_rewrite_response(query, &rewrites, query_id);
                Some(QueryOutcome::rewritten(resp, domain_str.to_string(), qtype))
            }
            Verdict::Allow(_) => None,
        }
    }

    /// True when any CNAME target in `response` is blocked by the current
    /// global/group filter rules, parental controls, or service blocking.
    /// Cached and stale entries are re-checked because rules can change after
    /// the response was stored.
    fn cname_target_blocked(
        &self,
        response: &Message,
        qtype: RecordType,
        client: &ClientContext,
        policy: &EffectivePolicy,
    ) -> bool {
        if !response
            .answers
            .iter()
            .any(|record| matches!(record.data, RData::CNAME(_)))
        {
            return false;
        }

        let global_snapshot = self.filter.snapshot();
        let group_snapshot = if !policy.lists.is_empty() || !policy.custom_rules.is_empty() {
            self.filter.group_snapshot(&policy.group_name)
        } else {
            None
        };

        for record in &response.answers {
            let RData::CNAME(cname) = &record.data else {
                continue;
            };
            let cname_target = &cname.0;
            let cname_domain_str = cname_target.to_ascii().to_lowercase();
            let normalized = normalized_query_domain(cname_target);

            let mut global_candidates = FilterCandidates::default();
            global_snapshot.allowlist.collect_candidates(
                &normalized,
                &global_snapshot.interner,
                &mut global_candidates.allow,
            );
            global_snapshot.blocklist.collect_candidates(
                &normalized,
                &global_snapshot.interner,
                &mut global_candidates.block,
            );

            let group_candidates = group_snapshot.as_ref().map(|gs| {
                let mut candidates = FilterCandidates::default();
                gs.allowlist
                    .collect_candidates(&normalized, &gs.interner, &mut candidates.allow);
                gs.blocklist
                    .collect_candidates(&normalized, &gs.interner, &mut candidates.block);
                candidates
            });

            // 1. $important rules on the CNAME target
            let mut imp = global_snapshot.evaluate_important_candidates(
                &normalized,
                qtype,
                client,
                &global_candidates.allow,
                &global_candidates.block,
            );
            if imp.is_none()
                && let (Some(gs), Some(gc)) = (group_snapshot.as_ref(), group_candidates.as_ref())
            {
                imp = gs.evaluate_important_candidates(
                    &normalized,
                    qtype,
                    client,
                    &gc.allow,
                    &gc.block,
                );
            }
            if let Some(verdict) = imp {
                if verdict.is_blocked() {
                    return true;
                }
                if verdict.is_allowed() {
                    continue;
                }
            }

            // 2. Parental control categories on the CNAME target
            if policy.parental
                && self.lists.parental().matches_any_category(
                    policy.parental_categories.iter().map(String::as_str),
                    &cname_domain_str,
                )
            {
                return true;
            }

            // 3. Blocked services on the CNAME target
            if !policy.active_blocked_services.is_empty()
                && self
                    .lists
                    .services()
                    .matches_any_service(
                        policy.active_blocked_services.iter().map(String::as_str),
                        &cname_domain_str,
                    )
                    .is_some()
            {
                return true;
            }

            // 4. Standard filter rules (global + per-group combined)
            let group_std =
                group_snapshot
                    .as_ref()
                    .zip(group_candidates.as_ref())
                    .map(|(gs, gc)| {
                        gs.evaluate_standard_candidates(
                            &normalized,
                            qtype,
                            client,
                            &gc.allow,
                            &gc.block,
                        )
                    });
            let global_std = global_snapshot.evaluate_standard_candidates(
                &normalized,
                qtype,
                client,
                &global_candidates.allow,
                &global_candidates.block,
            );
            if combine_standard_verdicts(global_std, group_std).is_blocked() {
                return true;
            }
        }

        false
    }

    /// Cache lookup honouring the stored validation status.
    ///
    /// While local validation is active, an `Unchecked` entry must never be
    /// served (it was cached by a CD=1 query or while validation was off).
    /// `Insecure`/`Indeterminate` entries are legitimate answers for unsigned
    /// or inconclusive data: they are served to DNSSEC-aware clients with AD=0
    /// instead of forcing an upstream re-resolution. DO=0 clients additionally
    /// never see DNSSEC records.
    async fn cached_response(
        &self,
        cache_query: &Message,
        validation_active: bool,
        client_wants_dnssec: bool,
    ) -> Option<Message> {
        let (mut response, status) = self.cache.get_for_query_with_status(cache_query).await?;
        if !cache_entry_servable(status, validation_active) {
            debug!("Ignoring unchecked cache entry while DNSSEC validation is active");
            return None;
        }
        if !status.is_secure() {
            response.metadata.authentic_data = false;
        }
        if !client_wants_dnssec {
            strip_dnssec_records(&mut response);
        }
        Some(response)
    }

    /// Builds the query outcome for a cache hit, including anti-bypass answer
    /// checks and the background prefetch refresh.
    #[allow(clippy::too_many_arguments)]
    async fn cache_hit_outcome(
        &self,
        query: &Message,
        cache_query: &Message,
        mut cached_resp: Message,
        qname: &Name,
        qtype: RecordType,
        query_id: u16,
        domain_str: String,
        bypass_check_needed: bool,
        config: &Config,
        effective_upstream: &Arc<UpstreamManager>,
    ) -> QueryOutcome {
        if bypass_check_needed
            && let Some(outcome) = self.anti_doh_blocked_by_answers(
                query,
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
        if self.cache.should_prefetch_for_query(cache_query).await
            && let Ok(permit) = Arc::clone(&self.prefetch_semaphore).try_acquire_owned()
        {
            let bg_upstream = Arc::clone(effective_upstream);
            let bg_cache = Arc::clone(&self.cache);
            // Start from the cache query so ECS policy and DO are identical to
            // the entry being refreshed.
            let mut bg_query = cache_query.clone();
            // Never propagate a client's CD=1 flag into the background refresh:
            // the shared cache must always be validated when DNSSEC is enabled
            // so a CD=1 query cannot poison cached answers for CD=0 clients.
            bg_query.metadata.checking_disabled = false;
            let bg_wants_dnssec = query_has_do(&bg_query);
            let dnssec_mode = self.dnssec.load().mode;
            let bg_validator = if dnssec_mode == sito_dnssec::DnssecMode::Disabled {
                None
            } else {
                Some(self.dnssec.load_full())
            };
            let bg_resolve_query = build_upstream_query(
                &bg_query,
                config,
                dnssec_mode != sito_dnssec::DnssecMode::Disabled,
            );
            tokio::spawn(async move {
                let _permit = permit;
                let Ok(mut resp) = bg_upstream.resolve(&bg_resolve_query).await else {
                    return;
                };
                let bg_status = if let Some(validator) = bg_validator {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs() as u32;
                    let key_fetcher =
                        sito_upstream::UpstreamKeyFetcher::new(Arc::clone(&bg_upstream));
                    let outcome = validate_dnssec_with_deadline(
                        &validator,
                        &mut resp,
                        None,
                        now,
                        &key_fetcher,
                        DNSSEC_VALIDATION_DEADLINE,
                    )
                    .await;
                    validation_status(Some(&outcome))
                } else {
                    // No local validation ran: never trust an upstream AD bit.
                    resp.metadata.authentic_data = false;
                    ValidationStatus::Unchecked
                };
                if !bg_wants_dnssec {
                    strip_dnssec_records(&mut resp);
                }
                if resp.metadata.response_code == ResponseCode::NoError
                    || resp.metadata.response_code == ResponseCode::NXDomain
                {
                    bg_cache
                        .insert_with_status(&bg_query, &resp, bg_status)
                        .await;
                }
            });
        }
        cached_resp.metadata.id = query_id;
        let cached_dnssec = if self.dnssec.load().mode == sito_dnssec::DnssecMode::Disabled
            || !cached_resp.metadata.authentic_data
        {
            None
        } else {
            Some("secure")
        };
        QueryOutcome {
            response: Some(cached_resp),
            verdict: "allowed",
            rule: Some(std::borrow::Cow::Borrowed("cache")),
            source: None,
            upstream: None,
            from_cache: true,
            domain_str,
            qtype,
            dnssec: cached_dnssec,
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
        // Evaluate schedules against the configured `clients.timezone`
        // (default: the system-local zone) instead of UTC.
        let now = clients.now();
        let policy = clients.resolve(&mut client, now);

        // Per-client upstream scope (falls back to the global manager).
        let scoped_upstream = if policy.use_global_upstreams {
            None
        } else {
            policy.upstreams.as_ref().and_then(|servers| {
                self.scoped_upstreams
                    .load()
                    .get(&servers.join(","))
                    .cloned()
            })
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

        // The client must signal DNSSEC awareness (DO bit or AD bit) before we
        // may assert AD on the response (RFC 6840 section 5.7).
        let client_wants_dnssec = query_has_do(&query);
        let client_accepts_ad = client_wants_dnssec || query.metadata.authentic_data;

        let outcome = async {
            let Some(first_query) = query.queries.first() else {
                return QueryOutcome::formerr(&query);
            };

            let qname = first_query.name();
            let qtype = first_query.query_type();
            // ASCII/punycode form: parental/service lists, safe-search and
            // per-domain routing are all stored as punycode. `to_utf8` would
            // UTS46-decode `xn--` labels and never match an IDN rule.
            let domain_str = qname.to_ascii().to_lowercase();

            // RFC 6891 §6.1.3: a request with an unsupported EDNS version is
            // answered with BADVERS and an empty OPT record at version 0.
            if query.edns.as_ref().is_some_and(|edns| edns.version() > 0) {
                return QueryOutcome::badvers(&query, domain_str, qtype);
            }
            // Only standard queries can be resolved/filtered/cached here.
            if query.metadata.op_code != OpCode::Query {
                return QueryOutcome::notimp(&query, domain_str, qtype);
            }

            let dnssec_mode = self.dnssec.load().mode;
            let validation_active = !query.metadata.checking_disabled
                && dnssec_mode != sito_dnssec::DnssecMode::Disabled;
            // Cache lookups/inserts use the same ECS policy as the upstream
            // query, so "off" deduplicates clients and "forward" keys on the
            // clamped subnet.
            let cache_query = build_cache_query(&query, config);

            // Both the global `filtering.enabled` switch and the client's
            // effective group policy must be enabled for filtering to run.
            let is_filtering_active = config.filtering.enabled && policy.is_filtering_enabled;

            // Collect filter candidates once for both the `$important`
            // (stage 1) and standard (stage 3) passes. The snapshot is loaded
            // once so both passes see the same compiled rule set, and the
            // candidate walk is not repeated. Clients with filtering disabled
            // skip the work entirely.
            let (normalized_domain, filter_snapshot, filter_candidates) = if is_filtering_active {
                let normalized = normalized_query_domain(qname);
                let snapshot = self.filter.snapshot();
                // Fail closed when filtering was never able to load its
                // rules: an initial download failure must not silently
                // turn into an allow-all resolver.
                if config.filtering.fail_closed && snapshot.unavailable {
                    // The engine logs/statuses the load failure once; keep this
                    // per-query path at debug level to avoid log flooding.
                    debug!(
                        domain = %normalized,
                        "Filtering enabled but no rule snapshot has loaded; failing closed"
                    );
                    return QueryOutcome::servfail(&query, domain_str, qtype);
                }
                let mut candidates = FilterCandidates::default();
                snapshot.allowlist.collect_candidates(
                    &normalized,
                    &snapshot.interner,
                    &mut candidates.allow,
                );
                snapshot.blocklist.collect_candidates(
                    &normalized,
                    &snapshot.interner,
                    &mut candidates.block,
                );
                (normalized, Some(snapshot), candidates)
            } else {
                (String::new(), None, FilterCandidates::default())
            };

            // Per-group extra rules (clients.groups.<name>.lists/custom_rules)
            // are compiled separately by the engine and applied only to clients
            // whose resolved policy selects the group.
            let (group_snapshot, group_candidates) = if is_filtering_active
                && (!policy.lists.is_empty() || !policy.custom_rules.is_empty())
            {
                match self.filter.group_snapshot(&policy.group_name) {
                    Some(snapshot) => {
                        let mut candidates = FilterCandidates::default();
                        snapshot.allowlist.collect_candidates(
                            &normalized_domain,
                            &snapshot.interner,
                            &mut candidates.allow,
                        );
                        snapshot.blocklist.collect_candidates(
                            &normalized_domain,
                            &snapshot.interner,
                            &mut candidates.block,
                        );
                        (Some(snapshot), Some(candidates))
                    }
                    None => (None, None),
                }
            } else {
                (None, None)
            };

            trace!(qname = %qname, qtype = ?qtype, "Processing DNS query");

            let bypass_check_needed = config.filtering.enabled
                && match config.filtering.anti_doh_bypass.as_str() {
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
            let mut important_verdict = filter_snapshot.as_ref().and_then(|snapshot| {
                snapshot.evaluate_important_candidates(
                    &normalized_domain,
                    qtype,
                    &client,
                    &filter_candidates.allow,
                    &filter_candidates.block,
                )
            });
            if important_verdict.is_none()
                && let (Some(group), Some(candidates)) =
                    (group_snapshot.as_ref(), group_candidates.as_ref())
            {
                important_verdict = group.evaluate_important_candidates(
                    &normalized_domain,
                    qtype,
                    &client,
                    &candidates.allow,
                    &candidates.block,
                );
            }
            if let Some(verdict) = important_verdict {
                match verdict {
                    Verdict::Block(reason) => {
                        info!(
                            qname = %qname,
                            qtype = ?qtype,
                            reason = ?reason,
                            "Query blocked by $important filter rule"
                        );
                        let (rule, source) = block_reason_labels(&reason);
                        return Self::blocked_outcome(
                            &query,
                            config,
                            query_id,
                            &domain_str,
                            qtype,
                            rule,
                            source,
                        );
                    }
                    Verdict::Rewrite(_) => {
                        let mut sets: Vec<(&FilterSnapshot, &FilterCandidates)> = Vec::new();
                        if let Some(snapshot) = filter_snapshot.as_ref() {
                            sets.push((snapshot, &filter_candidates));
                        }
                        if let (Some(group), Some(candidates)) =
                            (group_snapshot.as_ref(), group_candidates.as_ref())
                        {
                            sets.push((group, candidates));
                        }
                        let rewrites = effective_rewrites(
                            &sets,
                            &normalized_domain,
                            qtype,
                            &client,
                            true,
                        );
                        if rewrites.is_empty() {
                            debug!(
                                qname = %qname,
                                "Important DNS rewrite cancelled by an exception rule"
                            );
                        } else {
                            debug!(qname = %qname, count = rewrites.len(), "Query rewritten by $important rule");
                            let resp = make_rewrite_response(&query, &rewrites, query_id);
                            return QueryOutcome::rewritten(resp, domain_str, qtype);
                        }
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
            if !important_allowed
                && let Some(filter_snapshot) = filter_snapshot.as_ref()
                && let Some(outcome) = self.evaluate_filter_stages(
                    &query,
                    config,
                    &client,
                    &policy,
                    &domain_str,
                    &normalized_domain,
                    filter_snapshot,
                    &filter_candidates,
                    group_snapshot.as_deref().zip(group_candidates.as_ref()),
                    qtype,
                    query_id,
                )
            {
                return outcome;
            }

            // ADR-0007 Stage 4: Safe Search CNAME rewrites (Google, Bing, YouTube, DuckDuckGo)
            if !important_allowed
                && is_filtering_active
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

            let cname_uncloaking_active =
                is_filtering_active && config.filtering.cname_cloaking && !important_allowed;

            // 5. Cache lookup
            // The single-flight guard (when acquired) is held until this async
            // block finishes, i.e. across the upstream resolution and the
            // cache insert below.
            let _cache_single_flight: Option<sito_cache::SingleFlightGuard> = if cache_enabled {
                if let Some(cached_resp) = self
                    .cached_response(&cache_query, validation_active, client_wants_dnssec)
                    .await
                {
                    if cname_uncloaking_active
                        && self.cname_target_blocked(&cached_resp, qtype, &client, &policy)
                    {
                        info!(
                            qname = %qname,
                            "Cached response blocked via CNAME uncloaking"
                        );
                        return Self::blocked_outcome(
                            &query,
                            config,
                            query_id,
                            &domain_str,
                            qtype,
                            Some(std::borrow::Cow::Borrowed("cname_uncloaking")),
                            None,
                        );
                    }
                    return self
                        .cache_hit_outcome(
                            &query,
                            &cache_query,
                            cached_resp,
                            qname,
                            qtype,
                            query_id,
                            domain_str,
                            bypass_check_needed,
                            config,
                            &effective_upstream,
                        )
                        .await;
                }
                debug!(qname = %qname, qtype = ?qtype, "Cache miss");
                if let Some(ref m) = self.metrics {
                    m.inc_cache_misses();
                }

                // Single-flight: serialize concurrent misses for the same key
                // so only one query goes upstream (anti-stampede).
                let flight = self.cache.single_flight_for_query(&cache_query).await;
                if let Some(cached_resp) = self
                    .cached_response(&cache_query, validation_active, client_wants_dnssec)
                    .await
                {
                    // A concurrent query populated the entry while we waited.
                    if cname_uncloaking_active
                        && self.cname_target_blocked(&cached_resp, qtype, &client, &policy)
                    {
                        info!(
                            qname = %qname,
                            "Cached response blocked via CNAME uncloaking"
                        );
                        return Self::blocked_outcome(
                            &query,
                            config,
                            query_id,
                            &domain_str,
                            qtype,
                            Some(std::borrow::Cow::Borrowed("cname_uncloaking")),
                            None,
                        );
                    }
                    return self
                        .cache_hit_outcome(
                            &query,
                            &cache_query,
                            cached_resp,
                            qname,
                            qtype,
                            query_id,
                            domain_str,
                            bypass_check_needed,
                            config,
                            &effective_upstream,
                        )
                        .await;
                }
                flight
            } else {
                None
            };

            // 6. Upstream resolution
            // Force the DNSSEC OK bit when validation is enabled so upstreams
            // return RRSIGs even for non-DO clients, and apply the ECS policy.
            let upstream_query = build_upstream_query(
                &query,
                config,
                dnssec_mode != sito_dnssec::DnssecMode::Disabled,
            );
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

                    // 7. CNAME uncloaking: inspect any CNAME targets against active filter stages
                    if cname_uncloaking_active
                        && self.cname_target_blocked(&upstream_resp, qtype, &client, &policy)
                    {
                        info!(
                            qname = %qname,
                            via_cname = true,
                            "Query blocked via CNAME uncloaking"
                        );
                        return Self::blocked_outcome(
                            &query,
                            config,
                            query_id,
                            &domain_str,
                            qtype,
                            Some(std::borrow::Cow::Borrowed("cname_uncloaking")),
                            None,
                        );
                    }

                    // 8. DNSSEC validation
                    // CD=1 means the client takes responsibility for
                    // validation: never SERVFAIL on DNSSEC grounds and never
                    // assert AD. The same applies when validation is disabled.
                    let dnssec_outcome = if validation_active {
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs() as u32;
                        let key_fetcher =
                            sito_upstream::UpstreamKeyFetcher::new(Arc::clone(&effective_upstream));
                        // Clone the validator for the awaited call so no ArcSwap
                        // guard is held across the await.
                        let validator = self.dnssec.load_full();
                        let outcome = validate_dnssec_with_deadline(
                            &validator,
                            &mut upstream_resp,
                            Some(upstream_name.as_str()),
                            now,
                            &key_fetcher,
                            DNSSEC_VALIDATION_DEADLINE,
                        )
                        .await;
                        if let Some(ref m) = self.metrics {
                            if matches!(outcome, sito_dnssec::ValidationOutcome::Bogus { .. }) {
                                m.inc_dnssec_bogus(&upstream_name);
                            }
                            m.set_dnssec_key_cache(
                                validator.metrics.key_cache_hits(),
                                validator.metrics.key_cache_misses(),
                            );
                        }
                        Some(outcome)
                    } else {
                        upstream_resp.metadata.authentic_data = false;
                        None
                    };
                    let dnssec_str = dnssec_outcome
                        .as_ref()
                        .map(sito_dnssec::ValidationOutcome::as_str);
                    let cache_status = validation_status(dnssec_outcome.as_ref());

                    // A DO=0 client must never receive DNSSEC records, and the
                    // stripped form is what gets cached under the DO=0 key.
                    if !client_wants_dnssec {
                        strip_dnssec_records(&mut upstream_resp);
                    }

                    if cache_enabled
                        && (upstream_resp.metadata.response_code == ResponseCode::NoError
                            || upstream_resp.metadata.response_code == ResponseCode::NXDomain)
                    {
                        self.cache
                            .insert_with_status(&cache_query, &upstream_resp, cache_status)
                            .await;
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
                        let label = e.upstream.as_deref().unwrap_or("unattributed");
                        m.inc_upstream_errors(label, e.kind());
                        if e.upstream.is_some() {
                            m.set_upstream_health(label, 0.0);
                        }
                    }

                    if cache_enabled
                        && config.dns.cache.serve_stale_hours > 0
                        && let Some((mut stale_resp, stale_status)) = self
                            .cache
                            .get_stale_for_query_with_status(&cache_query)
                            .await
                    {
                        if stale_cache_entry_servable(stale_status, validation_active) {
                            if bypass_check_needed
                                && let Some(outcome) = self.anti_doh_blocked_by_answers(
                                    &query,
                                    config,
                                    &stale_resp.answers,
                                    query_id,
                                    &domain_str,
                                    qtype,
                                    "stale_cache",
                                )
                            {
                                return outcome;
                            }
                            if cname_uncloaking_active
                                && self.cname_target_blocked(&stale_resp, qtype, &client, &policy)
                            {
                                info!(
                                    qname = %qname,
                                    "Stale cached response blocked via CNAME uncloaking"
                                );
                                return Self::blocked_outcome(
                                    &query,
                                    config,
                                    query_id,
                                    &domain_str,
                                    qtype,
                                    Some(std::borrow::Cow::Borrowed("cname_uncloaking")),
                                    None,
                                );
                            }
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
                                rule: Some(std::borrow::Cow::Borrowed("stale_cache")),
                                source: None,
                                upstream: None,
                                from_cache: true,
                                domain_str,
                                qtype,
                                dnssec: None,
                            };
                        }
                        debug!(
                            qname = %qname,
                            "Ignoring stale Indeterminate/Unchecked cache entry while DNSSEC validation is active"
                        );
                    }

                    QueryOutcome::servfail(&query, domain_str, qtype)
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
            // Reuse the owned domain string rather than cloning it; the stored
            // query-log qname has no trailing root dot.
            let mut qname = outcome.domain_str;
            if qname.ends_with('.') {
                qname.pop();
            }
            let entry = sito_stats::QueryLogEntry {
                id: None,
                ts: chrono::Utc::now().timestamp_millis(),
                client_ip: client.ip.to_string(),
                client_name: client.client_name.clone(),
                qname,
                qtype: qtype_num,
                rcode,
                verdict: outcome.verdict.to_string(),
                rule: outcome.rule.map(std::borrow::Cow::into_owned),
                list_source: outcome.source.map(std::borrow::Cow::into_owned),
                upstream: outcome.upstream,
                elapsed_us: Some(elapsed_us),
                dnssec: outcome.dnssec.map(str::to_string),
                proto: client.proto.clone(),
            };
            let _ = ql.try_send(entry);
        }

        // Never assert AD for a client that did not signal DNSSEC awareness.
        let mut response = outcome.response;
        if !client_accepts_ad && let Some(resp) = response.as_mut() {
            resp.metadata.authentic_data = false;
        }
        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sito_core::client::ClientContext;
    use sito_core::config::FilteringConfig;

    /// A fetcher that never answers, simulating a black-holed DS/DNSKEY
    /// lookup. The deadline wrapper must not wait for it indefinitely.
    struct BlockingFetcher;

    #[async_trait::async_trait]
    impl sito_core::DnssecKeyFetcher for BlockingFetcher {
        async fn query(
            &self,
            _name: &Name,
            _rtype: RecordType,
        ) -> Result<Message, sito_core::error::UpstreamError> {
            std::future::pending::<Result<Message, sito_core::error::UpstreamError>>().await
        }
    }

    /// Builds an answer with eight CNAME hops and one relevant (unverifiable)
    /// RRSIG, so validation reaches the blocking chain fetch.
    fn cname_chain_needing_key_fetch(now: u32) -> Message {
        use hickory_proto::dnssec::Algorithm;
        use hickory_proto::dnssec::rdata::{RRSIG, SigInput};
        use hickory_proto::op::Query;
        use hickory_proto::rr::SerialNumber;

        let origin = Name::from_str("timeout.example.").unwrap();
        let qname = Name::from_str("h0.timeout.example.").unwrap();
        let mut response = Message::new(7, MessageType::Response, OpCode::Query);
        response
            .queries
            .push(Query::query(qname.clone(), RecordType::A));
        for hop in 0..8 {
            let current = Name::from_str(&format!("h{hop}.timeout.example.")).unwrap();
            let next = Name::from_str(&format!("h{}.timeout.example.", hop + 1)).unwrap();
            response
                .answers
                .push(Record::from_rdata(current, 300, RData::CNAME(CNAME(next))));
        }
        response.answers.push(Record::from_rdata(
            qname,
            300,
            RData::DNSSEC(hickory_proto::dnssec::rdata::DNSSECRData::RRSIG(
                RRSIG::from_sig(
                    SigInput {
                        type_covered: RecordType::CNAME,
                        algorithm: Algorithm::ECDSAP256SHA256,
                        num_labels: 3,
                        original_ttl: 300,
                        sig_expiration: SerialNumber::new(now.saturating_add(300)),
                        sig_inception: SerialNumber::new(now.saturating_sub(300)),
                        key_tag: 1234,
                        signer_name: origin,
                    },
                    vec![0u8; 64],
                ),
            )),
        ));
        response
    }

    #[tokio::test]
    async fn test_dnssec_validation_deadline_fails_closed_in_validate_mode() {
        let validator = DnssecValidator::new(sito_dnssec::DnssecMode::Validate, Vec::new());
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as u32;
        let mut response = cname_chain_needing_key_fetch(now);

        let outcome = validate_dnssec_with_deadline(
            &validator,
            &mut response,
            Some("blocked"),
            now,
            &BlockingFetcher,
            std::time::Duration::from_millis(25),
        )
        .await;

        assert!(
            matches!(outcome, sito_dnssec::ValidationOutcome::Bogus { .. }),
            "a blocked key fetch must not produce an unvalidated answer: {outcome:?}"
        );
        assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
        assert!(!response.metadata.authentic_data);
        assert_eq!(response.answers.len(), 0);
    }

    #[tokio::test]
    async fn test_dnssec_validation_deadline_keeps_log_only_response() {
        let validator = DnssecValidator::new(sito_dnssec::DnssecMode::LogOnly, Vec::new());
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as u32;
        let mut response = cname_chain_needing_key_fetch(now);

        let outcome = validate_dnssec_with_deadline(
            &validator,
            &mut response,
            Some("blocked"),
            now,
            &BlockingFetcher,
            std::time::Duration::from_millis(25),
        )
        .await;

        assert_eq!(outcome, sito_dnssec::ValidationOutcome::Indeterminate);
        assert_eq!(response.metadata.response_code, ResponseCode::NoError);
        assert!(!response.metadata.authentic_data);
        assert!(!response.answers.is_empty(), "log-only keeps the response");
    }

    fn rewrite_rule(rcode: &str, rtype: Option<&str>, value: Option<&str>) -> DnsRewriteRule {
        DnsRewriteRule {
            rcode: rcode.to_string(),
            rtype: rtype.map(str::to_string),
            value: value.map(str::to_string),
            bare: false,
        }
    }

    fn rewrite_query(name: &str, qtype: RecordType) -> Message {
        use hickory_proto::op::Query;
        let mut query = Message::new(42, MessageType::Query, OpCode::Query);
        query
            .queries
            .push(Query::query(Name::from_str(name).unwrap(), qtype));
        query
    }

    #[test]
    fn test_make_rewrite_response_synthesizes_ptr_txt_and_aggregates() {
        let long_txt = "x".repeat(300);
        let rules = vec![
            rewrite_rule("NOERROR", Some("A"), Some("10.0.0.1")),
            rewrite_rule("NOERROR", Some("A"), Some("10.0.0.2")),
            rewrite_rule("NOERROR", Some("PTR"), Some("printer.lan.")),
            rewrite_rule("NOERROR", Some("TXT"), Some("hello")),
            rewrite_rule("NOERROR", Some("TXT"), Some(&long_txt)),
        ];

        // A questions aggregate every A value and ignore PTR/TXT rewrites.
        let query = rewrite_query("rewrite.example.", RecordType::A);
        let resp = make_rewrite_response(&query, &rules, 7);
        assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
        assert_eq!(resp.metadata.id, 7);
        assert_eq!(
            resp.answers.len(),
            2,
            "only the two A rewrites are synthesized for an A question"
        );
        let a_values: Vec<_> = resp
            .answers
            .iter()
            .filter_map(|record| match &record.data {
                RData::A(a) => Some(a.0),
                _ => None,
            })
            .collect();
        assert_eq!(
            a_values,
            vec![
                std::net::Ipv4Addr::new(10, 0, 0, 1),
                std::net::Ipv4Addr::new(10, 0, 0, 2)
            ]
        );

        // PTR questions only receive the PTR rewrite.
        let query = rewrite_query("4.3.2.1.in-addr.arpa.", RecordType::PTR);
        let resp = make_rewrite_response(&query, &rules, 8);
        assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
        assert_eq!(resp.answers.len(), 1, "only the PTR rewrite applies");
        assert!(
            matches!(&resp.answers[0].data, RData::PTR(ptr) if ptr.0.to_ascii().trim_end_matches('.') == "printer.lan"),
            "missing PTR record: {:?}",
            resp.answers
        );

        // TXT questions receive the TXT rewrites with 255-byte chunking.
        let query = rewrite_query("txt.example.", RecordType::TXT);
        let resp = make_rewrite_response(&query, &rules, 9);
        assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
        let txt_chunk_counts: Vec<usize> = resp
            .answers
            .iter()
            .filter_map(|record| match &record.data {
                RData::TXT(txt) => Some(txt.txt_data.len()),
                _ => None,
            })
            .collect();
        assert_eq!(
            txt_chunk_counts,
            vec![1, 2],
            "long TXT is split at 255 bytes"
        );
    }

    #[test]
    fn test_make_rewrite_response_matches_query_type() {
        let rules = vec![rewrite_rule("NOERROR", Some("A"), Some("10.0.0.1"))];

        let query = rewrite_query("host.example.", RecordType::A);
        let resp = make_rewrite_response(&query, &rules, 1);
        assert_eq!(resp.answers.len(), 1, "an A rule answers an A question");

        for qtype in [RecordType::AAAA, RecordType::TXT, RecordType::PTR] {
            let query = rewrite_query("host.example.", qtype);
            let resp = make_rewrite_response(&query, &rules, 2);
            assert_eq!(
                resp.metadata.response_code,
                ResponseCode::NoError,
                "{qtype:?} must be NODATA, not an error"
            );
            assert!(
                resp.answers.is_empty(),
                "{qtype:?} must be NODATA for an A-only rewrite: {:?}",
                resp.answers
            );
        }
    }

    #[test]
    fn test_make_rewrite_response_aggregates_same_type_only() {
        let rules = vec![
            rewrite_rule("NOERROR", Some("A"), Some("10.0.0.1")),
            rewrite_rule("NOERROR", Some("A"), Some("10.0.0.2")),
            rewrite_rule("NOERROR", Some("AAAA"), Some("2001:db8::1")),
            rewrite_rule("NOERROR", Some("TXT"), Some("ignored")),
        ];

        let query = rewrite_query("multi.example.", RecordType::A);
        let resp = make_rewrite_response(&query, &rules, 3);
        assert_eq!(resp.answers.len(), 2, "only the two A rules aggregate");
        assert!(
            resp.answers
                .iter()
                .all(|record| matches!(record.data, RData::A(_))),
            "an A question must not receive AAAA/TXT records: {:?}",
            resp.answers
        );

        let query = rewrite_query("multi.example.", RecordType::AAAA);
        let resp = make_rewrite_response(&query, &rules, 4);
        assert_eq!(resp.answers.len(), 1);
        assert!(matches!(resp.answers[0].data, RData::AAAA(_)));
    }

    #[test]
    fn test_make_rewrite_response_cname_answers_any_type() {
        let rules = vec![rewrite_rule(
            "NOERROR",
            Some("CNAME"),
            Some("target.example.net."),
        )];

        for qtype in [
            RecordType::A,
            RecordType::AAAA,
            RecordType::TXT,
            RecordType::PTR,
        ] {
            let query = rewrite_query("alias.example.", qtype);
            let resp = make_rewrite_response(&query, &rules, 5);
            assert_eq!(
                resp.metadata.response_code,
                ResponseCode::NoError,
                "{qtype:?}"
            );
            assert_eq!(
                resp.answers.len(),
                1,
                "a CNAME rewrite answers any question type ({qtype:?})"
            );
            assert!(
                matches!(&resp.answers[0].data, RData::CNAME(cname) if cname.0.to_ascii().trim_end_matches('.') == "target.example.net"),
                "expected CNAME answer for {qtype:?}: {:?}",
                resp.answers
            );
        }
    }

    #[test]
    fn test_make_rewrite_response_rcode_wins_over_records() {
        let query = rewrite_query("rewrite.example.", RecordType::A);
        let rules = vec![
            rewrite_rule("NOERROR", Some("A"), Some("1.2.3.4")),
            rewrite_rule("NXDOMAIN", None, None),
        ];
        let resp = make_rewrite_response(&query, &rules, 9);
        assert_eq!(resp.metadata.response_code, ResponseCode::NXDomain);
        assert!(
            resp.answers.is_empty(),
            "NXDOMAIN rewrite must not carry answers: {:?}",
            resp.answers
        );

        // A non-NOERROR rcode wins even when no record matches the qtype.
        let query = rewrite_query("rewrite.example.", RecordType::AAAA);
        let resp = make_rewrite_response(&query, &rules, 10);
        assert_eq!(resp.metadata.response_code, ResponseCode::NXDomain);
        assert_eq!(resp.answers.len(), 0);
    }

    #[tokio::test]
    async fn test_pipeline_aggregates_and_cancels_dnsrewrite() {
        use std::sync::atomic::Ordering;

        let mut config = Config::default();
        // This test exercises rewrite aggregation/cancellation, not DNSSEC.
        // Keep validation off so the D-05 delegation probe does not add
        // upstream DNSKEY/DS lookups to the call counts asserted below.
        config.dns.dnssec.validate = false;
        config.filtering.custom_rules = vec![
            "||rewrite-pipeline.example^$dnsrewrite=1.2.3.4".to_string(),
            "||rewrite-pipeline.example^$dnsrewrite=5.6.7.8".to_string(),
            "||rewrite-cancelled.example^$dnsrewrite=1.2.3.4".to_string(),
            "@@||rewrite-cancelled.example^$dnsrewrite".to_string(),
            "||rewrite-important-cancelled.example^$dnsrewrite=9.9.9.9".to_string(),
            "@@||rewrite-important-cancelled.example^$dnsrewrite,important".to_string(),
        ];
        let (pipeline, calls, temp_dir) = test_pipeline(config).await;
        let client = ClientContext::new("127.0.0.1".parse().unwrap());

        // Both A values are returned in one synthesized answer.
        let resp = pipeline
            .handle(
                rewrite_query("rewrite-pipeline.example.", RecordType::A),
                client.clone(),
            )
            .await
            .unwrap();
        let a_values: Vec<_> = resp
            .answers
            .iter()
            .filter_map(|record| match &record.data {
                RData::A(a) => Some(a.0),
                _ => None,
            })
            .collect();
        assert_eq!(
            a_values,
            vec![
                std::net::Ipv4Addr::new(1, 2, 3, 4),
                std::net::Ipv4Addr::new(5, 6, 7, 8)
            ]
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "a rewrite must not query upstream"
        );

        // The bare `@@...$dnsrewrite` exception cancels the rewrite and the
        // query is resolved normally.
        let resp = pipeline
            .handle(
                rewrite_query("rewrite-cancelled.example.", RecordType::A),
                client.clone(),
            )
            .await
            .unwrap();
        assert_eq!(resp.answers.len(), 1);
        assert!(
            matches!(resp.answers[0].data, RData::A(A(ip)) if ip == std::net::Ipv4Addr::new(203, 0, 113, 9))
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        // An `$important` cancellation-only exception outranks a standard
        // rewrite, so the query also resolves upstream.
        let resp = pipeline
            .handle(
                rewrite_query("rewrite-important-cancelled.example.", RecordType::A),
                client,
            )
            .await
            .unwrap();
        assert_eq!(resp.answers.len(), 1);
        assert!(
            matches!(resp.answers[0].data, RData::A(A(ip)) if ip == std::net::Ipv4Addr::new(203, 0, 113, 9))
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2);

        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    #[tokio::test]
    async fn test_pipeline_rewrite_matches_query_type_without_upstream() {
        use std::sync::atomic::Ordering;

        let mut config = Config::default();
        config.dns.dnssec.validate = false;
        config.filtering.custom_rules = vec![
            "||rewrite-type-pipeline.example^$dnsrewrite=1.2.3.4".to_string(),
            "||rewrite-cname-pipeline.example^$dnsrewrite=cname.example.net".to_string(),
        ];
        let (pipeline, calls, temp_dir) = test_pipeline(config).await;
        let client = ClientContext::new("127.0.0.1".parse().unwrap());

        // The rewrite answers an A question and never queries upstream.
        let resp = pipeline
            .handle(
                rewrite_query("rewrite-type-pipeline.example.", RecordType::A),
                client.clone(),
            )
            .await
            .unwrap();
        assert_eq!(resp.answers.len(), 1);
        assert!(
            matches!(resp.answers[0].data, RData::A(A(ip)) if ip == std::net::Ipv4Addr::new(1, 2, 3, 4))
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);

        // Other qtypes match the rule set but have no applicable value: the
        // answer is NOERROR/NODATA, not an upstream fallback.
        for qtype in [RecordType::AAAA, RecordType::TXT] {
            let resp = pipeline
                .handle(
                    rewrite_query("rewrite-type-pipeline.example.", qtype),
                    client.clone(),
                )
                .await
                .unwrap();
            assert_eq!(
                resp.metadata.response_code,
                ResponseCode::NoError,
                "{qtype:?}"
            );
            assert!(
                resp.answers.is_empty(),
                "{qtype:?} must be NODATA instead of querying upstream: {:?}",
                resp.answers
            );
            assert_eq!(
                calls.load(Ordering::SeqCst),
                0,
                "{qtype:?} must not query upstream"
            );
        }

        // A CNAME rewrite answers any question type.
        let resp = pipeline
            .handle(
                rewrite_query("rewrite-cname-pipeline.example.", RecordType::TXT),
                client,
            )
            .await
            .unwrap();
        assert_eq!(resp.answers.len(), 1);
        assert!(
            matches!(&resp.answers[0].data, RData::CNAME(cname) if cname.0.to_ascii().trim_end_matches('.') == "cname.example.net")
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);

        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    /// Collects candidates exactly like [`DnsPipeline::handle`] does and
    /// compares the resulting verdicts with the engine's own `evaluate*`
    /// wrappers. This guards the WP-18 single-collection refactor against
    /// normalization drift and ADR-0007 precedence changes.
    #[tokio::test]
    async fn test_candidate_path_matches_engine_and_preserves_precedence() {
        let temp_dir =
            std::env::temp_dir().join(format!("sito-pipeline-filter-test-{}", std::process::id()));
        let config = FilteringConfig {
            custom_rules: vec![
                "||blocked.example^".to_string(),
                "@@||sub.blocked.example^".to_string(),
                "||important.sub.blocked.example^$important".to_string(),
                "@@||special.important.sub.blocked.example^$important".to_string(),
                "||xn--mnchen-3ya.de^".to_string(),
            ],
            ..Default::default()
        };
        let engine = HostsFilterEngine::init(config, temp_dir.clone()).await;
        let client = ClientContext::new("127.0.0.1".parse().unwrap());

        for domain in [
            "blocked.example.",
            "sub.blocked.example.",
            "important.sub.blocked.example.",
            "special.important.sub.blocked.example.",
            "allowed.example.",
        ] {
            let qname = Name::from_str(domain).unwrap();
            let snapshot = engine.snapshot();
            let normalized = normalized_query_domain(&qname);
            let mut candidates = FilterCandidates::default();
            snapshot.allowlist.collect_candidates(
                &normalized,
                &snapshot.interner,
                &mut candidates.allow,
            );
            snapshot.blocklist.collect_candidates(
                &normalized,
                &snapshot.interner,
                &mut candidates.block,
            );

            let expected_important = engine.evaluate_important(&qname, RecordType::A, &client);
            let actual_important = snapshot.evaluate_important_candidates(
                &normalized,
                RecordType::A,
                &client,
                &candidates.allow,
                &candidates.block,
            );
            assert_eq!(
                expected_important.is_some(),
                actual_important.is_some(),
                "{domain}: important outcome presence"
            );
            if let (Some(expected), Some(actual)) = (&expected_important, &actual_important) {
                assert_eq!(expected.is_blocked(), actual.is_blocked(), "{domain}");
                assert_eq!(expected.is_allowed(), actual.is_allowed(), "{domain}");
            }

            let expected_standard = engine.evaluate_standard(&qname, RecordType::A, &client);
            let actual_standard = snapshot.evaluate_standard_candidates(
                &normalized,
                RecordType::A,
                &client,
                &candidates.allow,
                &candidates.block,
            );
            assert_eq!(
                expected_standard.is_blocked(),
                actual_standard.is_blocked(),
                "{domain}"
            );
            assert_eq!(
                expected_standard.is_allowed(),
                actual_standard.is_allowed(),
                "{domain}"
            );
        }

        // ADR-0007 precedence spot checks.
        let standard_block = Name::from_str("blocked.example.").unwrap();
        assert!(
            engine
                .evaluate_standard(&standard_block, RecordType::A, &client)
                .is_blocked()
        );
        let important_allow = Name::from_str("special.important.sub.blocked.example.").unwrap();
        let snapshot = engine.snapshot();
        let normalized = normalized_query_domain(&important_allow);
        let mut candidates = FilterCandidates::default();
        snapshot.allowlist.collect_candidates(
            &normalized,
            &snapshot.interner,
            &mut candidates.allow,
        );
        snapshot.blocklist.collect_candidates(
            &normalized,
            &snapshot.interner,
            &mut candidates.block,
        );
        let important = snapshot
            .evaluate_important_candidates(
                &normalized,
                RecordType::A,
                &client,
                &candidates.allow,
                &candidates.block,
            )
            .expect("important allow must match");
        assert!(important.is_allowed());

        // IDNA/punycode names must normalize exactly like the engine does.
        let idn = Name::from_utf8("münchen.de").unwrap();
        assert_eq!(normalized_query_domain(&idn), "xn--mnchen-3ya.de");
        let snapshot = engine.snapshot();
        let normalized = normalized_query_domain(&idn);
        let mut candidates = FilterCandidates::default();
        snapshot.allowlist.collect_candidates(
            &normalized,
            &snapshot.interner,
            &mut candidates.allow,
        );
        snapshot.blocklist.collect_candidates(
            &normalized,
            &snapshot.interner,
            &mut candidates.block,
        );
        assert!(
            snapshot
                .evaluate_standard_candidates(
                    &normalized,
                    RecordType::A,
                    &client,
                    &candidates.allow,
                    &candidates.block,
                )
                .is_blocked(),
            "IDN query must match the punycode rule"
        );

        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    /// Spawns a UDP mock upstream that answers every query with an A record and
    /// (dishonestly) AD=1, counting upstream calls. When `fail` is set and
    /// true, the mock answers `SERVFAIL` instead so callers can exercise the
    /// pipeline failure path and then recover by clearing the flag.
    async fn spawn_mock_upstream(
        fail: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    ) -> (
        std::net::SocketAddr,
        std::sync::Arc<std::sync::atomic::AtomicUsize>,
    ) {
        use std::sync::atomic::AtomicUsize;

        let mock_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mock_addr = mock_socket.local_addr().unwrap();
        let calls = std::sync::Arc::new(AtomicUsize::new(0));
        let call_counter = std::sync::Arc::clone(&calls);
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            while let Ok((len, src)) = mock_socket.recv_from(&mut buf).await {
                if let Ok(query) = sito_proto::decode_message(&buf[..len]) {
                    call_counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    let failing = fail
                        .as_ref()
                        .is_some_and(|flag| flag.load(std::sync::atomic::Ordering::SeqCst));
                    let mut resp =
                        Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
                    resp.metadata.response_code = if failing {
                        ResponseCode::ServFail
                    } else {
                        ResponseCode::NoError
                    };
                    // A compromised upstream: AD=1 without any signature.
                    resp.metadata.authentic_data = true;
                    resp.queries = query.queries.clone();
                    if !failing && let Some(question) = query.queries.first() {
                        resp.answers.push(Record::from_rdata(
                            question.name().clone(),
                            300,
                            RData::A(A(std::net::Ipv4Addr::new(203, 0, 113, 9))),
                        ));
                    }
                    let encoded = sito_proto::encode_message(&resp).unwrap();
                    let _ = mock_socket.send_to(&encoded, src).await;
                }
            }
        });
        (mock_addr, calls)
    }

    /// Builds a pipeline around `upstream` with the standard test registries.
    async fn build_test_pipeline(
        config: Config,
        upstream: std::sync::Arc<UpstreamManager>,
    ) -> (DnsPipeline, std::path::PathBuf) {
        let validator = sito_dnssec::DnssecValidator::from_config(&config.dns.dnssec);
        build_test_pipeline_with_validator(config, upstream, validator).await
    }

    /// Builds a pipeline with a caller-supplied DNSSEC validator (used by
    /// tests that need a specific trust anchor).
    async fn build_test_pipeline_with_validator(
        mut config: Config,
        upstream: std::sync::Arc<UpstreamManager>,
        dnssec: sito_dnssec::DnssecValidator,
    ) -> (DnsPipeline, std::path::PathBuf) {
        use sito_clients::{ClientRegistry, ClientsConfig, ParentalRegistry, ServiceRegistry};
        use sito_filter::HostsFilterEngine;
        use sito_rewrites::{RewriteTable, RewritesConfig};
        use std::sync::atomic::AtomicUsize;

        let temp_dir = std::env::temp_dir().join(format!(
            "sito-pipeline-audit6-{}-{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        std::fs::create_dir_all(&temp_dir).unwrap();
        config.server.data_dir = temp_dir.clone();
        config.dns.cache.enabled = true;

        let cache = std::sync::Arc::new(DnsCache::new(config.dns.cache.clone()));
        let filter = std::sync::Arc::new(
            HostsFilterEngine::init(config.filtering.clone(), config.server.data_dir.clone()).await,
        );
        let pipeline = DnsPipeline::new(
            std::sync::Arc::new(ArcSwap::new(std::sync::Arc::new(config.clone()))),
            filter,
            cache,
            upstream,
            std::sync::Arc::new(dnssec),
            std::sync::Arc::new(ArcSwap::new(std::sync::Arc::new(ClientRegistry::new(
                ClientsConfig::default(),
            )))),
            std::sync::Arc::new(
                ParentalRegistry::try_bundled().expect("bundled parental lists must load"),
            ),
            std::sync::Arc::new(
                ServiceRegistry::try_bundled().expect("bundled services must load"),
            ),
            std::sync::Arc::new(ArcSwap::new(std::sync::Arc::new(RewriteTable::new(
                RewritesConfig::default(),
            )))),
            std::sync::Arc::new(AtomicUsize::new(0)),
        );
        (pipeline, temp_dir)
    }

    /// Builds a pipeline backed by the default successful UDP mock upstream.
    async fn test_pipeline(
        mut config: Config,
    ) -> (
        DnsPipeline,
        std::sync::Arc<std::sync::atomic::AtomicUsize>,
        std::path::PathBuf,
    ) {
        use sito_upstream::{BootstrapResolver, UpstreamManager};

        let (mock_addr, calls) = spawn_mock_upstream(None).await;
        config.upstream.servers = vec![mock_addr.to_string()];
        let bootstrap = BootstrapResolver::new(vec![], std::time::Duration::from_millis(500));
        let upstream = std::sync::Arc::new(
            UpstreamManager::from_config(&config.upstream, &bootstrap)
                .await
                .unwrap(),
        );
        let (pipeline, temp_dir) = build_test_pipeline(config, upstream).await;
        (pipeline, calls, temp_dir)
    }

    /// Builds a pipeline whose mock upstream fails while `fail` is true.
    async fn test_pipeline_with_failure_toggle(
        mut config: Config,
        fail: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) -> (
        DnsPipeline,
        String,
        std::sync::Arc<std::sync::atomic::AtomicUsize>,
        std::path::PathBuf,
    ) {
        use sito_upstream::{BootstrapResolver, UpstreamManager};

        let (mock_addr, calls) = spawn_mock_upstream(Some(std::sync::Arc::clone(&fail))).await;
        let server = mock_addr.to_string();
        config.upstream.servers = vec![server.clone()];
        let bootstrap = BootstrapResolver::new(vec![], std::time::Duration::from_millis(500));
        let upstream = std::sync::Arc::new(
            UpstreamManager::from_config(&config.upstream, &bootstrap)
                .await
                .unwrap(),
        );
        let (pipeline, temp_dir) = build_test_pipeline(config, upstream).await;
        (pipeline, server, calls, temp_dir)
    }

    /// Attaches metrics (and an in-memory query log writer) to a test pipeline.
    async fn with_test_metrics(
        pipeline: DnsPipeline,
    ) -> (DnsPipeline, sito_stats::MetricsRegistry) {
        let stats_db = sito_stats::StatsDb::in_memory().await.unwrap();
        let writer = sito_stats::QueryLogWriter::spawn(stats_db, 100);
        let metrics = sito_stats::MetricsRegistry::new("test", "test");
        let pipeline = pipeline.with_stats(writer.sender(), metrics.clone());
        (pipeline, metrics)
    }

    /// D-12: a failing upstream is labelled by its configured name, lowers that
    /// server's health gauge immediately, and recovers to 1 after a success.
    /// No failure may ever be recorded under the legacy `upstream="all"` label.
    #[tokio::test]
    async fn test_pipeline_upstream_metrics_attribution_and_recovery() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let mut config = Config::default();
        config.dns.dnssec.validate = false;
        let fail = std::sync::Arc::new(AtomicBool::new(true));
        let (pipeline, server, calls, temp_dir) =
            test_pipeline_with_failure_toggle(config, std::sync::Arc::clone(&fail)).await;
        let (pipeline, metrics) = with_test_metrics(pipeline).await;
        let client = ClientContext::new("127.0.0.1".parse().unwrap());
        let name = Name::from_str("metrics-recovery.example.").unwrap();

        let resp = pipeline
            .handle(
                rewrite_query("metrics-recovery.example.", RecordType::A),
                client.clone(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.metadata.response_code,
            ResponseCode::ServFail,
            "the failing upstream must surface SERVFAIL"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        let rendered = metrics.render_prometheus();
        assert!(
            rendered.contains(&format!(
                "sito_upstream_errors_total{{upstream=\"{server}\",kind=\"bad_response\"}} 1"
            )),
            "error must be attributed to the configured server: {rendered}"
        );
        assert!(
            rendered.contains(&format!("sito_upstream_health{{upstream=\"{server}\"}} 0")),
            "a failed query must set that server's health gauge to 0: {rendered}"
        );
        assert!(
            !rendered.contains(r#"upstream="all""#),
            "the legacy aggregate label must never be emitted: {rendered}"
        );

        // Recover: the next successful query resets the same server's gauge.
        fail.store(false, Ordering::SeqCst);
        let resp = pipeline
            .handle(rewrite_query(&name.to_ascii(), RecordType::A), client)
            .await
            .unwrap();
        assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
        assert_eq!(calls.load(Ordering::SeqCst), 2);

        let rendered = metrics.render_prometheus();
        assert!(
            rendered.contains(&format!("sito_upstream_health{{upstream=\"{server}\"}} 1")),
            "a success must recover the server's health gauge: {rendered}"
        );
        assert!(
            rendered.contains(&format!(
                "sito_upstream_errors_total{{upstream=\"{server}\",kind=\"bad_response\"}} 1"
            )),
            "the error counter is monotonic and keeps the attributed label: {rendered}"
        );
        assert!(!rendered.contains(r#"upstream="all""#));
        assert!(!rendered.contains("unattributed"));

        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    /// D-12: failures that cannot be attributed to one configured server use
    /// the constant `unattributed` label and must not write a health gauge.
    #[tokio::test]
    async fn test_pipeline_unattributed_upstream_label_is_constant() {
        use sito_core::config::UpstreamStrategy;
        use sito_upstream::UpstreamManager;

        let mut config = Config::default();
        config.dns.dnssec.validate = false;
        let upstream = std::sync::Arc::new(UpstreamManager::with_upstreams(
            Vec::new(),
            UpstreamStrategy::Failover,
            std::time::Duration::from_millis(500),
        ));
        let (pipeline, temp_dir) = build_test_pipeline(config, upstream).await;
        let (pipeline, metrics) = with_test_metrics(pipeline).await;
        let client = ClientContext::new("127.0.0.1".parse().unwrap());

        for id in 1..=2 {
            let name = format!("unattributed-{id}.example.");
            let resp = pipeline
                .handle(rewrite_query(&name, RecordType::A), client.clone())
                .await
                .unwrap();
            assert_eq!(resp.metadata.response_code, ResponseCode::ServFail);
        }

        let rendered = metrics.render_prometheus();
        assert!(
            rendered.contains(
                r#"sito_upstream_errors_total{upstream="unattributed",kind="all_down"} 2"#
            ),
            "unattributable failures must use the constant `unattributed` label: {rendered}"
        );
        assert!(
            !rendered.contains(r#"sito_upstream_health{upstream="unattributed""#),
            "an unattributed failure must not write a health gauge: {rendered}"
        );
        assert!(!rendered.contains(r#"upstream="all""#));
        assert_eq!(
            rendered.matches(r#"upstream="unattributed""#).count(),
            1,
            "`unattributed` is one constant series, not a per-query label: {rendered}"
        );

        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    fn do_query(id: u16, name: &Name) -> Message {
        let mut query = Message::new(id, MessageType::Query, OpCode::Query);
        query
            .queries
            .push(hickory_proto::op::Query::query(name.clone(), RecordType::A));
        let mut edns = Edns::new();
        edns.set_dnssec_ok(true);
        query.set_edns(edns);
        query
    }

    #[tokio::test]
    async fn test_opcode_notimp_and_edns_badvers() {
        let config = Config::default();
        let (pipeline, _calls, temp_dir) = test_pipeline(config).await;
        let client = ClientContext::new("127.0.0.1".parse().unwrap());
        let name = Name::from_str("example.com.").unwrap();

        let mut notify = Message::new(1, MessageType::Query, OpCode::Notify);
        notify
            .queries
            .push(hickory_proto::op::Query::query(name.clone(), RecordType::A));
        let resp = pipeline.handle(notify, client.clone()).await.unwrap();
        assert_eq!(resp.metadata.response_code, ResponseCode::NotImp);
        assert_eq!(resp.metadata.op_code, OpCode::Notify);

        let mut update = Message::new(2, MessageType::Query, OpCode::Update);
        update
            .queries
            .push(hickory_proto::op::Query::query(name.clone(), RecordType::A));
        let resp = pipeline.handle(update, client.clone()).await.unwrap();
        assert_eq!(resp.metadata.response_code, ResponseCode::NotImp);

        let mut v1 = Message::new(3, MessageType::Query, OpCode::Query);
        v1.queries
            .push(hickory_proto::op::Query::query(name.clone(), RecordType::A));
        let mut edns = Edns::new();
        edns.set_version(1);
        edns.set_dnssec_ok(true);
        v1.set_edns(edns);
        let resp = pipeline.handle(v1, client).await.unwrap();
        assert_eq!(resp.metadata.response_code, ResponseCode::BADVERS);
        let resp_edns = resp.edns.expect("BADVERS must carry an OPT record");
        assert_eq!(resp_edns.version(), 0);
        assert!(
            resp_edns.options().options.is_empty(),
            "BADVERS response must not echo EDNS options: {:?}",
            resp_edns.options().options
        );

        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    #[tokio::test]
    async fn test_do_client_gets_insecure_cache_hit_with_ad_zero() {
        let config = Config::default();
        let (pipeline, calls, temp_dir) = test_pipeline(config).await;
        let client = ClientContext::new("127.0.0.1".parse().unwrap());
        let name = Name::from_str("unsigned.example.").unwrap();
        let query = do_query(11, &name);

        let mut cached = Message::response(11, OpCode::Query);
        cached.queries = query.queries.clone();
        cached.answers.push(Record::from_rdata(
            name.clone(),
            300,
            RData::A(A(std::net::Ipv4Addr::new(192, 0, 2, 11))),
        ));
        cached.metadata.authentic_data = false;
        pipeline
            .cache
            .insert_with_status(&query, &cached, ValidationStatus::Insecure)
            .await;

        let resp = pipeline.handle(query, client.clone()).await.unwrap();
        assert_eq!(resp.answers.len(), 1);
        assert!(
            !resp.metadata.authentic_data,
            "Insecure entries must serve AD=0"
        );
        assert_eq!(
            calls.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "a DO=1 client must hit the Insecure cache entry instead of re-querying"
        );

        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    #[tokio::test]
    async fn test_do_client_never_served_unchecked_cache_entry() {
        let config = Config::default();
        let (pipeline, calls, temp_dir) = test_pipeline(config).await;
        let client = ClientContext::new("127.0.0.1".parse().unwrap());
        let name = Name::from_str("unchecked.example.").unwrap();
        let query = do_query(12, &name);

        let mut cached = Message::response(12, OpCode::Query);
        cached.queries = query.queries.clone();
        cached.answers.push(Record::from_rdata(
            name.clone(),
            300,
            RData::A(A(std::net::Ipv4Addr::new(192, 0, 2, 12))),
        ));
        // Forged: an entry cached without validation must never be trusted.
        cached.metadata.authentic_data = true;
        pipeline
            .cache
            .insert_with_status(&query, &cached, ValidationStatus::Unchecked)
            .await;

        let resp = pipeline.handle(query, client.clone()).await.unwrap();
        assert!(
            calls.load(std::sync::atomic::Ordering::SeqCst) >= 1,
            "an Unchecked entry must not be served while validation is active"
        );
        assert!(
            !resp.metadata.authentic_data,
            "the upstream AD bit must be replaced by local validation"
        );

        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    /// RFC 8767 stale answers are not revalidated. An entry cached without
    /// local validation (`Unchecked`) must never be served to a client while
    /// validation is active, even when the upstream is down.
    #[tokio::test]
    async fn test_stale_unchecked_entry_is_not_served_under_validation() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let mut config = Config::default();
        config.dns.cache.serve_stale_hours = 1;
        config.dns.cache.min_ttl = 1;
        config.dns.cache.max_ttl = 1;
        config.dns.cache.negative_ttl_max = 1;
        let fail = std::sync::Arc::new(AtomicBool::new(true));
        let (pipeline, _server, calls, temp_dir) =
            test_pipeline_with_failure_toggle(config, fail).await;
        let client = ClientContext::new("127.0.0.1".parse().unwrap());
        let name = Name::from_str("stale-unchecked.example.").unwrap();
        let query = do_query(15, &name);

        let mut cached = Message::response(15, OpCode::Query);
        cached.queries = query.queries.clone();
        cached.answers.push(Record::from_rdata(
            name.clone(),
            1,
            RData::A(A(std::net::Ipv4Addr::new(192, 0, 2, 15))),
        ));
        pipeline
            .cache
            .insert_with_status(&query, &cached, ValidationStatus::Unchecked)
            .await;

        // Let the entry leave the fresh window so only the stale path can
        // answer it.
        tokio::time::sleep(std::time::Duration::from_millis(1100)).await;

        let resp = pipeline.handle(query, client).await.unwrap();
        assert_eq!(
            resp.metadata.response_code,
            ResponseCode::ServFail,
            "a stale Unchecked entry must not bypass active validation"
        );
        assert!(
            resp.answers.is_empty(),
            "the rejected stale answer must not leak records"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    /// A stale `Indeterminate` entry is not an authenticated decision: it may
    /// be an inconclusive answer (or, in log-only mode, a Bogus result cached
    /// as Indeterminate). It must not be served to a validating client while
    /// the upstream is down.
    #[tokio::test]
    async fn test_stale_indeterminate_entry_is_not_served_under_validation() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let mut config = Config::default();
        config.dns.cache.serve_stale_hours = 1;
        config.dns.cache.min_ttl = 1;
        config.dns.cache.max_ttl = 1;
        config.dns.cache.negative_ttl_max = 1;
        let fail = std::sync::Arc::new(AtomicBool::new(true));
        let (pipeline, _server, calls, temp_dir) =
            test_pipeline_with_failure_toggle(config, fail).await;
        let client = ClientContext::new("127.0.0.1".parse().unwrap());
        let name = Name::from_str("stale-indeterminate.example.").unwrap();
        let query = do_query(16, &name);

        let mut cached = Message::response(16, OpCode::Query);
        cached.queries = query.queries.clone();
        cached.answers.push(Record::from_rdata(
            name.clone(),
            1,
            RData::A(A(std::net::Ipv4Addr::new(192, 0, 2, 16))),
        ));
        pipeline
            .cache
            .insert_with_status(&query, &cached, ValidationStatus::Indeterminate)
            .await;

        tokio::time::sleep(std::time::Duration::from_millis(1100)).await;

        let resp = pipeline.handle(query, client).await.unwrap();
        assert_eq!(
            resp.metadata.response_code,
            ResponseCode::ServFail,
            "a stale Indeterminate entry must not be served to a validating client"
        );
        assert!(
            resp.answers.is_empty(),
            "the rejected stale answer must not leak records"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    /// Stale `Insecure` data is an authenticated unsigned decision and remains
    /// RFC 8767-servable, with AD cleared.
    #[tokio::test]
    async fn test_stale_insecure_entry_is_served_with_ad_zero() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let mut config = Config::default();
        config.dns.cache.serve_stale_hours = 1;
        config.dns.cache.min_ttl = 1;
        config.dns.cache.max_ttl = 1;
        config.dns.cache.negative_ttl_max = 1;
        let fail = std::sync::Arc::new(AtomicBool::new(true));
        let (pipeline, _server, calls, temp_dir) =
            test_pipeline_with_failure_toggle(config, fail).await;
        let client = ClientContext::new("127.0.0.1".parse().unwrap());
        let name = Name::from_str("stale-insecure.example.").unwrap();
        let query = do_query(17, &name);

        let mut cached = Message::response(17, OpCode::Query);
        cached.queries = query.queries.clone();
        cached.answers.push(Record::from_rdata(
            name.clone(),
            1,
            RData::A(A(std::net::Ipv4Addr::new(192, 0, 2, 17))),
        ));
        pipeline
            .cache
            .insert_with_status(&query, &cached, ValidationStatus::Insecure)
            .await;

        tokio::time::sleep(std::time::Duration::from_millis(1100)).await;

        let resp = pipeline.handle(query, client).await.unwrap();
        assert_eq!(
            resp.metadata.response_code,
            ResponseCode::NoError,
            "a stale Insecure entry remains servable as unauthenticated data"
        );
        assert_eq!(resp.answers.len(), 1);
        assert!(
            !resp.metadata.authentic_data,
            "a stale entry must never be served as authenticated"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    /// A validated Secure NXDOMAIN/NODATA must be cached for DO=0 clients too.
    ///
    /// The pipeline strips NSEC/NSEC3/RRSIG before inserting a DO=0 response.
    /// The denial-proof TTL cap must therefore already be applied to the SOA
    /// (in `apply_authenticated_ttls`); deriving the cap only from the cached
    /// (stripped) records produced a zero lifespan and sent every repeated
    /// negative query upstream.
    #[tokio::test]
    async fn test_do0_secure_negative_answer_is_cached() {
        use hickory_proto::dnssec::TrustAnchors;
        use hickory_proto::dnssec::rdata::{DNSSECRData, NSEC};
        use hickory_proto::rr::{LowerName, RecordSet};
        use sito_dnssec::DnssecMode;
        use sito_proto::rdata::SOA;

        let (origin, dnskey, signer) =
            sito_dnssec::test_util::create_test_signer("signed.example.");
        let qname = Name::from_str("empty.signed.example.").unwrap();
        let next = Name::from_str("zzz.signed.example.").unwrap();

        // Signed SOA (long-lived) plus a signed NSEC NODATA proof (10 s).
        let soa = Record::from_rdata(
            origin.clone(),
            3600,
            RData::SOA(SOA::new(
                Name::from_str("ns1.signed.example.").unwrap(),
                Name::from_str("hostmaster.signed.example.").unwrap(),
                1,
                7200,
                3600,
                1_209_600,
                3600,
            )),
        );
        let mut soa_set = RecordSet::new(origin.clone(), RecordType::SOA, 3600);
        soa_set.insert(soa.clone(), 0);
        let mut soa_sig = sito_dnssec::test_util::sign_test_rrset(&soa_set, &signer);
        soa_sig.ttl = 3600;

        let nsec = NSEC::new(next, [RecordType::SOA, RecordType::NSEC, RecordType::RRSIG]);
        let nsec_record =
            Record::from_rdata(qname.clone(), 10, RData::DNSSEC(DNSSECRData::NSEC(nsec)));
        let mut nsec_set = RecordSet::new(qname.clone(), RecordType::NSEC, 10);
        nsec_set.insert(nsec_record.clone(), 0);
        let mut nsec_sig = sito_dnssec::test_util::sign_test_rrset(&nsec_set, &signer);
        nsec_sig.ttl = 10;

        let mut template = Message::new(0, MessageType::Response, OpCode::Query);
        template.metadata.response_code = ResponseCode::NoError;
        template.authorities = vec![soa, soa_sig, nsec_record, nsec_sig];
        template.additionals.push(Record::from_rdata(
            origin.clone(),
            3600,
            RData::DNSSEC(DNSSECRData::DNSKEY(dnskey.clone())),
        ));

        let mock_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mock_addr = mock_socket.local_addr().unwrap();
        let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let calls_task = std::sync::Arc::clone(&calls);
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            while let Ok((len, src)) = mock_socket.recv_from(&mut buf).await {
                if let Ok(query) = sito_proto::decode_message(&buf[..len]) {
                    calls_task.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    let mut resp = template.clone();
                    resp.metadata.id = query.metadata.id;
                    resp.queries = query.queries.clone();
                    if let Ok(encoded) = sito_proto::encode_message(&resp) {
                        let _ = mock_socket.send_to(&encoded, src).await;
                    }
                }
            }
        });

        let mut config = Config::default();
        config.upstream.servers = vec![mock_addr.to_string()];
        config.dns.cache.serve_stale_hours = 0;
        let bootstrap =
            sito_upstream::BootstrapResolver::new(vec![], std::time::Duration::from_millis(500));
        let upstream = std::sync::Arc::new(
            sito_upstream::UpstreamManager::from_config(&config.upstream, &bootstrap)
                .await
                .unwrap(),
        );

        let mut anchors = TrustAnchors::empty();
        anchors.insert_with_name(dnskey.public_key(), LowerName::from(&origin));
        let validator =
            DnssecValidator::new(DnssecMode::Validate, Vec::new()).with_trust_anchors(anchors);
        let (pipeline, temp_dir) =
            build_test_pipeline_with_validator(config, upstream, validator).await;

        let client = ClientContext::new("127.0.0.1".parse().unwrap());
        let make_query = |id: u16| {
            let mut query = Message::new(id, MessageType::Query, OpCode::Query);
            query.queries.push(hickory_proto::op::Query::query(
                qname.clone(),
                RecordType::A,
            ));
            // No DO bit: a plain client.
            query
        };

        let first = pipeline
            .handle(make_query(1), client.clone())
            .await
            .unwrap();
        assert_eq!(first.metadata.response_code, ResponseCode::NoError);
        assert!(first.answers.is_empty(), "expected a NODATA answer");
        assert!(
            !first.metadata.authentic_data,
            "DO=0 responses never carry AD"
        );
        assert_eq!(
            calls.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "first query must reach the upstream"
        );
        let soa_ttl = first
            .authorities
            .iter()
            .find(|record| record.record_type() == RecordType::SOA)
            .expect("negative answer carries an SOA")
            .ttl;
        assert!(
            soa_ttl <= 10,
            "the validator must cap the SOA TTL by the denial proof before the DO=0 strip (got {soa_ttl})"
        );

        let (_, status) = pipeline
            .cache
            .get_for_query_with_status(&make_query(2))
            .await
            .expect("the Secure negative answer must have a non-zero cache lifespan");
        assert_eq!(
            status,
            ValidationStatus::Secure,
            "the denial proof must validate before being cached for DO=0"
        );

        let second = pipeline.handle(make_query(3), client).await.unwrap();
        assert_eq!(second.metadata.response_code, ResponseCode::NoError);
        assert_eq!(second.answers.len(), 0);
        assert_eq!(
            calls.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "a repeated DO=0 Secure negative must be served from the fresh cache"
        );

        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    #[tokio::test]
    async fn test_do0_response_is_stripped_and_cache_key_stays_do0() {
        let mut config = Config::default();
        config.dns.dnssec.mode = "disabled".to_string();
        config.dns.dnssec.validate = false;
        let (pipeline, calls, temp_dir) = test_pipeline(config).await;
        let client = ClientContext::new("127.0.0.1".parse().unwrap());
        let name = Name::from_str("rrsig.example.").unwrap();

        // Mock upstream signature record appended by injecting it into the
        // cached response is not possible here; instead assert the DO=0 key is
        // separate from the DO=1 key by observing a second upstream call.
        let mut plain = Message::new(13, MessageType::Query, OpCode::Query);
        plain
            .queries
            .push(hickory_proto::op::Query::query(name.clone(), RecordType::A));
        let resp = pipeline
            .handle(plain.clone(), client.clone())
            .await
            .unwrap();
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert!(!resp.metadata.authentic_data);

        // Same question with DO=1 must not reuse the DO=0 entry.
        let mut do_query = plain.clone();
        do_query.metadata.id = 14;
        let mut edns = Edns::new();
        edns.set_dnssec_ok(true);
        do_query.set_edns(edns);
        let _ = pipeline.handle(do_query, client).await.unwrap();
        assert_eq!(
            calls.load(std::sync::atomic::Ordering::SeqCst),
            2,
            "DO=1 responses must be cached separately from DO=0 entries"
        );

        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    #[tokio::test]
    async fn test_prefetch_clears_ad_when_no_validation_ran() {
        let mut config = Config::default();
        config.dns.dnssec.mode = "disabled".to_string();
        config.dns.dnssec.validate = false;
        config.dns.cache.prefetch = true;
        config.dns.cache.min_ttl = 5;
        config.dns.cache.max_ttl = 10;
        let (pipeline, calls, temp_dir) = test_pipeline(config).await;
        let client = ClientContext::new("127.0.0.1".parse().unwrap());
        let name = Name::from_str("prefetch-ad.example.").unwrap();

        for id in 1..=3 {
            let resp = pipeline
                .handle(do_query(id, &name), client.clone())
                .await
                .unwrap();
            assert!(
                !resp.metadata.authentic_data,
                "primary path never asserts AD without local validation"
            );
        }
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        assert!(
            calls.load(std::sync::atomic::Ordering::SeqCst) >= 2,
            "prefetch is expected to have re-queried the upstream"
        );

        // Inspect the entry itself: the prefetch writer must clear AD, not
        // merely rely on the read path to mask it.
        let (cached, _) = pipeline
            .cache
            .get_for_query_with_status(&do_query(4, &name))
            .await
            .expect("prefetched entry present");
        assert!(
            !cached.metadata.authentic_data,
            "a prefetched entry must have AD cleared when no local validation ran"
        );

        let resp = pipeline.handle(do_query(4, &name), client).await.unwrap();
        assert!(!resp.metadata.authentic_data);

        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    #[test]
    fn test_strip_dnssec_records_for_do0_clients() {
        use hickory_proto::rr::rdata::NULL;
        use sito_proto::rdata::opt::EdnsCode;

        let name = Name::from_str("dnssec.example.").unwrap();
        let mut response = Message::new(21, MessageType::Response, OpCode::Query);
        response
            .queries
            .push(hickory_proto::op::Query::query(name.clone(), RecordType::A));
        response.answers.push(Record::from_rdata(
            name.clone(),
            300,
            RData::A(A(std::net::Ipv4Addr::new(192, 0, 2, 21))),
        ));
        for record_type in [
            RecordType::RRSIG,
            RecordType::NSEC,
            RecordType::NSEC3,
            RecordType::DNSKEY,
        ] {
            response.answers.push(Record::from_rdata(
                name.clone(),
                300,
                RData::Unknown {
                    code: record_type,
                    rdata: NULL::default(),
                },
            ));
        }
        let mut edns = Edns::new();
        edns.options_mut()
            .insert(EdnsOption::Unknown(u16::from(EdnsCode::DAU), vec![]));
        response.set_edns(edns);

        strip_dnssec_records(&mut response);
        assert_eq!(
            response.answers.len(),
            1,
            "only the A record may remain after DO=0 shaping"
        );
        assert_eq!(response.answers[0].record_type(), RecordType::A);
        assert!(
            response
                .edns
                .as_ref()
                .is_some_and(|e| e.option(EdnsCode::DAU).is_none()),
            "DO-dependent EDNS options must be stripped"
        );
    }

    #[test]
    fn test_ecs_policy_off_strips_and_forward_clamps() {
        use hickory_proto::rr::rdata::opt::ClientSubnet;
        use sito_cache::CacheKey;

        let name = Name::from_str("ecs.example.").unwrap();
        let mut query = Message::new(1, MessageType::Query, OpCode::Query);
        query
            .queries
            .push(hickory_proto::op::Query::query(name, RecordType::A));
        let mut edns = Edns::new();
        edns.options_mut()
            .insert(EdnsOption::Subnet(ClientSubnet::new(
                "192.0.2.55".parse().unwrap(),
                32,
                0,
            )));
        query.set_edns(edns);

        let mut off_config = Config::default();
        off_config.upstream.ecs = UpstreamEcs::Off;
        let off = build_cache_query(&query, &off_config);
        assert!(
            off.edns
                .as_ref()
                .is_some_and(|e| e.option(EdnsCode::Subnet).is_none()),
            "ECS off must strip the client option"
        );

        let mut forward_config = Config::default();
        forward_config.upstream.ecs = UpstreamEcs::Forward;
        let forwarded = build_cache_query(&query, &forward_config);
        let subnet = match forwarded
            .edns
            .as_ref()
            .and_then(|e| e.option(EdnsCode::Subnet))
        {
            Some(EdnsOption::Subnet(subnet)) => *subnet,
            other => panic!("expected ECS option, got {other:?}"),
        };
        assert_eq!(subnet.source_prefix(), 24, "IPv4 ECS must clamp to /24");
        assert_eq!(subnet.scope_prefix(), 0);
        assert_eq!(subnet.addr().to_string(), "192.0.2.0");

        // Two clients in the same /24 share one cache key.
        let mut sibling = query.clone();
        if let Some(edns) = sibling.edns.as_mut() {
            edns.options_mut().remove(EdnsCode::Subnet);
            edns.options_mut()
                .insert(EdnsOption::Subnet(ClientSubnet::new(
                    "192.0.2.200".parse().unwrap(),
                    24,
                    0,
                )));
        }
        let sibling_forwarded = build_cache_query(&sibling, &forward_config);
        assert_eq!(
            CacheKey::from_query(&forwarded),
            CacheKey::from_query(&sibling_forwarded),
            "clamped ECS must deduplicate cache keys"
        );
    }
}
