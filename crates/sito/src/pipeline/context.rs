//! Per-query state shared by the named pipeline stages.

#[allow(clippy::wildcard_imports)]
use super::*;

/// State built once per query and threaded through the pipeline stages.
///
/// The runtime snapshot is captured once so config, clients, rewrites, the
/// filter snapshot and the DNSSEC policy cannot be torn apart by a concurrent
/// hot reload (WP-1.4 invariant).
pub(super) struct PipelineContext<'a> {
    pub(super) pipeline: &'a DnsPipeline,
    pub(super) query: Message,
    pub(super) client: ClientContext,
    pub(super) policy: EffectivePolicy,
    pub(super) runtime_snapshot: Arc<sito_runtime::RuntimeSnapshot>,
    pub(super) query_id: u16,
    pub(super) qname: Name,
    pub(super) qtype: RecordType,
    pub(super) domain_str: String,
    pub(super) start: std::time::Instant,

    pub(super) effective_upstream: Arc<UpstreamManager>,
    pub(super) cache_enabled: bool,

    pub(super) cache_policy_epoch: Option<sito_cache::CachePolicyEpoch>,
    pub(super) dnssec_mode: sito_dnssec::DnssecMode,
    pub(super) validation_active: bool,
    pub(super) cache_query: Option<Message>,
    pub(super) is_filtering_active: bool,
    pub(super) normalized_domain: String,
    pub(super) filter_snapshot: Option<Arc<FilterSnapshot>>,
    pub(super) filter_candidates: FilterCandidates,
    pub(super) group_snapshot: Option<Arc<FilterSnapshot>>,
    pub(super) group_candidates: Option<FilterCandidates>,
    pub(super) bypass_check_needed: bool,
    pub(super) cname_uncloaking_active: bool,
    pub(super) important_allowed: bool,
    /// Held across upstream resolution to serialize concurrent misses. The
    /// value is intentionally only dropped, never read.
    #[allow(dead_code)]
    pub(super) cache_single_flight: Option<sito_cache::SingleFlightGuard>,
}

impl<'a> PipelineContext<'a> {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        pipeline: &'a DnsPipeline,
        query: Message,
        client: ClientContext,
        policy: EffectivePolicy,
        runtime_snapshot: Arc<sito_runtime::RuntimeSnapshot>,
        query_id: u16,
        qname: Name,
        qtype: RecordType,
        domain_str: String,
        start: std::time::Instant,
    ) -> Self {
        let config = &runtime_snapshot.config;
        // Per-client upstream scope (falls back to the global manager).
        let scoped_upstream = if policy.use_global_upstreams {
            None
        } else {
            policy.upstreams.as_ref().and_then(|servers| {
                pipeline
                    .scoped_upstreams
                    .load()
                    .get(&servers.join(","))
                    .cloned()
            })
        };
        let effective_upstream = scoped_upstream
            .clone()
            .unwrap_or_else(|| Arc::clone(&pipeline.upstream));
        // Answers from per-client upstreams must not be shared via the global cache.
        let cache_enabled = config.dns.cache.enabled && scoped_upstream.is_none();
        Self {
            pipeline,
            query,
            client,
            policy,
            runtime_snapshot,
            query_id,
            qname,
            qtype,
            domain_str,
            start,
            effective_upstream,
            cache_enabled,
            cache_policy_epoch: None,
            dnssec_mode: sito_dnssec::DnssecMode::Disabled,
            validation_active: false,
            cache_query: None,
            is_filtering_active: false,
            normalized_domain: String::new(),
            filter_snapshot: None,
            filter_candidates: FilterCandidates::default(),
            group_snapshot: None,
            group_candidates: None,
            bypass_check_needed: false,
            cname_uncloaking_active: false,
            important_allowed: false,
            cache_single_flight: None,
        }
    }

    /// Computes the filter/DNSSEC/cache policy for this query. Runs after the
    /// wire-level FORMERR/BADVERS/NOTIMP checks so those outcomes never do
    /// filter work, preserving the original order.
    pub(super) async fn execute(&mut self) -> QueryOutcome {
        let query = &self.query;
        // RFC 6891 §6.1.3: a request with an unsupported EDNS version is
        // answered with BADVERS and an empty OPT record at version 0.
        if query.edns.as_ref().is_some_and(|edns| edns.version() > 0) {
            return QueryOutcome::badvers(query, self.domain_str.clone(), self.qtype);
        }
        // Only standard queries can be resolved/filtered/cached here.
        if query.metadata.op_code != OpCode::Query {
            return QueryOutcome::notimp(query, self.domain_str.clone(), self.qtype);
        }
        if let Some(outcome) = self.prepare_filtering() {
            return outcome;
        }
        if let Some(outcome) = self.filter_and_rewrite() {
            return outcome;
        }
        if let Some(outcome) = self.cache_stage().await {
            return outcome;
        }
        self.upstream_stage().await
    }

    pub(super) fn prepare_filtering(&mut self) -> Option<QueryOutcome> {
        let config = &self.runtime_snapshot.config;
        let policy = &self.policy;
        let qname = &self.qname;

        // Capture the cache policy epoch before loading the validator: if a
        // reload swaps the validator after this point, the captured epoch no
        // longer matches and the insert is rejected.
        self.cache_policy_epoch = Some(DnsPipeline::cache_epoch_for(&self.runtime_snapshot));
        self.dnssec_mode = self.runtime_snapshot.dnssec_policy.mode();
        self.validation_active = !self.query.metadata.checking_disabled
            && self.dnssec_mode != sito_dnssec::DnssecMode::Disabled;
        self.cache_query = Some(build_cache_query(&self.query, config));
        self.is_filtering_active = config.filtering.enabled && policy.is_filtering_enabled;

        let (normalized, filter_snapshot, candidates) = if self.is_filtering_active {
            let normalized = normalized_query_domain(qname);
            let snapshot = match self.runtime_snapshot.filter.as_ref() {
                Some(snapshot) => Arc::clone(snapshot),
                None if config.filtering.fail_closed => {
                    debug!(
                        domain = %normalized,
                        "Filtering enabled but the generation has no compiled rules; failing closed"
                    );
                    return Some(QueryOutcome::servfail(
                        &self.query,
                        self.domain_str.clone(),
                        self.qtype,
                    ));
                }
                None => Arc::new(FilterSnapshot::default()),
            };
            if config.filtering.fail_closed && snapshot.unavailable {
                debug!(
                    domain = %normalized,
                    "Filtering enabled but no rule snapshot has loaded; failing closed"
                );
                return Some(QueryOutcome::servfail(
                    &self.query,
                    self.domain_str.clone(),
                    self.qtype,
                ));
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

        let (group_snapshot, group_candidates) = if self.is_filtering_active
            && (!policy.lists.is_empty() || !policy.custom_rules.is_empty())
        {
            match self
                .runtime_snapshot
                .group_filters
                .get(&policy.group_name)
                .cloned()
            {
                Some(snapshot) => {
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
                    (Some(snapshot), Some(candidates))
                }
                None => (None, None),
            }
        } else {
            (None, None)
        };

        self.normalized_domain = normalized;
        self.filter_snapshot = filter_snapshot;
        self.filter_candidates = candidates;
        self.group_snapshot = group_snapshot;
        self.group_candidates = group_candidates;
        self.bypass_check_needed = config.filtering.enabled
            && match config.filtering.anti_doh_bypass.as_str() {
                "block_all" => true,
                "block_except_trusted" => !policy.trusted,
                _ => false,
            };
        None
    }
}
