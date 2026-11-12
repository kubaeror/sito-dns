//! DnsPipeline construction and filter/cache stages.

#[allow(clippy::wildcard_imports)]
use super::*;

impl DnsPipeline {
    // `filter` is kept by value for source compatibility with every existing
    // call site; it is only used to seed the snapshot.
    #[allow(clippy::too_many_arguments, clippy::needless_pass_by_value)]
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
        let initial_config = config.load_full();
        let runtime =
            Arc::new(RuntimeState::new(config, clients, rewrites).with_cache(cache.clone()));
        runtime.bootstrap_components(
            Some(filter.snapshot()),
            filter.group_snapshots(),
            sito_runtime::DnssecPolicy::from_validator(&initial_config.dns.dnssec, dnssec),
            sito_runtime::TransportPolicy::from(&*initial_config),
        );
        let lists = Arc::new(RuntimeLists::from_arcs(parental, services));
        Self {
            runtime,
            anti_bypass: Arc::new(AntiBypassRegistry::try_bundled().unwrap_or_else(|e| {
                error!(
                    error = %e,
                    "Bundled DoH resolver list failed to load; anti-bypass domain/IP matching is disabled"
                );
                AntiBypassRegistry::empty()
            })),
            cache,
            upstream,
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
    /// The cache/DNSSEC epoch paired with a query snapshot.
    ///
    /// It is the snapshot generation, never a live `cache.policy_epoch()`
    /// read: the validator that produced the entry came from the same
    /// snapshot, so the epoch must too (P1-27).
    pub(super) fn cache_epoch_for(
        snapshot: &sito_runtime::RuntimeSnapshot,
    ) -> sito_cache::PolicyEpoch {
        snapshot.generation
    }

    /// Builds a blocked response for the configured blocking mode.
    pub(super) fn blocked_outcome(
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
    pub(super) fn anti_doh_blocked_by_domain(
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
    pub(super) fn anti_doh_blocked_by_answers(
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
    pub(super) fn evaluate_filter_stages(
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
    #[cfg(test)]
    pub(super) fn cname_target_blocked(
        &self,
        response: &Message,
        qtype: RecordType,
        client: &ClientContext,
        policy: &EffectivePolicy,
    ) -> bool {
        let snapshot = self.runtime.snapshot();
        self.cname_target_blocked_with(&snapshot, response, qtype, client, policy)
    }

    /// The query-path form: re-check a CNAME target against the same snapshot
    /// that produced the response, so the config and rules cannot be swapped
    /// halfway through one query.
    pub(super) fn cname_target_blocked_with(
        &self,
        runtime_snapshot: &sito_runtime::RuntimeSnapshot,
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

        let Some(global_snapshot) = runtime_snapshot.filter.as_ref().map(Arc::clone) else {
            // No compiled rules in this generation: the query path already
            // failed closed before reaching the CNAME re-check.
            return false;
        };
        let group_snapshot = if !policy.lists.is_empty() || !policy.custom_rules.is_empty() {
            runtime_snapshot
                .group_filters
                .get(&policy.group_name)
                .cloned()
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

            // 1. $important rules on the CNAME target. Rewrites are dropped
            //    because they cannot be applied to an already-resolved CNAME
            //    target; a real allow still wins.
            let global_imp = global_snapshot.evaluate_important_candidates(
                &normalized,
                qtype,
                client,
                &global_candidates.allow,
                &global_candidates.block,
            );
            let group_imp = group_snapshot
                .as_ref()
                .zip(group_candidates.as_ref())
                .and_then(|(gs, gc)| {
                    gs.evaluate_important_candidates(
                        &normalized,
                        qtype,
                        client,
                        &gc.allow,
                        &gc.block,
                    )
                });
            if let Some(verdict) = combine_cname_target_tier_verdicts(global_imp, group_imp) {
                if verdict.is_blocked() {
                    return true;
                }
                if matches!(verdict, Verdict::Allow(Some(_))) {
                    continue;
                }
            }
            // The evaluator returns the first important match, so a rewrite
            // can hide an important block later in candidate order. The
            // rewrite is dropped above; detect the block independently.
            let group_imp_block = group_snapshot
                .as_ref()
                .zip(group_candidates.as_ref())
                .is_some_and(|(gs, gc)| {
                    gs.important_block_candidates_contain_block(
                        &normalized,
                        qtype,
                        client,
                        &gc.block,
                    )
                });
            let global_imp_block = global_snapshot.important_block_candidates_contain_block(
                &normalized,
                qtype,
                client,
                &global_candidates.block,
            );
            if global_imp_block || group_imp_block {
                return true;
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

            // 4. Standard filter rules (global + per-group combined). A
            //    `$dnsrewrite` cannot be applied to an already-resolved CNAME
            //    target, so check for a real allow first and then for any
            //    matching non-rewrite block. Scanning block candidates
            //    independently matters because the evaluator returns the first
            //    match, and a rewrite can precede a block in candidate order.
            let group_allow = group_snapshot
                .as_ref()
                .zip(group_candidates.as_ref())
                .is_some_and(|(gs, gc)| {
                    gs.evaluate_standard_allow_candidates(&normalized, qtype, client, &gc.allow)
                        .is_some()
                });
            let global_allow = global_snapshot
                .evaluate_standard_allow_candidates(
                    &normalized,
                    qtype,
                    client,
                    &global_candidates.allow,
                )
                .is_some();
            if !global_allow && !group_allow {
                let group_block = group_snapshot
                    .as_ref()
                    .zip(group_candidates.as_ref())
                    .is_some_and(|(gs, gc)| {
                        gs.standard_block_candidates_contain_block(
                            &normalized,
                            qtype,
                            client,
                            &gc.block,
                        )
                    });
                let global_block = global_snapshot.standard_block_candidates_contain_block(
                    &normalized,
                    qtype,
                    client,
                    &global_candidates.block,
                );
                if global_block || group_block {
                    return true;
                }
            }
        }

        false
    }

    /// Cache lookup honouring the stored validation status.
    ///
    /// While local validation is active, only an authenticated
    /// `Secure`/`Insecure` decision may be served. `Unchecked` (CD=1 or
    /// validation disabled) and `Indeterminate` (inconclusive, or Bogus in
    /// log-only mode) entries force an upstream re-resolution so strict mode
    /// can fail closed. `Insecure` answers are served with AD=0; DO=0 clients
    /// additionally never see DNSSEC records.
    pub(super) async fn cached_response(
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
    pub(super) async fn cache_hit_outcome(
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
        runtime_snapshot: &sito_runtime::RuntimeSnapshot,
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
            // Same ordering rule as the query path: read the epoch before the
            // validator so a reload always wins against an in-flight refresh.
            let bg_policy_epoch = Self::cache_epoch_for(runtime_snapshot);
            let dnssec_mode = runtime_snapshot.dnssec_policy.mode();
            let bg_validator = if dnssec_mode == sito_dnssec::DnssecMode::Disabled {
                None
            } else {
                Some(Arc::clone(&runtime_snapshot.dnssec_policy.validator))
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
                // Store the same client-neutral shape that the normal path
                // caches: the current question/flags, no client-specific EDNS
                // options, and DNSSEC material only for a DO=1 key.
                shape_response(&bg_query, &mut resp, bg_wants_dnssec);
                if resp.metadata.response_code == ResponseCode::NoError
                    || resp.metadata.response_code == ResponseCode::NXDomain
                {
                    bg_cache
                        .insert_with_status_at_epoch(&bg_query, &resp, bg_status, bg_policy_epoch)
                        .await;
                }
            });
        }
        cached_resp.metadata.id = query_id;
        let cached_dnssec = if runtime_snapshot.dnssec_policy.mode()
            == sito_dnssec::DnssecMode::Disabled
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
