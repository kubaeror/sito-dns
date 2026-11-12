//! Upstream resolution, DNSSEC validation, and stale-cache fallback stage.

#[allow(clippy::wildcard_imports)]
use super::*;

impl PipelineContext<'_> {
    /// Resolves the query upstream, validating, shaping, and caching the
    /// response. On upstream failure, serves a servable stale entry (RFC 8767)
    /// or returns SERVFAIL.
    pub(super) async fn upstream_stage(&mut self) -> QueryOutcome {
        let pipeline = self.pipeline;
        let query = &self.query;
        let config = &self.runtime_snapshot.config;
        let client = &self.client;
        let policy = &self.policy;
        let qname = &self.qname;
        let qtype = self.qtype;
        let query_id = self.query_id;
        let domain_str = self.domain_str.clone();

        // Force the DNSSEC OK bit when validation is enabled so upstreams
        // return RRSIGs even for non-DO clients, and apply the ECS policy.
        let upstream_query = build_upstream_query(
            query,
            config,
            self.dnssec_mode != sito_dnssec::DnssecMode::Disabled,
        );
        let upstream_start = std::time::Instant::now();
        match self
            .effective_upstream
            .resolve_with_upstream(&upstream_query)
            .await
        {
            Ok((mut upstream_resp, upstream_name)) => {
                if let Some(ref m) = pipeline.metrics {
                    m.observe_upstream_rtt(&upstream_name, upstream_start.elapsed().as_secs_f64());
                    m.set_upstream_health(&upstream_name, 1.0);
                }
                upstream_resp.metadata.id = query_id;

                // Anti-DoH bypass: inspect resolved A and AAAA records for known resolver IPs
                if self.bypass_check_needed
                    && let Some(outcome) = pipeline.anti_doh_blocked_by_answers(
                        query,
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

                // CNAME uncloaking: inspect CNAME targets against active filter stages
                if self.cname_uncloaking_active
                    && pipeline.cname_target_blocked_with(
                        &self.runtime_snapshot,
                        &upstream_resp,
                        qtype,
                        client,
                        policy,
                    )
                {
                    info!(
                        qname = %qname,
                        via_cname = true,
                        "Query blocked via CNAME uncloaking"
                    );
                    return DnsPipeline::blocked_outcome(
                        query,
                        config,
                        query_id,
                        &domain_str,
                        qtype,
                        Some(std::borrow::Cow::Borrowed("cname_uncloaking")),
                        None,
                    );
                }

                // DNSSEC validation
                let dnssec_outcome = self
                    .validate_upstream_response(&mut upstream_resp, &upstream_name)
                    .await;
                let dnssec_str = dnssec_outcome
                    .as_ref()
                    .map(sito_dnssec::ValidationOutcome::as_str);
                let cache_status = validation_status(dnssec_outcome.as_ref());

                // Shape before caching so the stored entry never carries
                // upstream-only EDNS options; a DO=0 client never receives
                // DNSSEC records and the stripped form is what is cached.
                self.shape_and_insert(&mut upstream_resp, cache_status)
                    .await;

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
                if let Some(ref m) = pipeline.metrics {
                    let label = e.upstream.as_deref().unwrap_or("unattributed");
                    m.inc_upstream_errors(label, e.kind());
                    if e.upstream.is_some() {
                        m.set_upstream_health(label, 0.0);
                    }
                }

                if self.cache_enabled
                    && config.dns.cache.serve_stale_hours > 0
                    && let Some((mut stale_resp, stale_status)) = pipeline
                        .cache
                        .get_stale_for_query_with_status(
                            self.cache_query.as_ref().expect("cache query prepared"),
                        )
                        .await
                {
                    if stale_cache_entry_servable(stale_status, self.validation_active) {
                        if self.bypass_check_needed
                            && let Some(outcome) = pipeline.anti_doh_blocked_by_answers(
                                query,
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
                        if self.cname_uncloaking_active
                            && pipeline.cname_target_blocked_with(
                                &self.runtime_snapshot,
                                &stale_resp,
                                qtype,
                                client,
                                policy,
                            )
                        {
                            info!(
                                qname = %qname,
                                "Stale cached response blocked via CNAME uncloaking"
                            );
                            return DnsPipeline::blocked_outcome(
                                query,
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
                        if let Some(ref m) = pipeline.metrics {
                            m.inc_cache_stale_served();
                        }
                        ResponseShaper::shape_with_payload(
                            &mut stale_resp,
                            query,
                            self.dnssec_mode,
                            self.runtime_snapshot.config.dns.edns_udp_size,
                        );
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

                QueryOutcome::servfail(query, domain_str, qtype)
            }
        }
    }
}
