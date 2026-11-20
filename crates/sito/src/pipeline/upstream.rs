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
            .resolve_with_attempts(&upstream_query)
            .await
        {
            Ok((mut upstream_resp, upstream_name, attempts)) => {
                if !policy.ignore_stats
                    && let Some(ref m) = pipeline.metrics
                {
                    record_resolution_metrics(
                        m,
                        &upstream_name,
                        upstream_start.elapsed(),
                        &attempts,
                    );
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
                        policy.ignore_stats,
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

                // DNSSEC validation, shaping, and cache insertion.
                let dnssec_str = self
                    .validate_and_cache_upstream(&mut upstream_resp, &upstream_name)
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
                if !policy.ignore_stats
                    && let Some(ref m) = pipeline.metrics
                {
                    record_failure_metrics(m, &e);
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
                                policy.ignore_stats,
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
                        if !policy.ignore_stats
                            && let Some(ref m) = pipeline.metrics
                        {
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

/// Records a successful resolution: per attempt when the manager reported
/// them, or the historical single winner sample as a compatibility fallback.
fn record_resolution_metrics(
    metrics: &sito_stats::MetricsRegistry,
    upstream: &str,
    elapsed: std::time::Duration,
    attempts: &[sito_upstream::UpstreamAttempt],
) {
    if attempts.is_empty() {
        metrics.observe_upstream_rtt(upstream, elapsed.as_secs_f64());
        metrics.set_upstream_health(upstream, 1.0);
    } else {
        for attempt in attempts {
            record_upstream_attempt(metrics, attempt);
        }
    }
}

/// Records a failed resolution: per attempt when available, otherwise the
/// attributed final error (or the constant `unattributed` label).
fn record_failure_metrics(
    metrics: &sito_stats::MetricsRegistry,
    error: &sito_upstream::UpstreamQueryError,
) {
    if error.attempts.is_empty() {
        let label = error.upstream.as_deref().unwrap_or("unattributed");
        metrics.inc_upstream_errors(label, error.kind());
        if error.upstream.is_some() {
            metrics.set_upstream_health(label, 0.0);
        }
    } else {
        for attempt in &error.attempts {
            record_upstream_attempt(metrics, attempt);
        }
    }
}

/// Emits one candidate attempt: its own RTT, error kind (if any) and health.
///
/// Failed-attempt time is therefore never included in the winner's RTT.
fn record_upstream_attempt(
    metrics: &sito_stats::MetricsRegistry,
    attempt: &sito_upstream::UpstreamAttempt,
) {
    metrics.observe_upstream_rtt(&attempt.name, attempt.rtt.as_secs_f64());
    match attempt.error_kind() {
        Some(kind) => {
            metrics.inc_upstream_errors(&attempt.name, kind);
            metrics.set_upstream_health(&attempt.name, 0.0);
        }
        None => metrics.set_upstream_health(&attempt.name, 1.0),
    }
}
