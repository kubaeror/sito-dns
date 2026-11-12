//! Response-cache lookup and single-flight stage.

#[allow(clippy::wildcard_imports)]
use super::*;

impl PipelineContext<'_> {
    /// Cache lookup before upstream resolution. A hit returns the final
    /// outcome; a miss returns `None` and keeps the single-flight guard in the
    /// context until the upstream/cache-insert stage completes.
    pub(super) async fn cache_stage(&mut self) -> Option<QueryOutcome> {
        if !self.cache_enabled {
            return None;
        }
        let pipeline = self.pipeline;
        let cache_query = self.cache_query.clone().expect("cache query prepared");
        let query = &self.query;
        let client = &self.client;
        let policy = &self.policy;
        let qname = &self.qname;
        let qtype = self.qtype;
        let query_id = self.query_id;
        let runtime_snapshot = Arc::clone(&self.runtime_snapshot);
        let effective_upstream = Arc::clone(&self.effective_upstream);
        let validation_active = self.validation_active;
        let client_wants_dnssec = self.client_wants_dnssec;
        let cname_uncloaking_active = self.cname_uncloaking_active;
        let bypass_check_needed = self.bypass_check_needed;

        if let Some(cached_resp) = pipeline
            .cached_response(&cache_query, validation_active, client_wants_dnssec)
            .await
        {
            if cname_uncloaking_active
                && pipeline.cname_target_blocked_with(
                    &runtime_snapshot,
                    &cached_resp,
                    qtype,
                    client,
                    policy,
                )
            {
                info!(
                    qname = %qname,
                    "Cached response blocked via CNAME uncloaking"
                );
                return Some(DnsPipeline::blocked_outcome(
                    query,
                    &runtime_snapshot.config,
                    query_id,
                    &self.domain_str,
                    qtype,
                    Some(std::borrow::Cow::Borrowed("cname_uncloaking")),
                    None,
                ));
            }
            return Some(
                pipeline
                    .cache_hit_outcome(
                        query,
                        &cache_query,
                        cached_resp,
                        qname,
                        qtype,
                        query_id,
                        self.domain_str.clone(),
                        bypass_check_needed,
                        &runtime_snapshot.config,
                        &runtime_snapshot,
                        &effective_upstream,
                    )
                    .await,
            );
        }
        debug!(qname = %qname, qtype = ?qtype, "Cache miss");
        if let Some(ref m) = pipeline.metrics {
            m.inc_cache_misses();
        }

        // Single-flight: serialize concurrent misses for the same key so only
        // one query goes upstream (anti-stampede).
        let flight = pipeline.cache.single_flight_for_query(&cache_query).await;
        if let Some(cached_resp) = pipeline
            .cached_response(&cache_query, validation_active, client_wants_dnssec)
            .await
        {
            // A concurrent query populated the entry while we waited.
            if cname_uncloaking_active
                && pipeline.cname_target_blocked_with(
                    &runtime_snapshot,
                    &cached_resp,
                    qtype,
                    client,
                    policy,
                )
            {
                info!(
                    qname = %qname,
                    "Cached response blocked via CNAME uncloaking"
                );
                return Some(DnsPipeline::blocked_outcome(
                    query,
                    &runtime_snapshot.config,
                    query_id,
                    &self.domain_str,
                    qtype,
                    Some(std::borrow::Cow::Borrowed("cname_uncloaking")),
                    None,
                ));
            }
            return Some(
                pipeline
                    .cache_hit_outcome(
                        query,
                        &cache_query,
                        cached_resp,
                        qname,
                        qtype,
                        query_id,
                        self.domain_str.clone(),
                        bypass_check_needed,
                        &runtime_snapshot.config,
                        &runtime_snapshot,
                        &effective_upstream,
                    )
                    .await,
            );
        }
        self.cache_single_flight = flight;
        None
    }
}
