//! Response shaping and cache-insert stage.

#[allow(clippy::wildcard_imports)]
use super::*;

impl PipelineContext<'_> {
    /// Shapes an upstream response for the requesting client and, when it is
    /// cacheable, inserts it under the generation captured at query start.
    pub(super) async fn shape_and_insert(
        &self,
        upstream_resp: &mut Message,
        cache_status: ValidationStatus,
    ) {
        ResponseShaper::shape_with_payload(
            upstream_resp,
            &self.query,
            self.dnssec_mode,
            self.runtime_snapshot.config.dns.edns_udp_size,
        );
        if !self.cache_enabled
            || (upstream_resp.metadata.response_code != ResponseCode::NoError
                && upstream_resp.metadata.response_code != ResponseCode::NXDomain)
        {
            return;
        }
        let cache_query = self.cache_query.as_ref().expect("cache query prepared");
        self.pipeline
            .cache
            .insert_with_status_at_epochs(
                cache_query,
                upstream_resp,
                cache_status,
                self.cache_policy_epoch
                    .expect("cache policy epoch prepared"),
                self.cache_filter_epoch
                    .expect("cache filter epoch prepared"),
            )
            .await;
        if let Some(ref m) = self.pipeline.metrics {
            m.set_cache_size_bytes(
                i64::try_from(self.pipeline.cache.weighted_size()).unwrap_or(i64::MAX),
            );
        }
    }

    /// Shapes a strict-mode `ValidationOutcome::Bogus` SERVFAIL and caches it
    /// as a fail-closed [`ValidationStatus::Bogus`] entry.
    ///
    /// The normal insert path deliberately rejects SERVFAIL (RFC 2308) and
    /// refuses a `Bogus` status for ordinary data. This foreground method
    /// shares [`cache_bogus_failure`] with the background prefetch path, so
    /// both producers store the same fail-closed shape: no answer section and
    /// served as-is from the cache for
    /// [`sito_cache::DNSSEC_BOGUS_CACHE_TTL`] seconds, so a repeated query
    /// fails closed without another upstream call.
    pub(super) async fn shape_and_insert_bogus(&self, upstream_resp: &mut Message) {
        ResponseShaper::shape_with_payload(
            upstream_resp,
            &self.query,
            self.dnssec_mode,
            self.runtime_snapshot.config.dns.edns_udp_size,
        );
        if !self.cache_enabled {
            return;
        }
        let cache_query = self.cache_query.as_ref().expect("cache query prepared");
        cache_bogus_failure(
            &self.pipeline.cache,
            cache_query,
            upstream_resp,
            self.cache_policy_epoch
                .expect("cache policy epoch prepared"),
            self.cache_filter_epoch
                .expect("cache filter epoch prepared"),
        )
        .await;
        if let Some(ref m) = self.pipeline.metrics {
            m.set_cache_size_bytes(
                i64::try_from(self.pipeline.cache.weighted_size()).unwrap_or(i64::MAX),
            );
        }
    }
}

/// Caches a shaped strict-mode Bogus SERVFAIL as a fail-closed failure entry.
///
/// Clears the authority and additional sections: a cached SERVFAIL is replayed
/// as-is, so those sections could carry SOA/NSEC/RRSIG or helper records that
/// would leak through a different query path. EDNS (including the RFC 8914 EDE
/// diagnostic) stays on the message. The insert enforces the short
/// [`sito_cache::DNSSEC_BOGUS_CACHE_TTL`] window and rejects any response that
/// asserts AD.
///
/// Used by both the foreground validation path and the background prefetch so
/// the two producers cannot drift apart. Returns whether the entry was stored.
pub(super) async fn cache_bogus_failure(
    cache: &DnsCache,
    query: &Message,
    response: &mut Message,
    policy_epoch: sito_cache::PolicyEpoch,
    filter_epoch: u64,
) -> bool {
    response.authorities.clear();
    response.additionals.clear();
    cache
        .insert_validation_failure_at_epochs(
            query,
            response,
            ValidationStatus::Bogus,
            policy_epoch,
            filter_epoch,
            sito_cache::DNSSEC_BOGUS_CACHE_TTL,
        )
        .await
}
