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
    /// refuses a `Bogus` status for ordinary data. This method is the only
    /// producer of Bogus cache entries: the response has no answer section and
    /// is served as-is from the cache for [`sito_cache::DNSSEC_BOGUS_CACHE_TTL`]
    /// seconds, so a repeated query fails closed without another upstream call.
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
        // A cached SERVFAIL is replayed as-is. Never let a failure entry carry
        // authority or additional data: those sections can hold SOA/NSEC/RRSIG
        // or helper records that would leak through a different query path.
        // EDNS (including the EDE diagnostic) stays on the message.
        upstream_resp.authorities.clear();
        upstream_resp.additionals.clear();
        self.pipeline
            .cache
            .insert_validation_failure_at_epochs(
                cache_query,
                upstream_resp,
                ValidationStatus::Bogus,
                self.cache_policy_epoch
                    .expect("cache policy epoch prepared"),
                self.cache_filter_epoch
                    .expect("cache filter epoch prepared"),
                sito_cache::DNSSEC_BOGUS_CACHE_TTL,
            )
            .await;
        if let Some(ref m) = self.pipeline.metrics {
            m.set_cache_size_bytes(
                i64::try_from(self.pipeline.cache.weighted_size()).unwrap_or(i64::MAX),
            );
        }
    }
}
