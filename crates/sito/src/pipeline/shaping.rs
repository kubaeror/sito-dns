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
        shape_response(&self.query, upstream_resp, self.client_wants_dnssec);
        if !self.cache_enabled
            || (upstream_resp.metadata.response_code != ResponseCode::NoError
                && upstream_resp.metadata.response_code != ResponseCode::NXDomain)
        {
            return;
        }
        let cache_query = self.cache_query.as_ref().expect("cache query prepared");
        self.pipeline
            .cache
            .insert_with_status_at_epoch(
                cache_query,
                upstream_resp,
                cache_status,
                self.cache_policy_epoch
                    .expect("cache policy epoch prepared"),
            )
            .await;
        if let Some(ref m) = self.pipeline.metrics {
            m.set_cache_size_bytes(
                i64::try_from(self.pipeline.cache.weighted_size()).unwrap_or(i64::MAX),
            );
        }
    }
}
