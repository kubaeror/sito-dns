//! DNSSEC validation stage for upstream responses.

#[allow(clippy::wildcard_imports)]
use super::*;

impl PipelineContext<'_> {
    /// Validates `upstream_resp` against the snapshot's DNSSEC policy.
    ///
    /// CD=1 means the client takes responsibility: never SERVFAIL on DNSSEC
    /// grounds and never assert AD. The same applies when validation is
    /// disabled. Returns `None` when no validation ran.
    pub(super) async fn validate_upstream_response(
        &self,
        upstream_resp: &mut Message,
        upstream_name: &str,
    ) -> Option<sito_dnssec::ValidationOutcome> {
        if !self.validation_active {
            upstream_resp.metadata.authentic_data = false;
            return None;
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as u32;
        let key_fetcher =
            sito_upstream::UpstreamKeyFetcher::new(Arc::clone(&self.effective_upstream));
        // Clone the validator from this generation's snapshot.
        let validator = Arc::clone(&self.runtime_snapshot.dnssec_policy.validator);
        let outcome = validate_dnssec_with_deadline(
            &validator,
            upstream_resp,
            Some(upstream_name),
            now,
            &key_fetcher,
            DNSSEC_VALIDATION_DEADLINE,
        )
        .await;
        if let Some(ref m) = self.pipeline.metrics {
            if matches!(outcome, sito_dnssec::ValidationOutcome::Bogus { .. }) {
                m.inc_dnssec_bogus(upstream_name);
            }
            m.set_dnssec_key_cache(
                validator.metrics.key_cache_hits(),
                validator.metrics.key_cache_misses(),
            );
        }
        Some(outcome)
    }
}
