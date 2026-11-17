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
            m.set_dnssec_validations(
                validator.metrics.get_validations("secure"),
                validator.metrics.get_validations("insecure"),
                validator.metrics.get_validations("bogus"),
                validator.metrics.get_validations("indeterminate"),
            );
            m.set_dnssec_fetch_failures(
                validator.metrics.fetch_budget_exhausted(),
                validator.metrics.fetch_deadline_exceeded(),
            );
        }
        Some(outcome)
    }

    /// Validates an upstream response, then shapes and caches it under the
    /// decision it produced.
    ///
    /// Strict-mode Bogus is stored through the fail-closed failure insert as a
    /// SERVFAIL; log-only Bogus keeps the answer and is cached as unservable
    /// `Indeterminate` by the normal insert. Returns the metric/log label for
    /// the decision.
    pub(super) async fn validate_and_cache_upstream(
        &mut self,
        upstream_resp: &mut Message,
        upstream_name: &str,
    ) -> Option<&'static str> {
        let dnssec_outcome = self
            .validate_upstream_response(upstream_resp, upstream_name)
            .await;
        let dnssec_str = dnssec_outcome
            .as_ref()
            .map(sito_dnssec::ValidationOutcome::as_str);
        let cache_status = validation_status(dnssec_outcome.as_ref());
        // Strict mode converts Bogus into a fail-closed SERVFAIL with no
        // answer data. Cache that decision explicitly: it is not an RFC 2308
        // negative answer. LogOnly keeps the answer and is cached as
        // unservable `Indeterminate` by the normal path.
        let strict_bogus = matches!(
            dnssec_outcome.as_ref(),
            Some(sito_dnssec::ValidationOutcome::Bogus { .. })
        ) && self.dnssec_mode == sito_dnssec::DnssecMode::Validate;

        // Shape before caching so the stored entry never carries
        // upstream-only EDNS options; a DO=0 client never receives DNSSEC
        // records and the stripped form is what is cached.
        if strict_bogus {
            self.shape_and_insert_bogus(upstream_resp).await;
        } else {
            self.shape_and_insert(upstream_resp, cache_status).await;
        }
        dnssec_str
    }
}
