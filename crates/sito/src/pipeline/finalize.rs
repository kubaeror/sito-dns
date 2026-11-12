//! Final metrics, query log, and client-facing response shaping.

#[allow(clippy::wildcard_imports)]
use super::*;

impl PipelineContext<'_> {
    /// Finishes a query after the stage decision: records metrics and the
    /// query log, then applies the single client-facing shaping point.
    pub(super) fn finish(self, outcome: QueryOutcome) -> Option<Message> {
        let elapsed = self.start.elapsed();
        let elapsed_us = elapsed.as_micros() as i64;
        let elapsed_secs = elapsed.as_secs_f64();
        let qtype_num = u16::from(outcome.qtype);

        if let Some(ref m) = self.pipeline.metrics
            && !self.policy.ignore_stats
        {
            m.inc_queries(&self.client.proto, qtype_num, outcome.verdict);
            m.observe_query_duration(outcome.verdict, elapsed_secs);
            if outcome.from_cache {
                m.inc_cache_hits();
            }
        }

        if !self.policy.ignore_query_log
            && !outcome.domain_str.is_empty()
            && let Some(ref ql) = self.pipeline.querylog
        {
            let rcode = outcome
                .response
                .as_ref()
                .map(|r| u16::from(r.metadata.response_code) as u8);
            // Reuse the owned domain string rather than cloning it; the stored
            // query-log qname has no trailing root dot.
            let mut qname = outcome.domain_str;
            if qname.ends_with('.') {
                qname.pop();
            }
            let entry = sito_stats::QueryLogEntry {
                id: None,
                ts: chrono::Utc::now().timestamp_millis(),
                client_ip: self.client.ip.to_string(),
                client_name: self.client.client_name.clone(),
                qname,
                qtype: qtype_num,
                rcode,
                verdict: outcome.verdict.to_string(),
                rule: outcome.rule.map(std::borrow::Cow::into_owned),
                list_source: outcome.source.map(std::borrow::Cow::into_owned),
                upstream: outcome.upstream,
                elapsed_us: Some(elapsed_us),
                dnssec: outcome.dnssec.map(str::to_string),
                proto: self.client.proto.clone(),
            };
            let _ = ql.try_send(entry);
        }

        // Single shaping point for every response (cache hit, upstream, stale
        // or synthesized): copy the current question/RD/CD, rebuild EDNS from
        // this client, strip upstream-only options, and remove DNSSEC records
        // only when the client did not request them.
        let mut response = outcome.response;
        if let Some(resp) = response.as_mut() {
            ResponseShaper::shape_with_payload(
                resp,
                &self.query,
                self.dnssec_mode,
                self.runtime_snapshot.config.dns.edns_udp_size,
            );
        }
        response
    }
}
