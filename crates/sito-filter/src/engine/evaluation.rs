//! Query-time evaluation and the core FilterEngine implementation.

#[allow(clippy::wildcard_imports)]
use super::*;

impl FilterEngine for HostsFilterEngine {
    fn evaluate(&self, qname: &Name, qtype: RecordType, client: &ClientContext) -> Verdict {
        let config = self.config.load();
        if !config.enabled {
            return Verdict::Allow(None);
        }
        let snapshot = self.snapshot.load();
        if config.fail_closed && snapshot.unavailable {
            return Verdict::Block(BlockReason::FilterUnavailable);
        }

        let normalized = normalized_query_domain(qname);
        snapshot.evaluate(&normalized, qtype, client)
    }
}
