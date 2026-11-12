//! Filtering, anti-DoH, and rewrite stages.

#[allow(clippy::wildcard_imports)]
use super::*;

impl PipelineContext<'_> {
    /// ADR-0007 stages 1-4: `$important` rules, local rewrites, standard
    /// filtering, and safe-search CNAME rewrites. Returns an early response
    /// when one of those stages decides the query.
    pub(super) fn filter_and_rewrite(&mut self) -> Option<QueryOutcome> {
        let pipeline = self.pipeline;
        let query = &self.query;
        let config = &self.runtime_snapshot.config;
        let client = &self.client;
        let policy = &self.policy;
        let qname = &self.qname;
        let qtype = self.qtype;
        let query_id = self.query_id;
        let domain_str = self.domain_str.as_str();
        let normalized_domain = self.normalized_domain.as_str();
        let filter_snapshot = self.filter_snapshot.as_ref();
        let filter_candidates = &self.filter_candidates;
        let group_snapshot = self.group_snapshot.clone();
        let group_candidates = self.group_candidates.clone();

        trace!(qname = %qname, qtype = ?qtype, "Processing DNS query");

        // Anti-DoH bypass: check if domain matches known public resolver
        if self.bypass_check_needed
            && let Some(outcome) =
                pipeline.anti_doh_blocked_by_domain(query, config, query_id, domain_str, qtype)
        {
            return Some(outcome);
        }

        // ADR-0007 Stage 1: $important filter rules (takes precedence over local rewrites)
        let global_important = filter_snapshot.and_then(|snapshot| {
            snapshot.evaluate_important_candidates(
                normalized_domain,
                qtype,
                client,
                &filter_candidates.allow,
                &filter_candidates.block,
            )
        });
        let group_important = group_snapshot
            .as_ref()
            .zip(group_candidates.as_ref())
            .and_then(|(group, candidates)| {
                group.evaluate_important_candidates(
                    normalized_domain,
                    qtype,
                    client,
                    &candidates.allow,
                    &candidates.block,
                )
            });
        // Consistent precedence: within the important tier
        // `Allow > Rewrite > Block`, group wins ties.
        let important_verdict = combine_tier_verdicts(global_important, group_important);
        if let Some(verdict) = important_verdict {
            match verdict {
                Verdict::Block(reason) => {
                    info!(
                        qname = %qname,
                        qtype = ?qtype,
                        reason = ?reason,
                        "Query blocked by $important filter rule"
                    );
                    let (rule, source) = block_reason_labels(&reason);
                    return Some(DnsPipeline::blocked_outcome(
                        query, config, query_id, domain_str, qtype, rule, source,
                    ));
                }
                Verdict::Rewrite(_) => {
                    let mut sets: Vec<(&FilterSnapshot, &FilterCandidates)> = Vec::new();
                    if let Some(snapshot) = filter_snapshot {
                        sets.push((snapshot, filter_candidates));
                    }
                    if let (Some(group), Some(candidates)) =
                        (group_snapshot.as_ref(), group_candidates.as_ref())
                    {
                        sets.push((group, candidates));
                    }
                    let rewrites =
                        effective_rewrites(&sets, normalized_domain, qtype, client, true);
                    if rewrites.is_empty() {
                        debug!(
                            qname = %qname,
                            "Important DNS rewrite cancelled by an exception rule"
                        );
                    } else {
                        debug!(qname = %qname, count = rewrites.len(), "Query rewritten by $important rule");
                        let resp = make_rewrite_response(query, &rewrites, query_id);
                        return Some(QueryOutcome::rewritten(
                            resp,
                            self.domain_str.clone(),
                            qtype,
                        ));
                    }
                }
                Verdict::Allow(_) => {
                    // $important allow overrides rewrites and all standard blocks.
                    self.important_allowed = true;
                }
            }
        }

        // ADR-0007 Stage 2: Local DNS rewrites and auto-PTR
        if !self.important_allowed
            && let Some(outcome) = self.apply_local_rewrite()
        {
            return Some(outcome);
        }

        // ADR-0007 Stage 3: Standard filtering, Parental Control, and Service Blocking
        if !self.important_allowed
            && let Some(filter_snapshot) = filter_snapshot
            && let Some(outcome) = pipeline.evaluate_filter_stages(
                query,
                config,
                client,
                policy,
                domain_str,
                normalized_domain,
                filter_snapshot,
                filter_candidates,
                group_snapshot.as_deref().zip(group_candidates.as_ref()),
                qtype,
                query_id,
            )
        {
            return Some(outcome);
        }

        // ADR-0007 Stage 4: Safe Search CNAME rewrites
        if !self.important_allowed
            && let Some(outcome) = self.apply_safe_search_rewrite()
        {
            return Some(outcome);
        }

        self.cname_uncloaking_active =
            self.is_filtering_active && config.filtering.cname_cloaking && !self.important_allowed;
        None
    }
}
