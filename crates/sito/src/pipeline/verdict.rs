//! Filter candidate precedence and verdict combination.

#[allow(clippy::wildcard_imports)]
use super::*;

/// Candidate rule ids collected once per query and shared by the `$important`
/// (stage 1) and standard (stage 3) filter passes.
///
/// ADR-0007 requires local rewrites between the two passes, so a single
/// combined `evaluate` call cannot be used; collecting the candidates once
/// keeps the compiled structures from being walked twice without changing
/// precedence.
#[derive(Default, Clone)]
pub(super) struct FilterCandidates {
    pub(super) allow: Vec<u32>,
    pub(super) block: Vec<u32>,
}

/// Precedence rank within one rule tier (important or standard).
///
/// The table is `Allow > Rewrite > Block`. The per-group overlay wins ties
/// against the global set, so a group exception/rewrite has the same authority
/// as any other group rule. Important rules always outrank standard rules
/// because the caller evaluates that tier first.
pub(super) fn verdict_rank(verdict: &Verdict) -> u8 {
    match verdict {
        // `Allow(None)` is the "no rule matched" neutral verdict returned by
        // the standard evaluators; only `Allow(Some(rule))` is a real allow.
        Verdict::Allow(Some(_)) => 3,
        Verdict::Rewrite(_) => 2,
        Verdict::Block(_) => 1,
        Verdict::Allow(None) => 0,
    }
}

/// Combines one tier's global and per-group verdicts using [`verdict_rank`].
pub(super) fn combine_tier_verdicts(
    global: Option<Verdict>,
    group: Option<Verdict>,
) -> Option<Verdict> {
    match (global, group) {
        (None, None) => None,
        (Some(global), None) => Some(global),
        (None, Some(group)) => Some(group),
        // Ignore a neutral `Allow(None)`; otherwise the group overlay wins
        // equally-ranked verdicts and the higher-precedence verdict wins
        // regardless of source.
        (Some(global), Some(group)) => {
            let global_rank = verdict_rank(&global);
            let group_rank = verdict_rank(&group);
            if group_rank == 0 {
                Some(global)
            } else if global_rank == 0 || group_rank >= global_rank {
                Some(group)
            } else {
                Some(global)
            }
        }
    }
}

/// Combines the global and per-group standard verdicts.
///
/// Precedence within the standard tier is `Allow > Rewrite > Block`; the
/// group overlay wins ties. This lets a group `$dnsrewrite` override a global
/// standard block, consistently with any group allow/block overlay.
pub(super) fn combine_standard_verdicts(global: Verdict, group: Option<Verdict>) -> Verdict {
    combine_tier_verdicts(Some(global), group).unwrap_or(Verdict::Allow(None))
}

/// [`combine_tier_verdicts`] for the CNAME-target `$important` tier.
///
/// A `$dnsrewrite` cannot be applied on the CNAME-target path: the response is
/// already resolved, so rewriting the target would require synthesizing a new
/// answer. Drop rewrite verdicts entirely instead of converting them into
/// `Allow(None)`, which callers would otherwise treat as a real allow and use
/// to skip parental, service, and standard checks.
pub(super) fn combine_cname_target_tier_verdicts(
    global: Option<Verdict>,
    group: Option<Verdict>,
) -> Option<Verdict> {
    pub(super) fn actionable(verdict: Option<Verdict>) -> Option<Verdict> {
        match verdict {
            Some(Verdict::Rewrite(_)) | None => None,
            other => other,
        }
    }

    combine_tier_verdicts(actionable(global), actionable(group))
}

/// Normalizes a query name to its ASCII/punycode, lowercased form.
///
/// Mirrors `sito_filter`'s private `normalized_query_domain` exactly so the
/// candidate lists collected here address the same compiled structures as the
/// engine's own `evaluate*` methods, including the malformed-punycode fallback.
pub(super) fn normalized_query_domain(qname: &Name) -> String {
    let ascii = qname.to_ascii();
    sito_proto::normalize_domain(&ascii).unwrap_or_else(|_| {
        let fallback = ascii.trim_end_matches('.').to_ascii_lowercase();
        if fallback.is_empty() {
            // Root: keep a non-empty placeholder so substring/regex rules
            // cannot accidentally match the empty string.
            ".".to_string()
        } else {
            fallback
        }
    })
}
