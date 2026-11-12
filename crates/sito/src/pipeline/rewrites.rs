//! Rewrite matching and response synthesis.

#[allow(clippy::wildcard_imports)]
use super::*;

/// Whether a `$dnsrewrite` record type can answer the given question type.
///
/// DNS applies exact record-type matching, except that a CNAME answers any
/// query type. Unsupported types are rejected by the parser; they fall through
/// so the synthesis path can still warn about programmatically built rules.
pub(super) fn rewrite_applies_to_qtype(rtype: &str, qtype: RecordType) -> bool {
    if rtype == "CNAME" {
        return true;
    }
    match rtype {
        "A" => qtype == RecordType::A,
        "AAAA" => qtype == RecordType::AAAA,
        "PTR" => qtype == RecordType::PTR,
        "TXT" => qtype == RecordType::TXT,
        _ => true,
    }
}

/// Builds a synthesized response for all matching ABP `$dnsrewrite` rules.
///
/// AdGuard aggregates every matching rewrite for an owner: two `A` rewrites
/// produce two answer records. Records are filtered by the question type
/// (`A`/`AAAA`/`PTR`/`TXT` exact match, `CNAME` answers any type); when no
/// matching value applies the result is NOERROR/NODATA, never an upstream
/// fallback. A non-`NOERROR` rcode is exclusive and wins over any record
/// synthesis.
pub(super) fn make_rewrite_response(
    query: &Message,
    rules: &[DnsRewriteRule],
    query_id: u16,
) -> Message {
    let mut resp = Message::new(query_id, MessageType::Response, query.metadata.op_code);
    copy_query_response_flags(&mut resp, query);

    let rcode = rules
        .iter()
        .map(|rule| rule.rcode.trim())
        .find(|rcode| !rcode.is_empty() && !rcode.eq_ignore_ascii_case("NOERROR"));
    resp.metadata.response_code = match rcode.map(str::to_ascii_uppercase).as_deref() {
        Some("NXDOMAIN") => ResponseCode::NXDomain,
        Some("REFUSED") => ResponseCode::Refused,
        Some("SERVFAIL") => ResponseCode::ServFail,
        Some("FORMERR") => ResponseCode::FormErr,
        Some("NOTIMP") => ResponseCode::NotImp,
        _ => ResponseCode::NoError,
    };

    if resp.metadata.response_code == ResponseCode::NoError
        && let Some(question) = query.queries.first()
    {
        for rule in rules {
            let (Some(rtype), Some(value)) = (rule.rtype.as_deref(), rule.value.as_deref()) else {
                continue;
            };
            let rtype = rtype.to_ascii_uppercase();
            if !rewrite_applies_to_qtype(&rtype, question.query_type()) {
                continue;
            }
            let rdata = match rtype.as_str() {
                "A" => value
                    .parse::<std::net::Ipv4Addr>()
                    .ok()
                    .map(|ip| RData::A(A(ip))),
                "AAAA" => value
                    .parse::<std::net::Ipv6Addr>()
                    .ok()
                    .map(|ip| RData::AAAA(AAAA(ip))),
                "CNAME" => Name::from_str(value.trim_end_matches('.'))
                    .ok()
                    .map(|name| RData::CNAME(CNAME(name))),
                "PTR" => Name::from_str(value.trim_end_matches('.'))
                    .ok()
                    .map(|name| RData::PTR(PTR(name))),
                "TXT" => Some(RData::TXT(TXT::new(txt_chunks(value)))),
                other => {
                    // The parser rejects unsupported `$dnsrewrite` types; this
                    // only guards programmatically constructed rules.
                    warn!(
                        record_type = other,
                        "Unsupported $dnsrewrite record type; omitting record"
                    );
                    None
                }
            };
            if let Some(rdata) = rdata {
                let record = Record::from_rdata(question.name().clone(), 60, rdata);
                resp.answers.push(record);
            }
        }
    }

    resp
}

pub(super) fn answers_contain_bypass_ip(
    anti_bypass: &AntiBypassRegistry,
    answers: &[hickory_proto::rr::Record],
) -> bool {
    answers.iter().any(|rec| match &rec.data {
        RData::A(a) => anti_bypass.matches_ip(&IpAddr::V4(a.0)),
        RData::AAAA(aaaa) => anti_bypass.matches_ip(&IpAddr::V6(aaaa.0)),
        _ => false,
    })
}

/// Aggregates all matching `$dnsrewrite` rules from the global and per-group
/// snapshots and applies their `@@...$dnsrewrite` exceptions.
///
/// Rewrites and cancellations from every applicable set are merged before
/// cancellation so a group exception can disable a global rewrite (and vice
/// versa), matching AdGuard's "all lists are one rule set" model.
pub(super) fn effective_rewrites(
    sets: &[(&FilterSnapshot, &FilterCandidates)],
    domain: &str,
    qtype: RecordType,
    client: &ClientContext,
    important: bool,
) -> Vec<DnsRewriteRule> {
    let mut rules = Vec::new();
    let mut cancellations = Vec::new();
    // An `$important` cancellation outranks standard rewrite rules, so the
    // standard tier must also consult important exceptions. The important tier
    // only honours important cancellations (a standard exception cannot
    // override an important rewrite).
    let cancellation_tiers: &[bool] = if important { &[true] } else { &[false, true] };
    for (snapshot, candidates) in sets {
        rules.extend(snapshot.collect_rewrite_rules(
            domain,
            qtype,
            client,
            &candidates.block,
            important,
        ));
        for &tier in cancellation_tiers {
            cancellations.extend(snapshot.collect_rewrite_cancellations(
                domain,
                qtype,
                client,
                &candidates.allow,
                tier,
            ));
        }
    }
    sito_filter::apply_rewrite_cancellations(&mut rules, &cancellations);
    rules
}

impl PipelineContext<'_> {
    /// ADR-0007 stage 2: local rewrite table and auto-PTR records.
    pub(super) fn apply_local_rewrite(&self) -> Option<QueryOutcome> {
        let records =
            self.runtime_snapshot
                .rewrites
                .lookup(&self.qname, self.qtype, &self.client)?;
        trace!(
            qname = %self.qname,
            qtype = ?self.qtype,
            count = records.len(),
            "Resolved via local rewrite table"
        );
        let mut rewrite_resp = synthesize_records_response(&self.query, records);
        rewrite_resp.metadata.id = self.query_id;
        Some(QueryOutcome::rewritten(
            rewrite_resp,
            self.domain_str.clone(),
            self.qtype,
        ))
    }

    /// ADR-0007 stage 4: safe-search CNAME rewrite.
    pub(super) fn apply_safe_search_rewrite(&self) -> Option<QueryOutcome> {
        if !self.is_filtering_active || !self.policy.safe_search || self.important_allowed {
            return None;
        }
        let target = match_safe_search(&self.domain_str, self.policy.safe_search_youtube)?;
        let cname_target = Name::from_str(&format!("{}.", target.trim_end_matches('.'))).ok()?;
        debug!(
            qname = %self.qname,
            target = %target,
            "Enforcing safe search CNAME rewrite"
        );
        let mut ss_resp = synthesize_cname_response(&self.query, &cname_target, 300);
        ss_resp.metadata.id = self.query_id;
        Some(QueryOutcome::rewritten(
            ss_resp,
            self.domain_str.clone(),
            self.qtype,
        ))
    }
}
