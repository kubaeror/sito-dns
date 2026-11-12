//! Query outcomes and blocked/error response construction.

#[allow(clippy::wildcard_imports)]
use super::*;

/// Outcome of executing a query through the DNS pipeline.
pub(super) struct QueryOutcome {
    pub(super) response: Option<Message>,
    pub(super) verdict: &'static str,
    /// Matched rule/list identifiers: static labels use `Cow::Borrowed` and
    /// matched filter rules carry their rule text and list name via `Cow::Owned`.
    pub(super) rule: Option<std::borrow::Cow<'static, str>>,
    pub(super) source: Option<std::borrow::Cow<'static, str>>,
    pub(super) upstream: Option<String>,
    pub(super) from_cache: bool,
    pub(super) domain_str: String,
    pub(super) qtype: RecordType,
    pub(super) dnssec: Option<&'static str>,
}

pub(super) fn block_reason_labels(
    reason: &sito_core::verdict::BlockReason,
) -> (
    Option<std::borrow::Cow<'static, str>>,
    Option<std::borrow::Cow<'static, str>>,
) {
    use std::borrow::Cow;
    match reason {
        sito_core::verdict::BlockReason::Rule(rule_ref) => (
            Some(Cow::Owned(rule_ref.rule_text.clone())),
            rule_ref.list_name.clone().map(Cow::Owned),
        ),
        sito_core::verdict::BlockReason::Parental => (Some(Cow::Borrowed("parental")), None),
        sito_core::verdict::BlockReason::Service(svc) => (
            Some(Cow::Borrowed("service")),
            Some(Cow::Owned(svc.clone())),
        ),
        sito_core::verdict::BlockReason::AntiDohBypass => (
            Some(Cow::Borrowed("anti_doh_bypass")),
            Some(Cow::Borrowed("anti_doh_bypass")),
        ),
        sito_core::verdict::BlockReason::FilterUnavailable => {
            (Some(Cow::Borrowed("filter_unavailable")), None)
        }
    }
}

impl QueryOutcome {
    pub(super) fn blocked(
        response: Message,
        rule: Option<std::borrow::Cow<'static, str>>,
        source: Option<std::borrow::Cow<'static, str>>,
        domain_str: String,
        qtype: RecordType,
    ) -> Self {
        Self {
            response: Some(response),
            verdict: "blocked",
            rule,
            source,
            upstream: None,
            from_cache: false,
            domain_str,
            qtype,
            dnssec: None,
        }
    }

    pub(super) fn rewritten(response: Message, domain_str: String, qtype: RecordType) -> Self {
        Self {
            response: Some(response),
            verdict: "rewritten",
            rule: None,
            source: None,
            upstream: None,
            from_cache: false,
            domain_str,
            qtype,
            dnssec: None,
        }
    }

    pub(super) fn notimp(query: &Message, domain_str: String, qtype: RecordType) -> Self {
        Self::error(query, ResponseCode::NotImp, "notimp", domain_str, qtype)
    }

    pub(super) fn badvers(query: &Message, domain_str: String, qtype: RecordType) -> Self {
        Self::error(query, ResponseCode::BADVERS, "badvers", domain_str, qtype)
    }

    pub(super) fn error(
        query: &Message,
        response_code: ResponseCode,
        verdict: &'static str,
        domain_str: String,
        qtype: RecordType,
    ) -> Self {
        Self {
            response: Some(error_response(query, response_code)),
            verdict,
            rule: None,
            source: None,
            upstream: None,
            from_cache: false,
            domain_str,
            qtype,
            dnssec: None,
        }
    }

    pub(super) fn servfail(query: &Message, domain_str: String, qtype: RecordType) -> Self {
        Self::error(query, ResponseCode::ServFail, "servfail", domain_str, qtype)
    }
}

pub(super) fn make_blocked_response(
    query: &Message,
    blocking_mode: &sito_core::BlockingMode,
    blocking_ttl: u32,
    query_id: u16,
) -> Message {
    let mut blocked_resp = synthesize_blocked_response(query, blocking_mode, blocking_ttl);
    blocked_resp.metadata.id = query_id;
    blocked_resp
}

/// Splits TXT data into the 255-byte character-strings a DNS TXT record allows.
pub(super) fn txt_chunks(value: &str) -> Vec<String> {
    let mut chunks = Vec::new();
    let mut start = 0;
    while start < value.len() {
        let mut end = (start + 255).min(value.len());
        while end > start && !value.is_char_boundary(end) {
            end -= 1;
        }
        chunks.push(value[start..end].to_string());
        start = end;
    }
    if chunks.is_empty() {
        chunks.push(String::new());
    }
    chunks
}
