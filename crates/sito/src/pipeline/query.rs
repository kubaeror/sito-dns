//! Query/response helpers: deadlines, flags, ECS, and cache keys.

#[allow(clippy::wildcard_imports)]
use super::*;

/// Maximum wall-clock time the pipeline spends on DNSSEC validation and its
/// DNSKEY/DS chain fetches for one query.
///
/// The fetcher performs network I/O and an upstream can stall a response (or
/// an attacker can black-hole DS/DNSKEY queries). A bound here keeps one query
/// from pinning a worker for the upstream timeout times the chain depth.
pub(super) const DNSSEC_VALIDATION_DEADLINE: std::time::Duration =
    std::time::Duration::from_secs(5);

/// Validates a response under a hard wall-clock deadline.
///
/// On timeout strict (`Validate`) mode fails closed with SERVFAIL (never an
/// unvalidated answer), while `LogOnly` keeps the response without AD, and
/// `Disabled` never calls this helper.
pub(super) async fn validate_dnssec_with_deadline(
    validator: &DnssecValidator,
    response: &mut Message,
    upstream: Option<&str>,
    now: u32,
    fetcher: &dyn sito_core::DnssecKeyFetcher,
    deadline: std::time::Duration,
) -> sito_dnssec::ValidationOutcome {
    use sito_dnssec::{DnssecMode, ValidationOutcome};

    // The chain walk appends fetched DNSKEY/DS helpers to the response. If the
    // future is cancelled on timeout, drop anything it already appended so
    // unvalidated helper records cannot leak to the client (or into a log-only
    // cached response).
    let original_additionals = response.additionals.len();
    if let Ok(outcome) = tokio::time::timeout(
        deadline,
        validator.validate_with_key_fetcher(response, upstream, now, fetcher),
    )
    .await
    {
        return outcome;
    }
    response.additionals.truncate(original_additionals);

    response.metadata.authentic_data = false;
    if validator.mode == DnssecMode::Validate {
        response.metadata.response_code = ResponseCode::ServFail;
        response.answers.clear();
        sito_dnssec::apply_ede(
            response,
            sito_dnssec::EDE_DNSSEC_BOGUS,
            "DNSSEC validation timed out",
        );
        let outcome = ValidationOutcome::Bogus {
            reason: "DNSSEC validation timed out".to_string(),
            ede_code: sito_dnssec::EDE_DNSSEC_BOGUS,
        };
        validator.metrics.record_validation(&outcome);
        outcome
    } else {
        let outcome = ValidationOutcome::Indeterminate;
        validator.metrics.record_validation(&outcome);
        outcome
    }
}

/// Copies the query-derived metadata (ID/opcode are set by the caller) that
/// every synthesized or error response must echo: RD, CD, the question and a
/// minimal OPT record with the client's DO bit.
pub(super) fn copy_query_response_flags(response: &mut Message, query: &Message) {
    response.metadata.recursion_desired = query.metadata.recursion_desired;
    response.metadata.recursion_available = true;
    response.metadata.checking_disabled = query.metadata.checking_disabled;
    response.queries.clone_from(&query.queries);
    if let Some(client_edns) = &query.edns {
        let mut edns = Edns::new();
        edns.set_max_payload(client_edns.max_payload());
        edns.set_dnssec_ok(client_edns.flags().dnssec_ok);
        response.set_edns(edns);
    }
}

/// Builds an error/synthesized response that preserves the query's opcode,
/// question, CD bit and EDNS/DO signalling.
pub(super) fn error_response(query: &Message, response_code: ResponseCode) -> Message {
    let mut response = Message::new(
        query.metadata.id,
        MessageType::Response,
        query.metadata.op_code,
    );
    response.metadata.response_code = response_code;
    copy_query_response_flags(&mut response, query);
    response
}

/// Masks the host bits of an address so the cache key and the forwarded ECS
/// option describe the same network prefix.
pub(super) fn truncate_ip(addr: IpAddr, prefix: u8) -> IpAddr {
    match addr {
        IpAddr::V4(v4) if prefix < 32 => {
            let mask = u32::MAX << (32 - u32::from(prefix));
            IpAddr::V4((u32::from(v4) & mask).into())
        }
        IpAddr::V6(v6) if prefix < 128 => {
            let mask = u128::MAX << (128 - u32::from(prefix));
            IpAddr::V6((u128::from(v6) & mask).into())
        }
        other => other,
    }
}

/// Applies the configured ECS policy to an outbound/cache query.
///
/// `off` removes the client's ECS option entirely (privacy-preserving and
/// cache-friendly); `forward` validates the prefix, clamps it to /24 (IPv4)
/// or /56 (IPv6), clears the scope and zeroes host bits. A zero-length source
/// prefix (RFC 7871 opt-out) is never forwarded.
pub(super) fn apply_ecs_policy(query: &mut Message, policy: UpstreamEcs) {
    let Some(edns) = query.edns.as_mut() else {
        return;
    };
    let subnet = match edns.option(EdnsCode::Subnet).cloned() {
        Some(EdnsOption::Subnet(subnet)) => Some(subnet),
        _ => None,
    };
    edns.options_mut().remove(EdnsCode::Subnet);
    if policy == UpstreamEcs::Off {
        return;
    }
    let Some(subnet) = subnet else {
        return;
    };
    if subnet.source_prefix() == 0 {
        return;
    }
    let (max_prefix, bits) = match subnet.addr() {
        IpAddr::V4(_) => (24u8, 32u8),
        IpAddr::V6(_) => (56u8, 128u8),
    };
    let prefix = subnet.source_prefix().min(max_prefix).min(bits);
    if prefix == 0 {
        return;
    }
    let clamped = ClientSubnet::new(truncate_ip(subnet.addr(), prefix), prefix, 0);
    edns.options_mut().insert(EdnsOption::Subnet(clamped));
}

/// Builds the query used for cache lookups/inserts: the client's DO/CD/opcode
/// flags plus the ECS actually forwarded upstream (`off` deduplicates keys,
/// `forward` keys on the clamped subnet).
pub(super) fn build_cache_query(query: &Message, config: &Config) -> Message {
    let mut cache_query = query.clone();
    apply_ecs_policy(&mut cache_query, config.upstream.ecs);
    cache_query
}

/// Builds the query sent upstream, optionally forcing DO so validation has
/// signatures to check.
pub(super) fn build_upstream_query(
    query: &Message,
    config: &Config,
    force_dnssec: bool,
) -> Message {
    let mut upstream_query = query.clone();
    if force_dnssec {
        let mut edns = upstream_query.edns.clone().unwrap_or_default();
        edns.set_dnssec_ok(true);
        edns.set_max_payload(config.dns.edns_udp_size.max(1232));
        upstream_query.set_edns(edns);
    }
    apply_ecs_policy(&mut upstream_query, config.upstream.ecs);
    upstream_query
}

/// Maps a DNSSEC validation outcome onto the status stored in the cache.
pub(super) fn validation_status(
    outcome: Option<&sito_dnssec::ValidationOutcome>,
) -> ValidationStatus {
    match outcome {
        Some(sito_dnssec::ValidationOutcome::Secure) => ValidationStatus::Secure,
        Some(
            sito_dnssec::ValidationOutcome::Insecure | sito_dnssec::ValidationOutcome::NtaBypass,
        ) => ValidationStatus::Insecure,
        Some(
            sito_dnssec::ValidationOutcome::Indeterminate
            | sito_dnssec::ValidationOutcome::Bogus { .. },
        ) => ValidationStatus::Indeterminate,
        None => ValidationStatus::Unchecked,
    }
}

/// Whether a cached entry may be served while local validation is active.
///
/// `Unchecked` entries (CD=1 / validation disabled) must never be served when
/// a CD=0 query expects the resolver to have validated the answer.
/// `Indeterminate` is not an authenticated decision either: in log-only mode a
/// Bogus result is recorded that way, and strict mode answers it with SERVFAIL
/// rather than serving the data. Only an authenticated `Secure`/`Insecure`
/// decision may be served; both are returned with AD cleared when not
/// `Secure`.
pub(super) fn cache_entry_servable(status: ValidationStatus, validation_active: bool) -> bool {
    !validation_active
        || matches!(
            status,
            ValidationStatus::Secure | ValidationStatus::Insecure
        )
}

/// Whether a *stale* (RFC 8767) entry may be served while local validation is
/// active.
///
/// Stale answers are not revalidated, so only authenticated cache decisions
/// (`Secure`/`Insecure`) may be served. An `Indeterminate` entry is
/// inconclusive by definition — in log-only mode even Bogus data is recorded
/// that way — and `Unchecked` means no local validation ran at all. Neither
/// may be handed to a CD=0 client that relies on the resolver. Stale answers
/// are always sanitized to AD=0 before they leave the cache.
pub(super) fn stale_cache_entry_servable(
    status: ValidationStatus,
    validation_active: bool,
) -> bool {
    !validation_active
        || matches!(
            status,
            ValidationStatus::Secure | ValidationStatus::Insecure
        )
}
