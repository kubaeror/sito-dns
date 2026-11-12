//! One client-facing response-shaping path for every DNS answer.
//!
//! A DNS response is an envelope (ID, opcode, question, RD/CD/DO/AD, OPT)
//! plus data. The data may come from the cache, a stale entry, an upstream, a
//! local rewrite or a synthesized block/search answer; the envelope must always
//! describe the *current* client query. Replaying a stored or upstream envelope
//! leaks another client's question case, RD/CD flags and EDNS options.

use hickory_proto::op::{Edns, Message, MessageType};
use hickory_proto::rr::rdata::opt::EdnsCode;
use hickory_proto::rr::{Record, RecordType};
use sito_core::DnssecMode;

/// UDP payload size advertised when no listener configuration is available.
///
/// The transport layer rewrites the OPT CLASS to `dns.edns_udp_size`; this
/// default keeps the shaping contract self-contained for embedders and tests.
pub const DEFAULT_EDNS_PAYLOAD: u16 = 1232;

/// Single response-shaping path shared by every query result.
pub struct ResponseShaper;

impl ResponseShaper {
    /// Shapes `response` for `client_query`.
    ///
    /// `dnssec_mode` decides whether an AD assertion can be meaningful:
    /// with validation disabled the resolver never proved anything, so AD is
    /// always cleared.
    pub fn shape(response: &mut Message, client_query: &Message, dnssec_mode: DnssecMode) {
        Self::shape_with_payload(response, client_query, dnssec_mode, DEFAULT_EDNS_PAYLOAD);
    }

    /// Shapes `response` and advertises `payload_size` as the resolver's UDP
    /// receive size in the OPT record.
    ///
    /// The envelope always comes from `client_query`; the response is treated
    /// as opaque data. That is what makes this safe for cache hits, stale
    /// entries, upstream answers, local rewrites and synthesized answers: none
    /// of them may replay a stored/upstream ID, question, RD/CD or OPT.
    pub fn shape_with_payload(
        response: &mut Message,
        client_query: &Message,
        dnssec_mode: DnssecMode,
        payload_size: u16,
    ) {
        response.metadata.id = client_query.metadata.id;
        response.metadata.op_code = client_query.metadata.op_code;
        response.metadata.message_type = MessageType::Response;
        // A recursive resolver is never authoritative for the answer, even
        // when the upstream/local source set AA. TC is left to the transport/
        // framing layer, which owns truncation for the negotiated payload.
        response.metadata.authoritative = false;
        response.metadata.recursion_desired = client_query.metadata.recursion_desired;
        response.metadata.recursion_available = true;
        response.metadata.checking_disabled = client_query.metadata.checking_disabled;
        response.queries.clone_from(&client_query.queries);

        let client_dnssec_ok = client_query
            .edns
            .as_ref()
            .is_some_and(|edns| edns.flags().dnssec_ok);

        // RFC 8914 Extended DNS Error is a non-client-specific diagnostic and
        // may survive shaping; every other upstream option is dropped. COOKIE,
        // ECS, NSID, padding and unknown options can be client- or
        // upstream-specific and must never cross a cache boundary.
        let extended_error = response.edns.as_ref().and_then(|edns| {
            edns.options()
                .options
                .iter()
                .find(|(code, _)| u16::from(*code) == 15)
                .map(|(_, option)| option.clone())
        });

        match &client_query.edns {
            Some(_) => {
                let mut edns = Edns::new();
                edns.set_max_payload(payload_size.max(512));
                edns.set_dnssec_ok(client_dnssec_ok);
                if let Some(option) = extended_error {
                    edns.options_mut().insert(option);
                }
                response.set_edns(edns);
            }
            // RFC 6891 §6.1.1: a response to a non-EDNS query must not carry
            // an OPT RR at all.
            None => response.edns = None,
        }

        // RFC 6840 §5.7: only a client that signalled DNSSEC awareness (DO or
        // AD) may receive AD. CD=1 means the client disabled validation, so it
        // must never be told the data was authenticated; a disabled resolver
        // never validated anything either.
        let client_accepts_ad = client_dnssec_ok || client_query.metadata.authentic_data;
        if dnssec_mode == DnssecMode::Disabled
            || !client_accepts_ad
            || client_query.metadata.checking_disabled
        {
            response.metadata.authentic_data = false;
        }

        // RFC 3225: DO=0 clients must not receive RRSIG/NSEC/NSEC3/DNSKEY
        // material (or the DO-only DAU/DHU/N3U options).
        if !client_dnssec_ok {
            strip_dnssec_records(response);
        }
    }
}

/// Strips DNSSEC records and DO-dependent EDNS options from a response.
///
/// RFC 3225: clients that did not set DO must not receive RRSIG/NSEC/NSEC3/
/// DNSKEY material. The same shaping is applied before such a response is
/// cached so a DO=0 cache entry never carries DNSSEC data.
pub fn strip_dnssec_records(response: &mut Message) {
    let is_dnssec_type = |record: &Record| {
        matches!(
            record.record_type(),
            RecordType::RRSIG | RecordType::NSEC | RecordType::NSEC3 | RecordType::DNSKEY
        )
    };
    response.answers.retain(|record| !is_dnssec_type(record));
    response
        .authorities
        .retain(|record| !is_dnssec_type(record));
    response
        .additionals
        .retain(|record| !is_dnssec_type(record));
    if let Some(edns) = response.edns.as_mut() {
        // DAU/DHU/N3U only make sense for DNSSEC-aware clients.
        for code in [EdnsCode::DAU, EdnsCode::DHU, EdnsCode::N3U] {
            edns.options_mut().remove(code);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{Edns, MessageType, OpCode, Query};
    use hickory_proto::rr::rdata::opt::{EdnsCode, EdnsOption};
    use hickory_proto::rr::rdata::{A, NULL};
    use hickory_proto::rr::{Name, RData, Record, RecordType};
    use std::net::Ipv4Addr;
    use std::str::FromStr;

    /// Builds a case-preserving name. `Name::from_str`/IDNA lowercases
    /// labels, which would hide a stored-vs-client question-case regression;
    /// wire labels preserve the bytes the client sent, so build them directly.
    fn mixed_name(name: &str) -> Name {
        let labels: Vec<Vec<u8>> = name
            .trim_end_matches('.')
            .split('.')
            .map(|label| label.as_bytes().to_vec())
            .collect();
        let mut name = Name::from_labels(labels).unwrap();
        name.set_fqdn(true);
        name
    }

    fn query(id: u16, name: &str, edns: Option<bool>, rd: bool, cd: bool) -> Message {
        let mut q = Message::new(id, MessageType::Query, OpCode::Query);
        q.queries
            .push(Query::query(mixed_name(name), RecordType::A));
        q.metadata.recursion_desired = rd;
        q.metadata.checking_disabled = cd;
        if let Some(do_bit) = edns {
            let mut e = Edns::new();
            e.set_max_payload(4096);
            e.set_dnssec_ok(do_bit);
            q.set_edns(e);
        }
        q
    }

    /// A response that looks like it came from a cache entry or an upstream:
    /// different ID/opcode/question/RD/CD/AA, AD possibly forged, and
    /// upstream-only EDNS options plus an EDE diagnostic.
    fn stored_response(ad: bool, tc: bool) -> Message {
        let stored_name = Name::from_str("stored.example.").unwrap();
        let mut r = Message::new(99, MessageType::Response, OpCode::Notify);
        r.metadata.authoritative = true;
        r.metadata.recursion_available = false;
        r.metadata.recursion_desired = false;
        r.metadata.checking_disabled = false;
        r.metadata.authentic_data = ad;
        r.metadata.truncation = tc;
        r.queries
            .push(Query::query(stored_name.clone(), RecordType::A));
        r.answers.push(Record::from_rdata(
            stored_name.clone(),
            300,
            RData::A(A(Ipv4Addr::new(192, 0, 2, 1))),
        ));
        r.answers.push(Record::from_rdata(
            stored_name,
            300,
            RData::Unknown {
                code: RecordType::RRSIG,
                rdata: NULL::default(),
            },
        ));
        let mut edns = Edns::new();
        edns.set_max_payload(4096);
        edns.options_mut().insert(EdnsOption::Unknown(
            u16::from(EdnsCode::Cookie),
            vec![1, 2, 3, 4],
        ));
        edns.options_mut()
            .insert(EdnsOption::Unknown(u16::from(EdnsCode::NSID), vec![b'x']));
        edns.options_mut()
            .insert(EdnsOption::Unknown(15, b"diagnostic".to_vec()));
        r.set_edns(edns);
        r
    }

    struct Case {
        do_bit: bool,
        cd: bool,
        edns: bool,
        mode: DnssecMode,
        ad_in: bool,
        ad_out: bool,
        opt: bool,
        rrsig: bool,
    }

    /// The DO/EDNS/CD/AD matrix required by WP-1.6. Every row asserts the
    /// complete client-facing envelope, not just a single flag.
    #[test]
    fn test_response_shaper_flag_matrix() {
        let cases = [
            Case {
                do_bit: false,
                cd: false,
                edns: false,
                mode: DnssecMode::Validate,
                ad_in: true,
                ad_out: false,
                opt: false,
                rrsig: false,
            },
            Case {
                do_bit: true,
                cd: false,
                edns: true,
                mode: DnssecMode::Validate,
                ad_in: true,
                ad_out: true,
                opt: true,
                rrsig: true,
            },
            Case {
                do_bit: false,
                cd: false,
                edns: true,
                mode: DnssecMode::Validate,
                ad_in: true,
                ad_out: false,
                opt: true,
                rrsig: false,
            },
            Case {
                do_bit: true,
                cd: true,
                edns: true,
                mode: DnssecMode::Validate,
                ad_in: true,
                ad_out: false,
                opt: true,
                rrsig: true,
            },
            Case {
                do_bit: true,
                cd: false,
                edns: true,
                mode: DnssecMode::Disabled,
                ad_in: true,
                ad_out: false,
                opt: true,
                rrsig: true,
            },
            Case {
                do_bit: false,
                cd: false,
                edns: true,
                mode: DnssecMode::LogOnly,
                ad_in: true,
                ad_out: false,
                opt: true,
                rrsig: false,
            },
            Case {
                do_bit: true,
                cd: false,
                edns: true,
                mode: DnssecMode::LogOnly,
                ad_in: true,
                ad_out: true,
                opt: true,
                rrsig: true,
            },
            Case {
                do_bit: true,
                cd: false,
                edns: true,
                mode: DnssecMode::Validate,
                ad_in: false,
                ad_out: false,
                opt: true,
                rrsig: true,
            },
        ];

        for case in cases {
            let q = query(
                42,
                "MiXeD.Example.",
                case.edns.then_some(case.do_bit),
                true,
                case.cd,
            );
            let mut response = stored_response(case.ad_in, false);

            ResponseShaper::shape(&mut response, &q, case.mode);

            assert_eq!(
                response.metadata.id, 42,
                "ID must come from the current query"
            );
            assert_eq!(response.metadata.op_code, OpCode::Query);
            assert_eq!(response.metadata.message_type, MessageType::Response);
            assert!(
                !response.metadata.authoritative,
                "a recursive resolver must not replay the stored AA bit"
            );
            assert!(response.metadata.recursion_available);
            assert!(
                response.metadata.recursion_desired,
                "RD must come from query"
            );
            assert_eq!(
                response.metadata.checking_disabled, case.cd,
                "CD must come from the current query"
            );
            assert_eq!(
                response.queries[0].name().to_ascii(),
                "MiXeD.Example.",
                "the current client question must be echoed, not the stored one"
            );
            assert_eq!(
                response.metadata.authentic_data, case.ad_out,
                "AD must follow the DNSSEC decision and client awareness"
            );
            assert_eq!(
                response.edns.is_some(),
                case.opt,
                "only an EDNS client may receive an OPT record"
            );
            assert_eq!(
                response
                    .answers
                    .iter()
                    .any(|record| record.record_type() == RecordType::RRSIG),
                case.rrsig,
                "DNSSEC records follow the client's DO bit"
            );
            if case.opt {
                let edns = response.edns.as_ref().expect("OPT present");
                assert_eq!(edns.flags().dnssec_ok, case.do_bit);
                assert_eq!(
                    edns.max_payload(),
                    DEFAULT_EDNS_PAYLOAD,
                    "the resolver advertises its own payload size"
                );
                let options: Vec<u16> = edns
                    .options()
                    .options
                    .iter()
                    .map(|(code, _)| u16::from(*code))
                    .collect();
                assert_eq!(
                    options,
                    vec![15],
                    "only the non-client-specific EDE option may survive"
                );
            }
        }
    }

    /// RFC 6840 §5.7: a client that sets AD (without DO) has signalled that
    /// it wants the authenticated flag, so it may receive AD.
    #[test]
    fn test_response_shaper_keeps_ad_for_client_that_requests_ad_without_do() {
        let mut q = query(5, "ad.example.", Some(false), false, false);
        q.metadata.authentic_data = true;
        let mut response = stored_response(true, false);

        ResponseShaper::shape(&mut response, &q, DnssecMode::Validate);

        assert!(
            response.metadata.authentic_data,
            "an AD-signalling client must not lose the resolver's AD assertion"
        );
    }

    /// The transport configures the resolver's UDP receive size; shaping must
    /// advertise that size rather than replaying the client's or upstream's.
    #[test]
    fn test_response_shaper_uses_configured_payload_size() {
        let q = query(9, "size.example.", Some(true), true, false);
        let mut response = stored_response(false, false);

        ResponseShaper::shape_with_payload(&mut response, &q, DnssecMode::Validate, 1400);

        assert_eq!(response.edns.as_ref().map(Edns::max_payload), Some(1400));
    }

    #[test]
    fn test_response_shaper_preserves_truncation() {
        let q = query(11, "tc.example.", Some(false), true, false);
        let mut response = stored_response(false, true);

        ResponseShaper::shape(&mut response, &q, DnssecMode::Validate);

        assert!(
            response.metadata.truncation,
            "TC is owned by the transport/framing layer and must not be cleared"
        );
    }

    #[test]
    fn test_strip_dnssec_records_removes_all_dnssec_types_and_do_only_options() {
        let name = Name::from_str("strip.example.").unwrap();
        let mut response = Message::response(1, OpCode::Query);
        response
            .queries
            .push(Query::query(name.clone(), RecordType::A));
        response.answers.push(Record::from_rdata(
            name.clone(),
            300,
            RData::A(A(Ipv4Addr::new(192, 0, 2, 2))),
        ));
        for record_type in [
            RecordType::RRSIG,
            RecordType::NSEC,
            RecordType::NSEC3,
            RecordType::DNSKEY,
        ] {
            response.answers.push(Record::from_rdata(
                name.clone(),
                300,
                RData::Unknown {
                    code: record_type,
                    rdata: NULL::default(),
                },
            ));
        }
        let mut edns = Edns::new();
        for code in [EdnsCode::DAU, EdnsCode::DHU, EdnsCode::N3U] {
            edns.options_mut()
                .insert(EdnsOption::Unknown(u16::from(code), vec![]));
        }
        edns.options_mut()
            .insert(EdnsOption::Unknown(u16::from(EdnsCode::Cookie), vec![1]));
        response.set_edns(edns);

        strip_dnssec_records(&mut response);

        assert_eq!(response.answers.len(), 1);
        assert_eq!(response.answers[0].record_type(), RecordType::A);
        let edns = response.edns.expect("OPT remains");
        for code in [EdnsCode::DAU, EdnsCode::DHU, EdnsCode::N3U] {
            assert!(
                edns.option(code).is_none(),
                "DO-dependent option {code:?} must be removed"
            );
        }
        assert!(
            edns.option(EdnsCode::Cookie).is_some(),
            "this helper only removes DO-dependent options; the shaper rebuilds OPT"
        );
    }

    /// A synthesized local rewrite or safe-search answer is constructed with
    /// the query's flags, but still goes through the shaper. Verify the final
    /// envelope (including OPT reconstruction) for that shape.
    #[test]
    fn test_synthesized_rewrite_and_safe_search_responses_are_shaped_for_client() {
        let q = query(77, "ReWrItE.Example.", Some(false), true, false);
        let mut rewrite = Message::response(1, OpCode::Query);
        rewrite.queries = q.queries.clone();
        rewrite.metadata.authoritative = true;
        rewrite.answers.push(Record::from_rdata(
            q.queries[0].name().clone(),
            60,
            RData::A(A(Ipv4Addr::new(10, 0, 0, 1))),
        ));
        // Simulate an upstream/rewrite path that attached a cookie.
        let mut edns = Edns::new();
        edns.options_mut()
            .insert(EdnsOption::Unknown(u16::from(EdnsCode::Cookie), vec![9]));
        rewrite.set_edns(edns);

        ResponseShaper::shape(&mut rewrite, &q, DnssecMode::Validate);

        assert_eq!(rewrite.metadata.id, 77);
        assert!(!rewrite.metadata.authoritative);
        assert_eq!(rewrite.queries[0].name().to_ascii(), "ReWrItE.Example.");
        let edns = rewrite.edns.expect("EDNS client keeps OPT");
        assert!(
            edns.options().options.is_empty(),
            "local paths must not replay client-specific options"
        );
    }

    #[test]
    fn test_safe_search_cname_response_is_shaped_for_client() {
        let q = query(78, "SaFe.YouTube.", Some(true), true, false);
        let mut safe_search = crate::wire::synthesize_cname_response(
            &q,
            &Name::from_str("restrict.youtube.com.").unwrap(),
            300,
        );
        // Simulate a synthesized path that marked AA or added an option.
        safe_search.metadata.authoritative = true;
        safe_search.metadata.id = 1;

        ResponseShaper::shape(&mut safe_search, &q, DnssecMode::Validate);

        assert_eq!(safe_search.metadata.id, 78);
        assert_eq!(safe_search.metadata.op_code, OpCode::Query);
        assert!(!safe_search.metadata.authoritative);
        assert!(safe_search.metadata.recursion_available);
        assert_eq!(safe_search.queries[0].name().to_ascii(), "SaFe.YouTube.");
        let edns = safe_search.edns.expect("EDNS client keeps OPT");
        assert!(edns.flags().dnssec_ok);
        assert!(
            edns.options().options.is_empty(),
            "a safe-search response must not replay EDNS options"
        );
    }
}
