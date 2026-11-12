#![no_main]

use libfuzzer_sys::fuzz_target;
use sito_dnssec::{DnssecMode, DnssecValidator};
use sito_proto::decode_message;

// DNSSEC validator input path on an arbitrary DNS response.
//
// No network access: `validate_response` is the synchronous pre-fetch entry
// point. It exercises message parsing, relevant-RRSIG/DNSKEY collection,
// signature evidence, and — when the input carries a verifiable chain — the
// NSEC/NSEC3 denial evaluator. Both strict and log-only modes are covered so
// a malformed response cannot panic in either result mapping.
fuzz_target!(|data: &[u8]| {
    if data.len() > 65_535 || data.len() < 12 {
        return;
    }

    let Ok(response) = decode_message(data) else {
        return;
    };

    for mode in [DnssecMode::Validate, DnssecMode::LogOnly] {
        let validator = DnssecValidator::new(mode, Vec::new());
        let mut candidate = response.clone();
        let _ = validator.validate_response(&mut candidate, Some("fuzz"), 1_700_000_000);
    }
});
