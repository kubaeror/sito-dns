#![no_main]

use libfuzzer_sys::fuzz_target;
use sito_dnssec::{DnssecMode, DnssecValidator};
use sito_proto::decode_message;

// Feeds arbitrary wire data into the DNSSEC verification layer. The validator
// must never panic on malformed DNSKEY/DS/RRSIG/NSEC records; bogus inputs may
// only produce validation outcomes.
fuzz_target!(|data: &[u8]| {
    let Ok(mut message) = decode_message(data) else {
        return;
    };
    let validator = DnssecValidator::new(DnssecMode::LogOnly, Vec::new());
    let _ = validator.validate_response(&mut message, Some("fuzz"), 1_700_000_000);
});
