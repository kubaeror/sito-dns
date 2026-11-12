#![no_main]

use libfuzzer_sys::fuzz_target;
use sito_proto::{decode_message, encode_message};

// DNS wire decoder/encoder round-trip.
//
// Inputs are capped at the maximum UDP/TCP DNS message size so a single
// mutation cannot force a multi-megabyte allocation before the decoder's own
// bounds apply. A decode failure is a valid outcome; anything that panics or
// fails to re-encode/ re-decode is not.
fuzz_target!(|data: &[u8]| {
    if data.len() > 65_535 {
        return;
    }

    let Ok(message) = decode_message(data) else {
        return;
    };

    let encoded = encode_message(&message).expect("decoded message must re-encode");

    // The second decode proves the encoder produced a self-consistent message.
    // Some hickory fields normalize on decode, so byte equality is not asserted.
    decode_message(&encoded).expect("encoded message must re-decode");
});
