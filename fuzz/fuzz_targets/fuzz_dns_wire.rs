#![no_main]

use libfuzzer_sys::fuzz_target;
use sito_proto::{decode_message, encode_message};

fuzz_target!(|data: &[u8]| {
    if let Ok(msg) = decode_message(data) {
        let _ = encode_message(&msg);
    }
});
