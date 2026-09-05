#![no_main]

use libfuzzer_sys::fuzz_target;
use sito_clients::registry::{extract_id_from_sni, extract_id_from_url_path};

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = extract_id_from_sni(s);
        let _ = extract_id_from_url_path(s);
    }
});
