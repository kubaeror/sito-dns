#![no_main]

use libfuzzer_sys::fuzz_target;
use sito_filter::parser::parse_line;

fuzz_target!(|data: &[u8]| {
    if let Ok(line) = std::str::from_utf8(data) {
        let _ = parse_line(line, "fuzz", 1);
    }
});
