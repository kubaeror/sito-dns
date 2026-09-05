#![no_main]

use libfuzzer_sys::fuzz_target;
use sito_core::config::Config;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = Config::from_toml_str(s);
    }
});
