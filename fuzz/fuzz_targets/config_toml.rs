#![no_main]

use libfuzzer_sys::fuzz_target;
use sito_core::config::Config;

// Config v2 parser and validator on arbitrary TOML.
//
// `Config::from_toml_str` is the single production entry point: it rejects
// unknown keys, non-v2 documents and invalid cross-section values. Those
// errors are expected outcomes. The only failure is a panic.
fuzz_target!(|data: &[u8]| {
    if data.len() > 1_048_576 {
        return;
    }
    let Ok(document) = std::str::from_utf8(data) else {
        return;
    };

    let _ = Config::from_toml_str(document);
});
