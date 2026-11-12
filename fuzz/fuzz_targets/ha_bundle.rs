#![no_main]

use libfuzzer_sys::fuzz_target;
use sito_ha::{ConfigBundle, sanitize_config_for_bundle};

// HA configuration bundle parsing and sanitization.
//
// A bundle is JSON with a nested TOML config document and structured
// clients/lists. The target parses both layers and runs the sanitizer that
// strips secrets before replication. Size is capped at 1 MiB because a real
// bundle is bounded by the HA wire message limit; larger input is rejected
// rather than materialized.
fuzz_target!(|data: &[u8]| {
    if data.len() > 1_048_576 {
        return;
    }
    let Ok(document) = std::str::from_utf8(data) else {
        return;
    };

    if let Ok(bundle) = ConfigBundle::from_json(document) {
        let sanitized = bundle.sanitized();
        let _ = sanitized.to_json();
        let _ = sanitize_config_for_bundle(&bundle.config_toml);
    }
});
