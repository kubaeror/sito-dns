#![no_main]

use libfuzzer_sys::fuzz_target;
use sito_ha::{HaMessage, sanitize_config_for_bundle, substitute_secrets, verify_and_unpack_push};
use std::collections::HashMap;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    // Sanitization must never panic on arbitrary TOML-ish input.
    let _ = sanitize_config_for_bundle(text);

    // Secret substitution over arbitrary templates/values.
    let mut secrets = HashMap::new();
    secrets.insert("k".to_string(), "v".to_string());
    let _ = substitute_secrets(text, &secrets, true);
    let _ = substitute_secrets(text, &secrets, false);

    // Deserialization must never panic; signature verification must reject
    // everything when it cannot be verified, never panic.
    if let Ok(message) = HaMessage::from_json(text)
        && let HaMessage::ConfigPush { .. } = &message
    {
        let pubkey = [0u8; 32];
        let _ = verify_and_unpack_push(&message, 0, &pubkey);
    }
});
