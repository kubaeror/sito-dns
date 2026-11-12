#![no_main]

use libfuzzer_sys::fuzz_target;
use sito_filter::parser::{compute_canonical, parse_line};

// ABP/hosts parser and canonicalizer on arbitrary text.
//
// The budgets mirror the parser's hostile-input limits: a single line over
// 4 KiB or a document over 8 KiB is rejected before parsing, so the target
// never materializes data the production parser would refuse.
fuzz_target!(|data: &[u8]| {
    if data.len() > 8_192 {
        return;
    }
    let Ok(line) = std::str::from_utf8(data) else {
        return;
    };
    if line.len() > 4_096 {
        return;
    }

    if let Some(rule) = parse_line(line, "fuzz", 1) {
        let canonical = compute_canonical(rule.kind, &rule.pattern, &rule.modifiers);
        std::hint::black_box(canonical);
    }
});
