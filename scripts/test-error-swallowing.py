#!/usr/bin/env python3
"""Fixture tests for scripts/find-error-swallowing.py."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

SCANNER = Path(__file__).with_name("find-error-swallowing.py")
spec = importlib.util.spec_from_file_location("find_error_swallowing", SCANNER)
assert spec and spec.loader
scanner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scanner)


class ScannerTests(unittest.TestCase):
    def test_multiline_let_read_is_detected(self) -> None:
        source = """fn f() {
    let _ = tokio::fs::read_to_string(
        "/tmp/config.toml",
    )
    .await;
}
"""
        findings = scanner.scan_source(source)
        self.assertIn((2, "let _ = tokio::fs::read_to_string("), findings)

    def test_multiline_ok_chain_is_detected(self) -> None:
        source = """fn f() {
    let value = map
        .read()
        .ok();
}
"""
        findings = scanner.scan_source(source)
        self.assertTrue(
            any(text == ".read()" for _, text in findings),
            f"expected a read() finding, got {findings}",
        )

    def test_cfg_test_struct_field_does_not_hide_following_production(self) -> None:
        source = """struct S {
    #[cfg(test)]
    field: usize,
    value: usize,
}

fn f() {
    let _ = std::fs::read("/etc/sito/config.toml");
}
"""
        findings = scanner.scan_source(source)
        self.assertEqual(len(findings), 1, findings)
        self.assertIn("std::fs::read", findings[0][1])

    def test_cfg_test_module_is_skipped(self) -> None:
        source = """#[cfg(test)]
mod tests {
    fn f() {
        let _ = std::fs::remove_file("/tmp/x");
    }
}

fn g() {
    let _ = std::fs::remove_file("/tmp/y");
}
"""
        findings = scanner.scan_source(source)
        self.assertEqual(len(findings), 1, findings)
        self.assertIn("/tmp/y", findings[0][1])

    def test_formatting_macro_argument_is_not_flagged(self) -> None:
        source = """fn f() {
    let _ = writeln!(out, "{}", self.cache_hits.load(Ordering::Relaxed));
}
"""
        self.assertEqual(scanner.scan_source(source), [])

    def test_benign_function_call_is_not_flagged(self) -> None:
        source = """fn f() {
    let _ = something_benign(compute_value());
}
"""
        self.assertEqual(scanner.scan_source(source), [])

    def test_read_load_and_write_keywords(self) -> None:
        source = """fn f() {
    let _ = std::fs::read("/tmp/a");
    let _ = config.load();
    let _ = std::fs::write("/tmp/b", b"x");
}
"""
        findings = scanner.scan_source(source)
        self.assertEqual(len(findings), 3, findings)

    def test_comment_and_string_content_is_ignored(self) -> None:
        source = """fn f() {
    // let _ = std::fs::read("/tmp/a");
    let text = "let _ = std::fs::write(\\"/tmp/b\\")";
    let _ = something_benign(text);
}
"""
        self.assertEqual(scanner.scan_source(source), [])


if __name__ == "__main__":
    unittest.main()
