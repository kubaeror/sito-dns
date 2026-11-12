#!/usr/bin/env python3
"""Regression tests for scripts/check-fuzz-targets.py.

The checker is the fast PR-side half of the fuzz mechanism: cargo-fuzz builds
the targets in the `fuzz-build` CI job, while this test/checker catches a
missing manifest entry, target source, seed corpus, or gitignore rule without
installing cargo-fuzz.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CHECKER = ROOT / "scripts" / "check-fuzz-targets.py"

TARGETS = ("dns_wire", "abp_parser", "dnssec_response", "ha_bundle", "config_toml")


def manifest(targets: tuple[str, ...]) -> str:
    bins = "\n".join(
        f'[[bin]]\nname = "{name}"\npath = "fuzz_targets/{name}.rs"\ntest = false\ndoc = false\n'
        for name in targets
    )
    return (
        '[package]\nname = "sito-fuzz"\nversion = "0.0.0"\n'
        'edition = "2024"\npublish = false\n\n'
        "[package.metadata]\ncargo-fuzz = true\n\n"
        "[dependencies]\nlibfuzzer-sys = \"0.4\"\n\n"
        f"{bins}\n[workspace]\n"
    )


def build_fixture(root: Path, targets: tuple[str, ...] = TARGETS) -> None:
    fuzz = root / "fuzz"
    (fuzz / "fuzz_targets").mkdir(parents=True)
    (fuzz / "corpus").mkdir()
    (fuzz / "dictionaries").mkdir()
    (fuzz / "Cargo.toml").write_text(manifest(targets), encoding="utf-8")
    (fuzz / ".gitignore").write_text(
        "target/\nartifacts/\ncoverage/\ncorpus/**/*\n!corpus/**/\n!corpus/**/seed-*\n",
        encoding="utf-8",
    )
    for name in targets:
        if name == "dns_wire":
            source = (
                "use libfuzzer_sys::fuzz_target;\n"
                "use sito_proto::{decode_message, encode_message};\n"
                "fuzz_target!(|data: &[u8]| {\n"
                "    let Ok(message) = decode_message(data) else { return; };\n"
                "    let encoded = encode_message(&message)\n"
                '        .expect("decoded message must re-encode");\n'
                "    decode_message(&encoded)\n"
                '        .expect("encoded message must re-decode");\n'
                "});\n"
            )
        else:
            source = (
                "use libfuzzer_sys::fuzz_target;\n"
                "fuzz_target!(|_data: &[u8]| {});\n"
            )
        (fuzz / "fuzz_targets" / f"{name}.rs").write_text(source, encoding="utf-8")
        seed_dir = fuzz / "corpus" / name
        seed_dir.mkdir()
        (seed_dir / "seed-0001").write_bytes(b"seed\n")
    for dictionary in ("dns_wire", "abp_parser", "ha_bundle", "config_toml"):
        (fuzz / "dictionaries" / f"{dictionary}.dict").write_text(
            '"seed"\n', encoding="utf-8"
        )


def run_checker(root: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(CHECKER), "--root", str(root)],
        text=True,
        capture_output=True,
        check=False,
    )


class FuzzTargetCheck(unittest.TestCase):
    def test_accepts_a_complete_fuzz_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)
            result = run_checker(root)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("5 fuzz targets", result.stdout)

    def test_rejects_a_missing_target_source(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)
            (root / "fuzz" / "fuzz_targets" / "ha_bundle.rs").unlink()
            result = run_checker(root)
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertIn("ha_bundle", result.stdout)

    def test_rejects_a_missing_manifest_entry(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root, targets=TARGETS[:-1])
            result = run_checker(root)
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertIn("config_toml", result.stdout)

    def test_rejects_a_missing_seed_corpus(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)
            for seed in (root / "fuzz" / "corpus" / "abp_parser").iterdir():
                seed.unlink()
            result = run_checker(root)
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertIn("corpus/abp_parser", result.stdout)

    def test_rejects_an_untracked_seed_rule(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)
            (root / "fuzz" / ".gitignore").write_text(
                "target/\nartifacts/\ncoverage/\ncorpus/\n", encoding="utf-8"
            )
            result = run_checker(root)
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertIn("seed", result.stdout)

    def test_rejects_a_missing_dictionary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)
            (root / "fuzz" / "dictionaries" / "config_toml.dict").unlink()
            result = run_checker(root)
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertIn("config_toml.dict", result.stdout)

    def test_rejects_dns_wire_target_that_discards_the_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)
            (root / "fuzz" / "fuzz_targets" / "dns_wire.rs").write_text(
                "use libfuzzer_sys::fuzz_target;\n"
                "use sito_proto::{decode_message, encode_message};\n"
                "fuzz_target!(|data: &[u8]| {\n"
                "    let Ok(message) = decode_message(data) else { return; };\n"
                "    let Ok(encoded) = encode_message(&message) else { return; };\n"
                "    let _ = decode_message(&encoded);\n"
                "});\n",
                encoding="utf-8",
            )
            result = run_checker(root)
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertIn("must re-encode", result.stdout)
            self.assertIn("must re-decode", result.stdout)

    def test_rejects_an_empty_seed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)
            (root / "fuzz" / "corpus" / "dns_wire" / "seed-0001").write_bytes(b"")
            result = run_checker(root)
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertIn("empty seed", result.stdout)

    def test_rejects_a_malformed_dictionary_line(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)
            (root / "fuzz" / "dictionaries" / "dns_wire.dict").write_text(
                '"ok"\n"unterminated\n', encoding="utf-8"
            )
            result = run_checker(root)
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertIn("malformed dictionary", result.stdout)

    def test_rejects_an_empty_dictionary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)
            (root / "fuzz" / "dictionaries" / "dns_wire.dict").write_text(
                "# only a comment\n", encoding="utf-8"
            )
            result = run_checker(root)
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertIn("no dictionary tokens", result.stdout)

    def test_rejects_a_target_without_fuzz_target_macro(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)
            (root / "fuzz" / "fuzz_targets" / "dns_wire.rs").write_text(
                "fn main() {}\n", encoding="utf-8"
            )
            result = run_checker(root)
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertIn("fuzz_target!", result.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
