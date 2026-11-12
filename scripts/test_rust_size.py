#!/usr/bin/env python3
"""Regression tests for scripts/rust_size.py and the two size checkers.

The fixtures pin the cfg(test) forms that previously let a production file
hide behind comments/strings. Large threshold cases are generated here so the
repository does not need 2,001-line fixture files.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "scripts" / "fixtures" / "rust-size"
RUST_SIZE = ROOT / "scripts" / "rust_size.py"

sys.path.insert(0, str(ROOT / "scripts"))
import rust_size as size  # noqa: E402


def fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def production_lines(source: str) -> int:
    _, spans = size.production_source(source)
    return size.production_line_count(source, spans)


def write_lib(root: Path, source: str) -> Path:
    path = root / "crates" / "fixture" / "src" / "lib.rs"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source, encoding="utf-8")
    return path


def run_checker(mode: str, root: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(RUST_SIZE), mode, "--root", str(root)],
        text=True,
        capture_output=True,
        check=False,
    )


class CfgTestForms(unittest.TestCase):
    def test_attribute_in_comment_is_not_a_test_item(self) -> None:
        source = fixture("comment_attribute.rs")
        self.assertEqual(production_lines(source), len(source.splitlines()))

    def test_attribute_in_string_is_not_a_test_item(self) -> None:
        source = fixture("string_attribute.rs")
        self.assertEqual(production_lines(source), len(source.splitlines()))

    def test_inner_attribute_in_comment_does_not_zero_the_file(self) -> None:
        source = fixture("inner_attr_comment.rs")
        self.assertFalse(size.has_file_test_gate(size.mask_rust(source)))
        self.assertEqual(production_lines(source), len(source.splitlines()))

    def test_inner_attribute_in_string_does_not_zero_the_file(self) -> None:
        source = fixture("inner_attr_string.rs")
        self.assertFalse(size.has_file_test_gate(size.mask_rust(source)))
        self.assertEqual(production_lines(source), len(source.splitlines()))

    def test_real_test_module_is_excluded(self) -> None:
        source = fixture("real_test_module.rs")
        self.assertLess(production_lines(source), len(source.splitlines()))
        production, _ = size.production_source(source)
        names = {function.name for function in size.find_functions(production)}
        self.assertEqual(names, {"production"})

    def test_cfg_test_if_and_match_blocks_do_not_hide_following_functions(self) -> None:
        for name in ("cfg_if_block.rs", "cfg_match_block.rs"):
            source = fixture(name)
            production, _ = size.production_source(source)
            functions = {function.name: function for function in size.find_functions(production)}
            self.assertIn("after_block", functions, name)
            self.assertLessEqual(functions["production"].line_count, 10, name)
            self.assertLessEqual(functions["after_block"].line_count, 4, name)


class Thresholds(unittest.TestCase):
    def test_comment_and_string_cannot_hide_a_2001_line_file(self) -> None:
        pad = "// production filler\n"
        for name in (
            "comment_attribute.rs",
            "string_attribute.rs",
            "inner_attr_comment.rs",
            "inner_attr_string.rs",
        ):
            with self.subTest(fixture=name), tempfile.TemporaryDirectory() as temp:
                source = fixture(name)
                lines = source.splitlines()
                source = pad * max(0, 2001 - len(lines)) + source
                root = Path(temp)
                write_lib(root, source)
                violations = size.file_size_violations(2000, root)
                self.assertEqual(len(violations), 1, name)
                result = run_checker("files", root)
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)

    def test_real_test_module_can_exceed_2000_total_lines(self) -> None:
        filler = "    // test-only filler\n"
        source = (
            "pub fn production() -> u32 {\n    1\n}\n\n#[cfg(test)]\nmod tests {\n"
            + filler * 2200
            + "}\n"
        )
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_lib(root, source)
            self.assertEqual(size.file_size_violations(2000, root), [])
            result = run_checker("files", root)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_file_threshold_is_strictly_greater_than_2000(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_lib(root, "// filler\n" * 2000)
            self.assertEqual(size.file_size_violations(2000, root), [])
            self.assertEqual(run_checker("files", root).returncode, 0)
            write_lib(root, "// filler\n" * 2001)
            self.assertEqual(len(size.file_size_violations(2000, root)), 1)
            self.assertEqual(run_checker("files", root).returncode, 1)

    def test_src_tests_module_is_excluded_only_when_parent_gated(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            lib = write_lib(root, "pub fn production() -> u32 { 1 }\n")
            tests = root / "crates" / "fixture" / "src" / "tests" / "mod.rs"
            tests.parent.mkdir(parents=True)
            tests.write_text("// test filler\n" * 2101, encoding="utf-8")
            self.assertEqual(len(size.file_size_violations(2000, root)), 1)
            self.assertEqual(run_checker("files", root).returncode, 1)

            lib.write_text("#[cfg(test)]\nmod tests;\n", encoding="utf-8")
            self.assertEqual(size.file_size_violations(2000, root), [])
            self.assertEqual(run_checker("files", root).returncode, 0)

    def test_cargo_test_target_is_excluded(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_lib(root, "pub fn production() -> u32 { 1 }\n")
            integration = root / "crates" / "fixture" / "tests" / "conformance.rs"
            integration.parent.mkdir(parents=True)
            integration.write_text("// integration filler\n" * 2101, encoding="utf-8")
            self.assertEqual(size.file_size_violations(2000, root), [])
            self.assertEqual(run_checker("files", root).returncode, 0)

    def test_function_threshold_is_strictly_greater_than_200(self) -> None:
        def function(filler: int) -> str:
            return "pub fn big() -> u32 {\n" + "    // filler\n" * filler + "    1\n}\n"

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_lib(root, function(197))  # 200 lines inclusive
            self.assertEqual(size.function_violations(200, root), [])
            self.assertEqual(run_checker("functions", root).returncode, 0)
            write_lib(root, function(198))  # 201 lines inclusive
            self.assertEqual(len(size.function_violations(200, root)), 1)
            self.assertEqual(run_checker("functions", root).returncode, 1)
            docs = root / "docs"
            docs.mkdir()
            (docs / "large-functions.md").write_text(
                "| Function | File | Lines | Reason |\n"
                "|---|---|---|---|\n"
                "| `big` | `crates/fixture/src/lib.rs` | 201 | fixture |\n",
                encoding="utf-8",
            )
            self.assertEqual(run_checker("functions", root).returncode, 0)


if __name__ == "__main__":
    unittest.main()
