#!/usr/bin/env python3
"""Regression fixtures for scripts/check_test_matrix.py."""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CHECKER = ROOT / "scripts" / "check_test_matrix.py"


def write_fixture(root: Path, rows: list[str]) -> None:
    (root / "docs").mkdir(parents=True)
    header = "| ID | Named test / check | Focused command |\n|---|---|---|\n"
    (root / "docs" / "audit6-test-matrix.md").write_text(
        header + "\n".join(rows) + "\n", encoding="utf-8"
    )


def run_checker(root: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(CHECKER), "--root", str(root)],
        text=True,
        capture_output=True,
        check=False,
    )


class TestMatrixCheck(unittest.TestCase):
    def test_accepts_a_test_function_and_script(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_fixture(
                root,
                [
                    "| P0-1 | `test_present`, `scripts/present.sh` | `cargo test -p demo` |",
                ],
            )
            (root / "crates" / "demo" / "src").mkdir(parents=True)
            (root / "crates" / "demo" / "src" / "lib.rs").write_text(
                "fn test_present() {}\n", encoding="utf-8"
            )
            (root / "scripts").mkdir()
            (root / "scripts" / "present.sh").write_text("#!/bin/sh\n", encoding="utf-8")

            result = run_checker(root)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("named tests/checks resolve", result.stdout)

    def test_rejects_a_renamed_test(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_fixture(root, ["| P1-1 | `test_removed_name` | `cargo test` |"])
            (root / "crates" / "demo" / "src").mkdir(parents=True)
            (root / "crates" / "demo" / "src" / "lib.rs").write_text(
                "fn test_actual_name() {}\n", encoding="utf-8"
            )

            result = run_checker(root)
            self.assertEqual(result.returncode, 1)
            self.assertIn("missing test or fixture: test_removed_name", result.stderr)

    def test_rejects_a_missing_script(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_fixture(root, ["| P1-2 | `scripts/missing.sh` | `bash scripts/missing.sh` |"])
            (root / "scripts").mkdir()

            result = run_checker(root)
            self.assertEqual(result.returncode, 1)
            self.assertIn("missing path: scripts/missing.sh", result.stderr)

    def test_ignores_commands_wildcards_and_path_anchors(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_fixture(
                root,
                [
                    "| P2-1 | `test_readiness_*`, `cargo test -p demo` | `cargo test` |",
                    "| P2-2 | `scripts/present.sh#anchor` | `bash scripts/present.sh` |",
                ],
            )
            (root / "scripts").mkdir()
            (root / "scripts" / "present.sh").write_text("#!/bin/sh\n", encoding="utf-8")

            result = run_checker(root)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
