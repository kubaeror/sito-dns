#!/usr/bin/env python3
"""Regression fixtures for scripts/check_migration_guide.py."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import shutil
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_migration_guide.py"
DIFF_REL = "docs/2.0-public-api-diff.md"
GUIDE_REL = "docs/2.0-migration.md"


def _load(tmp: Path):
    spec = importlib.util.spec_from_file_location(
        f"check_migration_guide_fixture_{id(tmp)}", SCRIPT
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.ROOT = tmp
    module.DIFF_PATH = tmp / DIFF_REL
    module.GUIDE_PATH = tmp / GUIDE_REL
    return module


class MigrationCheckerFixture(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory(prefix="sito-migration-check-")
        self.root = Path(self._tmpdir.name)
        for rel in (DIFF_REL, GUIDE_REL):
            destination = self.root / rel
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / rel, destination)

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def run_checker(self, *args: str) -> tuple[int, str, str]:
        module = _load(self.root)
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = module.main(list(args))
        return code, stdout.getvalue(), stderr.getvalue()

    def guide_text(self) -> str:
        return (self.root / GUIDE_REL).read_text()

    def write_guide(self, text: str) -> None:
        (self.root / GUIDE_REL).write_text(text)

    def test_current_tree_passes(self) -> None:
        code, stdout, stderr = self.run_checker()
        self.assertEqual(code, 0, stderr)
        self.assertIn("migration guide OK", stdout)

    def test_missing_breaking_id_fails(self) -> None:
        text = self.guide_text()
        filtered = [
            line
            for line in text.splitlines()
            if not line.startswith("| BC-1 |")
        ]
        self.assertEqual(len(text.splitlines()) - 1, len(filtered))
        self.write_guide("\n".join(filtered) + "\n")

        code, _stdout, stderr = self.run_checker()
        self.assertEqual(code, 1)
        self.assertIn("BC-1", stderr)
        self.assertIn("migration step", stderr)

    def test_empty_migration_step_fails(self) -> None:
        text = self.guide_text()
        lines = []
        replaced = False
        for line in text.splitlines():
            if line.startswith("| BC-1 |") and not replaced:
                cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
                cells[2] = ""
                line = "| " + " | ".join(cells) + " |"
                replaced = True
            lines.append(line)
        self.assertTrue(replaced)
        self.write_guide("\n".join(lines) + "\n")

        code, _stdout, stderr = self.run_checker()
        self.assertEqual(code, 1)
        self.assertIn("BC-1", stderr)

    def test_duplicate_breaking_id_fails(self) -> None:
        text = self.guide_text()
        marker = next(line for line in text.splitlines() if line.startswith("| BC-1 |"))
        self.write_guide(text.replace(marker, marker + "\n" + marker, 1))

        code, _stdout, stderr = self.run_checker()
        self.assertEqual(code, 1)
        self.assertIn("duplicate", stderr.lower())

    def test_missing_guide_table_fails_closed(self) -> None:
        self.write_guide("# 2.0 Migration\n\nNo index here.\n")

        code, _stdout, stderr = self.run_checker("--github")
        self.assertEqual(code, 1)
        self.assertIn("migration guide check failed", stderr)

    def test_missing_diff_fails_closed(self) -> None:
        (self.root / DIFF_REL).unlink()

        code, _stdout, stderr = self.run_checker("--github")
        self.assertEqual(code, 1)
        self.assertIn("migration guide check failed", stderr)

    def test_github_output_is_concise(self) -> None:
        text = self.guide_text()
        filtered = [
            line
            for line in text.splitlines()
            if not line.startswith("| BC-2 |")
        ]
        self.write_guide("\n".join(filtered) + "\n")

        code, stdout, stderr = self.run_checker("--github")
        self.assertEqual(code, 1)
        errors = [
            line
            for line in (stdout + "\n" + stderr).splitlines()
            if line.startswith("::error::")
        ]
        self.assertEqual(len(errors), 1, stdout + stderr)
        self.assertNotIn("Traceback", stdout + stderr)


if __name__ == "__main__":
    unittest.main()
