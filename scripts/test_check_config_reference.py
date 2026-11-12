#!/usr/bin/env python3
"""Regression fixtures for scripts/check_config_reference.py.

Each test copies the checker inputs into a temporary tree, mutates one piece of
documentation or the checked-in v1->v2 map, and asserts that the checker fails
closed with a focused message. The checker itself is imported (not executed in
a subprocess) so its module-level paths can be pointed at the fixture tree.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_config_reference.py"
DOC_REL = "docs/configuration-reference.md"
MAP_REL = "crates/sito-core/config-v1-to-v2-map.toml"
INPUTS = (
    DOC_REL,
    MAP_REL,
    "crates/sito-core/src/config/schema.rs",
    "crates/sito-clients/src/config.rs",
    "crates/sito-clients/src/routeros.rs",
    "crates/sito-clients/src/runtime_lists.rs",
    "crates/sito-rewrites/src/config.rs",
    "crates/sito-ha/src/config.rs",
)


def _load_checker(tmp: Path):
    spec = importlib.util.spec_from_file_location(
        f"check_config_reference_fixture_{id(tmp)}", SCRIPT
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.ROOT = tmp
    module.DOC = tmp / DOC_REL
    module.MAP_PATH = tmp / MAP_REL
    return module


class CheckerFixture(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory(prefix="sito-config-check-")
        self.root = Path(self._tmpdir.name)
        for rel in INPUTS:
            destination = self.root / rel
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / rel, destination)

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def run_checker(self, *args: str) -> tuple[int, str, str]:
        module = _load_checker(self.root)
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = module.main(list(args))
        return code, stdout.getvalue(), stderr.getvalue()

    def mutate_doc(self, old: str, new: str) -> None:
        path = self.root / DOC_REL
        text = path.read_text()
        self.assertIn(old, text, "fixture row must exist before it can be mutated")
        path.write_text(text.replace(old, new, 1))

    def insert_doc_line_after(self, prefix: str, new_line: str) -> None:
        path = self.root / DOC_REL
        lines = path.read_text().splitlines()
        index = next(
            (i for i, line in enumerate(lines) if line.startswith(prefix)), None
        )
        self.assertIsNotNone(index, f"fixture line starting with {prefix!r} must exist")
        lines.insert(index + 1, new_line)
        path.write_text("\n".join(lines) + "\n")

    def mutate_map(self, addition: str) -> None:
        path = self.root / MAP_REL
        path.write_text(path.read_text() + addition)

    # --- baseline ---------------------------------------------------------

    def test_current_tree_passes(self) -> None:
        code, stdout, stderr = self.run_checker()
        self.assertEqual(code, 0, stderr)
        self.assertIn("configuration reference OK", stdout)

    # --- nested struct coverage ------------------------------------------

    def test_missing_nested_key_fails(self) -> None:
        path = self.root / DOC_REL
        lines = path.read_text().splitlines()
        filtered = [line for line in lines if not line.startswith("| `sni_certs.key` |")]
        self.assertEqual(len(lines) - 1, len(filtered), "sni_certs.key row must exist")
        path.write_text("\n".join(filtered) + "\n")

        code, _stdout, stderr = self.run_checker()
        self.assertEqual(code, 1)
        self.assertIn("sni_certs.key", stderr)

    def test_wrong_nested_default_fails(self) -> None:
        self.mutate_doc(
            "| `entries.use_global_upstreams` | boolean | `true` |",
            "| `entries.use_global_upstreams` | boolean | `false` |",
        )

        code, _stdout, stderr = self.run_checker()
        self.assertEqual(code, 1)
        self.assertIn("entries.use_global_upstreams", stderr)
        self.assertIn("default", stderr)

    def test_wrong_nested_type_fails(self) -> None:
        self.mutate_doc(
            "| `entries.ids` | array of strings | `[]` |",
            "| `entries.ids` | integer | `[]` |",
        )

        code, _stdout, stderr = self.run_checker()
        self.assertEqual(code, 1)
        self.assertIn("entries.ids", stderr)
        self.assertIn("typed", stderr)

    def test_required_nested_field_is_checked(self) -> None:
        self.mutate_doc(
            "| `entries.name` | string | required |",
            "| `entries.name` | string | `None` |",
        )

        code, _stdout, stderr = self.run_checker()
        self.assertEqual(code, 1)
        self.assertIn("entries.name", stderr)

    # --- v1->v2 map / legacy allowlists ----------------------------------

    def test_documented_key_without_struct_or_map_entry_fails(self) -> None:
        self.insert_doc_line_after(
            "| `entries.id` |",
            "| `entries.made_up` | string | `None` | Fixture-only key. |",
        )

        code, _stdout, stderr = self.run_checker()
        self.assertEqual(code, 1)
        self.assertIn("entries.made_up", stderr)

    def test_unknown_kept_map_path_is_not_documented(self) -> None:
        self.mutate_map(
            "\n[[field]]\npath = \"clients.made_up\"\nstatus = \"kept\"\n"
        )

        code, _stdout, stderr = self.run_checker()
        self.assertEqual(code, 1)
        self.assertIn("clients.made_up", stderr)

    def test_deprecated_target_must_be_a_documented_kept_key(self) -> None:
        path = self.root / MAP_REL
        text = path.read_text().replace(
            'to = "acme.enabled"', 'to = "acme.does_not_exist"', 1
        )
        path.write_text(text)

        code, _stdout, stderr = self.run_checker()
        self.assertEqual(code, 1)
        self.assertIn("acme.does_not_exist", stderr)

    # --- fail closed / CI output -----------------------------------------

    def test_corrupt_map_fails_closed(self) -> None:
        (self.root / MAP_REL).write_text("[[field]\npath = \"broken\"\n")

        code, _stdout, stderr = self.run_checker("--github")
        self.assertEqual(code, 1)
        self.assertIn("configuration reference check failed", stderr)

    def test_missing_doc_fails_closed(self) -> None:
        (self.root / DOC_REL).unlink()

        code, _stdout, stderr = self.run_checker("--github")
        self.assertEqual(code, 1)
        self.assertIn("configuration reference check failed", stderr)

    def test_github_output_is_concise(self) -> None:
        self.mutate_doc(
            "| `entries.ids` | array of strings | `[]` |",
            "| `entries.ids` | integer | `[]` |",
        )

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
