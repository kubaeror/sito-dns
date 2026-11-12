#!/usr/bin/env python3
"""Regression tests for scripts/check-bench-regression.py.

The fixtures are synthetic Criterion ``estimates.json`` files, so the test
does not need a benchmark run. The gate itself is exercised through its CLI so
exit codes and the saved baseline format are pinned.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CHECKER = ROOT / "scripts" / "check-bench-regression.py"

sys.path.insert(0, str(ROOT / "scripts"))
import check_bench_regression as gate  # noqa: E402


def write_estimate(root: Path, benchmark: str, median_ns: float) -> Path:
    """Writes a minimal Criterion 0.8 estimates.json for ``benchmark``."""
    path = root / benchmark / "new" / "estimates.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "mean": {"point_estimate": median_ns * 1.01},
                "median": {
                    "confidence_interval": {
                        "confidence_level": 0.95,
                        "lower_bound": median_ns * 0.98,
                        "upper_bound": median_ns * 1.02,
                    },
                    "point_estimate": median_ns,
                    "standard_error": median_ns * 0.01,
                },
            }
        ),
        encoding="utf-8",
    )
    return path


def write_baseline(
    path: Path,
    benchmarks: dict[str, float],
    tolerance: float = 0.10,
    environment: str = "unit-test",
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "environment": {"description": environment},
                "tolerance": tolerance,
                "benchmarks": {
                    key: {"median_ns": value} for key, value in benchmarks.items()
                },
            }
        ),
        encoding="utf-8",
    )


def run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    argv = [sys.executable, str(CHECKER), *args]
    # Most cases run in the same synthetic environment. Tests that exercise
    # the environment guard pass their own --environment explicitly.
    if "--save" not in args and "--environment" not in args:
        argv.extend(["--environment", "unit-test"])
    return subprocess.run(argv, text=True, capture_output=True, check=False)


class ParseEstimates(unittest.TestCase):
    def test_nested_group_and_function_names_reach_the_baseline(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_estimate(root, "pipeline_stages/rewrite_wildcard_lookup", 120.0)
            write_estimate(root, "cache_hit_lookup", 400.0)

            estimates = gate.collect_estimates(root)

            self.assertEqual(
                estimates,
                {
                    "pipeline_stages::rewrite_wildcard_lookup": 120.0,
                    "cache_hit_lookup": 400.0,
                },
            )

    def test_bench_without_new_estimates_is_ignored(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_estimate(root, "group/bench", 10.0)
            stale = root / "group" / "other" / "base" / "estimates.json"
            stale.parent.mkdir(parents=True)
            stale.write_text('{"median": {"point_estimate": 1.0}}', encoding="utf-8")

            self.assertEqual(gate.collect_estimates(root), {"group::bench": 10.0})


class Compare(unittest.TestCase):
    def test_within_tolerance_passes(self) -> None:
        regressions, missing, new = gate.compare(
            {"a": 100.0}, {"a": 109.9}, tolerance=0.10
        )
        self.assertEqual((regressions, missing, new), ([], [], []))

    def test_exactly_at_tolerance_passes(self) -> None:
        regressions, _, _ = gate.compare({"a": 100.0}, {"a": 110.0}, tolerance=0.10)
        self.assertEqual(regressions, [])

    def test_above_tolerance_fails(self) -> None:
        regressions, _, _ = gate.compare({"a": 100.0}, {"a": 110.01}, tolerance=0.10)
        self.assertEqual(len(regressions), 1)
        self.assertEqual(regressions[0].benchmark, "a")
        self.assertAlmostEqual(regressions[0].change_pct, 10.01, places=2)

    def test_missing_benchmark_is_reported(self) -> None:
        _, missing, _ = gate.compare({"gone": 100.0}, {}, tolerance=0.10)
        self.assertEqual(missing, ["gone"])

    def test_new_benchmark_is_reported_but_not_a_regression(self) -> None:
        regressions, _, new = gate.compare({"old": 100.0}, {"old": 100.0, "new": 1.0})
        self.assertEqual(regressions, [])
        self.assertEqual(new, ["new"])

    def test_non_positive_baseline_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            gate.compare({"zero": 0.0}, {"zero": 1.0})


class Cli(unittest.TestCase):
    def test_check_fails_on_regression(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            estimates = root / "criterion"
            baseline = root / "baseline.json"
            write_estimate(estimates, "group/bench", 130.0)
            write_baseline(baseline, {"group::bench": 100.0})

            result = run_cli(
                "--estimates-dir",
                str(estimates),
                "--baseline",
                str(baseline),
            )

            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertIn("REGRESSION", result.stdout)

    def test_check_passes_and_reports_improvement(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            estimates = root / "criterion"
            baseline = root / "baseline.json"
            write_estimate(estimates, "group/bench", 80.0)
            write_baseline(baseline, {"group::bench": 100.0})

            result = run_cli(
                "--estimates-dir",
                str(estimates),
                "--baseline",
                str(baseline),
            )

            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("-20.00%", result.stdout)

    def test_missing_estimate_fails_by_default_and_can_be_allowed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            estimates = root / "criterion"
            baseline = root / "baseline.json"
            write_estimate(estimates, "group/present", 100.0)
            write_baseline(baseline, {"group::present": 100.0, "group::absent": 100.0})

            failed = run_cli(
                "--estimates-dir", str(estimates), "--baseline", str(baseline)
            )
            allowed = run_cli(
                "--estimates-dir",
                str(estimates),
                "--baseline",
                str(baseline),
                "--allow-missing",
            )

            self.assertEqual(failed.returncode, 1, failed.stdout + failed.stderr)
            self.assertIn("group::absent", failed.stdout)
            self.assertEqual(allowed.returncode, 0, allowed.stdout + allowed.stderr)

    def test_save_then_check_round_trips(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            estimates = root / "criterion"
            baseline = root / "baseline.json"
            write_estimate(estimates, "group/one", 100.0)
            write_estimate(estimates, "group/two", 200.0)

            saved = run_cli(
                "--estimates-dir",
                str(estimates),
                "--baseline",
                str(baseline),
                "--save",
                "--environment",
                "unit-test-runner",
            )
            checked = run_cli(
                "--estimates-dir",
                str(estimates),
                "--baseline",
                str(baseline),
                "--environment",
                "unit-test-runner",
            )

            self.assertEqual(saved.returncode, 0, saved.stdout + saved.stderr)
            payload = json.loads(baseline.read_text(encoding="utf-8"))
            self.assertEqual(payload["environment"]["description"], "unit-test-runner")
            self.assertEqual(payload["schema_version"], 1)
            self.assertEqual(
                payload["benchmarks"],
                {"group::one": {"median_ns": 100.0}, "group::two": {"median_ns": 200.0}},
            )
            self.assertEqual(checked.returncode, 0, checked.stdout + checked.stderr)

    def test_save_without_estimates_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            result = run_cli(
                "--estimates-dir",
                str(root / "missing"),
                "--baseline",
                str(root / "baseline.json"),
                "--save",
            )
            self.assertEqual(result.returncode, 2, result.stdout + result.stderr)

    def test_tolerance_input_is_a_fraction(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            estimates = root / "criterion"
            baseline = root / "baseline.json"
            write_estimate(estimates, "group/bench", 115.0)
            write_baseline(baseline, {"group::bench": 100.0})

            strict = run_cli(
                "--estimates-dir",
                str(estimates),
                "--baseline",
                str(baseline),
                "--tolerance",
                "0.10",
            )
            relaxed = run_cli(
                "--estimates-dir",
                str(estimates),
                "--baseline",
                str(baseline),
                "--tolerance",
                "0.20",
            )

            self.assertEqual(strict.returncode, 1, strict.stdout + strict.stderr)
            self.assertEqual(relaxed.returncode, 0, relaxed.stdout + relaxed.stderr)

    def test_baseline_tolerance_is_used_when_cli_omits_it(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            estimates = root / "criterion"
            baseline = root / "baseline.json"
            write_estimate(estimates, "group/bench", 115.0)
            write_baseline(baseline, {"group::bench": 100.0}, tolerance=0.20)

            defaulted = run_cli(
                "--estimates-dir", str(estimates), "--baseline", str(baseline)
            )
            strict = run_cli(
                "--estimates-dir",
                str(estimates),
                "--baseline",
                str(baseline),
                "--tolerance",
                "0.10",
            )

            self.assertEqual(defaulted.returncode, 0, defaulted.stdout + defaulted.stderr)
            self.assertEqual(strict.returncode, 1, strict.stdout + strict.stderr)

    def test_environment_mismatch_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            estimates = root / "criterion"
            baseline = root / "baseline.json"
            write_estimate(estimates, "group/bench", 100.0)
            write_baseline(
                baseline, {"group::bench": 100.0}, environment="runner-a"
            )

            result = run_cli(
                "--estimates-dir",
                str(estimates),
                "--baseline",
                str(baseline),
                "--environment",
                "runner-b",
            )

            self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
            self.assertIn("environment mismatch", result.stderr)
            self.assertIn("runner-a", result.stderr)
            self.assertIn("runner-b", result.stderr)

    def test_environment_match_passes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            estimates = root / "criterion"
            baseline = root / "baseline.json"
            write_estimate(estimates, "group/bench", 100.0)
            write_baseline(
                baseline, {"group::bench": 100.0}, environment="runner-a"
            )

            result = run_cli(
                "--estimates-dir",
                str(estimates),
                "--baseline",
                str(baseline),
                "--environment",
                "runner-a",
            )

            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_reference_only_allows_a_documented_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            estimates = root / "criterion"
            baseline = root / "baseline.json"
            write_estimate(estimates, "group/bench", 100.0)
            write_baseline(
                baseline, {"group::bench": 100.0}, environment="runner-a"
            )

            result = run_cli(
                "--estimates-dir",
                str(estimates),
                "--baseline",
                str(baseline),
                "--environment",
                "runner-b",
                "--reference-only",
            )

            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("reference-only", result.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
