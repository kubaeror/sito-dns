#!/usr/bin/env python3
"""Criterion benchmark regression gate.

Reads Criterion's ``estimates.json`` files from ``target/criterion`` (the
``new`` measurement of the latest run) and compares each benchmark's median
against a committed baseline. A benchmark more than the configured tolerance
slower than the baseline fails the gate (default: 10%).

Usage::

    # Compare the latest run with the committed baseline
    python3 scripts/check-bench-regression.py

    # Write/refresh the baseline from the latest run
    python3 scripts/check-bench-regression.py --save

    # Same, explicitly naming the dedicated benchmark runner
    BENCH_ENVIRONMENT=<runner-label> python3 scripts/check-bench-regression.py --save

The baseline stores absolute medians in nanoseconds, so it is environment
specific. Generate it on the dedicated benchmark runner (see
``.github/workflows/bench.yml``) and never compare a laptop baseline with CI.
Record the same label in ``BENCH_ENVIRONMENT``: the checker fails closed when
the current environment does not match the baseline.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

SCHEMA_VERSION = 1
DEFAULT_TOLERANCE = 0.10
ESTIMATE_NAME = "estimates.json"
NEW_DIR = "new"


class BaselineError(Exception):
    """The baseline or estimate files are malformed or incomplete."""


@dataclass(frozen=True)
class Regression:
    benchmark: str
    baseline_ns: float
    current_ns: float
    change_pct: float

    @property
    def factor(self) -> float:
        return self.current_ns / self.baseline_ns


@dataclass(frozen=True)
class Baseline:
    benchmarks: dict[str, float]
    tolerance: float
    environment: dict[str, object]

    @property
    def environment_description(self) -> str:
        description = self.environment.get("description")
        return description if isinstance(description, str) else "<unknown>"


def _median_from_estimate(path: Path) -> float:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BaselineError(f"cannot read {path}: {exc}") from exc

    median = payload.get("median")
    if not isinstance(median, dict):
        raise BaselineError(f"{path} has no median object")
    value = median.get("point_estimate")
    if not isinstance(value, (int, float)) or value <= 0:
        raise BaselineError(f"{path} has no positive median point_estimate")
    return float(value)


def collect_estimates(estimates_dir: Path) -> dict[str, float]:
    """Returns ``{"group::bench": median_ns}`` for every ``new`` estimate."""
    if not estimates_dir.is_dir():
        return {}

    estimates: dict[str, float] = {}
    for path in sorted(estimates_dir.rglob(f"{NEW_DIR}/{ESTIMATE_NAME}")):
        relative = path.relative_to(estimates_dir)
        parts = list(relative.parts[:-2])
        if not parts:
            # A top-level bench (no Criterion group) still appears as
            # ``<bench>/new/estimates.json``; keep its name.
            parts = [relative.parts[0]]
        key = "::".join(parts)
        estimates[key] = _median_from_estimate(path)
    return estimates


def load_baseline(path: Path) -> Baseline:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BaselineError(f"cannot read baseline {path}: {exc}") from exc

    if not isinstance(payload, dict):
        raise BaselineError(f"baseline {path} must be a JSON object")
    if payload.get("schema_version") != SCHEMA_VERSION:
        raise BaselineError(
            f"baseline {path} schema_version is {payload.get('schema_version')!r}, "
            f"expected {SCHEMA_VERSION}"
        )
    benchmarks = payload.get("benchmarks")
    if not isinstance(benchmarks, dict) or not benchmarks:
        raise BaselineError(f"baseline {path} has no benchmarks")

    tolerance = payload.get("tolerance", DEFAULT_TOLERANCE)
    if not isinstance(tolerance, (int, float)) or tolerance < 0:
        raise BaselineError(
            f"baseline {path} has an invalid tolerance: {tolerance!r}"
        )

    environment = payload.get("environment", {})
    if not isinstance(environment, dict):
        raise BaselineError(f"baseline {path} environment must be an object")
    if not isinstance(environment.get("description"), str):
        raise BaselineError(f"baseline {path} has no environment.description")

    loaded: dict[str, float] = {}
    for name, entry in benchmarks.items():
        if isinstance(entry, dict):
            value = entry.get("median_ns")
        else:
            value = entry
        if not isinstance(value, (int, float)) or value <= 0:
            raise BaselineError(
                f"baseline entry {name!r} has no positive median_ns"
            )
        loaded[name] = float(value)
    return Baseline(
        benchmarks=loaded,
        tolerance=float(tolerance),
        environment=environment,
    )


def compare(
    baseline: dict[str, float],
    current: dict[str, float],
    tolerance: float = DEFAULT_TOLERANCE,
) -> tuple[list[Regression], list[str], list[str]]:
    """Compares medians and returns ``(regressions, missing, new)``.

    A value exactly at ``baseline * (1 + tolerance)`` passes. A missing
    current estimate is reported separately so the caller can fail closed.
    """
    if tolerance < 0:
        raise ValueError("tolerance must be non-negative")

    regressions: list[Regression] = []
    missing: list[str] = []
    for name, base_ns in sorted(baseline.items()):
        if base_ns <= 0:
            raise ValueError(f"baseline median for {name!r} must be positive")
        current_ns = current.get(name)
        if current_ns is None:
            missing.append(name)
            continue
        change = (current_ns - base_ns) / base_ns
        if current_ns > base_ns * (1.0 + tolerance):
            regressions.append(
                Regression(
                    benchmark=name,
                    baseline_ns=base_ns,
                    current_ns=current_ns,
                    change_pct=change * 100.0,
                )
            )

    new = sorted(set(current) - set(baseline))
    return regressions, missing, new


def environment_description(explicit: str | None) -> dict[str, str | int]:
    if explicit:
        return {"description": explicit}
    return {
        "description": f"{platform.system()} {platform.machine()}",
        "system": platform.system(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "python": platform.python_version(),
        "cpu_count": _cpu_count(),
    }


def current_environment_label(explicit: str | None) -> str:
    """Returns the label a comparison must match.

    An explicit ``--environment`` wins, then ``BENCH_ENVIRONMENT`` (set by the
    workflow from the repository variable), then the automatic host
    description. The baseline is only comparable when this label equals the
    baseline's recorded description.
    """
    if explicit:
        return explicit
    from_env = os.environ.get("BENCH_ENVIRONMENT")
    if from_env:
        return from_env
    return str(environment_description(None)["description"])


def _cpu_count() -> int:
    try:
        import os

        return os.cpu_count() or 0
    except Exception:  # pragma: no cover - defensive only
        return 0


def save_baseline(
    path: Path,
    estimates: dict[str, float],
    environment: str | None,
    tolerance: float,
) -> None:
    if not estimates:
        raise BaselineError("no Criterion estimates found; run cargo bench first")
    if tolerance < 0:
        raise BaselineError("tolerance must be non-negative")

    payload = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "environment": environment_description(environment),
        "tolerance": tolerance,
        "benchmarks": {
            name: {"median_ns": round(value, 3)}
            for name, value in sorted(estimates.items())
        },
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _format_table(
    estimate_count: int,
    regressions: list[Regression],
    missing: list[str],
    new: list[str],
    improvements: list[tuple[str, float, float, float]],
    tolerance: float,
) -> str:
    lines = [
        f"criterion benchmarks: {estimate_count} measured, "
        f"tolerance {tolerance * 100:.0f}%",
    ]
    for regression in regressions:
        lines.append(
            f"REGRESSION {regression.benchmark}: "
            f"{regression.baseline_ns:.1f} ns -> {regression.current_ns:.1f} ns "
            f"({regression.change_pct:+.2f}%, {regression.factor:.2f}x)"
        )
    for name in missing:
        lines.append(f"MISSING {name}: no current Criterion estimate")
    for name, base_ns, current_ns, change_pct in improvements:
        lines.append(
            f"improved {name}: {base_ns:.1f} ns -> {current_ns:.1f} ns "
            f"({change_pct:+.2f}%)"
        )
    for name in new:
        lines.append(f"new {name}: not in the baseline (informational)")
    if not regressions and not missing:
        lines.append("all benchmarks are within tolerance")
    return "\n".join(lines)


def improvements(
    baseline: dict[str, float], current: dict[str, float], threshold_pct: float = 1.0
) -> list[tuple[str, float, float, float]]:
    """Returns benchmarks at least ``threshold_pct`` faster than the baseline."""
    result: list[tuple[str, float, float, float]] = []
    for name, base_ns in sorted(baseline.items()):
        current_ns = current.get(name)
        if current_ns is None:
            continue
        change_pct = (current_ns - base_ns) / base_ns * 100.0
        if change_pct <= -threshold_pct:
            result.append((name, base_ns, current_ns, change_pct))
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--estimates-dir",
        type=Path,
        default=Path("target/criterion"),
        help="Criterion output directory (default: target/criterion)",
    )
    parser.add_argument(
        "--baseline",
        type=Path,
        default=Path("benches/baseline.json"),
        help="Baseline JSON (default: benches/baseline.json)",
    )
    parser.add_argument(
        "--tolerance",
        type=float,
        default=None,
        help=(
            "Maximum allowed slowdown as a fraction. Default: the baseline's "
            "stored tolerance (normally 0.10)"
        ),
    )
    parser.add_argument(
        "--allow-missing",
        action="store_true",
        help="Do not fail when a baseline benchmark has no current estimate",
    )
    parser.add_argument(
        "--save",
        action="store_true",
        help="Write the current estimates to --baseline instead of comparing",
    )
    parser.add_argument(
        "--environment",
        default=None,
        help=(
            "Current benchmark environment label. Defaults to "
            "BENCH_ENVIRONMENT, then the automatic host description"
        ),
    )
    parser.add_argument(
        "--reference-only",
        action="store_true",
        help=(
            "Allow a baseline/current environment mismatch for a documented "
            "reference-only comparison; never use this in the nightly gate"
        ),
    )
    parser.add_argument(
        "--github",
        action="store_true",
        help="Emit GitHub Actions error annotations for failures",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        estimates = collect_estimates(args.estimates_dir)
        if args.save:
            tolerance = (
                DEFAULT_TOLERANCE if args.tolerance is None else args.tolerance
            )
            environment = current_environment_label(args.environment)
            save_baseline(args.baseline, estimates, environment, tolerance)
            print(
                f"saved {len(estimates)} benchmark(s) to {args.baseline} "
                f"(tolerance {tolerance * 100:.0f}%, "
                f"environment {environment!r})"
            )
            return 0

        baseline = load_baseline(args.baseline)
        tolerance = (
            baseline.tolerance if args.tolerance is None else args.tolerance
        )
        current_environment = current_environment_label(args.environment)
        if baseline.environment_description != current_environment:
            if not args.reference_only:
                raise BaselineError(
                    "environment mismatch: baseline was generated on "
                    f"{baseline.environment_description!r}, current environment "
                    f"is {current_environment!r}. Regenerate the baseline on "
                    "this runner, or pass --reference-only for a documented "
                    "non-gating comparison."
                )
            print(
                "reference-only: comparing across benchmark environments "
                f"({baseline.environment_description!r} -> "
                f"{current_environment!r}); do not use this result as a gate"
            )
        regressions, missing, new = compare(
            baseline.benchmarks, estimates, tolerance
        )
        faster = improvements(baseline.benchmarks, estimates)
    except (BaselineError, ValueError) as exc:
        message = f"benchmark gate: {exc}"
        if args.github:
            print(f"::error::{message}")
        print(message, file=sys.stderr)
        return 2

    print(
        _format_table(
            len(estimates), regressions, missing, new, faster, tolerance
        )
    )

    failed = bool(regressions) or (bool(missing) and not args.allow_missing)
    if failed and args.github:
        for regression in regressions:
            print(
                f"::error::{regression.benchmark} regressed "
                f"{regression.change_pct:+.2f}% "
                f"({regression.baseline_ns:.1f} ns -> "
                f"{regression.current_ns:.1f} ns)"
            )
        for name in missing:
            print(f"::error::{name} has no current Criterion estimate")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
