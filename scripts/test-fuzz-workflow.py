#!/usr/bin/env python3
"""Static policy checks for the fuzz workflow and its documented 24h recipe.

The scheduled fuzz workflow has failed in the past for two reasons that no
local test caught:

* ``prepare`` printed a bare JSON array, but GitHub's ``strategy.matrix``
  requires a mapping (``A sequence was not expected``);
* the documented 24h recipe (4 x 21,600 s) used the entire 6-hour job ceiling,
  leaving no time for checkout, build, setup or artifact upload.

This test executes the matrix generator itself (with a couple of shard counts)
and reads the workflow's duration guard and ``timeout-minutes``. It then
requires every documented 24h recipe to aggregate to at least 86,400 seconds
within the shard and per-shard limits advertised by the workflow.

Run from the repository root: ``python3 scripts/test-fuzz-workflow.py``.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import textwrap
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT = SCRIPT_DIR.parent
WORKFLOW = ROOT / ".github" / "workflows" / "fuzz.yml"
RECIPE_FILES = (
    ROOT / "docs" / "release-verification.md",
    ROOT / "fuzz" / "README.md",
    ROOT / "docs" / "ci.md",
)

TARGETS = {
    "dns_wire",
    "abp_parser",
    "dnssec_response",
    "ha_bundle",
    "config_toml",
}
MIN_AGGREGATE_SECONDS = 24 * 60 * 60
MAX_SHARDS = 8
MIN_SETUP_MARGIN_MINUTES = 30

failures: list[str] = []


def check(condition: bool, message: str) -> None:
    if condition:
        print(f"ok - {message}")
    else:
        print(f"not ok - {message}", file=sys.stderr)
        failures.append(message)


def matrix_generator(text: str) -> str:
    """Extract the inline Python generator from the ``id: matrix`` step.

    The workflow stays readable without a YAML parser dependency: the step is
    located by its id, then the single-quoted ``python3 -c`` payload is sliced
    out. The payload itself contains no single quotes.
    """
    try:
        step = text.index("id: matrix")
        start = text.index("python3 -c '", step) + len("python3 -c '")
        end = text.index("'", start)
    except ValueError as exc:
        raise SystemExit("prepare matrix step no longer runs python3 -c") from exc
    return textwrap.dedent(text[start:end])


def run_generator(code: str, shards: int) -> object:
    env = dict(os.environ, INPUT_SHARDS=str(shards))
    result = subprocess.run(
        [sys.executable, "-c", code],
        env=env,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise SystemExit(
            "matrix generator failed for shards="
            f"{shards}:\n{result.stderr.strip()}"
        )
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise SystemExit(
            f"matrix generator did not print JSON for shards={shards}: {exc}"
        )


def main() -> int:
    text = WORKFLOW.read_text(encoding="utf-8")

    generator = matrix_generator(text)
    for shards in (1, 5):
        matrix = run_generator(generator, shards)
        check(
            isinstance(matrix, dict),
            f"matrix generator returns a mapping for shards={shards}",
        )
        if not isinstance(matrix, dict):
            continue
        include = matrix.get("include")
        check(
            isinstance(include, list),
            f"matrix mapping has an 'include' list for shards={shards}",
        )
        if not isinstance(include, list):
            continue
        check(
            len(include) == len(TARGETS) * shards,
            f"matrix has one entry per target x shard for shards={shards}",
        )
        check(
            {entry.get("target") for entry in include} == TARGETS,
            f"matrix covers all five targets for shards={shards}",
        )
        check(
            all(
                isinstance(entry.get("shard"), int)
                and isinstance(entry.get("dictionary"), str)
                for entry in include
            ),
            f"matrix entries carry shard and dictionary for shards={shards}",
        )

    check(
        "matrix: ${{ fromJSON(needs.prepare.outputs.matrix) }}" in text,
        "fuzz job consumes the prepare output with fromJSON",
    )
    check(
        "fromJSON(needs.prepare.outputs.matrix)" in text
        and "matrix: [[" not in text,
        "workflow does not inline a bare sequence matrix",
    )

    guard = re.search(r'if \[ "\$\{seconds\}" -gt (\d+) \]', text)
    check(guard is not None, "workflow has a fuzz_seconds upper-bound guard")
    if guard is None:
        return 1
    max_seconds = int(guard.group(1))

    timeout_match = re.search(
        r"(?ms)^  fuzz:\n.*?^    timeout-minutes: (\d+)$", text
    )
    check(
        timeout_match is not None,
        "fuzz job has an integer timeout-minutes",
    )
    if timeout_match is not None:
        timeout = int(timeout_match.group(1))
        check(
            timeout > max_seconds / 60 + MIN_SETUP_MARGIN_MINUTES,
            f"timeout-minutes {timeout} exceeds {max_seconds / 60:g} min of "
            f"fuzzing plus a {MIN_SETUP_MARGIN_MINUTES}-minute setup margin",
        )

    check(
        re.search(
            rf"fuzz_seconds must be <= {max_seconds}", text
        )
        is not None,
        "guard error message states the same maximum",
    )

    recipes_found = 0
    recipe_pattern = re.compile(r"fuzz_seconds=(\d+)[\s\S]{0,120}?shards=(\d+)")
    for path in RECIPE_FILES:
        if not path.is_file():
            check(False, f"documented recipe file exists: {path.relative_to(ROOT)}")
            continue
        matches = recipe_pattern.findall(path.read_text(encoding="utf-8"))
        for raw_seconds, raw_shards in matches:
            seconds = int(raw_seconds)
            shards = int(raw_shards)
            recipes_found += 1
            check(
                seconds <= max_seconds,
                f"{path.relative_to(ROOT)}: per-shard {seconds}s <= workflow max {max_seconds}s",
            )
            check(
                shards <= MAX_SHARDS,
                f"{path.relative_to(ROOT)}: {shards} shards <= {MAX_SHARDS}",
            )
            check(
                seconds * shards >= MIN_AGGREGATE_SECONDS,
                f"{path.relative_to(ROOT)}: {seconds}s x {shards} shards "
                f"aggregates to {seconds * shards}s >= {MIN_AGGREGATE_SECONDS}s",
            )

    check(recipes_found > 0, "at least one 24h recipe is documented")
    check(
        "21600" not in text
        and all(
            "21600" not in path.read_text(encoding="utf-8")
            for path in RECIPE_FILES
            if path.is_file()
        ),
        "no stale 21,600 s (6-hour, zero-margin) recipe remains in the workflow or docs",
    )

    if failures:
        print(f"\n{len(failures)} fuzz workflow check(s) failed", file=sys.stderr)
        return 1
    print("\nfuzz workflow policy OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
