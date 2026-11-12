#!/usr/bin/env python3
"""Check that every 2.0 breaking change has a migration step.

``docs/2.0-public-api-diff.md`` declares the stable breaking-change IDs
(``BC-<n>``). ``docs/2.0-migration.md`` must list each of them in its
breaking-change index with a concrete migration step and an affected
document/test. The checker also rejects duplicate IDs, placeholder steps and a
missing or malformed index so the migration contract cannot silently rot.

Manual direction: the checker cannot infer that a new change is breaking. When
you add one, first give it a new ``BC-<n>`` in the public API diff's
breaking-change index, then add the matching migration row. A breaking change
without an ID is out of this check's reach and must be caught in review.

Run with ``--github`` for annotations.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DIFF_PATH = ROOT / "docs" / "2.0-public-api-diff.md"
GUIDE_PATH = ROOT / "docs" / "2.0-migration.md"

BC_RE = re.compile(r"\bBC-(\d+)\b")
HEADING_RE = re.compile(
    r"^##+\s+(?:\d+\.\s*)?breaking-change index\s*$", re.IGNORECASE
)
PLACEHOLDER_STEPS = {"", "-", "—", "n/a", "na", "none", "tbd", "todo", "planned"}


def breaking_ids(path: Path) -> list[str]:
    """Return the stable breaking IDs in source order (one per line)."""
    seen: list[str] = []
    for match in BC_RE.finditer(path.read_text()):
        identifier = f"BC-{match.group(1)}"
        if identifier not in seen:
            seen.append(identifier)
    return seen


def parse_index(path: Path) -> list[dict[str, str]]:
    """Parse the `## Breaking-change index` table into row dictionaries."""
    lines = path.read_text().splitlines()
    heading = next((i for i, line in enumerate(lines) if HEADING_RE.match(line)), None)
    if heading is None:
        raise ValueError("missing `## Breaking-change index` section")

    rows: list[dict[str, str]] = []
    started = False
    for line in lines[heading + 1 :]:
        if line.startswith("## ") and started:
            break
        if not line.startswith("|"):
            if started and line.strip():
                break
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) >= 3 and cells[0].lower() == "id":
            started = True
            continue
        if not started:
            continue
        if all(set(cell) <= set("-: ") for cell in cells):
            continue
        match = BC_RE.fullmatch(cells[0])
        if not match:
            continue
        rows.append(
            {
                "id": cells[0],
                "change": cells[1] if len(cells) > 1 else "",
                "step": cells[2] if len(cells) > 2 else "",
                "affected": cells[3] if len(cells) > 3 else "",
            }
        )
    if not rows:
        raise ValueError("`## Breaking-change index` has no BC rows")
    return rows


def check() -> tuple[list[str], int]:
    errors: list[str] = []
    diff_ids = breaking_ids(DIFF_PATH)
    if not diff_ids:
        errors.append(
            f"{DIFF_PATH.relative_to(ROOT)} declares no BC-<n> breaking-change IDs"
        )

    rows = parse_index(GUIDE_PATH)
    by_id: dict[str, dict[str, str]] = {}
    for row in rows:
        identifier = row["id"]
        if identifier in by_id:
            errors.append(
                f"{GUIDE_PATH.relative_to(ROOT)}: duplicate breaking-change ID {identifier}"
            )
            continue
        by_id[identifier] = row

    for identifier in diff_ids:
        row = by_id.get(identifier)
        if row is None:
            errors.append(
                f"{GUIDE_PATH.relative_to(ROOT)}: {identifier} has no migration step "
                "row in the breaking-change index"
            )
            continue
        step = row["step"].strip()
        if step.lower().strip("`*_ ") in PLACEHOLDER_STEPS:
            errors.append(
                f"{GUIDE_PATH.relative_to(ROOT)}: {identifier} has no concrete migration step"
            )
        if not row["change"].strip():
            errors.append(
                f"{GUIDE_PATH.relative_to(ROOT)}: {identifier} has no breaking-change description"
            )
        if not row["affected"].strip():
            errors.append(
                f"{GUIDE_PATH.relative_to(ROOT)}: {identifier} names no affected doc/test"
            )

    return errors, len(diff_ids)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--github", action="store_true", help="annotate failures for GitHub Actions")
    args = parser.parse_args(argv)

    try:
        errors, checked = check()
    except (OSError, ValueError) as exc:
        errors = [str(exc)]
        checked = 0

    if errors:
        print("migration guide check failed:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
            if args.github:
                print(f"::error::{error}")
        print(
            "\nUpdate docs/2.0-migration.md so every BC-<n> in "
            "docs/2.0-public-api-diff.md has a concrete migration step.",
            file=sys.stderr,
        )
        return 1

    print(
        f"migration guide OK ({checked} breaking-change IDs each map to a migration step "
        "and an affected doc/test)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
