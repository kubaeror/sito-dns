#!/usr/bin/env python3
"""Fast structural check for the cargo-fuzz workspace.

``cargo fuzz build`` is the authoritative compile check and runs in the
``fuzz-build`` CI job. This checker catches the cheap drift cases on every PR
and in the normal test lane:

* ``fuzz/Cargo.toml`` exists, declares ``cargo-fuzz = true`` and its own
  ``[workspace]`` (so it stays outside the root workspace);
* exactly the five required ``[[bin]]`` targets are declared and point at
  existing, non-empty ``fuzz_targets/*.rs`` files that call ``fuzz_target!``;
* every target has at least one tracked ``corpus/<target>/seed-*`` file;
* ``fuzz/.gitignore`` ignores build output but keeps the seed corpus tracked.

Run ``--root`` for the regression fixtures; the default is the repository root.
"""

from __future__ import annotations

import argparse
import re
import sys
import tomllib
from pathlib import Path

REQUIRED_TARGETS = (
    "dns_wire",
    "abp_parser",
    "dnssec_response",
    "ha_bundle",
    "config_toml",
)

REQUIRED_GITIGNORE_PATTERNS = ("target/", "artifacts/", "coverage/")
SEED_UNIGNORE = "!corpus/**/seed-*"
REQUIRED_DICTIONARIES = {
    "dns_wire": "dns_wire.dict",
    "abp_parser": "abp_parser.dict",
    "dnssec_response": "dns_wire.dict",
    "ha_bundle": "ha_bundle.dict",
    "config_toml": "config_toml.dict",
}

DNS_WIRE_ROUND_TRIP = (
    (
        "missing re-encode assertion: encode_message(&message) must use "
        '.expect("decoded message must re-encode")',
        re.compile(
            r"encode_message\(&message\)[\s\S]{0,120}?\.expect\(\"decoded message must re-encode\"\)"
        ),
    ),
    (
        "missing re-decode assertion: decode_message(&encoded) must use "
        '.expect("encoded message must re-decode")',
        re.compile(
            r"decode_message\(&encoded\)[\s\S]{0,120}?\.expect\(\"encoded message must re-decode\"\)"
        ),
    ),
)


def dictionary_errors(path: Path) -> list[str]:
    """Validates the libFuzzer dictionary syntax and requires a token."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        return [f"cannot read dictionary {path}: {exc}"]

    errors: list[str] = []
    tokens = 0
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if not line.startswith('"'):
            errors.append(f"malformed dictionary line {path}:{number}: {raw!r}")
            continue
        escaped = False
        closing = None
        for index, char in enumerate(line[1:], start=1):
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                closing = index
                break
        if closing is None:
            errors.append(f"malformed dictionary line {path}:{number}: {raw!r}")
            continue
        remainder = line[closing + 1 :].strip()
        if remainder and not remainder.startswith("#"):
            errors.append(f"malformed dictionary line {path}:{number}: {raw!r}")
            continue
        tokens += 1

    if tokens == 0:
        errors.append(f"no dictionary tokens in {path}")
    return errors


def check(root: Path) -> list[str]:
    errors: list[str] = []
    fuzz = root / "fuzz"
    manifest_path = fuzz / "Cargo.toml"

    if not manifest_path.is_file():
        return [f"missing fuzz manifest: {manifest_path}"]

    try:
        manifest = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        return [f"cannot parse {manifest_path}: {exc}"]

    if "workspace" not in manifest:
        errors.append("fuzz/Cargo.toml must declare an empty [workspace] table")

    metadata = manifest.get("package", {}).get("metadata", {})
    if metadata.get("cargo-fuzz") is not True:
        errors.append("fuzz/Cargo.toml must set [package.metadata] cargo-fuzz = true")

    bins = manifest.get("bin", [])
    declared = {entry.get("name"): entry for entry in bins if isinstance(entry, dict)}
    for name in REQUIRED_TARGETS:
        if name not in declared:
            errors.append(f"fuzz/Cargo.toml is missing the [[bin]] target {name}")
            continue
        entry = declared[name]
        if entry.get("test") is not False or entry.get("doc") is not False:
            errors.append(f"target {name} must set test = false and doc = false")
        relative = entry.get("path")
        if not isinstance(relative, str):
            errors.append(f"target {name} has no path")
            continue
        source = fuzz / relative
        if not source.is_file():
            errors.append(f"missing target source: fuzz/{relative}")
            continue
        text = source.read_text(encoding="utf-8", errors="replace")
        if not text.strip():
            errors.append(f"target source is empty: fuzz/{relative}")
        if "fuzz_target!" not in text:
            errors.append(f"target {name} does not call fuzz_target!")
        if name == "dns_wire":
            for message, pattern in DNS_WIRE_ROUND_TRIP:
                if not pattern.search(text):
                    errors.append(f"target {name}: {message}")

    extra = sorted(set(declared) - set(REQUIRED_TARGETS))
    if extra:
        errors.append(
            "unexpected fuzz target(s) not covered by the checker: " + ", ".join(extra)
        )

    for name in REQUIRED_TARGETS:
        seed_dir = fuzz / "corpus" / name
        seeds = (
            sorted(path for path in seed_dir.glob("seed-*") if path.is_file())
            if seed_dir.is_dir()
            else []
        )
        if not seeds:
            errors.append(f"missing tracked seed corpus: fuzz/corpus/{name}/seed-*")
        for seed in seeds:
            if seed.stat().st_size == 0:
                errors.append(f"empty seed file: fuzz/corpus/{name}/{seed.name}")

        dictionary = REQUIRED_DICTIONARIES[name]
        dictionary_path = fuzz / "dictionaries" / dictionary
        if not dictionary_path.is_file():
            errors.append(f"missing fuzz dictionary: fuzz/dictionaries/{dictionary}")
        else:
            errors.extend(dictionary_errors(dictionary_path))

    gitignore = fuzz / ".gitignore"
    if not gitignore.is_file():
        errors.append("missing fuzz/.gitignore")
    else:
        text = gitignore.read_text(encoding="utf-8")
        for pattern in REQUIRED_GITIGNORE_PATTERNS:
            if pattern not in text:
                errors.append(f"fuzz/.gitignore must ignore {pattern}")
        if SEED_UNIGNORE not in text:
            errors.append(
                f"fuzz/.gitignore must keep seed corpus tracked (missing {SEED_UNIGNORE})"
            )

    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parent.parent,
        help="Repository root (default: the script's parent directory)",
    )
    args = parser.parse_args(argv)

    errors = check(args.root)
    if errors:
        print("fuzz target check failed:")
        for error in errors:
            print(f"  - {error}")
        return 1

    print(f"{len(REQUIRED_TARGETS)} fuzz targets, seed corpora and gitignore rules are present")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
