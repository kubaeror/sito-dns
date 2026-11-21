#!/usr/bin/env python3
"""Check that named tests and scripts in the audit test matrix still exist.

``docs/audit6-test-matrix.md`` is the evidence map for the P0/P1 findings. A
renamed test or a deleted script silently turns a security claim into prose, so
this checker extracts every backticked token from the "Named test / check"
column and verifies it against the tree:

* ``test_*`` names (and non-prefixed test functions) must appear as a Rust
  ``fn`` or inside a checker script (the config/migration fixture tests live in
  Python);
* ``path/to/script`` and workflow references must exist (``#anchor`` suffixes
  are ignored);
* commands, wildcards, constants and labels are ignored.

Run with ``--github`` for pull-request annotations.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

SOURCE_SUFFIXES = {".rs", ".py", ".sh"}
SKIP_DIRS = {".git", "target", "vendor"}
PATH_PREFIXES = (
    ".github/",
    "benches/",
    "contrib/",
    "crates/",
    "docs/",
    "fuzz/",
    "scripts/",
)
ROOT_FILES = {".dockerignore", "deny.toml", "Dockerfile", "Dockerfile.release"}

# Backticked labels/constants that are not tests or paths.
IGNORED_IDENTIFIERS = {
    "MAX_HANDSHAKES_PER_IP",
    "MAX_SLAVE_CONNECTIONS",
    "MAX_SLAVE_QUEUE_BYTES",
    "MAX_WS_MESSAGE_SIZE",
    "RUSTSEC-2026-0374",
    "Unchecked",
    "Unknown",
    "WS_SEND_TIMEOUT",
    "abp_parser",
    "askama_derive",
    "basic-toml",
    "bench-build",
    "cargo-deny",
    "ci-gate",
    "clippy",
    "config_toml",
    "contrib",
    "coverage",
    "dns_wire",
    "dnssec_response",
    "docker-build-push",
    "embed-ui,ha,mimalloc",
    "fixtures::ha",
    "fuzz-build",
    "ha-matrix",
    "ha_bundle",
    "hygiene",
    "m11_ha_partition",
    "m7",
    "m8_acceptance",
    "merge_group",
    "security-check",
    "sito-api",
    "sito-test",
    "sito-transport",
    "test",
    "ubuntu-24.04",
    "workflow_dispatch",
}


def read_sources(root: Path) -> tuple[set[str], str]:
    functions: set[str] = set()
    chunks: list[str] = []
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix not in SOURCE_SUFFIXES:
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        chunks.append(text)
        functions.update(re.findall(r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*)", text))
    return functions, "\n".join(chunks)


def matrix_path(root: Path) -> Path:
    return root / "docs" / "audit6-test-matrix.md"


def matrix_tokens(root: Path) -> list[tuple[int, str]]:
    tokens: list[tuple[int, str]] = []
    for number, line in enumerate(matrix_path(root).read_text(encoding="utf-8").splitlines(), 1):
        if not line.startswith("|"):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) < 2:
            continue
        tokens.extend(
            (number, match.group(1)) for match in re.finditer(r"`([^`]+)`", cells[1])
        )
    return tokens


def is_path_token(token: str) -> bool:
    if "/" in token:
        return token.startswith(PATH_PREFIXES)
    return token in ROOT_FILES


def check(root: Path) -> list[tuple[int, str]]:
    functions, blob = read_sources(root)
    errors: list[tuple[int, str]] = []
    for line, token in matrix_tokens(root):
        if not token or any(char.isspace() for char in token) or token.endswith("*"):
            continue
        if is_path_token(token):
            path = token.split("#", 1)[0]
            if not (root / path).exists():
                errors.append((line, f"missing path: {token}"))
            continue
        if "::" in token:
            base = token.rsplit("::", 1)[-1]
            if base.startswith("test_") and base not in functions and base not in blob:
                errors.append((line, f"missing test: {token}"))
            continue
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", token):
            continue
        if token in IGNORED_IDENTIFIERS:
            continue
        if token in functions or re.search(rf"\b{re.escape(token)}\b", blob):
            continue
        if token.startswith("test_") or (len(token) >= 15 and "_" in token):
            errors.append((line, f"missing test or fixture: {token}"))
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=ROOT,
        help="repository root (the default is the checkout containing this script)",
    )
    parser.add_argument(
        "--github",
        action="store_true",
        help="emit GitHub Actions error annotations",
    )
    args = parser.parse_args()
    root = args.root.resolve()

    try:
        errors = check(root)
    except OSError as exc:
        print(f"test matrix check failed: {exc}", file=sys.stderr)
        return 1

    if errors:
        matrix = matrix_path(root)
        try:
            display = matrix.relative_to(root)
        except ValueError:
            display = matrix
        for line, message in errors:
            if args.github:
                print(f"::error file={display},line={line}::{message}")
            else:
                print(f"{display}:{line}: {message}", file=sys.stderr)
        return 1

    print(f"test matrix: {len(set(token for _, token in matrix_tokens(root)))} named tests/checks resolve")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
