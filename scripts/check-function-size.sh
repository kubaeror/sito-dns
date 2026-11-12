#!/usr/bin/env bash
# Fail when a production Rust function exceeds 200 lines without a documented
# exception in docs/large-functions.md.
#
# Production code excludes #[cfg(test)] items and the test-only crates
# (sito-test, sito-test-support). See scripts/rust_size.py for the exact rule.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

exec python3 scripts/rust_size.py functions "$@"
