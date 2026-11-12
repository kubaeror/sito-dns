#!/usr/bin/env bash
# Fail when a production Rust file exceeds the module-size budget.
#
# Production lines exclude #[cfg(test)] items and the test-only crates
# (sito-test, sito-test-support). See scripts/rust_size.py for the exact rule.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

exec python3 scripts/rust_size.py files "$@"
