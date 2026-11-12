#!/usr/bin/env bash
# Runs the workspace Criterion benchmarks and writes benches/baseline.json.
#
# The saved medians are environment specific. Run this on the dedicated
# benchmark runner (or the same machine class the gate compares against), not
# on an arbitrary laptop, or the nightly gate will compare across hardware.
#
# Usage:
#   scripts/save-bench-baseline.sh
#   BENCH_ENVIRONMENT=<runner-label> scripts/save-bench-baseline.sh
#
# The checker records BENCH_ENVIRONMENT and later fails closed when the
# comparison runner's environment differs from the baseline.
#
# For a short local check, run the five Criterion targets individually with
# `-- --quick` (see benches/README.md), then invoke the checker directly.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

if ! command -v cargo >/dev/null 2>&1; then
    echo "error: cargo is not installed" >&2
    exit 1
fi

echo "==> running Criterion benchmarks"
cargo bench --workspace --all-features --locked

echo "==> writing benches/baseline.json"
environment=()
if [ -n "${BENCH_ENVIRONMENT:-}" ]; then
    environment=(--environment "${BENCH_ENVIRONMENT}")
fi
python3 scripts/check-bench-regression.py --save "${environment[@]}"
