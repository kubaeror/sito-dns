#!/usr/bin/env bash
# WP-3.2 HA v1-rejection evidence.
#
# HA protocol v2 is a coordinated cluster upgrade: a v1 peer/state/bundle must
# be refused, not migrated in place. This script runs the named rejection
# tests. `sito-ha` has no feature gate (the `ha` feature belongs to `sito` and
# `sito-api`), so the package is built as-is. It is not a two-node E2E.
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

TESTS=(
  test_master_rejects_v1_slave_and_keeps_listening
  test_slave_rejects_v1_master_and_accepts_next_valid_push
  test_restore_preserves_term_and_rejects_v1_state
  test_v1_bundle_is_rejected_by_protocol_v2
  test_v1_watermark_is_rejected_by_protocol_v2
)

echo "HA v1-rejection evidence (sito-ha package)"
for test_name in "${TESTS[@]}"; do
  echo "  cargo test -p sito-ha ${test_name}"
  cargo test -p sito-ha "$test_name"
done

echo "HA v1-rejection evidence: PASS (${#TESTS[@]} tests)"
