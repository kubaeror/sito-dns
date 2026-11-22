#!/usr/bin/env bash
# Root-gated HA certificate ownership test.
#
# Generates root-owned 0600 certificates, proves uid/gid 65532 cannot read the
# private key, chowns the files to the runtime identity, and verifies that the
# real mTLS listener plus /health and /api/v2/ha/status flip to ready.
#
# The test itself skips when not root; this wrapper refuses to run
# unprivileged so a CI mistake cannot be mistaken for a passing ownership test.
# It also enables the `ha` feature (the target is otherwise empty) and fails
# unless exactly one test ran, so a filter mismatch cannot pass as a skip.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

if [ "$(id -u)" -ne 0 ]; then
    echo "error: this test must run as root (it chowns a key to uid 65532 and runs a probe as that uid)." >&2
    echo "re-run with: sudo $0" >&2
    exit 1
fi

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$REPO_ROOT/target}"
cd "$REPO_ROOT"

# `m8_acceptance` is `#![cfg(feature = "ha")]`. Without the feature cargo
# compiles an empty test target and a filtered `cargo test` exits 0 without
# running anything, which would turn this root gate into a silent skip.
log="$(mktemp)"
trap 'rm -f "${log}"' EXIT

set +e
cargo test -p sito-test --features ha --locked --test m8_acceptance \
    -- --exact test_m8_root_owned_key_chown_activates_ha --nocapture 2>&1 | tee "${log}"
status="${PIPESTATUS[0]}"
set -e

if [ "${status}" -ne 0 ]; then
    exit "${status}"
fi

# A green cargo exit with zero matching tests is not evidence. Fail closed.
if ! grep -Eq '^test result: ok\. 1 passed' "${log}"; then
    echo "error: test_m8_root_owned_key_chown_activates_ha did not run exactly once." >&2
    grep -E '^test result:' "${log}" >&2 || true
    exit 1
fi
