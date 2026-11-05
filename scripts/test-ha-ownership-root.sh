#!/usr/bin/env bash
# Root-gated HA certificate ownership test.
#
# Generates root-owned 0600 certificates, proves uid/gid 65532 cannot read the
# private key, chowns the files to the runtime identity, and verifies that the
# real mTLS listener plus /health and /api/v1/ha/status flip to ready.
#
# The test itself skips when not root; this wrapper refuses to run
# unprivileged so a CI mistake cannot be mistaken for a passing ownership test.
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

exec cargo test -p sito-test --test m8_acceptance \
    test_m8_root_owned_key_chown_activates_ha -- --nocapture
