#!/usr/bin/env bash
# Regression test for the bundled SQLite advisory fix (RUSTSEC-2026-0459).
#
# libsqlite3-sys < 0.39 bundles SQLite < 3.54.0. sqlx-sqlite 0.9.0 upstream
# caps the dependency at <0.38.0, so sito vendors sqlx-sqlite with only that
# range widened. This test keeps the lockfile and patch from silently drifting
# back to the vulnerable bundle.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
LOCK="${ROOT}/Cargo.lock"
MANIFEST="${ROOT}/Cargo.toml"
VENDORED="${ROOT}/vendor/sqlx-sqlite/Cargo.toml"
DENY="${ROOT}/deny.toml"

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

version="$(
    awk '
        /^name = "libsqlite3-sys"$/ { found = 1; next }
        found && /^version = / { gsub(/[",]/, "", $3); print $3; exit }
    ' "${LOCK}"
)"
[ -n "${version}" ] || fail "libsqlite3-sys is missing from Cargo.lock"

# sort -V returns the lower version first; anything below 0.39.0 is vulnerable.
if [ "$(printf '%s\n' 0.39.0 "${version}" | sort -V | head -n1)" != "0.39.0" ]; then
    fail "libsqlite3-sys ${version} bundles SQLite < 3.54.0 (need >= 0.39.0)"
fi

grep -Fq 'sqlx-sqlite = { path = "vendor/sqlx-sqlite" }' "${MANIFEST}" ||
    fail "Cargo.toml is missing the sqlx-sqlite [patch.crates-io] entry"
grep -Fq 'version = ">=0.30.1, <0.40.0"' "${VENDORED}" ||
    fail "vendored sqlx-sqlite no longer widens libsqlite3-sys to <0.40.0"
if grep -q 'RUSTSEC-2026-0459' "${DENY}"; then
    fail "RUSTSEC-2026-0459 must not be ignored in deny.toml"
fi

echo "sqlite advisory pin OK (libsqlite3-sys ${version})"
