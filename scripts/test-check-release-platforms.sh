#!/usr/bin/env bash
# Focused, Docker-free tests for scripts/check-release-platforms.sh.
#
# Covers the OCI/BuildKit `linux/arm64/v8` spelling that a real multi-arch
# index reports, the bare `linux/arm64` spelling, and enforcement of every
# required platform. Run directly: scripts/test-check-release-platforms.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHECK="${SCRIPT_DIR}/check-release-platforms.sh"

failures=0
cases=0

run_case() {
    local name="$1"
    local expected_rc="$2"
    local platforms="$3"
    local output rc

    cases=$((cases + 1))
    set +e
    output="$(printf '%s\n' "${platforms}" | "${CHECK}" 2>&1)"
    rc=$?
    set -e

    if [ "${rc}" -ne "${expected_rc}" ]; then
        echo "not ok - ${name}: expected exit ${expected_rc}, got ${rc}"
        printf '%s\n' "${output}" | sed 's/^/    /'
        failures=$((failures + 1))
    else
        echo "ok - ${name}"
    fi
}

# A real BuildKit index reports the implicit v8 variant.
run_case "accepts linux/arm64/v8" 0 \
    "linux/amd64 linux/arm64/v8 linux/arm/v7 unknown/unknown"
# A builder that omits the implicit variant must keep working.
run_case "accepts linux/arm64" 0 \
    "linux/amd64 linux/arm64 linux/arm/v7 unknown/unknown"

# Every promised platform remains mandatory.
run_case "rejects a missing linux/arm64" 1 \
    "linux/amd64 linux/arm/v7 unknown/unknown"
run_case "rejects a missing linux/amd64" 1 \
    "linux/arm64/v8 linux/arm/v7 unknown/unknown"
run_case "rejects a missing linux/arm/v7" 1 \
    "linux/amd64 linux/arm64"
run_case "rejects an empty index" 1 ""

# Only the arm64 v8 spelling is equivalent to bare linux/arm64.
run_case "rejects linux/arm64/v9" 1 \
    "linux/amd64 linux/arm64/v9 linux/arm/v7"

echo "${cases} cases, ${failures} failure(s)"
if [ "${failures}" -ne 0 ]; then
    exit 1
fi
