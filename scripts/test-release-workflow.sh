#!/usr/bin/env bash
# Static policy checks for the release workflow and installer safety
# properties that are enforced by CI wiring rather than unit tests.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
RELEASE="${ROOT}/.github/workflows/release.yml"
CI="${ROOT}/.github/workflows/ci.yml"
SECURITY="${ROOT}/.github/workflows/security.yml"
INSTALLER="${ROOT}/contrib/install.sh"

failures=0
expect_match() {
    local file="$1" pattern="$2" message="$3"
    if ! grep -Eq -- "${pattern}" "${file}"; then
        echo "not ok - ${message}" >&2
        failures=$((failures + 1))
    else
        echo "ok - ${message}"
    fi
}

expect_match "${RELEASE}" '^  release-gate:' "release workflow has a release-gate job"
expect_match "${RELEASE}" 'scripts/verify-release-gate\.sh' "release workflow invokes the release gate"
expect_match "${RELEASE}" 'needs: \[verify-tag, release-gate\]' "build job depends on the release gate"
expect_match "${RELEASE}" 'needs: \[verify-tag, release-gate, build-binaries\]' "publish job depends on the release gate"
expect_match "${RELEASE}" 'needs: \[verify-tag, release-gate, build-binaries, sbom-and-release, artifact-e2e\]' "image job depends on the release gate"
expect_match "${RELEASE}" 'aquasec/trivy:[0-9.]+@sha256:[0-9a-f]{64}' "image scanner is pinned by digest"
expect_match "${RELEASE}" 'severity HIGH,CRITICAL' "image scan gates on HIGH/CRITICAL"
expect_match "${RELEASE}" 'exit-code 1' "image scan fails the release"
expect_match "${RELEASE}" 'cosign sign --yes' "image digest is signed with cosign"
expect_match "${RELEASE}" 'cosign verify' "image signature is verified"
expect_match "${RELEASE}" 'provenance: true' "image provenance is retained"
expect_match "${RELEASE}" 'sbom: true' "image SBOM attestation is retained"

expect_match "${CI}" 'branches: \[main, release/1\.9\.x\]' "CI runs on the release branch"
expect_match "${SECURITY}" 'branches: \[main, release/1\.9\.x\]' "security runs on the release branch"
expect_match "${CI}" 'bash contrib/tests/test-installer\.sh' "CI runs the installer E2E"

expect_match "${INSTALLER}" 'SITO_REQUIRE_SIGNATURE:-1' "release signatures are required by default"
expect_match "${INSTALLER}" 'install_binary_atomic "\$\{TMP_DIR\}/sito"' "release binary uses the atomic installer"
expect_match "${INSTALLER}" 'install_binary_atomic "target/release/sito"' "local binary uses the atomic installer"

# Every third-party action must be pinned to a full commit SHA. Local reusable
# workflows (`uses: ./...`) are exempt.
unpinned="$(grep -hE '^[[:space:]]*(-[[:space:]]*)?uses:' "${ROOT}"/.github/workflows/*.yml |
    grep -v 'uses: \./' |
    grep -vE '@[0-9a-f]{40}([[:space:]]|$)' || true)"
if [ -n "${unpinned}" ]; then
    echo "not ok - unpinned action reference(s):" >&2
    printf '%s\n' "${unpinned}" | sed 's/^/    /' >&2
    failures=$((failures + 1))
else
    echo "ok - every third-party action is SHA-pinned"
fi

if [ "${failures}" -ne 0 ]; then
    echo "${failures} release workflow check(s) failed" >&2
    exit 1
fi
echo "release workflow policy OK"
