#!/usr/bin/env bash
# Static policy checks for the release workflow and installer safety
# properties that are enforced by CI wiring rather than unit tests.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
RELEASE="${ROOT}/.github/workflows/release.yml"
ARTIFACT_E2E="${ROOT}/.github/workflows/artifact-e2e.yml"
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

expect_absent() {
    local file="$1" pattern="$2" message="$3"
    if grep -Eq -- "${pattern}" "${file}"; then
        echo "not ok - ${message}" >&2
        failures=$((failures + 1))
    else
        echo "ok - ${message}"
    fi
}

# Prints one top-level job body so a policy check cannot be satisfied by an
# unrelated job elsewhere in the same workflow.
job_section() {
    local job="$1" file="$2"
    awk -v header="  ${job}:" '
        $0 == header { in_job = 1; next }
        in_job && /^  [A-Za-z0-9_-]+:$/ { exit }
        in_job { print }
    ' "${file}"
}

expect_job_match() {
    local file="$1" job="$2" pattern="$3" message="$4"
    # No `grep -q`: under pipefail an early exit can SIGPIPE the producer and
    # turn a match into a false failure.
    if ! job_section "${job}" "${file}" | grep -E -- "${pattern}" >/dev/null; then
        echo "not ok - ${message}" >&2
        failures=$((failures + 1))
    else
        echo "ok - ${message}"
    fi
}

expect_job_absent() {
    local file="$1" job="$2" pattern="$3" message="$4"
    if job_section "${job}" "${file}" | grep -E -- "${pattern}" >/dev/null; then
        echo "not ok - ${message}" >&2
        failures=$((failures + 1))
    else
        echo "ok - ${message}"
    fi
}

expect_match "${RELEASE}" '^  release-gate:' "release workflow has a release-gate job"
expect_job_match "${RELEASE}" "release-gate" 'scripts/verify-release-gate\.sh' "release-gate job invokes the gate script"
expect_job_match "${RELEASE}" "release-gate" 'checks: read' "release-gate job can read check runs"
expect_job_match "${RELEASE}" "release-gate" 'statuses: read' "release-gate job can read legacy statuses"
expect_job_absent "${RELEASE}" "release-gate" 'continue-on-error' "release-gate cannot continue on error"
expect_match "${RELEASE}" 'needs: \[verify-tag, release-gate\]' "build job depends on the release gate"
expect_match "${RELEASE}" 'needs: \[verify-tag, release-gate, build-binaries\]' "publish job depends on the release gate"
expect_match "${RELEASE}" 'needs: \[verify-tag, release-gate, build-binaries, sbom-and-release, artifact-e2e\]' "image job depends on the release gate"

# The release is staged as a draft and published only after both consumers
# succeed, so an E2E or image failure cannot leave published assets behind.
expect_job_match "${RELEASE}" "sbom-and-release" 'draft: true' "release assets are staged as a draft"
expect_job_match "${RELEASE}" "sbom-and-release" 'Stage GitHub Release \(draft\)' "release staging step is explicit"
expect_job_absent "${RELEASE}" "sbom-and-release" 'draft: false' "release staging never publishes immediately"
expect_job_match "${RELEASE}" "sbom-and-release" "make_latest: 'false'" "draft staging does not move latest"
expect_match "${RELEASE}" '^  publish-release:' "release workflow has a publish-release job"
expect_job_match "${RELEASE}" "publish-release" 'needs: \[sbom-and-release, artifact-e2e, docker-build-push\]' "publish job waits for artifacts and image"
expect_job_match "${RELEASE}" "publish-release" 'gh release edit' "publish job edits the staged release"
expect_job_match "${RELEASE}" "publish-release" '\-\-draft=false' "publish job flips the draft"
expect_job_match "${RELEASE}" "publish-release" 'contents: write' "publish job can publish the release"
expect_job_absent "${RELEASE}" "publish-release" 'continue-on-error' "release publication cannot continue on error"
expect_job_match "${RELEASE}" "artifact-e2e" 'contents: write' "artifact E2E can read the staged draft"
expect_match "${ARTIFACT_E2E}" '^  contents: write' "artifact E2E workflow requests draft access"
expect_match "${ARTIFACT_E2E}" 'could not remove.*cannot overwrite digest' "image removal failure is reported"

expect_job_match "${RELEASE}" "docker-build-push" 'aquasec/trivy:[0-9.]+@sha256:[0-9a-f]{64}' "image scanner is pinned by digest"
expect_job_match "${RELEASE}" "docker-build-push" 'severity HIGH,CRITICAL' "image scan gates on HIGH/CRITICAL"
expect_job_match "${RELEASE}" "docker-build-push" 'exit-code 1' "image scan fails the release"
expect_job_match "${RELEASE}" "docker-build-push" 'cosign sign --yes' "image digest is signed with cosign"
expect_job_match "${RELEASE}" "docker-build-push" 'cosign verify' "image signature is verified"
expect_job_match "${RELEASE}" "docker-build-push" 'provenance: true' "image provenance is retained"
expect_job_match "${RELEASE}" "docker-build-push" 'sbom: true' "image SBOM attestation is retained"
expect_job_match "${RELEASE}" "docker-build-push" 'id-token: write' "image signing can use GitHub OIDC"
expect_job_absent "${RELEASE}" "docker-build-push" 'continue-on-error' "image scanning/signing cannot continue on error"

expect_match "${CI}" 'branches: \[main, release/1\.9\.x\]' "CI runs on the release branch"
expect_match "${SECURITY}" 'branches: \[main, release/1\.9\.x\]' "security runs on the release branch"
expect_match "${CI}" 'bash contrib/tests/test-installer\.sh' "CI runs the installer E2E"
expect_match "${CI}" "needs.changes.outputs.workflows == 'true'" "contrib job runs when workflows change"

expect_match "${INSTALLER}" 'SITO_REQUIRE_SIGNATURE:-1' "release signatures are required by default"
expect_match "${INSTALLER}" 'must be 0 or 1' "signature policy values are validated"
expect_match "${INSTALLER}" 'install_binary_atomic "\$\{TMP_DIR\}/sito"' "release binary uses the atomic installer"
expect_match "${INSTALLER}" 'install_binary_atomic "target/release/sito"' "local binary uses the atomic installer"
expect_absent "${INSTALLER}" '^[[:space:]]*cp[[:space:]].*"\$\{INSTALL_BIN\}"[[:space:]]*$' "installer never copies over the live binary"

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
