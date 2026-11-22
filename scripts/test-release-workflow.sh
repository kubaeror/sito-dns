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
FUZZ="${ROOT}/.github/workflows/fuzz.yml"
BENCH="${ROOT}/.github/workflows/bench.yml"
INSTALLER="${ROOT}/contrib/install.sh"
GATE_SCRIPT="${ROOT}/scripts/verify-release-gate.sh"
RELEASE_DOC="${ROOT}/docs/release-verification.md"
CI_DOC="${ROOT}/docs/ci.md"

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

# Prints one `- name:` step body so a policy check cannot be satisfied by a
# different step in the same job. Steps in this workflow are indented six
# spaces and the body runs until the next step starts.
step_section() {
    local step="$1" file="$2"
    awk -v header="      - name: ${step}" '
        $0 == header { in_step = 1; next }
        in_step && /^      - name: / { exit }
        in_step { print }
    ' "${file}"
}

expect_step_match() {
    local file="$1" step="$2" pattern="$3" message="$4"
    if ! step_section "${step}" "${file}" | grep -E -- "${pattern}" >/dev/null; then
        echo "not ok - ${message}" >&2
        failures=$((failures + 1))
    else
        echo "ok - ${message}"
    fi
}

expect_step_absent() {
    local file="$1" step="$2" pattern="$3" message="$4"
    if step_section "${step}" "${file}" | grep -E -- "${pattern}" >/dev/null; then
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
# The gate script is the single definition of the required check set. Assert
# the set here so a silent widening/narrowing is caught without re-testing the
# E6 pagination behavior (that lives in test-verify-release-gate.sh).
expect_match "${GATE_SCRIPT}" 'required = \("ci-gate", "cargo-deny"\)' "the release gate requires exactly ci-gate and cargo-deny"
expect_match "${GATE_SCRIPT}" 'git merge-base --is-ancestor' "the release gate enforces branch ancestry"
expect_match "${RELEASE}" 'needs: \[verify-tag, release-gate\]' "build job depends on the release gate"
expect_absent "${RELEASE}" 'test-hooks' "release workflow never enables test hooks"
expect_absent "${RELEASE}" '--all-features' "release workflow never builds with all features"
expect_absent "${ROOT}/Dockerfile" 'test-hooks' "release image never enables test hooks"
expect_absent "${ROOT}/Dockerfile" '--all-features' "release image never builds with all features"
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
expect_job_match "${RELEASE}" "artifact-e2e" '^      contents: write$' "artifact E2E can read the staged draft"
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

# The vulnerability gate must cover every platform the image index promises.
SCAN_STEP="Scan the published image for vulnerabilities"
expect_step_match "${RELEASE}" "${SCAN_STEP}" 'linux/amd64' "image scan covers linux/amd64"
expect_step_match "${RELEASE}" "${SCAN_STEP}" 'linux/arm64' "image scan covers linux/arm64"
expect_step_match "${RELEASE}" "${SCAN_STEP}" 'linux/arm/v7' "image scan covers linux/arm/v7"
expect_step_match "${RELEASE}" "${SCAN_STEP}" 'platforms=\(linux/amd64 linux/arm64 linux/arm/v7\)' "image scan lists the three promised platforms in one set"
expect_step_match "${RELEASE}" "${SCAN_STEP}" 'for platform in "\$\{platforms\[@\]\}"; do' "image scan loops over every platform"
expect_step_match "${RELEASE}" "${SCAN_STEP}" '--platform "\$\{platform\}"' "image scan passes the loop platform to Trivy"
# A hardcoded single platform would silently restore the amd64-only gate.
expect_step_absent "${RELEASE}" "${SCAN_STEP}" '--platform linux/amd64' "image scan does not hardcode linux/amd64 as the only platform"
expect_step_match "${RELEASE}" "${SCAN_STEP}" 'severity HIGH,CRITICAL' "per-platform scan keeps the HIGH/CRITICAL gate"
expect_step_match "${RELEASE}" "${SCAN_STEP}" 'ignore-unfixed' "per-platform scan still ignores unfixed findings"
expect_step_match "${RELEASE}" "${SCAN_STEP}" 'exit-code 1' "per-platform scan fails the release"
expect_step_match "${RELEASE}" "${SCAN_STEP}" '\$\{HOME\}/\.docker:/root/\.docker:ro' "per-platform scan keeps the read-only Docker config mount"
expect_step_match "${RELEASE}" "${SCAN_STEP}" '"\$\{IMAGE\}@\$\{DIGEST\}"' "per-platform scan pulls the pushed digest"
expect_step_absent "${RELEASE}" "${SCAN_STEP}" ':latest' "per-platform scan never scans a mutable latest tag"
expect_step_absent "${RELEASE}" "${SCAN_STEP}" 'continue-on-error' "per-platform scan cannot continue on error"
expect_step_absent "${RELEASE}" "${SCAN_STEP}" 'deferred' "per-platform scan is no longer deferred"

expect_match "${CI}" 'branches: \[main, release/1\.9\.x\]' "CI runs on the release branch"
expect_match "${SECURITY}" 'branches: \[main, release/1\.9\.x\]' "security runs on the release branch"
expect_match "${CI}" 'bash contrib/tests/test-installer\.sh' "CI runs the installer E2E"
expect_job_match "${RELEASE}" "build-binaries" 'cp contrib/install\.sh "\$\{ARCHIVE_DIR\}/contrib/"' "release archive ships contrib/install.sh"
expect_job_match "${RELEASE}" "build-binaries" 'cp contrib/systemd/sito\.service' "release archive ships contrib/systemd/sito.service"
expect_match "${ARTIFACT_E2E}" 'contrib/install\.sh' "artifact E2E checks the archived installer"
expect_match "${ARTIFACT_E2E}" 'contrib/systemd/sito\.service' "artifact E2E checks the archived systemd unit"
expect_match "${CI}" "needs.changes.outputs.workflows == 'true'" "contrib job runs when workflows change"

# WP-1.9: the long fuzz/benchmark runs stay out of PR CI, but their structural
# gates and the aggregate check must exist.
expect_match "${CI}" '^  bench-build:' "CI has a benchmark compile job"
expect_match "${CI}" '^  fuzz-build:' "CI has a fuzz target build job"
expect_match "${CI}" '^  hygiene:' "CI has a machete/udeps job"
expect_match "${CI}" '^  coverage:' "CI has a coverage job"
expect_match "${CI}" '^  ha-matrix:' "CI has a no-HA/HA feature matrix job"
expect_job_match "${CI}" "ha-matrix" 'cargo tree -p sito -p sito-api -p sito-test --no-default-features' "the HA matrix asserts the default workspace crates are HA-free"
expect_match "${CI}" 'needs: \[changes, fmt, clippy, test, build, openapi, contrib, docs-check, container-check, security-check, bench-build, fuzz-build, hygiene, coverage, ha-matrix\]' "ci-gate requires the new jobs"
expect_match "${CI}" 'cargo bench --workspace --all-features --locked --no-run' "CI compiles the benches"
expect_absent "${FUZZ}" 'pull_request' "fuzzing is not a pull-request trigger"
expect_absent "${BENCH}" 'pull_request' "the thresholded benchmark gate is not a pull-request trigger"
expect_match "${FUZZ}" 'fuzz_seconds' "the fuzz workflow accepts a manual duration"
expect_match "${FUZZ}" 'shards' "the fuzz workflow supports GitHub-hosted shards"
expect_match "${FUZZ}" '17280' "the fuzz workflow caps each shard below the 6-hour GitHub-hosted limit"
expect_match "${BENCH}" 'scripts/check-bench-regression\.py' "the bench workflow runs the regression gate"
expect_match "${BENCH}" 'BENCH_TOLERANCE' "the bench tolerance is configurable"
expect_match "${BENCH}" 'ubuntu-24\.04' "the bench workflow uses GitHub-hosted runners"
expect_match "${BENCH}" 'update_baseline' "the bench workflow can regenerate the baseline on GitHub"

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

# The release checklist is the 2.0 gate record. Keep each release-blocking
# gate named so a documentation edit cannot silently drop a lane. Detailed
# E4/E5/E6 internals stay in their own policy tests; this only pins the
# checklist's coverage.
expect_match "${RELEASE_DOC}" '^## 2\.0 release gate checklist$' "the release checklist is explicitly titled for 2.0"
expect_match "${RELEASE_DOC}" 'Scan the published image for vulnerabilities' "the checklist names the per-architecture image scan (E4)"
expect_match "${RELEASE_DOC}" 'ha-ownership\.yml' "the checklist names the root-gated HA ownership lane (E5)"
expect_match "${RELEASE_DOC}" 'fuzz_seconds=17280' "the checklist names the 24-hour fuzz campaign"
expect_match "${RELEASE_DOC}" 'bench\.yml' "the checklist names the thresholded benchmark gate"
expect_match "${RELEASE_DOC}" 'test-migration-1\.9\.5\.sh' "the checklist names the 1.9.5 migration and rollback E2E"
expect_match "${RELEASE_DOC}" 'test-docker-upgrade\.sh' "the checklist names the Docker upgrade and rollback E2E"
expect_match "${RELEASE_DOC}" 'latest.*stays on 1\.9\.5' "the checklist keeps latest on 1.9.5 until the final tag"
expect_match "${RELEASE_DOC}" 'check_test_matrix\.py' "the checklist includes the docs-truth test-matrix check"
expect_match "${CI_DOC}" 'check_test_matrix\.py' "docs/ci.md documents the test-matrix docs check"
expect_match "${CI_DOC}" 'scans each promised platform' "docs/ci.md documents the per-architecture image scan"

# The fuzz matrix shape, job timeout headroom and documented 24h recipe are
# checked by the fuzz-specific policy test.
python3 "${ROOT}/scripts/test-fuzz-workflow.py"

if [ "${failures}" -ne 0 ]; then
    echo "${failures} release workflow check(s) failed" >&2
    exit 1
fi
echo "release workflow policy OK"
