#!/usr/bin/env bash
# Static policy checks for the root-gated HA ownership lane.
#
# The lane is the only place a root-only acceptance test runs. It is easy to
# break silently: move it to a pull request, drop `sudo -E`, lose the cargo
# environment, add `continue-on-error`, or let the wrapper run zero tests. These
# checks fail on each of those shapes without needing a root runner.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
WORKFLOW="${ROOT}/.github/workflows/ha-ownership.yml"
WRAPPER="${ROOT}/scripts/test-ha-ownership-root.sh"
CI="${ROOT}/.github/workflows/ci.yml"
CI_DOC="${ROOT}/docs/ci.md"
RELEASE_DOC="${ROOT}/docs/release-verification.md"

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

# --- The lane exists, is manual (plus optional schedule), and is least privilege.

if [ ! -f "${WORKFLOW}" ]; then
    echo "not ok - ${WORKFLOW} is missing" >&2
    exit 1
fi
echo "ok - the root-gated HA ownership workflow exists"

expect_match "${WORKFLOW}" '^on:' "the workflow has a trigger block"
expect_match "${WORKFLOW}" '^  workflow_dispatch:' "the lane can be dispatched manually"
expect_match "${WORKFLOW}" '^  schedule:' "the lane also has a weekly drift trigger"
expect_absent "${WORKFLOW}" '^  pull_request:' "the lane is not a pull-request trigger"
expect_absent "${WORKFLOW}" '^  push:' "the lane is not a push trigger"
expect_absent "${WORKFLOW}" 'merge_group' "the lane is not part of the merge queue"
expect_absent "${WORKFLOW}" 'workflow_call' "normal CI cannot call the root lane"

expect_match "${WORKFLOW}" '^permissions:' "the workflow declares permissions"
expect_match "${WORKFLOW}" '^  contents: read$' "the lane only reads repository contents"
expect_match "${WORKFLOW}" '^    runs-on: ubuntu-24\.04$' "the lane uses the pinned runner image"
expect_match "${WORKFLOW}" '^    timeout-minutes: ([1-9]|[12][0-9]|30)$' "the lane times out within 30 minutes"
expect_absent "${WORKFLOW}" '^[[:space:]]*if:' "no job or step can be skipped by a condition"
expect_absent "${WORKFLOW}" 'continue-on-error' "the lane cannot continue on error"
expect_absent "${WORKFLOW}" '^\s*\|\|\s*true' "a failing command is never masked with || true"

# --- The pinned toolchain and the root wrapper invocation.

expect_match "${WORKFLOW}" 'dtolnay/rust-toolchain@[0-9a-f]{40}' "the toolchain action is SHA-pinned"
expect_match "${WORKFLOW}" 'toolchain: 1\.99\.1' "the lane uses the CI toolchain version"
expect_match "${WORKFLOW}" 'actions/checkout@[0-9a-f]{40}' "checkout is SHA-pinned"
expect_match "${WORKFLOW}" 'bash scripts/test-ha-ownership-root\.sh' "the lane runs the root wrapper"

# Root's environment must survive sudo: PATH, CARGO_HOME and RUSTUP_HOME are
# what make the pinned cargo/rustc visible, and the explicit target dir keeps
# root from writing to /root.
expect_match "${WORKFLOW}" 'sudo -E env' "the wrapper runs under sudo with the preserving env"
expect_match "${WORKFLOW}" 'PATH="\$PATH"' "the root run preserves PATH"
expect_match "${WORKFLOW}" 'CARGO_HOME="\$CARGO_HOME"' "the root run preserves CARGO_HOME"
expect_match "${WORKFLOW}" 'RUSTUP_HOME="\$RUSTUP_HOME"' "the root run preserves RUSTUP_HOME"
expect_match "${WORKFLOW}" 'CARGO_TARGET_DIR="\$GITHUB_WORKSPACE/target"' "the root run uses the workspace target dir"
expect_match "${WORKFLOW}" 'CARGO_HOME=\$\{CARGO_HOME:-\$HOME/\.cargo\}' "the lane resolves a non-empty CARGO_HOME"
expect_match "${WORKFLOW}" 'RUSTUP_HOME=\$\{RUSTUP_HOME:-\$HOME/\.rustup\}' "the lane resolves a non-empty RUSTUP_HOME"

# Every `uses:` line in the new workflow must be pinned to a full commit SHA.
unpinned="$(grep -hE '^[[:space:]]*(-[[:space:]]*)?uses:' "${WORKFLOW}" |
    grep -v 'uses: \./' |
    grep -vE '@[0-9a-f]{40}([[:space:]]|$)' || true)"
if [ -n "${unpinned}" ]; then
    echo "not ok - unpinned action reference(s):" >&2
    printf '%s\n' "${unpinned}" | sed 's/^/    /' >&2
    failures=$((failures + 1))
else
    echo "ok - every action in the lane is SHA-pinned"
fi

# --- The wrapper cannot be turned into a skip.

expect_match "${WRAPPER}" 'id -u' "the wrapper inspects the effective uid"
expect_match "${WRAPPER}" 'exit 1' "the wrapper fails instead of skipping"
expect_match "${WRAPPER}" 'test_m8_root_owned_key_chown_activates_ha' "the wrapper names the m8 ownership test"
expect_match "${WRAPPER}" 'features ha' "the wrapper enables the HA feature that makes the target non-empty"
expect_match "${WRAPPER}" '\-\-locked' "the wrapper uses the locked dependency set"
expect_match "${WRAPPER}" 'test result: ok\\\. 1 passed' "the wrapper requires exactly one passing test"
expect_match "${WRAPPER}" 'did not run exactly once' "the wrapper explains a zero-test failure"

# --- The lane stays out of the pull-request gate but its policy test runs in CI.

expect_absent "${CI}" 'uses: \./\.github/workflows/ha-ownership\.yml' "the PR CI workflow does not call the root lane"
expect_absent "${CI}" 'bash scripts/test-ha-ownership-root\.sh' "the PR CI workflow does not run the root wrapper"
expect_absent "${CI}" '^      - ha-ownership$' "the ci-gate dependency list does not include the root lane"
expect_match "${CI}" 'bash scripts/test-ha-ownership-workflow\.sh' "CI runs this static policy test"

expect_match "${CI_DOC}" 'ha-ownership\.yml' "docs/ci.md documents the lane"
expect_match "${RELEASE_DOC}" 'ha-ownership\.yml' "docs/release-verification.md makes the lane 2.0 evidence"

if [ "${failures}" -ne 0 ]; then
    echo "${failures} HA ownership workflow check(s) failed" >&2
    exit 1
fi
echo "HA ownership workflow policy OK"
