#!/usr/bin/env bash
# Focused tests for scripts/verify-release-gate.sh. Runs offline against a
# temporary git repository and a fake `gh` that serves check-run JSON.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GATE="${SCRIPT_DIR}/verify-release-gate.sh"

tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT

repo="${tmp}/repo"
fakebin="${tmp}/bin"
mkdir -p "${repo}" "${fakebin}"

git -C "${repo}" init -q
git -C "${repo}" config user.email test@example.com
git -C "${repo}" config user.name "Release Gate Test"

printf 'base\n' >"${repo}/VERSION"
git -C "${repo}" add VERSION
git -C "${repo}" commit -q -m base
git -C "${repo}" branch -M release/1.9.x
git -C "${repo}" branch main release/1.9.x
git -C "${repo}" tag v1.9.4

# A tag from a side branch that is not an ancestor of the release branch.
git -C "${repo}" checkout -q -b side
printf 'side\n' >"${repo}/SIDE"
git -C "${repo}" add SIDE
git -C "${repo}" commit -q -m side
git -C "${repo}" tag v1.9.4-side
git -C "${repo}" checkout -q release/1.9.x

cat >"${fakebin}/gh" <<'SH'
#!/usr/bin/env bash
case "$*" in
    *check-runs*) cat "${FAKE_CHECKS_FILE}" ;;
    *status*) cat "${FAKE_STATUS_FILE}" ;;
    *) echo "unexpected gh invocation: $*" >&2; exit 1 ;;
esac
SH
chmod +x "${fakebin}/gh"

green_checks="${tmp}/green-checks.json"
red_checks="${tmp}/red-checks.json"
missing_checks="${tmp}/missing-checks.json"
green_status="${tmp}/green-status.json"
red_status="${tmp}/red-status.json"

cat >"${green_checks}" <<'JSON'
[{"total_count":3,"check_runs":[
  {"name":"ci-gate","status":"completed","conclusion":"success"},
  {"name":"cargo-deny","status":"completed","conclusion":"success"},
  {"name":"release-gate","status":"in_progress","conclusion":null}
]}]
JSON
cat >"${red_checks}" <<'JSON'
[{"total_count":2,"check_runs":[
  {"name":"ci-gate","status":"completed","conclusion":"failure"},
  {"name":"cargo-deny","status":"completed","conclusion":"success"}
]}]
JSON
cat >"${missing_checks}" <<'JSON'
[{"total_count":1,"check_runs":[
  {"name":"ci-gate","status":"completed","conclusion":"success"}
]}]
JSON
cat >"${green_status}" <<'JSON'
{"state":"success","statuses":[]}
JSON
cat >"${red_status}" <<'JSON'
{"state":"failure","statuses":[{"context":"security-scan","state":"failure"}]}
JSON

run_gate() {
    (
        cd "${repo}"
        PATH="${fakebin}:${PATH}" \
            RELEASE_TAG="${case_tag}" \
            GITHUB_REPOSITORY="example/sito" \
            GH_TOKEN="test-token" \
            RELEASE_REQUIRED_BRANCH="${case_branch:-release/1.9.x}" \
            SITO_GATE_SKIP_FETCH=1 \
            FAKE_CHECKS_FILE="${case_checks}" \
            FAKE_STATUS_FILE="${case_status}" \
            bash "${GATE}"
    )
}

failures=0
cases=0
check_case() {
    local name="$1"
    local expected_rc="$2"
    local output rc

    cases=$((cases + 1))
    set +e
    output="$(run_gate 2>&1)"
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

case_tag="v1.9.4"; case_checks="${green_checks}"; case_status="${green_status}"
check_case "accepts a tag on the required branch with green checks" 0

case_tag="v1.9.4"; case_checks="${red_checks}"; case_status="${green_status}"
check_case "rejects a red ci-gate check" 1

case_tag="v1.9.4"; case_checks="${missing_checks}"; case_status="${green_status}"
check_case "rejects a missing security check" 1

case_tag="v1.9.4"; case_checks="${green_checks}"; case_status="${red_status}"
check_case "rejects a red legacy status" 1

case_tag="v1.9.4-side"; case_checks="${green_checks}"; case_status="${green_status}"
check_case "rejects a tag from a non-required branch" 1

case_tag="v1.9.4"; case_checks="${green_checks}"; case_status="${green_status}"
case_branch="release/1.9.x"
check_case "accepts an explicit branch override" 0
unset case_branch

echo "${cases} cases, ${failures} failure(s)"
if [ "${failures}" -ne 0 ]; then
    exit 1
fi
