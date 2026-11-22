#!/usr/bin/env bash
# Focused tests for scripts/verify-release-gate.sh. Runs offline against a
# temporary git repository and a fake `gh` that serves check-run JSON. The fake
# can emulate both pagination shapes: `--slurp` (one JSON array) and older `gh`
# releases without `--slurp` (concatenated JSON objects), plus API failures.
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
git -C "${repo}" tag v1.9.4
# A different branch that does contain the tag commit, used to prove the
# RELEASE_REQUIRED_BRANCH override is actually consulted.
git -C "${repo}" branch stable release/1.9.x
# A different branch that does not contain the tag commit.
git -C "${repo}" checkout -q --orphan main
git -C "${repo}" rm -rf . >/dev/null 2>&1 || true
printf 'main-only\n' >"${repo}/MAIN"
git -C "${repo}" add MAIN
git -C "${repo}" commit -q -m main-only
# 2.0 releases (stable and prerelease) are cut from the tested `main` history.
printf 'tested-main\n' >>"${repo}/MAIN"
git -C "${repo}" add MAIN
git -C "${repo}" commit -q -m tested-main
git -C "${repo}" tag v2.0.0
git -C "${repo}" tag v2.0.0-alpha.1
git -C "${repo}" checkout -q release/1.9.x

# A tag from a side branch that is not an ancestor of the release branch.
git -C "${repo}" checkout -q -b side
printf 'side\n' >"${repo}/SIDE"
git -C "${repo}" add SIDE
git -C "${repo}" commit -q -m side
git -C "${repo}" tag v1.9.4-side
git -C "${repo}" checkout -q release/1.9.x

cat >"${fakebin}/gh" <<'SH'
#!/usr/bin/env bash
# FAKE_GH_MODE:
#   slurp          supports --slurp and serves one JSON array (default)
#   no-slurp       rejects --slurp like an older gh and concatenates pages
#   no-slurp-error rejects --slurp, then fails the retry with an API error
#   api-error      fails every call with an authentication error
set -euo pipefail
mode="${FAKE_GH_MODE:-slurp}"
case "$*" in
    *check-runs*)
        case "${mode}" in
            slurp)
                case " $* " in
                    *" --slurp "*) cat "${FAKE_CHECKS_FILE}" ;;
                    *)
                        echo "fake gh: expected --slurp in slurp mode" >&2
                        exit 1
                        ;;
                esac
                ;;
            no-slurp | no-slurp-error)
                case " $* " in
                    *" --slurp "*)
                        echo "unknown flag: --slurp" >&2
                        exit 1
                        ;;
                esac
                if [ "${mode}" = "no-slurp-error" ]; then
                    echo "HTTP 401: Bad credentials (https://api.github.com)" >&2
                    exit 1
                fi
                cat "${FAKE_CHECKS_FILE}"
                ;;
            api-error)
                echo "HTTP 401: Bad credentials (https://api.github.com)" >&2
                exit 1
                ;;
            *)
                echo "fake gh: unknown mode ${mode}" >&2
                exit 1
                ;;
        esac
        ;;
    *status*) cat "${FAKE_STATUS_FILE}" ;;
    *) echo "unexpected gh invocation: $*" >&2; exit 1 ;;
esac
SH
chmod +x "${fakebin}/gh"

green_checks="${tmp}/green-checks.json"
red_checks="${tmp}/red-checks.json"
missing_checks="${tmp}/missing-checks.json"
single_checks="${tmp}/single-checks.json"
paged_green_checks="${tmp}/paged-green-checks.ndjson"
paged_red_checks="${tmp}/paged-red-checks.ndjson"
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
# Some `gh` versions return a single page object instead of an array.
cat >"${single_checks}" <<'JSON'
{"total_count":2,"check_runs":[
  {"name":"ci-gate","status":"completed","conclusion":"success"},
  {"name":"cargo-deny","status":"completed","conclusion":"success"}
]}
JSON
# Plain `gh api --paginate` concatenates one JSON object per page. The required
# checks are split across the pages to prove the parser reads all of them.
cat >"${paged_green_checks}" <<'JSON'
{"total_count":2,"check_runs":[
  {"name":"ci-gate","status":"completed","conclusion":"success"}
]}
{"total_count":2,"check_runs":[
  {"name":"cargo-deny","status":"completed","conclusion":"success"},
  {"name":"release-gate","status":"in_progress","conclusion":null}
]}
JSON
cat >"${paged_red_checks}" <<'JSON'
{"total_count":1,"check_runs":[
  {"name":"cargo-deny","status":"completed","conclusion":"success"}
]}
{"total_count":1,"check_runs":[
  {"name":"ci-gate","status":"completed","conclusion":"failure"}
]}
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
            RELEASE_REQUIRED_BRANCH="${case_branch:-}" \
            SITO_GATE_SKIP_FETCH=1 \
            FAKE_GH_MODE="${case_mode:-slurp}" \
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
    local expected_pattern="${3:-}"
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
    elif [ -n "${expected_pattern}" ] &&
        ! printf '%s\n' "${output}" | grep -Eq -- "${expected_pattern}"; then
        echo "not ok - ${name}: output did not match ${expected_pattern}"
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
case_branch="stable"
check_case "accepts a different branch override that contains the tag" 0

case_tag="v1.9.4"; case_checks="${green_checks}"; case_status="${green_status}"
case_branch="main"
check_case "rejects a different branch override that does not contain the tag" 1
unset case_branch

# 2.0 stable/prerelease tags must resolve to `main` without an override.
case_tag="v2.0.0"; case_checks="${green_checks}"; case_status="${green_status}"
check_case "accepts v2.0.0 on tested main with green checks" 0

case_tag="v2.0.0-alpha.1"; case_checks="${green_checks}"; case_status="${green_status}"
check_case "accepts v2.0.0-alpha.1 on tested main with green checks" 0

case_tag="v2.0.0-alpha.1"; case_checks="${red_checks}"; case_status="${green_status}"
check_case "rejects a v2.0.0-alpha.1 tag without green checks" 1

case_tag="v2.0.0"; case_checks="${green_checks}"; case_status="${green_status}"
case_branch="release/1.9.x"
check_case "rejects v2.0.0 when forced onto the 1.9 release branch" 1
unset case_branch

# Newer gh: `--slurp` returns one JSON array and must keep working.
case_tag="v1.9.4"; case_checks="${green_checks}"; case_status="${green_status}"
check_case "accepts green checks with --slurp pagination" 0

case_tag="v1.9.4"; case_checks="${red_checks}"; case_status="${green_status}"
check_case "rejects red checks with --slurp pagination" 1

case_tag="v1.9.4"; case_checks="${single_checks}"; case_status="${green_status}"
check_case "accepts a single check-run page object" 0

# Older gh: `--slurp` is unknown, so the gate retries with plain `--paginate`
# and the parser must read concatenated page objects.
case_mode="no-slurp"
case_tag="v1.9.4"; case_checks="${paged_green_checks}"; case_status="${green_status}"
check_case "accepts green checks from concatenated pages without --slurp" 0

case_tag="v1.9.4"; case_checks="${paged_red_checks}"; case_status="${green_status}"
check_case "rejects red checks from concatenated pages without --slurp" 1
unset case_mode

# Authentication/API errors are fatal and must never turn into a green gate.
case_mode="api-error"
case_tag="v1.9.4"; case_checks="${green_checks}"; case_status="${green_status}"
check_case "rejects an authentication error without falling back" 1 \
    "Bad credentials"
unset case_mode

# When the `--slurp`-less retry also fails, the original error is reported.
case_mode="no-slurp-error"
case_tag="v1.9.4"; case_checks="${paged_green_checks}"; case_status="${green_status}"
check_case "rejects an API error during the --slurp fallback" 1 \
    "Bad credentials"
unset case_mode

echo "${cases} cases, ${failures} failure(s)"
if [ "${failures}" -ne 0 ]; then
    exit 1
fi
