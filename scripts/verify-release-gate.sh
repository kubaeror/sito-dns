#!/usr/bin/env bash
# Release gate: refuse to publish a tag unless its commit is on the required
# release branch and that commit has green CI and security checks.
#
# The branch mapping is intentionally explicit:
#   * 1.9.x releases are cut from `release/1.9.x`
#   * 2.0+ releases are cut from `main`
#
# Required checks are the aggregate CI gate (`ci-gate`) and the security
# workflow's `cargo-deny` job. Other check runs on the commit (including the
# release workflow currently publishing the tag) are ignored so a tag push does
# not fail on its own in-progress jobs.
#
# Environment:
#   RELEASE_TAG             Tag being published (for example v1.9.4). Required.
#   GITHUB_REPOSITORY       owner/repo. Required for the checks API.
#   GH_TOKEN / GITHUB_TOKEN Token used by `gh api`.
#   RELEASE_REQUIRED_BRANCH Override the derived branch (tests/ops escape hatch).
#   SITO_GATE_SKIP_FETCH=1  Do not fetch the branch from origin (tests/offline).
set -euo pipefail

tag="${RELEASE_TAG:-}"
if [ -z "${tag}" ]; then
    echo "::error::RELEASE_TAG is required" >&2
    exit 1
fi

repo="${GITHUB_REPOSITORY:-${REPO:-}}"
if [ -z "${repo}" ]; then
    echo "::error::GITHUB_REPOSITORY is required" >&2
    exit 1
fi

version="${tag#v}"
version="${version%%-*}"
required_branch="${RELEASE_REQUIRED_BRANCH:-}"
if [ -z "${required_branch}" ]; then
    case "${version}" in
        1.9.*) required_branch="release/1.9.x" ;;
        2.*) required_branch="main" ;;
        *)
            echo "::error::no required release branch is configured for version ${version}" >&2
            exit 1
            ;;
    esac
fi

if ! git rev-parse --git-dir >/dev/null 2>&1; then
    echo "::error::verify-release-gate.sh must run inside a git checkout" >&2
    exit 1
fi

tag_commit="$(git rev-parse --verify "refs/tags/${tag}^{commit}" 2>/dev/null || true)"
if [ -z "${tag_commit}" ]; then
    echo "::error::tag ${tag} does not exist in this checkout" >&2
    exit 1
fi

resolve_branch_ref() {
    local candidate
    for candidate in \
        "refs/remotes/origin/${required_branch}" \
        "origin/${required_branch}" \
        "refs/heads/${required_branch}" \
        "${required_branch}"; do
        if git rev-parse --verify "${candidate}^{commit}" >/dev/null 2>&1; then
            printf '%s\n' "${candidate}"
            return 0
        fi
    done
    return 1
}

branch_ref="$(resolve_branch_ref || true)"
if [ -z "${branch_ref}" ] && [ "${SITO_GATE_SKIP_FETCH:-0}" != "1" ]; then
    if git remote get-url origin >/dev/null 2>&1; then
        git fetch --no-tags origin \
            "refs/heads/${required_branch}:refs/remotes/origin/${required_branch}" || true
        branch_ref="$(resolve_branch_ref || true)"
    fi
fi

if [ -z "${branch_ref}" ]; then
    echo "::error::required release branch '${required_branch}' is not available" >&2
    exit 1
fi

branch_commit="$(git rev-parse --verify "${branch_ref}^{commit}")"
if ! git merge-base --is-ancestor "${tag_commit}" "${branch_commit}"; then
    echo "::error::tag ${tag} (${tag_commit}) is not on ${required_branch} (${branch_commit})" >&2
    exit 1
fi
echo "tag ${tag} is on ${required_branch}"

if ! command -v gh >/dev/null 2>&1; then
    echo "::error::the GitHub CLI 'gh' is required to verify check runs" >&2
    exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
    echo "::error::python3 is required to parse check-run responses" >&2
    exit 1
fi

tmp_dir="$(mktemp -d)"
trap 'rm -rf "${tmp_dir}"' EXIT
checks_file="${tmp_dir}/checks.json"
statuses_file="${tmp_dir}/statuses.json"

gh api --paginate --slurp \
    "repos/${repo}/commits/${tag_commit}/check-runs?per_page=100" >"${checks_file}"
gh api "repos/${repo}/commits/${tag_commit}/status" >"${statuses_file}"

python3 - "${checks_file}" "${statuses_file}" "${tag_commit}" <<'PY'
import json
import sys

checks_path, statuses_path, sha = sys.argv[1:4]

with open(checks_path, encoding="utf-8") as handle:
    pages = json.load(handle)
if isinstance(pages, dict):
    pages = [pages]
runs = []
for page in pages:
    runs.extend(page.get("check_runs", []))

required = ("ci-gate", "cargo-deny")
bad = {"failure", "cancelled", "timed_out", "action_required", "stale"}
success = set()
failures = []

for run in runs:
    name = run.get("name", "<unnamed>")
    if name not in required:
        continue
    if run.get("status") != "completed":
        failures.append(f"{name} is {run.get('status')}")
    elif run.get("conclusion") == "success":
        success.add(name)
    elif run.get("conclusion") in bad:
        failures.append(f"{name} concluded {run.get('conclusion')}")

for name in required:
    if name not in success and not any(item.startswith(f"{name} ") for item in failures):
        failures.append(f"{name} is missing")

with open(statuses_path, encoding="utf-8") as handle:
    status_payload = json.load(handle)
for status in status_payload.get("statuses", []):
    state = status.get("state")
    if state in ("failure", "error"):
        failures.append(
            f"legacy status {status.get('context', '<unknown>')} is {state}"
        )

if failures:
    print("::error::release gate failed for commit " + sha, file=sys.stderr)
    for failure in failures:
        print(f"::error::{failure}", file=sys.stderr)
    sys.exit(1)

print(f"release checks are green for {sha}: {', '.join(required)}")
PY
