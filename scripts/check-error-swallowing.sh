#!/usr/bin/env bash
# D14: enforce a reviewed allowlist for best-effort error swallowing.
#
# This is deliberately narrower than "all `let _ =`/`.ok()` calls": the codebase
# has hundreds of benign probe/cleanup sites. It flags swallowing around calls
# that mutate durable state or report health (fsync/rename/permissions/persist/
# publish/secret writes/reload/shutdown/lease/bootstrap/readiness/health and
# lock/unlock). Every flagged production site must appear in
# scripts/error-swallowing-allowlist.txt (tab-separated) with the exact source
# text, and every allowlist entry must have a reason in
# docs/audit6-best-effort.md.
#
# The scanner skips inline `#[cfg(test)]` items and `tests/` targets; tests may
# intentionally exercise failure cleanup without production error policy.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ALLOWLIST="${ROOT}/scripts/error-swallowing-allowlist.txt"
cd "${ROOT}"

if [[ ! -f "${ALLOWLIST}" ]]; then
    echo "missing allowlist: ${ALLOWLIST}" >&2
    exit 2
fi

matches="$(mktemp)"
keys="$(mktemp)"
trap 'rm -f "${matches}" "${keys}"' EXIT

# Fixture tests for the statement-aware scanner (multi-line statements,
# cfg(test) ranges, formatting-macro arguments).
python3 "${ROOT}/scripts/test-error-swallowing.py"

python3 "${ROOT}/scripts/find-error-swallowing.py" "${ROOT}" >"${matches}"

# Allowlist entries are tab-separated `path<TAB>source text<TAB>reason`. Build `path<TAB>source text`
# keys, trimming surrounding whitespace on both sides.
grep -v '^#' "${ALLOWLIST}" | grep -v '^[[:space:]]*$' |
    awk -F'\t' '{key=$1 "\t" $2; gsub(/^[[:space:]]+|[[:space:]]+$/, "", key); print key}' >"${keys}"

fail=0
while IFS= read -r line; do
    [[ -z "${line}" ]] && continue
    path="${line%%:*}"
    rest="${line#*:}"
    content="${rest#*:}"
    content="$(printf '%s' "${content}" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
    key="${path}	${content}"
    if ! grep -Fqx -- "${key}" "${keys}"; then
        echo "UNREVIEWED error swallowing: ${line}" >&2
        fail=1
    fi
done <"${matches}"

if [[ "${fail}" -ne 0 ]]; then
    echo "" >&2
    echo "Add the exact site to scripts/error-swallowing-allowlist.txt and a reason" >&2
    echo "to docs/audit6-best-effort.md, or handle the error explicitly." >&2
    exit 1
fi

echo "error-swallowing check: all reviewed (allowlist: ${ALLOWLIST})"
