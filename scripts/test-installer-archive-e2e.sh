#!/usr/bin/env bash
# Static wiring and policy checks for the archived-installer E2E (E2).
#
# This test is offline and safe for pull-request CI. It pins the shape of
# scripts/test-installer-archive-1.9.5.sh: the network lane must stay gated,
# the checksum must always be verified, signature verification must default to
# required, and the manual workflow/docs must point at the same command.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="${ROOT}/scripts/test-installer-archive-1.9.5.sh"
WORKFLOW="${ROOT}/.github/workflows/archive-installer-e2e.yml"
DOC="${ROOT}/docs/release-verification.md"
CI="${ROOT}/.github/workflows/ci.yml"

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

expect_file() {
    [ -f "$1" ] || fail "missing $1"
}

expect_match() {
    local file="$1" pattern="$2" message="$3"
    grep -Eq -- "${pattern}" "${file}" || fail "${message}"
}

expect_no_match() {
    local file="$1" pattern="$2" message="$3"
    if grep -Eq -- "${pattern}" "${file}"; then
        fail "${message}"
    fi
}

expect_file "${SCRIPT}"
expect_file "${WORKFLOW}"
expect_file "${DOC}"

bash -n "${SCRIPT}" || fail "archived installer E2E has a shell syntax error"

# Network gate: running it without SITO_ARCHIVE_E2E=1 must skip, not download.
expect_match "${SCRIPT}" 'case "\$\{SITO_ARCHIVE_E2E:-0\}" in' \
    "the archive E2E is missing its environment gate"
expect_match "${SCRIPT}" 'Set SITO_ARCHIVE_E2E=1' "the gate does not explain how to run the lane"
expect_match "${SCRIPT}" 'exit 2' "the gate does not exit before network access"
expect_no_match "${SCRIPT}" '^[[:space:]]*SITO_ARCHIVE_E2E=1[[:space:]]*$' \
    "the script must not enable its own network gate"
GATE_LINE="$(grep -n 'case "\${SITO_ARCHIVE_E2E:-0}" in' "${SCRIPT}" | head -n 1 | cut -d: -f1)"
FIRST_DOWNLOAD_LINE="$(grep -n 'download_file "\${BASE_URL}' "${SCRIPT}" | head -n 1 | cut -d: -f1)"
[ -n "${GATE_LINE}" ] || fail "could not locate the network gate"
[ -n "${FIRST_DOWNLOAD_LINE}" ] || fail "could not locate the first release download"
[ "${GATE_LINE}" -lt "${FIRST_DOWNLOAD_LINE}" ] ||
    fail "the network gate must run before the first release download"

# Pin the real release and the real archive/checksum/signature path.
expect_match "${SCRIPT}" 'TAG="\$\{SITO_ARCHIVE_TAG:-v1\.9\.5\}"' "the default release tag is not pinned to v1.9.5"
expect_match "${SCRIPT}" 'SITO_ARCHIVE_E2E=1' "the manual lane is not documented in the script"
expect_match "${SCRIPT}" 'SHA256SUMS' "the script does not download SHA256SUMS"
expect_match "${SCRIPT}" 'grep -F "  \$\{ARCHIVE\}" SHA256SUMS \| sha256sum -c -' \
    "the script does not verify the archive against SHA256SUMS"
expect_match "${SCRIPT}" '"\$\{COSIGN_BIN\}" verify-blob' \
    "the script does not verify the cosign signature with an explicit cosign binary"
expect_match "${SCRIPT}" 'bootstrap_cosign' "the script does not bootstrap an independent cosign"
expect_match "${SCRIPT}" 'cosign_checksums\.txt' "the independent cosign checksum file is missing"
expect_match "${SCRIPT}" 'awk -v asset="\$\{asset\}"' "the independent cosign checksum is not exact"
expect_match "${SCRIPT}" 'certificate-identity "\$\{ARCHIVE_CERT_IDENTITY\}"' \
    "the signature identity is not pinned to the archived tag"
expect_no_match "${SCRIPT}" 'certificate-identity-regexp' \
    "the signature identity must not use a wildcard regexp"
expect_match "${SCRIPT}" 'ARCHIVE_CERT_IDENTITY=.*refs/tags/\$\{TAG\}' \
    "the certificate identity is not derived from the archived tag"
expect_match "${SCRIPT}" 'SITO_REQUIRE_SIGNATURE="\$\{SIGNATURE_POLICY\}"' \
    "the archived installer is not passed the signature policy"
expect_match "${SCRIPT}" 'SIGNATURE_POLICY=1' "signature verification does not default to required"
expect_match "${SCRIPT}" 'SITO_ARCHIVE_ALLOW_UNSIGNED' \
    "the unsigned skip is not an explicit opt-in"
expect_no_match "${SCRIPT}" '^[[:space:]]*SITO_REQUIRE_SIGNATURE=0[[:space:]]*$' \
    "the script contains an unconditional SITO_REQUIRE_SIGNATURE=0 assignment"

# The checksum block must precede the signature block, and both must precede any
# extraction or execution of archive contents.
CHECKSUM_LINE="$(grep -n 'grep -F "  \${ARCHIVE}" SHA256SUMS | sha256sum -c -' "${SCRIPT}" | head -n 1 | cut -d: -f1)"
SIGNATURE_LINE="$(grep -n 'log "Verify the cosign keyless signature before executing archive contents"' "${SCRIPT}" | head -n 1 | cut -d: -f1)"
VERIFY_LINE="$(grep -n '"\${COSIGN_BIN}" verify-blob' "${SCRIPT}" | head -n 1 | cut -d: -f1)"
EXTRACT_LINE="$(grep -n 'tar -xzf "\${DOWNLOAD_DIR}/\${ARCHIVE}"' "${SCRIPT}" | head -n 1 | cut -d: -f1)"
[ -n "${CHECKSUM_LINE}" ] || fail "could not locate the checksum verification block"
[ -n "${SIGNATURE_LINE}" ] || fail "could not locate the signature verification block"
[ -n "${VERIFY_LINE}" ] || fail "could not locate the signature verification command"
[ -n "${EXTRACT_LINE}" ] || fail "could not locate the archive extraction"
[ "${CHECKSUM_LINE}" -lt "${SIGNATURE_LINE}" ] ||
    fail "signature verification runs before the mandatory checksum"
[ "${VERIFY_LINE}" -lt "${EXTRACT_LINE}" ] ||
    fail "the archive is extracted before its signature is verified"

# The real archived installer must be used, not the current installer and not a
# fake 1.9.5 binary.
expect_match "${SCRIPT}" 'for candidate in "\$\{ARCHIVE_ROOT\}/install\.sh" "\$\{ARCHIVE_ROOT\}/contrib/install\.sh"' \
    "the script does not discover the installer packaged in the archive"
expect_match "${SCRIPT}" 'bash "\$\{ARCHIVED_INSTALLER\}"' \
    "the script does not execute the archived installer"
expect_match "${SCRIPT}" 'ARCHIVED_VERSION_LINE.*sito \$\{EXPECTED_VERSION\}' \
    "the archived binary version is not asserted"
expect_no_match "${SCRIPT}" 'write_fake_binary' "the archive path must not fabricate a 1.9.5 binary"

# The upgrade and rollback evidence the brief requires.
expect_match "${SCRIPT}" 'config migrate --from v1 --to v2 --backup' \
    "the v2 config precondition is missing"
expect_match "${SCRIPT}" 'stats\.db\.v1\.bak' "the DB migration backup is not asserted"
expect_match "${SCRIPT}" 'Migrating stats database' "the installer DB migration is not asserted"
expect_match "${SCRIPT}" 'Restoring matching v1 configuration' \
    "the pre-2.0 rollback pairing is not asserted"
expect_match "${SCRIPT}" 'db_query "\$\{DATA_DIR\}/stats\.db" v2 "\$\{PRE_COUNT\}"' \
    "the live migrated database does not assert its exact row count"
expect_match "${SCRIPT}" 'db_query "\$\{DB_BACKUP\}" v1 "\$\{PRE_COUNT\}"' \
    "the v1 backup does not assert its exact row count"
expect_match "${SCRIPT}" 'db_query "\$\{DATA_DIR\}/stats\.db" v1 "\$\{PRE_COUNT\}"' \
    "the restored operator database does not assert its exact row count"
expect_match "${SCRIPT}" 'db_query "\$\{DB_BACKUP\}" v1 "\$\{ROLLBACK_COUNT\}"' \
    "the failed-health backup does not assert its exact row count"
expect_match "${SCRIPT}" 'assert_live_service_version' \
    "rollback does not verify the live PID executable/version"
expect_match "${SCRIPT}" 'readlink -f "/proc/\$\{pid\}/exe"' \
    "rollback does not inspect the live PID inode"
expect_match "${SCRIPT}" 'assert_v2_api_absent' \
    "rollback does not prove the 2.0-only API is absent"

# It must remain an offline-static test's companion, not a default CI run.
expect_match "${CI}" 'scripts/test-installer-archive-1\.9\.5\.sh' \
    "the network script is not shellchecked by CI"
expect_match "${CI}" 'scripts/test-installer-archive-e2e\.sh' \
    "the static archive-E2E test is not wired into CI"
expect_no_match "${CI}" '(^|[[:space:]])bash[[:space:]]+scripts/test-installer-archive-1\.9\.5\.sh' \
    "the network archive E2E must not run in default CI"

# Manual/nightly lane and docs must use the same gated command.
expect_match "${WORKFLOW}" 'workflow_dispatch' "the archive lane has no manual trigger"
expect_match "${WORKFLOW}" 'SITO_ARCHIVE_E2E' "the workflow does not set the environment gate"
expect_match "${WORKFLOW}" "'1'" "the workflow gate is not set to 1"
expect_match "${WORKFLOW}" 'scripts/test-installer-archive-1\.9\.5\.sh' \
    "the workflow does not run the archive E2E"
expect_match "${DOC}" 'SITO_ARCHIVE_E2E=1' "the release verification doc does not document the gate"
expect_match "${DOC}" 'scripts/test-installer-archive-1\.9\.5\.sh' \
    "the release verification doc does not name the archive E2E"
expect_match "${DOC}" 'PASS: real archived 1\.9\.5 installer upgrade, migration and rollback' \
    "the release verification doc does not pin the expected transcript"

echo "archived installer E2E wiring OK"
