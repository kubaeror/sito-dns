#!/usr/bin/env bash
# E2 real archived-installer acceptance for the 1.9.5 -> 2.0 upgrade.
#
# This is a network-gated, manual/nightly lane. It is deliberately NOT part of
# the default pull-request CI: it downloads the real published v1.9.5 release
# assets from GitHub. Set SITO_ARCHIVE_E2E=1 to run it.
#
# Evidence produced, in one isolated unprivileged temp prefix:
#   1. the pinned real `sito-v1.9.5-<target>.tar.gz` and `SHA256SUMS` are
#      downloaded from the GitHub release; the SHA-256 checksum is always
#      verified. The cosign keyless signature is verified by default (the
#      archived installer installs a checksum-verified cosign when needed).
#      SHA-256-only mode is available only through the explicit
#      SITO_ARCHIVE_ALLOW_UNSIGNED=1 opt-out, which is reported as a skip.
#   2. the archive's own packaged `install.sh` installs 1.9.5 into a temp prefix
#      behind a fake systemctl service wrapper; no root and no real systemd.
#   3. a v1 data directory is seeded through the real 1.9.5 server: admin user,
#      TOTP key, a local rewrite answer and query_log rows.
#   4. the current 2.0 binary migrates the config to v2 with --backup (the
#      documented precondition: the 2.0 installer refuses a v1 config with an
#      existing stats database and prints this exact recovery command).
#   5. the current installer upgrades the real 1.9.5 installation with a local
#      current binary, runs `sito db migrate` with a 0600 `stats.db.v1.bak`,
#      starts the service, and the rewrite plus /health still answer.
#   6. an operator rollback restores the v1 config/DB backup pairing and the
#      real 1.9.5 server answers again.
#   7. a second, current-installer upgrade with a simulated failed health check
#      proves the installer restores the matching v1 config for the pre-2.0
#      binary instead of restarting 1.9.5 against config v2.
#
# Environment:
#   SITO_ARCHIVE_E2E=1              required gate (manual/nightly only)
#   SITO_ARCHIVE_TAG=v1.9.5         pinned release tag
#   SITO_NEW_BIN=/path/to/sito      current 2.x binary; otherwise cargo builds it
#   SITO_ARCHIVE_ALLOW_UNSIGNED=1   explicitly accept SHA-256-only (reports skip)
#   SITO_ARCHIVE_CACHE=/path        optional directory for already-downloaded assets
#   SITO_ARCHIVE_KEEP_TMP=1         keep the temp evidence directory
#   SITO_ARCHIVE_DNS_PORT / SITO_ARCHIVE_WEB_PORT
#                                   optional fixed ports (default: free ports)
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TAG="${SITO_ARCHIVE_TAG:-v1.9.5}"
VERSION="${TAG#v}"
EXPECTED_VERSION="1.9.5"
TMP_BASE="${SITO_ARCHIVE_TMPDIR:-/tmp/opencode}"
ADMIN_PASSWORD="ArchivePass123!"
SEED_DOMAIN="archive.test"
SEED_ANSWER="192.0.2.53"
ALLOW_UNSIGNED="${SITO_ARCHIVE_ALLOW_UNSIGNED:-0}"
KEEP_TMP="${SITO_ARCHIVE_KEEP_TMP:-0}"
INSTALL_COSIGN="${SITO_ARCHIVE_INSTALL_COSIGN:-1}"

log() { printf '\n== %s\n' "$*"; }
step() { printf '+ %s\n' "$*"; }
fail() {
    printf '\nFAIL: %s\n' "$*" >&2
    if [ -n "${TMP:-}" ] && [ -d "${TMP}/logs" ]; then
        for file in "${TMP}"/logs/*.log; do
            [ -f "${file}" ] || continue
            printf '\n--- %s (tail) ---\n' "${file}" >&2
            tail -40 "${file}" >&2 || true
        done
    fi
    exit 1
}

case "${SITO_ARCHIVE_E2E:-0}" in
    1) ;;
    *)
        echo "SKIP: the archived installer E2E downloads the real v1.9.5 release." >&2
        echo "      Set SITO_ARCHIVE_E2E=1 to run it (manual/nightly lane, not PR CI)." >&2
        exit 2
        ;;
esac

case "${ALLOW_UNSIGNED}" in
    0 | 1) ;;
    *) fail "SITO_ARCHIVE_ALLOW_UNSIGNED must be 0 or 1 (got '${ALLOW_UNSIGNED}')" ;;
esac

case "${TAG}" in
    v[0-9]*) ;;
    *) fail "SITO_ARCHIVE_TAG must look like v1.9.5 (got '${TAG}')" ;;
esac
case "${TAG}" in
    *[!0-9A-Za-z._-]*) fail "SITO_ARCHIVE_TAG contains unsafe characters: '${TAG}'" ;;
esac

if [ "${ALLOW_UNSIGNED}" = "1" ]; then
    SIGNATURE_POLICY=0
    INSTALL_COSIGN=0
else
    SIGNATURE_POLICY=1
fi

command -v python3 >/dev/null 2>&1 || fail "python3 is required"
command -v sha256sum >/dev/null 2>&1 || fail "sha256sum is required"
command -v tar >/dev/null 2>&1 || fail "tar is required"
command -v curl >/dev/null 2>&1 || command -v wget >/dev/null 2>&1 ||
    fail "curl or wget is required"

mkdir -p "${TMP_BASE}"
TMP="$(mktemp -d "${TMP_BASE}/sito-archive-e2e.XXXXXX")"
PREFIX="${TMP}/prefix"
BIN_DIR="${PREFIX}/bin"
CONFIG_DIR="${PREFIX}/etc/sito"
DATA_DIR="${PREFIX}/var/lib/sito"
INSTALL_BIN="${PREFIX}/usr/local/bin/sito"
SERVICE_PATH="${PREFIX}/etc/systemd/system/sito.service"
WORK="${TMP}/work"
LOGS="${TMP}/logs"
DOWNLOAD_DIR="${TMP}/downloads"
EXTRACT_DIR="${TMP}/extract"
CONFIG_FILE="${CONFIG_DIR}/config.toml"
SERVICE_PID="${LOGS}/service.pid"
SERVICE_MARKER="${LOGS}/service.active"
SERVICE_LOG="${LOGS}/service.log"
SYSTEMCTL_LOG="${LOGS}/systemctl.log"
INSTALLER_LOG="${LOGS}/install-1.9.5.log"
UPGRADE_LOG="${LOGS}/upgrade-2.0.log"
FAILED_UPGRADE_LOG="${LOGS}/upgrade-failed-health.log"

mkdir -p "${BIN_DIR}" "${CONFIG_DIR}" "${DATA_DIR}" \
    "${PREFIX}/usr/local/bin" "${PREFIX}/etc/systemd/system" "${WORK}" \
    "${LOGS}" "${DOWNLOAD_DIR}" "${EXTRACT_DIR}" "${WORK}/target/release"

cleanup() {
    local status=$?
    if [ -x "${BIN_DIR}/systemctl" ]; then
        FAKE_SYSTEMCTL_ACTIVE=1 "${BIN_DIR}/systemctl" stop sito >/dev/null 2>&1 || true
    fi
    if [ -f "${SERVICE_PID}" ]; then
        local pid
        pid="$(cat "${SERVICE_PID}" 2>/dev/null || true)"
        if [ -n "${pid}" ] && kill -0 "${pid}" 2>/dev/null; then
            kill "${pid}" 2>/dev/null || true
        fi
    fi
    if [ "${KEEP_TMP}" = "1" ]; then
        printf '\nEvidence kept at %s\n' "${TMP}" >&2
    else
        rm -rf "${TMP}"
    fi
    exit "${status}"
}
trap cleanup EXIT INT TERM

# ---------------------------------------------------------------------------
# Fake systemctl / service wrapper
# ---------------------------------------------------------------------------
# It never touches the real system. `start`/`restart` execute the currently
# installed binary with the temp config, so the installer's health check and
# every DNS/HTTP assertion exercise a real server process. Setting
# FAKE_SYSTEMCTL_ACTIVE=0 makes `is-active` fail without stopping the process;
# that is the simulated failed-health upgrade used by the pairing rollback.
write_fake_systemctl() {
    cat >"${BIN_DIR}/systemctl" <<'SH'
#!/usr/bin/env bash
set -u
echo "$*" >>"${FAKE_SYSTEMCTL_LOG:?}"

pid_of() { [ -f "${FAKE_SERVICE_PID:-/nonexistent}" ] && cat "${FAKE_SERVICE_PID}" 2>/dev/null || true; }
is_running() {
    local pid
    pid="$(pid_of)"
    [ -n "${pid}" ] && kill -0 "${pid}" 2>/dev/null
}
start_service() {
    if is_running; then
        return 0
    fi
    if [ ! -f "${FAKE_CONFIG_FILE:-/nonexistent}" ]; then
        # A fresh install has no config yet. Mark the unit active; the server
        # listeners start after the first-run setup writes a config.
        : >"${FAKE_SERVICE_MARKER:?}"
        return 0
    fi
    nohup "${FAKE_INSTALL_BIN:?}" --config "${FAKE_CONFIG_FILE}" \
        >>"${FAKE_SERVICE_LOG:?}" 2>&1 &
    echo "$!" >"${FAKE_SERVICE_PID:?}"
}
stop_service() {
    local pid
    pid="$(pid_of)"
    if [ -n "${pid}" ] && kill -0 "${pid}" 2>/dev/null; then
        kill "${pid}" 2>/dev/null || true
        for _ in $(seq 1 100); do
            kill -0 "${pid}" 2>/dev/null || break
            sleep 0.1
        done
        kill -9 "${pid}" 2>/dev/null || true
    fi
    rm -f "${FAKE_SERVICE_PID:-/nonexistent}" "${FAKE_SERVICE_MARKER:-/nonexistent}"
}
case "${1:-}" in
    start) start_service ;;
    stop) stop_service ;;
    restart) stop_service; start_service ;;
    is-active)
        [ "${FAKE_SYSTEMCTL_ACTIVE:-1}" = "1" ] || exit 1
        is_running && exit 0
        [ -f "${FAKE_SERVICE_MARKER:-/nonexistent}" ] && exit 0
        exit 1
        ;;
    *) exit 0 ;;
esac
SH
    chmod +x "${BIN_DIR}/systemctl"
}

write_fake_systemctl
export PATH="${BIN_DIR}:/usr/bin:/bin"
export FAKE_SYSTEMCTL_LOG="${SYSTEMCTL_LOG}"
export FAKE_SERVICE_PID="${SERVICE_PID}"
export FAKE_SERVICE_MARKER="${SERVICE_MARKER}"
export FAKE_SERVICE_LOG="${SERVICE_LOG}"
export FAKE_CONFIG_FILE="${CONFIG_FILE}"
export FAKE_INSTALL_BIN="${INSTALL_BIN}"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
download_file() {
    local url="$1" output="$2" attempt
    if [ -f "${output}" ] && [ -s "${output}" ]; then
        return 0
    fi
    for attempt in 1 2 3; do
        step "download ${url} (attempt ${attempt}/3)"
        if command -v curl >/dev/null 2>&1; then
            if curl -fsSL "${url}" -o "${output}"; then
                return 0
            fi
        elif wget -q "${url}" -O "${output}"; then
            return 0
        fi
        sleep $((attempt * 2))
    done
    return 1
}

pick_port() {
    python3 - "$1" "$2" <<'PY'
import socket
import sys

kind = sys.argv[1]
start = int(sys.argv[2])
for port in range(start, start + 400):
    sockets = []
    try:
        families = [socket.SOCK_STREAM]
        if kind == "dns":
            # The server binds both UDP and TCP for the same DNS port.
            families = [socket.SOCK_DGRAM, socket.SOCK_STREAM]
        for family in families:
            sock = socket.socket(socket.AF_INET, family)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("127.0.0.1", port))
            sockets.append(sock)
    except OSError:
        port = None
    finally:
        for sock in sockets:
            sock.close()
    if port is not None:
        print(port)
        raise SystemExit(0)
raise SystemExit(1)
PY
}

dns_rewrite_answers() {
    python3 - "$1" "${SEED_ANSWER}" <<'PY'
import socket
import struct
import sys

port = int(sys.argv[1])
answer = bytes(int(part) for part in sys.argv[2].split("."))
name = "archive.test"
qname = b"".join(bytes([len(label)]) + label.encode() for label in name.split(".")) + b"\x00"
query = struct.pack("!HHHHHH", 0x5A17, 0x0100, 1, 0, 0, 0) + qname + struct.pack("!HH", 1, 1)
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(1.0)
try:
    sock.sendto(query, ("127.0.0.1", port))
    data, _ = sock.recvfrom(4096)
except OSError:
    raise SystemExit(1)
finally:
    sock.close()
if len(data) < 12:
    raise SystemExit(1)
ident, flags, _qd, an, _ns, _ar = struct.unpack("!HHHHHH", data[:12])
if ident != 0x5A17 or (flags & 0x000F) != 0 or an < 1:
    raise SystemExit(1)
if answer not in data:
    raise SystemExit(1)
PY
}

wait_for_dns() {
    local port="$1" label="$2"
    for _ in $(seq 1 160); do
        if dns_rewrite_answers "${port}" >/dev/null 2>&1; then
            return 0
        fi
        if [ -f "${SERVICE_PID}" ]; then
            local pid
            pid="$(cat "${SERVICE_PID}" 2>/dev/null || true)"
            if [ -n "${pid}" ] && ! kill -0 "${pid}" 2>/dev/null; then
                printf '\n%s service exited early:\n' "${label}" >&2
                cat "${SERVICE_LOG}" >&2 || true
                return 1
            fi
        fi
        sleep 0.25
    done
    printf '\n%s did not answer %s on 127.0.0.1:%s within 40s:\n' \
        "${label}" "${SEED_DOMAIN}" "${port}" >&2
    cat "${SERVICE_LOG}" >&2 || true
    return 1
}

wait_for_http() {
    local url="$1" label="$2"
    for _ in $(seq 1 120); do
        if curl -fsS "${url}" >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.25
    done
    printf '\n%s did not answer %s within 30s:\n' "${label}" "${url}" >&2
    cat "${SERVICE_LOG}" >&2 || true
    return 1
}

assert_sha256_equal() {
    local before="$1" after="$2" message="$3"
    [ "${before}" = "${after}" ] || fail "${message}"
}

db_query() {
    python3 - "$1" "$2" <<'PY'
import sqlite3
import sys

path, mode = sys.argv[1], sys.argv[2]
con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
try:
    assert con.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    marker = con.execute(
        "SELECT value FROM stats_meta WHERE key = 'schema_version'"
    ).fetchall()
    count = con.execute("SELECT COUNT(*) FROM query_log").fetchone()[0]
    seed = con.execute(
        "SELECT COUNT(*) FROM query_log WHERE qname = 'archive.test'"
    ).fetchone()[0]
    if mode == "v1":
        assert marker == [], marker
        assert seed >= 1, seed
    elif mode == "v2":
        assert marker == [("2",)], marker
        assert seed >= 1, seed
    else:
        raise AssertionError(mode)
    print(f"{path}: integrity=ok marker={marker} query_log={count} archive_rows={seed}")
finally:
    con.close()
PY
}

stop_service() {
    FAKE_SYSTEMCTL_ACTIVE=1 "${BIN_DIR}/systemctl" stop sito >/dev/null 2>&1 || true
}

start_service() {
    FAKE_SYSTEMCTL_ACTIVE=1 "${BIN_DIR}/systemctl" start sito
}

# ---------------------------------------------------------------------------
# Current 2.x binary
# ---------------------------------------------------------------------------
log "Current 2.x binary"
if [ -n "${SITO_NEW_BIN:-}" ]; then
    NEW_BIN="${SITO_NEW_BIN}"
else
    step "cargo build -p sito --features embed-ui (cwd: ${ROOT})"
    (cd "${ROOT}" && env -u CARGO_TARGET_DIR cargo build -p sito --features embed-ui)
    NEW_BIN="${ROOT}/target/debug/sito"
fi
[ -x "${NEW_BIN}" ] || fail "current binary is not executable: ${NEW_BIN}"
NEW_VERSION_LINE="$("${NEW_BIN}" --version)"
NEW_VERSION="${NEW_VERSION_LINE#sito }"
case "${NEW_VERSION%%.*}" in
    2 | [3-9]) ;;
    *) fail "current binary must be 2.x, got '${NEW_VERSION_LINE}'" ;;
esac
step "${NEW_VERSION_LINE} (${NEW_BIN})"

# The current installer installs a local binary only from ./target/release/sito
# relative to its working directory. Copy the current build there; this is the
# same unprivileged hook used by the offline installer E2E.
cp "${NEW_BIN}" "${WORK}/target/release/sito"
chmod 0755 "${WORK}/target/release/sito"

# ---------------------------------------------------------------------------
# Download and verify the real archived release
# ---------------------------------------------------------------------------
log "Download the real ${TAG} release assets"
ARCH="$(uname -m)"
case "${ARCH}" in
    x86_64 | amd64) TARGET="x86_64-unknown-linux-gnu" ;;
    aarch64 | arm64) TARGET="aarch64-unknown-linux-gnu" ;;
    armv7* | armhf) TARGET="armv7-unknown-linux-gnueabihf" ;;
    *) fail "unsupported test architecture ${ARCH}" ;;
esac
ARCHIVE="sito-${TAG}-${TARGET}.tar.gz"
BASE_URL="https://github.com/kubaeror/sito-dns/releases/download/${TAG}"
if [ -n "${SITO_ARCHIVE_CACHE:-}" ]; then
    mkdir -p "${SITO_ARCHIVE_CACHE}"
    DOWNLOAD_DIR="${SITO_ARCHIVE_CACHE}"
fi
[ "${VERSION}" = "${EXPECTED_VERSION}" ] ||
    printf 'notice: SITO_ARCHIVE_TAG=%s is not the pinned %s; continuing with the requested tag\n' \
        "${TAG}" "${EXPECTED_VERSION}" >&2

download_file "${BASE_URL}/${ARCHIVE}" "${DOWNLOAD_DIR}/${ARCHIVE}" ||
    fail "could not download ${ARCHIVE}"
download_file "${BASE_URL}/SHA256SUMS" "${DOWNLOAD_DIR}/SHA256SUMS" ||
    fail "could not download SHA256SUMS"

HAVE_SIG_ARTIFACTS=0
if download_file "${BASE_URL}/${ARCHIVE}.sig" "${DOWNLOAD_DIR}/${ARCHIVE}.sig" >/dev/null 2>&1 &&
    download_file "${BASE_URL}/${ARCHIVE}.pem" "${DOWNLOAD_DIR}/${ARCHIVE}.pem" >/dev/null 2>&1; then
    HAVE_SIG_ARTIFACTS=1
fi
if download_file "${BASE_URL}/${ARCHIVE}.sha256" "${DOWNLOAD_DIR}/${ARCHIVE}.sha256" >/dev/null 2>&1; then
    HAVE_PER_ARCHIVE_SHA=1
else
    HAVE_PER_ARCHIVE_SHA=0
fi

log "Verify SHA-256 checksums (always)"
(
    cd "${DOWNLOAD_DIR}"
    if ! awk -v archive="${ARCHIVE}" '$2 == archive { found = 1 } END { exit found ? 0 : 1 }' SHA256SUMS; then
        echo "Error: ${ARCHIVE} is not listed in SHA256SUMS." >&2
        exit 1
    fi
    grep -F "  ${ARCHIVE}" SHA256SUMS | sha256sum -c -
)
if [ "${HAVE_PER_ARCHIVE_SHA}" = "1" ]; then
    (cd "${DOWNLOAD_DIR}" && sha256sum -c "${ARCHIVE}.sha256")
fi
step "SHA-256 verified for ${ARCHIVE}"

log "Verify the cosign keyless signature"
if [ "${SIGNATURE_POLICY}" = "0" ]; then
    printf 'SKIP: SITO_ARCHIVE_ALLOW_UNSIGNED=1; relying on the verified SHA-256 only.\n'
    [ "${HAVE_SIG_ARTIFACTS}" = "1" ] || printf 'SKIP: no .sig/.pem assets were available either.\n'
else
    [ "${HAVE_SIG_ARTIFACTS}" = "1" ] ||
        fail "release signatures are required but ${ARCHIVE}.sig/.pem are unavailable"
    if command -v cosign >/dev/null 2>&1; then
        step "cosign verify-blob (existing $(command -v cosign))"
        cosign verify-blob \
            --certificate "${DOWNLOAD_DIR}/${ARCHIVE}.pem" \
            --signature "${DOWNLOAD_DIR}/${ARCHIVE}.sig" \
            --certificate-identity-regexp \
            "^https://github.com/kubaeror/sito-dns/\.github/workflows/release\.yml@refs/tags/.*$" \
            --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
            "${DOWNLOAD_DIR}/${ARCHIVE}"
    else
        # The archived installer installs a checksum-verified cosign before it
        # verifies the release signature. The direct verification below runs
        # after that install.
        step "cosign is absent; the archived installer will install and use it"
    fi
fi

log "Extract the archive and locate its packaged installer"
tar -xzf "${DOWNLOAD_DIR}/${ARCHIVE}" -C "${EXTRACT_DIR}"
ARCHIVE_ROOT="${EXTRACT_DIR}/sito-${TAG}-${TARGET}"
[ -d "${ARCHIVE_ROOT}" ] || fail "archive did not contain ${ARCHIVE_ROOT}"
ARCHIVED_BIN="${ARCHIVE_ROOT}/sito"
[ -x "${ARCHIVED_BIN}" ] || fail "archive did not contain an executable sito"
ARCHIVED_VERSION_LINE="$("${ARCHIVED_BIN}" --version)"
[ "${ARCHIVED_VERSION_LINE}" = "sito ${EXPECTED_VERSION}" ] ||
    fail "archived binary is '${ARCHIVED_VERSION_LINE}', expected 'sito ${EXPECTED_VERSION}'"
ARCHIVED_INSTALLER=""
for candidate in "${ARCHIVE_ROOT}/install.sh" "${ARCHIVE_ROOT}/contrib/install.sh"; do
    if [ -f "${candidate}" ]; then
        ARCHIVED_INSTALLER="${candidate}"
        break
    fi
done
[ -n "${ARCHIVED_INSTALLER}" ] || fail "archive did not contain the packaged install.sh"
step "archive layout: $(find "${ARCHIVE_ROOT}" -maxdepth 2 -type f -printf '%P ' | sort)"
step "archived binary ${ARCHIVED_VERSION_LINE}; installer ${ARCHIVED_INSTALLER}"

# ---------------------------------------------------------------------------
# Install the real 1.9.5 with its own archived installer
# ---------------------------------------------------------------------------
log "Install ${VERSION} with the archived installer (fake systemctl, no root)"
: >"${SYSTEMCTL_LOG}"
(
    cd "${WORK}"
    PATH="${BIN_DIR}:/usr/bin:/bin" \
        SITO_ALLOW_NON_ROOT=1 \
        SITO_VERSION="${VERSION}" \
        SITO_INSTALL_COSIGN="${INSTALL_COSIGN}" \
        SITO_INSTALL_COSIGN_BIN="${BIN_DIR}/cosign" \
        SITO_REQUIRE_SIGNATURE="${SIGNATURE_POLICY}" \
        SITO_INSTALL_BIN="${INSTALL_BIN}" \
        SITO_CONFIG_DIR="${CONFIG_DIR}" \
        SITO_DATA_DIR="${DATA_DIR}" \
        SITO_SERVICE_PATH="${SERVICE_PATH}" \
        SITO_SYSTEMCTL="${BIN_DIR}/systemctl" \
        SITO_INSTALL_LOCAL_BINARY=0 \
        bash "${ARCHIVED_INSTALLER}"
) >"${INSTALLER_LOG}" 2>&1 || fail "the archived ${VERSION} installer failed"
STEP_INSTALLED_VERSION="$("${INSTALL_BIN}" --version)"
[ "${STEP_INSTALLED_VERSION}" = "sito ${EXPECTED_VERSION}" ] ||
    fail "archived installer installed '${STEP_INSTALLED_VERSION}'"
[ -f "${SERVICE_PATH}" ] || fail "archived installer did not write the systemd unit"

if [ "${SIGNATURE_POLICY}" = "1" ]; then
    grep -q 'Cosign keyless signature verified successfully' "${INSTALLER_LOG}" ||
        fail "the archived installer did not report a verified cosign signature"
    [ -x "${BIN_DIR}/cosign" ] || command -v cosign >/dev/null 2>&1 ||
        fail "signature verification was required but cosign is unavailable"
    if [ -x "${BIN_DIR}/cosign" ]; then
        step "direct cosign verify-blob with the installer-provided cosign"
        "${BIN_DIR}/cosign" verify-blob \
            --certificate "${DOWNLOAD_DIR}/${ARCHIVE}.pem" \
            --signature "${DOWNLOAD_DIR}/${ARCHIVE}.sig" \
            --certificate-identity-regexp \
            "^https://github.com/kubaeror/sito-dns/\.github/workflows/release\.yml@refs/tags/.*$" \
            --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
            "${DOWNLOAD_DIR}/${ARCHIVE}" ||
            fail "direct cosign verification of the downloaded archive failed"
    fi
else
    grep -qi 'SITO_REQUIRE_SIGNATURE=0' "${INSTALLER_LOG}" ||
        fail "unsigned mode did not produce the installer's explicit policy warning"
    printf 'SKIP: signature verification skipped by SITO_ARCHIVE_ALLOW_UNSIGNED=1.\n'
fi
stop_service
step "installed ${STEP_INSTALLED_VERSION} from the real archived installer"

# ---------------------------------------------------------------------------
# Seed the v1 data directory through the real 1.9.5 server
# ---------------------------------------------------------------------------
log "Seed a v1 data directory with the real ${VERSION} server"
DNS_PORT="${SITO_ARCHIVE_DNS_PORT:-$(pick_port dns 15350)}"
WEB_PORT="${SITO_ARCHIVE_WEB_PORT:-$(pick_port tcp 18080)}"

cat >"${CONFIG_FILE}" <<EOF
config_version = 1

[server]
role = "master"
instance_name = "archive-acceptance"
data_dir = "${DATA_DIR}"
log_level = "warn"
log_format = "json"

[dns]
bind = ["127.0.0.1"]
port = ${DNS_PORT}
dot_port = 0
doh_port = 0
doq_port = 0
doh3_port = 0
allow_plaintext_doh = false

[dns.cache]
enabled = false

[dns.dnssec]
mode = "off"
validate = false

[upstream]
servers = ["udp://127.0.0.1:9"]
timeout_ms = 1000
probe_domain = "example.com"
pool_size = 1
strategy = "failover"

[filtering]
enabled = false

[rewrites]
ttl = 60

[[rewrites.entries]]
domain = "${SEED_DOMAIN}"
type = "A"
answer = "${SEED_ANSWER}"

[stats]
retention_days = 90
rollup_retention_days = 365
rollup_client_names = false

[web]
enabled = true
bind = "127.0.0.1"
port = ${WEB_PORT}
metrics_auth = false
EOF

step "${INSTALL_BIN} --config ${CONFIG_FILE} reset-admin --password <redacted>"
"${INSTALL_BIN}" --config "${CONFIG_FILE}" reset-admin --password "${ADMIN_PASSWORD}" >/dev/null
[ -s "${DATA_DIR}/users.toml" ] || fail "reset-admin did not write users.toml"
[ -s "${DATA_DIR}/totp.key" ] || fail "the v1 server did not create totp.key"
USERS_SHA_BEFORE="$(sha256sum "${DATA_DIR}/users.toml" | awk '{print $1}')"
TOTP_SHA_BEFORE="$(sha256sum "${DATA_DIR}/totp.key" | awk '{print $1}')"
V1_CONFIG_SHA="$(sha256sum "${CONFIG_FILE}" | awk '{print $1}')"

step "start ${VERSION} through the fake systemctl wrapper"
start_service
wait_for_dns "${DNS_PORT}" "${VERSION}" || fail "${VERSION} did not answer the rewrite"
wait_for_http "http://127.0.0.1:${WEB_PORT}/health" "${VERSION} /health" ||
    fail "${VERSION} /health is unavailable"
step "v1 rewrite answered ${SEED_DOMAIN} A ${SEED_ANSWER} on 127.0.0.1:${DNS_PORT}"
step "v1 /health: $(curl -fsS "http://127.0.0.1:${WEB_PORT}/health")"

# A few queries make the pre-upgrade query_log rows deterministic; SIGTERM
# flushes the writer before the database is snapshotted by `db migrate`.
for _ in 1 2 3; do
    dns_rewrite_answers "${DNS_PORT}" >/dev/null
done
stop_service
[ -s "${DATA_DIR}/stats.db" ] || fail "the v1 server did not create stats.db"
db_query "${DATA_DIR}/stats.db" v1 >/dev/null ||
    fail "the seeded v1 stats.db is not legacy (or has no query_log rows)"
PRE_COUNT="$(python3 - "${DATA_DIR}/stats.db" <<'PY'
import sqlite3
import sys
con = sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True)
print(con.execute("SELECT COUNT(*) FROM query_log").fetchone()[0])
PY
)"
step "seeded stats.db: ${PRE_COUNT} query_log rows, no schema_version marker"

# ---------------------------------------------------------------------------
# Config v2 precondition
# ---------------------------------------------------------------------------
log "Config v2 precondition (documented: migrate before the 2.0 installer)"
cat <<'EOF'
The 2.0 installer refuses to run `sito db migrate` against a v1 config when a
stats database exists. Migrate the config explicitly with the current 2.0
binary first; the installer's refusal message prints exactly this command.
EOF
step "${NEW_BIN} config migrate --from v1 --to v2 --backup --config ${CONFIG_FILE}"
"${NEW_BIN}" config migrate --from v1 --to v2 --backup --config "${CONFIG_FILE}"
grep -qx 'config_version = 2' "${CONFIG_FILE}" || fail "config was not migrated to v2"
V1_CONFIG_BACKUP="${CONFIG_FILE}.v1.bak"
[ -f "${V1_CONFIG_BACKUP}" ] || fail "config migrate did not write ${V1_CONFIG_BACKUP}"
[ "$(stat -c '%a' "${V1_CONFIG_BACKUP}")" = "600" ] ||
    fail "config backup is not mode 0600"
assert_sha256_equal "${V1_CONFIG_SHA}" \
    "$(sha256sum "${V1_CONFIG_BACKUP}" | awk '{print $1}')" \
    "config.toml.v1.bak does not match the pre-upgrade v1 config"
step "${NEW_BIN} check-config"
"${NEW_BIN}" --config "${CONFIG_FILE}" check-config
step "config v2 validates; v1 backup is 0600 and byte-identical"

# ---------------------------------------------------------------------------
# Successful current-installer upgrade
# ---------------------------------------------------------------------------
log "Upgrade with the current installer and the local ${NEW_VERSION} binary"
: >"${SYSTEMCTL_LOG}"
: >"${SERVICE_LOG}"
(
    cd "${WORK}"
    PATH="${BIN_DIR}:/usr/bin:/bin" \
        SITO_ALLOW_NON_ROOT=1 \
        SITO_VERSION=latest \
        SITO_INSTALL_LOCAL_BINARY=1 \
        SITO_INSTALL_COSIGN=0 \
        SITO_REQUIRE_SIGNATURE=1 \
        SITO_INSTALL_BIN="${INSTALL_BIN}" \
        SITO_CONFIG_DIR="${CONFIG_DIR}" \
        SITO_DATA_DIR="${DATA_DIR}" \
        SITO_SERVICE_PATH="${SERVICE_PATH}" \
        SITO_SYSTEMCTL="${BIN_DIR}/systemctl" \
        bash "${ROOT}/contrib/install.sh"
) >"${UPGRADE_LOG}" 2>&1 || fail "the current installer upgrade failed"
UPGRADED_VERSION="$("${INSTALL_BIN}" --version)"
[ "${UPGRADED_VERSION}" = "sito ${NEW_VERSION}" ] ||
    fail "installed binary is '${UPGRADED_VERSION}', expected 'sito ${NEW_VERSION}'"
grep -q 'Migrating stats database' "${UPGRADE_LOG}" ||
    fail "the current installer did not run sito db migrate"
grep -q 'Migrated stats database' "${UPGRADE_LOG}" ||
    fail "the current installer migration did not report a migrated database"
grep -q 'service is active and responding' "${UPGRADE_LOG}" ||
    fail "the current installer health check did not pass"
[ -f "${CONFIG_DIR}/sito.env" ] || fail "the current installer did not write sito.env"
[ "$(stat -c '%a' "${CONFIG_DIR}/sito.env")" = "600" ] ||
    fail "sito.env is not mode 0600"
wait_for_dns "${DNS_PORT}" "2.0" || fail "2.0 did not answer the rewrite after the upgrade"
wait_for_http "http://127.0.0.1:${WEB_PORT}/health" "2.0 /health" ||
    fail "2.0 /health is unavailable after the upgrade"
step "2.0 rewrite answered ${SEED_DOMAIN} A ${SEED_ANSWER} on 127.0.0.1:${DNS_PORT}"

DB_BACKUP="${DATA_DIR}/stats.db.v1.bak"
[ -f "${DB_BACKUP}" ] || fail "the installer migration did not write stats.db.v1.bak"
[ "$(stat -c '%a' "${DB_BACKUP}")" = "600" ] ||
    fail "stats.db.v1.bak is not mode 0600"
db_query "${DATA_DIR}/stats.db" v2 || fail "the migrated stats.db failed its v2 assertions"
db_query "${DB_BACKUP}" v1 || fail "the pre-migration stats.db backup failed its v1 assertions"
POST_COUNT="$(python3 - "${DATA_DIR}/stats.db" <<'PY'
import sqlite3
import sys
con = sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True)
print(con.execute("SELECT COUNT(*) FROM query_log").fetchone()[0])
PY
)"
[ "${POST_COUNT}" -ge "${PRE_COUNT}" ] ||
    fail "the migrated database lost query_log rows (${PRE_COUNT} -> ${POST_COUNT})"
step "db migrate wrote a 0600 stats.db.v1.bak; ${PRE_COUNT} v1 rows survive in both databases"

COOKIE_JAR="${LOGS}/cookies.txt"
step "curl /api/v2/status (session required)"
curl -fsS -c "${COOKIE_JAR}" -H 'Content-Type: application/json' \
    -d "{\"user\":\"admin\",\"pass\":\"${ADMIN_PASSWORD}\"}" \
    "http://127.0.0.1:${WEB_PORT}/api/v2/auth/login" >/dev/null
STATUS_JSON="$(curl -fsS -b "${COOKIE_JAR}" "http://127.0.0.1:${WEB_PORT}/api/v2/status")"
python3 - "${STATUS_JSON}" "${NEW_VERSION}" <<'PY'
import json
import sys
body = json.loads(sys.argv[1])
assert body.get("version") == sys.argv[2], body
print(f"  /api/v2/status OK: version={body['version']} role={body.get('role')}")
PY

assert_sha256_equal "${USERS_SHA_BEFORE}" \
    "$(sha256sum "${DATA_DIR}/users.toml" | awk '{print $1}')" \
    "users.toml changed across the upgrade"
assert_sha256_equal "${TOTP_SHA_BEFORE}" \
    "$(sha256sum "${DATA_DIR}/totp.key" | awk '{print $1}')" \
    "totp.key changed across the upgrade"
step "users.toml and totp.key survived byte-for-byte; /api/v2/status is served"
stop_service

# ---------------------------------------------------------------------------
# Operator rollback to 1.9.5 using the v1 config/DB backup pairing
# ---------------------------------------------------------------------------
log "Operator rollback: restore v1.9.5 binary, v1 config and DB backup"
BIN_BACKUP="${INSTALL_BIN}.bak"
[ -x "${BIN_BACKUP}" ] || fail "the installer did not leave ${BIN_BACKUP}"
[ "$("${BIN_BACKUP}" --version)" = "sito ${EXPECTED_VERSION}" ] ||
    fail "binary backup is not ${EXPECTED_VERSION}"
cp -p "${DB_BACKUP}" "${TMP}/operator-rollback-stats.db.v1.bak"
restore_binary_atomically() {
    local src="$1"
    local dir tmp
    dir="$(dirname -- "${INSTALL_BIN}")"
    tmp="$(mktemp "${dir}/.sito-archive-restore.XXXXXX")"
    install -m 0755 "${src}" "${tmp}"
    mv -f -- "${tmp}" "${INSTALL_BIN}"
}
restore_binary_atomically "${BIN_BACKUP}"
cp -p "${V1_CONFIG_BACKUP}" "${CONFIG_FILE}"
cp -p "${TMP}/operator-rollback-stats.db.v1.bak" "${DATA_DIR}/stats.db"
rm -f "${DATA_DIR}/stats.db-wal" "${DATA_DIR}/stats.db-shm"
step "restored ${BIN_BACKUP}, ${V1_CONFIG_BACKUP}, and stats.db.v1.bak"
[ "$("${INSTALL_BIN}" --version)" = "sito ${EXPECTED_VERSION}" ] ||
    fail "operator rollback did not restore the 1.9.5 binary"
grep -qx 'config_version = 1' "${CONFIG_FILE}" || fail "operator rollback did not restore v1 config"
db_query "${DATA_DIR}/stats.db" v1 >/dev/null || fail "operator rollback did not restore the v1 database"
start_service
wait_for_dns "${DNS_PORT}" "rollback 1.9.5" ||
    fail "the rolled-back 1.9.5 did not answer the rewrite"
wait_for_http "http://127.0.0.1:${WEB_PORT}/health" "rollback 1.9.5 /health" ||
    fail "the rolled-back 1.9.5 /health is unavailable"
assert_sha256_equal "${USERS_SHA_BEFORE}" \
    "$(sha256sum "${DATA_DIR}/users.toml" | awk '{print $1}')" \
    "users.toml changed across the rollback"
assert_sha256_equal "${TOTP_SHA_BEFORE}" \
    "$(sha256sum "${DATA_DIR}/totp.key" | awk '{print $1}')" \
    "totp.key changed across the rollback"
step "rolled-back 1.9.5 answered the rewrite, /health, and preserved users/TOTP"
stop_service

# ---------------------------------------------------------------------------
# Current installer failed-health rollback: v1 config pair, not v2
# ---------------------------------------------------------------------------
log "Failed-health upgrade rollback must pair the pre-2.0 binary with v1 config"
# The previous migration backup is preserved above; move it aside so this
# attempt creates its own unambiguous 0600 backup.
rm -f "${DB_BACKUP}"
"${NEW_BIN}" config migrate --from v1 --to v2 --backup --config "${CONFIG_FILE}" >/dev/null
grep -qx 'config_version = 2' "${CONFIG_FILE}" ||
    fail "the second config migration did not produce v2"
: >"${SYSTEMCTL_LOG}"
: >"${SERVICE_LOG}"
if (
    cd "${WORK}"
    PATH="${BIN_DIR}:/usr/bin:/bin" \
        SITO_ALLOW_NON_ROOT=1 \
        SITO_VERSION=latest \
        SITO_INSTALL_LOCAL_BINARY=1 \
        SITO_INSTALL_COSIGN=0 \
        SITO_REQUIRE_SIGNATURE=1 \
        SITO_INSTALL_BIN="${INSTALL_BIN}" \
        SITO_CONFIG_DIR="${CONFIG_DIR}" \
        SITO_DATA_DIR="${DATA_DIR}" \
        SITO_SERVICE_PATH="${SERVICE_PATH}" \
        SITO_SYSTEMCTL="${BIN_DIR}/systemctl" \
        FAKE_SYSTEMCTL_ACTIVE=0 \
        bash "${ROOT}/contrib/install.sh"
) >"${FAILED_UPGRADE_LOG}" 2>&1; then
    fail "the installer succeeded despite a simulated failed health check"
fi
grep -q 'Migrating stats database' "${FAILED_UPGRADE_LOG}" ||
    fail "the failed-health attempt did not attempt the database migration"
grep -q 'Restoring matching v1 configuration' "${FAILED_UPGRADE_LOG}" ||
    fail "the pre-2.0 rollback did not restore the matching v1 config"
[ "$("${INSTALL_BIN}" --version)" = "sito ${EXPECTED_VERSION}" ] ||
    fail "the failed-health rollback did not restore the 1.9.5 binary"
grep -qx 'config_version = 1' "${CONFIG_FILE}" ||
    fail "the failed-health rollback left config v2 for a 1.9.5 binary"
assert_sha256_equal "${V1_CONFIG_SHA}" \
    "$(sha256sum "${CONFIG_FILE}" | awk '{print $1}')" \
    "the failed-health rollback did not restore the byte-identical v1 config"
[ -f "${DB_BACKUP}" ] || fail "the failed-health attempt did not write a new DB backup"
[ "$(stat -c '%a' "${DB_BACKUP}")" = "600" ] ||
    fail "the failed-health DB backup is not mode 0600"
step "failed-health rollback restored the 1.9.5 binary and matching v1 config"
start_service
wait_for_dns "${DNS_PORT}" "failed-health rollback 1.9.5" ||
    fail "the failed-health rollback did not leave a working 1.9.5 service"
wait_for_http "http://127.0.0.1:${WEB_PORT}/health" "failed-health rollback /health" ||
    fail "the failed-health rollback /health is unavailable"
# The installer does not roll the database back on a health failure; 1.9.5 must
# still open the additive schema version 2 database. The v1 backup remains the
# documented recovery copy.
if ! python3 - "${DATA_DIR}/stats.db" <<'PY'
import sqlite3
import sys
con = sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True)
assert con.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
assert con.execute("SELECT COUNT(*) FROM query_log WHERE qname = 'archive.test'").fetchone()[0] >= 1
print("  recovered 1.9.5 still opens the additive migrated stats.db")
PY
then
    fail "1.9.5 could not open the additive migrated stats.db after the rollback"
fi
step "recovered 1.9.5 answered the rewrite and /health after the failed upgrade"
stop_service

log "PASS: real archived ${VERSION} installer upgrade, migration and rollback"
printf 'Evidence directory: %s\n' "${TMP}"
if [ "${KEEP_TMP}" = "1" ]; then
    printf 'Archived installer log: %s\n' "${INSTALLER_LOG}"
    printf 'Successful upgrade log: %s\n' "${UPGRADE_LOG}"
    printf 'Failed-health rollback log: %s\n' "${FAILED_UPGRADE_LOG}"
fi
