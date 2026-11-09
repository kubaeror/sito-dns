#!/usr/bin/env bash
# Behavioral installer E2E. Runs unprivileged and never touches the real
# /usr/local, /etc/sito, /var/lib/sito or systemctl:
#   * fresh install
#   * live upgrade while the previously installed binary is executing (the old
#     `cp -f` implementation fails with ETXTBSY)
#   * failed-health rollback restores the previous binary and config backup
#   * uninstall keeps config/data
#   * signature policy: required by default, explicit opt-out, missing assets
set -euo pipefail

INSTALLER="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/contrib/install.sh"
TMP="$(mktemp -d)"
HOLD_PID=""
trap 'if [ -n "${HOLD_PID}" ]; then kill "${HOLD_PID}" 2>/dev/null || true; fi; rm -rf "${TMP}"' EXIT

SANDBOX="${TMP}/sandbox"
INSTALLER_OUT="${TMP}/installer.out"

fail() {
    echo "FAIL: $*" >&2
    if [ -f "${INSTALLER_OUT}" ]; then
        sed 's/^/    /' "${INSTALLER_OUT}" >&2
    fi
    exit 1
}

assert_eq() {
    local expected="$1" actual="$2" message="$3"
    if [ "${actual}" != "${expected}" ]; then
        fail "${message}: expected '${expected}', got '${actual}'"
    fi
}

assert_file_exists() {
    [ -e "$1" ] || fail "expected $1 to exist"
}

assert_file_missing() {
    [ ! -e "$1" ] || fail "expected $1 to be absent"
}

# The held-process upgrade test needs a real ELF executable: bash closes a
# script's file descriptor before the final `exec`, so `cp -f` over a running
# shell script does not reproduce ETXTBSY. Compile a tiny binary that answers
# `--version` and otherwise sleeps.
write_fake_binary() {
    local path="$1" version="$2"
    local source="${path}.c"
    command -v cc >/dev/null 2>&1 || fail "a C compiler (cc) is required for the installer E2E"
    cat >"${source}" <<EOF
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "--version") == 0) {
        printf("sito ${version}\\n");
        return 0;
    }
    sleep(600);
    return 0;
}
EOF
    cc -O0 -o "${path}" "${source}" || fail "could not compile the fake sito binary"
    rm -f "${source}"
}

write_fake_systemctl() {
    cat >"${SANDBOX}/bin/systemctl" <<'SH'
#!/usr/bin/env bash
echo "$*" >>"${FAKE_SYSTEMCTL_LOG}"
case "${1:-}" in
    is-active)
        [ "${FAKE_SYSTEMCTL_ACTIVE:-1}" = "1" ]
        ;;
    start)
        # Simulate the real service by executing the installed binary, so the
        # rollback test can hold the new inode open and reproduce ETXTBSY.
        if [ "${FAKE_SYSTEMCTL_START_EXEC:-0}" = "1" ]; then
            "${FAKE_INSTALL_BIN}" &
            echo "$!" >"${FAKE_START_PID_FILE}"
        fi
        # Simulate a startup migration writing to the live config. Rollback
        # must restore /etc/sito/config.toml from config.toml.bak.
        if [ "${FAKE_SYSTEMCTL_START_MUTATES_CONFIG:-0}" = "1" ] && [ -f "${FAKE_CONFIG_FILE}" ]; then
            printf '\n# mutated by simulated startup migration\n' >>"${FAKE_CONFIG_FILE}"
        fi
        ;;
    *) exit 0 ;;
esac
SH
    chmod +x "${SANDBOX}/bin/systemctl"
}

# Some cp implementations (and the reported audit environment) return ETXTBSY
# when `cp -f` tries to replace a running executable instead of unlinking it.
# GNU coreutils happens to unlink and succeed; the test injects the strict
# behaviour so a regression back to `cp -f` over ${INSTALL_BIN} fails.
write_fake_install() {
    cat >"${SANDBOX}/bin/install" <<'SH'
#!/usr/bin/env bash
if [ "${FAKE_INSTALL_FAIL:-0}" = "1" ]; then
    case "$*" in
        *target/release/sito*)
            echo "install: simulated failure" >&2
            exit 1
            ;;
    esac
fi
exec /usr/bin/install "$@"
SH
    chmod +x "${SANDBOX}/bin/install"
}

write_fake_cp() {
    cat >"${SANDBOX}/bin/cp" <<'SH'
#!/usr/bin/env bash
dest=""
for arg in "$@"; do
    case "${arg}" in
        -*) ;;
        *) dest="${arg}" ;;
    esac
done
if [ "${FAKE_CP_ETXTBSY:-0}" = "1" ] && [ "${dest}" = "${FAKE_CP_EXECUTABLE:-}" ]; then
    echo "cp: cannot create regular file '${dest}': Text file busy" >&2
    exit 1
fi
exec /bin/cp "$@"
SH
    chmod +x "${SANDBOX}/bin/cp"
}

reset_sandbox() {
    rm -rf "${SANDBOX}"
    mkdir -p \
        "${SANDBOX}/bin" \
        "${SANDBOX}/install" \
        "${SANDBOX}/systemd" \
        "${SANDBOX}/etc/sito" \
        "${SANDBOX}/var/lib/sito" \
        "${SANDBOX}/work/target/release" \
        "${SANDBOX}/logs"
    : >"${SANDBOX}/logs/systemctl.log"
    write_fake_systemctl
    write_fake_cp
    write_fake_install
}

run_installer() {
    (
        cd "${SANDBOX}/work"
        if [ "${SIGNATURE_POLICY+x}" = "x" ]; then
            export SITO_REQUIRE_SIGNATURE="${SIGNATURE_POLICY}"
        else
            unset SITO_REQUIRE_SIGNATURE
        fi
        PATH="${SANDBOX}/bin:/usr/bin:/bin" \
            SITO_VERSION="${SITO_VERSION_FOR_TEST:-1.9.3}" \
            SITO_INSTALL_LOCAL_BINARY="${SITO_INSTALL_LOCAL_BINARY_FOR_TEST:-1}" \
            SITO_ALLOW_NON_ROOT=1 \
            SITO_INSTALL_BIN="${SANDBOX}/install/sito" \
            SITO_SERVICE_PATH="${SANDBOX}/systemd/sito.service" \
            SITO_SYSTEMCTL="${SANDBOX}/bin/systemctl" \
            SITO_CONFIG_DIR="${SANDBOX}/etc/sito" \
            SITO_DATA_DIR="${SANDBOX}/var/lib/sito" \
            SITO_INSTALL_COSIGN="${SITO_INSTALL_COSIGN_FOR_TEST:-0}" \
            FAKE_SYSTEMCTL_LOG="${SANDBOX}/logs/systemctl.log" \
            FAKE_SYSTEMCTL_ACTIVE="${FAKE_SYSTEMCTL_ACTIVE:-1}" \
            FAKE_SYSTEMCTL_START_EXEC="${FAKE_SYSTEMCTL_START_EXEC:-0}" \
            FAKE_SYSTEMCTL_START_MUTATES_CONFIG="${FAKE_SYSTEMCTL_START_MUTATES_CONFIG:-0}" \
            FAKE_INSTALL_BIN="${SANDBOX}/install/sito" \
            FAKE_START_PID_FILE="${SANDBOX}/logs/start.pid" \
            FAKE_CONFIG_FILE="${SANDBOX}/etc/sito/config.toml" \
            FAKE_CP_EXECUTABLE="${SANDBOX}/install/sito" \
            FAKE_CP_ETXTBSY="${FAKE_CP_ETXTBSY:-0}" \
            FAKE_INSTALL_FAIL="${FAKE_INSTALL_FAIL:-0}" \
            bash "${INSTALLER}" "$@"
    )
}

installed_version() {
    "${SANDBOX}/install/sito" --version
}

# ---------------------------------------------------------------------------
# Fresh install + live upgrade
# ---------------------------------------------------------------------------
reset_sandbox
write_fake_binary "${SANDBOX}/work/target/release/sito" "1.9.3"
SITO_VERSION_FOR_TEST=1.9.3 run_installer >"${INSTALLER_OUT}" 2>&1 || fail "fresh install failed"

assert_file_exists "${SANDBOX}/install/sito"
assert_file_exists "${SANDBOX}/systemd/sito.service"
assert_eq "sito 1.9.3" "$(installed_version)" "fresh install binary version"
grep -q 'enable sito' "${SANDBOX}/logs/systemctl.log" || fail "fresh install did not enable the service"
grep -q 'start sito' "${SANDBOX}/logs/systemctl.log" || fail "fresh install did not start the service"

# Hold the installed inode open as an executing process. A `cp -f` replacement
# now fails with ETXTBSY; the atomic rename must succeed and leave the running
# process alive.
"${SANDBOX}/install/sito" &
HOLD_PID=$!
sleep 0.3
kill -0 "${HOLD_PID}" 2>/dev/null || fail "could not start the held binary"

write_fake_binary "${SANDBOX}/work/target/release/sito" "1.9.4"
: >"${SANDBOX}/logs/systemctl.log"
FAKE_CP_ETXTBSY=1 SITO_VERSION_FOR_TEST=1.9.4 run_installer >"${INSTALLER_OUT}" 2>&1 || \
    fail "live upgrade failed while the old binary was executing"
assert_eq "sito 1.9.4" "$(installed_version)" "upgraded binary version"
grep -q 'stop sito' "${SANDBOX}/logs/systemctl.log" || fail "upgrade did not stop the service before replacing the binary"
kill -0 "${HOLD_PID}" 2>/dev/null || fail "upgrade killed the previously executing process"
kill "${HOLD_PID}" 2>/dev/null || true
HOLD_PID=""

# ---------------------------------------------------------------------------
# Failed-health rollback restores binary and config backup
# ---------------------------------------------------------------------------
reset_sandbox
write_fake_binary "${SANDBOX}/work/target/release/sito" "1.9.3"
SITO_VERSION_FOR_TEST=1.9.3 run_installer >"${INSTALLER_OUT}" 2>&1 || fail "rollback setup install failed"

printf '[dns]\nport = 0\n[web]\nenabled = false\n' >"${SANDBOX}/etc/sito/config.toml"
cp "${SANDBOX}/etc/sito/config.toml" "${TMP}/config.before"

write_fake_binary "${SANDBOX}/work/target/release/sito" "1.9.4"
if FAKE_SYSTEMCTL_ACTIVE=0 \
    FAKE_SYSTEMCTL_START_EXEC=1 \
    FAKE_SYSTEMCTL_START_MUTATES_CONFIG=1 \
    FAKE_CP_ETXTBSY=1 \
    SITO_VERSION_FOR_TEST=1.9.4 run_installer >"${INSTALLER_OUT}" 2>&1; then
    fail "installer succeeded despite a failed health check"
fi

# The fake `systemctl start` executed the new binary and appended a migration
# marker to the live config; the rollback must replace both despite ETXTBSY.
assert_file_exists "${SANDBOX}/logs/start.pid"
HOLD_PID="$(cat "${SANDBOX}/logs/start.pid")"
kill -0 "${HOLD_PID}" 2>/dev/null || fail "fake systemctl start did not hold the new binary open"
assert_eq "sito 1.9.3" "$(installed_version)" "rollback restored the previous binary"
assert_file_exists "${SANDBOX}/install/sito.bak"
assert_file_exists "${SANDBOX}/etc/sito/config.toml.bak"
cmp -s "${TMP}/config.before" "${SANDBOX}/etc/sito/config.toml" || fail "rollback did not restore the config backup"
if grep -q 'mutated by simulated startup migration' "${SANDBOX}/etc/sito/config.toml"; then
    fail "rollback left the startup-migration marker in the live config"
fi
kill "${HOLD_PID}" 2>/dev/null || true
HOLD_PID=""

# ---------------------------------------------------------------------------
# An unexpected install failure after stop restarts the existing service
# ---------------------------------------------------------------------------
reset_sandbox
write_fake_binary "${SANDBOX}/work/target/release/sito" "1.9.3"
SITO_VERSION_FOR_TEST=1.9.3 run_installer >"${INSTALLER_OUT}" 2>&1 || fail "trap setup install failed"
write_fake_binary "${SANDBOX}/work/target/release/sito" "1.9.4"
: >"${SANDBOX}/logs/systemctl.log"
if FAKE_INSTALL_FAIL=1 SITO_VERSION_FOR_TEST=1.9.4 run_installer >"${INSTALLER_OUT}" 2>&1; then
    fail "installer succeeded despite a simulated atomic-install failure"
fi
grep -q 'restart sito' "${SANDBOX}/logs/systemctl.log" || fail "failed install did not restart the existing service"
assert_eq "sito 1.9.3" "$(installed_version)" "failed install left the previous binary in place"

# ---------------------------------------------------------------------------
# Uninstall keeps config and data
# ---------------------------------------------------------------------------
run_installer --uninstall >"${INSTALLER_OUT}" 2>&1 || fail "uninstall failed"
assert_file_missing "${SANDBOX}/install/sito"
assert_file_missing "${SANDBOX}/install/sito.bak"
assert_file_missing "${SANDBOX}/systemd/sito.service"
assert_file_exists "${SANDBOX}/etc/sito"
assert_file_exists "${SANDBOX}/var/lib/sito"
grep -q 'stop sito' "${SANDBOX}/logs/systemctl.log" || fail "uninstall did not stop the service"
grep -q 'disable sito' "${SANDBOX}/logs/systemctl.log" || fail "uninstall did not disable the service"

# ---------------------------------------------------------------------------
# Signature policy
# ---------------------------------------------------------------------------
write_fake_curl() {
    cat >"${SANDBOX}/bin/curl" <<'SH'
#!/usr/bin/env bash
out=""
url=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        -o)
            out="$2"
            shift 2
            ;;
        -*)
            shift
            ;;
        *)
            url="$1"
            shift
            ;;
    esac
done
name="${url##*/}"
case "${name}" in
    "${FAKE_TARBALL_NAME}")
        [ "${FAKE_CURL_MISSING_TARBALL:-0}" = "1" ] && exit 22
        cp "${FAKE_RELEASE_DIR}/${name}" "${out}"
        ;;
    SHA256SUMS)
        cp "${FAKE_RELEASE_DIR}/SHA256SUMS" "${out}"
        ;;
    *.sig)
        [ "${FAKE_CURL_MISSING_SIG:-0}" = "1" ] && exit 22
        cp "${FAKE_RELEASE_DIR}/${name}" "${out}"
        ;;
    *.pem)
        [ "${FAKE_CURL_MISSING_PEM:-0}" = "1" ] && exit 22
        cp "${FAKE_RELEASE_DIR}/${name}" "${out}"
        ;;
    *) exit 22 ;;
esac
SH
    chmod +x "${SANDBOX}/bin/curl"
}

write_fake_cosign() {
    cat >"${SANDBOX}/bin/cosign" <<'SH'
#!/usr/bin/env bash
[ "${1:-}" = "verify-blob" ] || exit 0
exit "${FAKE_COSIGN_RC:-0}"
SH
    chmod +x "${SANDBOX}/bin/cosign"
}

make_release_assets() {
    local arch target archive dir
    arch="$(uname -m)"
    case "${arch}" in
        x86_64 | amd64) target="x86_64-unknown-linux-gnu" ;;
        aarch64 | arm64) target="aarch64-unknown-linux-gnu" ;;
        armv7* | armhf) target="armv7-unknown-linux-gnueabihf" ;;
        *) fail "unsupported test architecture ${arch}" ;;
    esac
    dir="${SANDBOX}/release/sito-v1.9.4-${target}"
    archive="sito-v1.9.4-${target}.tar.gz"
    mkdir -p "${dir}" "${SANDBOX}/release"
    write_fake_binary "${dir}/sito" "1.9.4"
    tar -czf "${SANDBOX}/release/${archive}" -C "${SANDBOX}/release" "sito-v1.9.4-${target}"
    (
        cd "${SANDBOX}/release"
        sha256sum "${archive}" >SHA256SUMS
    )
    printf 'signature\n' >"${SANDBOX}/release/${archive}.sig"
    printf 'certificate\n' >"${SANDBOX}/release/${archive}.pem"
    export FAKE_TARBALL_NAME="${archive}"
    export FAKE_RELEASE_DIR="${SANDBOX}/release"
}

release_install_env() {
    SITO_INSTALL_LOCAL_BINARY_FOR_TEST=0
    SITO_VERSION_FOR_TEST=1.9.4
    SITO_INSTALL_COSIGN_FOR_TEST=0
}

# Required by default: a missing verifier fails closed.
reset_sandbox
make_release_assets
write_fake_curl
release_install_env
if SIGNATURE_POLICY=1 run_installer >"${INSTALLER_OUT}" 2>&1; then
    fail "installer accepted a required signature without cosign installed"
fi
grep -qi 'cosign' "${INSTALLER_OUT}" || fail "missing-cosign failure did not mention cosign"
assert_file_missing "${SANDBOX}/install/sito"

# Required by default: a release without .sig/.pem fails closed.
reset_sandbox
make_release_assets
write_fake_curl
write_fake_cosign
release_install_env
if FAKE_CURL_MISSING_SIG=1 SIGNATURE_POLICY=1 run_installer >"${INSTALLER_OUT}" 2>&1; then
    fail "installer accepted a required signature with missing .sig/.pem assets"
fi
grep -qi 'signature' "${INSTALLER_OUT}" || fail "missing-signature failure did not mention signatures"
assert_file_missing "${SANDBOX}/install/sito"

# The default is required even when SITO_REQUIRE_SIGNATURE is not set at all.
reset_sandbox
make_release_assets
write_fake_curl
write_fake_cosign
release_install_env
if FAKE_CURL_MISSING_SIG=1 run_installer >"${INSTALLER_OUT}" 2>&1; then
    fail "unset SITO_REQUIRE_SIGNATURE did not default to required"
fi
assert_file_missing "${SANDBOX}/install/sito"

# A missing certificate (.pem) with a present .sig must also fail closed.
reset_sandbox
make_release_assets
write_fake_curl
write_fake_cosign
release_install_env
if FAKE_CURL_MISSING_PEM=1 SIGNATURE_POLICY=1 run_installer >"${INSTALLER_OUT}" 2>&1; then
    fail "installer accepted a required signature with missing .pem"
fi
grep -qi 'signature' "${INSTALLER_OUT}" || fail "missing-PEM failure did not mention signatures"
assert_file_missing "${SANDBOX}/install/sito"

# Invalid policy values are rejected instead of being treated as truthy.
reset_sandbox
make_release_assets
write_fake_curl
write_fake_cosign
release_install_env
if SIGNATURE_POLICY=yes run_installer >"${INSTALLER_OUT}" 2>&1; then
    fail "invalid SITO_REQUIRE_SIGNATURE value was accepted"
fi
grep -qi 'must be 0 or 1' "${INSTALLER_OUT}" || fail "invalid signature policy did not report the accepted values"
assert_file_missing "${SANDBOX}/install/sito"

# Required by default: signed release with cosign succeeds.
reset_sandbox
make_release_assets
write_fake_curl
write_fake_cosign
release_install_env
if ! SIGNATURE_POLICY=1 run_installer >"${INSTALLER_OUT}" 2>&1; then
    fail "installer rejected a correctly signed release"
fi
assert_eq "sito 1.9.4" "$(installed_version)" "signed release binary version"

# Explicit opt-out allows SHA-256-only installs and warns.
reset_sandbox
make_release_assets
write_fake_curl
release_install_env
if ! FAKE_CURL_MISSING_SIG=1 SIGNATURE_POLICY=0 run_installer >"${INSTALLER_OUT}" 2>&1; then
    fail "SITO_REQUIRE_SIGNATURE=0 did not allow an unsigned install"
fi
grep -qi 'SITO_REQUIRE_SIGNATURE=0' "${INSTALLER_OUT}" || fail "explicit opt-out did not warn"
assert_eq "sito 1.9.4" "$(installed_version)" "unsigned release binary version"

echo "installer E2E OK"
