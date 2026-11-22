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
# `--version`, logs invocations, simulates `db migrate`, and otherwise sleeps.
write_fake_binary() {
    local path="$1" version="$2"
    local source="${path}.c"
    command -v cc >/dev/null 2>&1 || fail "a C compiler (cc) is required for the installer E2E"
    cat >"${source}" <<EOF
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void log_argv(int argc, char **argv) {
    const char *log = getenv("FAKE_SITO_LOG");
    if (log != NULL) {
        FILE *file = fopen(log, "a");
        if (file != NULL) {
            fprintf(file, "sito");
            for (int i = 1; i < argc; i++) {
                fprintf(file, " %s", argv[i]);
            }
            fprintf(file, "\n");
            fclose(file);
        }
    }
    const char *events = getenv("FAKE_EVENT_LOG");
    if (events != NULL) {
        FILE *file = fopen(events, "a");
        if (file != NULL) {
            fprintf(file, "sito");
            for (int i = 1; i < argc; i++) {
                fprintf(file, " %s", argv[i]);
            }
            fprintf(file, "\n");
            fclose(file);
        }
    }
}

static int copy_file(const char *src, const char *dst) {
    FILE *in = fopen(src, "rb");
    if (in == NULL) {
        return 1;
    }
    FILE *out = fopen(dst, "wb");
    if (out == NULL) {
        fclose(in);
        return 1;
    }
    char buffer[4096];
    size_t read;
    while ((read = fread(buffer, 1, sizeof(buffer), in)) > 0) {
        if (fwrite(buffer, 1, read, out) != read) {
            fclose(in);
            fclose(out);
            return 1;
        }
    }
    fclose(in);
    fclose(out);
    return 0;
}

int main(int argc, char **argv) {
    log_argv(argc, argv);
    if (argc > 1 && strcmp(argv[1], "--version") == 0) {
        printf("sito ${version}\\n");
        return 0;
    }
    if (argc > 2 && strcmp(argv[1], "config") == 0 && strcmp(argv[2], "migrate") == 0) {
        return 0;
    }
    if (argc > 2 && strcmp(argv[1], "db") == 0 && strcmp(argv[2], "migrate") == 0) {
        if (getenv("FAKE_DB_MIGRATE_PARTIAL") != NULL
            && strcmp(getenv("FAKE_DB_MIGRATE_PARTIAL"), "1") == 0) {
            const char *db = getenv("FAKE_DB_PATH");
            const char *backup = getenv("FAKE_DB_BACKUP");
            if (db != NULL && backup != NULL && copy_file(db, backup) == 0) {
                FILE *file = fopen(db, "ab");
                if (file != NULL) {
                    fputs("\\nCORRUPTED BY FAILED MIGRATION\\n", file);
                    fclose(file);
                }
            }
            fprintf(stderr, "simulated partial database migration failure\\n");
            return 1;
        }
        const char *rc = getenv("FAKE_DB_MIGRATE_RC");
        if (rc != NULL && atoi(rc) != 0) {
            fprintf(stderr, "simulated database migration failure\\n");
            return atoi(rc);
        }
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
if [ -n "${FAKE_EVENT_LOG:-}" ]; then
    echo "systemctl $*" >>"${FAKE_EVENT_LOG}"
fi
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
if [ -n "${FAKE_EVENT_LOG:-}" ] && [ -n "${dest}" ]; then
    echo "cp ${dest}" >>"${FAKE_EVENT_LOG}"
fi
exec /bin/cp "$@"
SH
    chmod +x "${SANDBOX}/bin/cp"
}

# Fake capability tools: setcap success/failure is controllable and getcap
# reports the expected capability so the installer's verification path runs.
write_fake_setcap() {
    cat >"${SANDBOX}/bin/setcap" <<'SH'
#!/usr/bin/env bash
echo "$*" >>"${FAKE_SETCAP_LOG}"
exit "${FAKE_SETCAP_RC:-0}"
SH
    cat >"${SANDBOX}/bin/getcap" <<'SH'
#!/usr/bin/env bash
echo "$*" >>"${FAKE_GETCAP_LOG}"
if [ "${FAKE_GETCAP_EMPTY:-0}" = "1" ]; then
    exit 0
fi
echo "${1:-} cap_net_bind_service=ep"
SH
    chmod +x "${SANDBOX}/bin/setcap" "${SANDBOX}/bin/getcap"
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
    : >"${SANDBOX}/logs/events.log"
    : >"${SANDBOX}/logs/sito.log"
    : >"${SANDBOX}/logs/setcap.log"
    : >"${SANDBOX}/logs/getcap.log"
    write_fake_systemctl
    write_fake_cp
    write_fake_install
    write_fake_setcap
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
            SITO_SYSTEMCTL="${SITO_SYSTEMCTL_FOR_TEST:-${SANDBOX}/bin/systemctl}" \
            SITO_CONFIG_DIR="${SANDBOX}/etc/sito" \
            SITO_DATA_DIR="${SANDBOX}/var/lib/sito" \
            SITO_NO_MIGRATE="${SITO_NO_MIGRATE_FOR_TEST:-0}" \
            SITO_INSTALL_COSIGN="${SITO_INSTALL_COSIGN_FOR_TEST:-0}" \
            SITO_INSTALL_COSIGN_BIN="${SANDBOX}/install/cosign" \
            FAKE_SITO_LOG="${SANDBOX}/logs/sito.log" \
            FAKE_DB_MIGRATE_RC="${FAKE_DB_MIGRATE_RC:-0}" \
            FAKE_DB_MIGRATE_PARTIAL="${FAKE_DB_MIGRATE_PARTIAL:-0}" \
            FAKE_DB_PATH="${SANDBOX}/var/lib/sito/stats.db" \
            FAKE_DB_BACKUP="${SANDBOX}/var/lib/sito/stats.db.v1.bak" \
            FAKE_EVENT_LOG="${SANDBOX}/logs/events.log" \
            FAKE_SETCAP_LOG="${SANDBOX}/logs/setcap.log" \
            FAKE_GETCAP_LOG="${SANDBOX}/logs/getcap.log" \
            FAKE_SETCAP_RC="${FAKE_SETCAP_RC:-0}" \
            FAKE_GETCAP_EMPTY="${FAKE_GETCAP_EMPTY:-0}" \
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

write_test_config() {
    local version="$1" file="${2:-${SANDBOX}/etc/sito/config.toml}"
    printf 'config_version = %s\n[server]\ndata_dir = "%s"\n[dns]\nport = 0\n[web]\nenabled = false\n' \
        "${version}" "${SANDBOX}/var/lib/sito" >"${file}"
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
assert_file_exists "${SANDBOX}/etc/sito/sito.env"
assert_eq "600" "$(stat -c '%a' "${SANDBOX}/etc/sito/sito.env")" "fresh install env file mode"
printf 'RUST_LOG=info\n' >"${SANDBOX}/etc/sito/sito.env"
grep -q 'cap_net_bind_service=+ep' "${SANDBOX}/logs/setcap.log" || fail "installer did not set cap_net_bind_service"
grep -q "${SANDBOX}/install/sito" "${SANDBOX}/logs/getcap.log" || fail "installer did not verify capabilities with getcap"

# Hold the installed inode open as an executing process. A `cp -f` replacement
# now fails with ETXTBSY; the atomic rename must succeed and leave the running
# process alive.
"${SANDBOX}/install/sito" &
HOLD_PID=$!
sleep 0.3
kill -0 "${HOLD_PID}" 2>/dev/null || fail "could not start the held binary"

printf '[dns]\nport = 0\n[web]\nenabled = false\n' >"${SANDBOX}/etc/sito/config.toml"
write_fake_binary "${SANDBOX}/work/target/release/sito" "1.9.4"
: >"${SANDBOX}/logs/systemctl.log"
: >"${SANDBOX}/logs/events.log"
FAKE_CP_ETXTBSY=1 SITO_VERSION_FOR_TEST=1.9.4 run_installer >"${INSTALLER_OUT}" 2>&1 || \
    fail "live upgrade failed while the old binary was executing"
assert_eq "sito 1.9.4" "$(installed_version)" "upgraded binary version"
assert_eq "RUST_LOG=info" "$(cat "${SANDBOX}/etc/sito/sito.env")" "upgrade must preserve sito.env"
grep -q 'stop sito' "${SANDBOX}/logs/systemctl.log" || fail "upgrade did not stop the service before replacing the binary"
assert_file_exists "${SANDBOX}/etc/sito/config.toml.bak"
stop_line="$(grep -n 'systemctl stop sito' "${SANDBOX}/logs/events.log" | head -n 1 | cut -d: -f1)"
backup_line="$(grep -n 'cp .*config.toml.bak' "${SANDBOX}/logs/events.log" | head -n 1 | cut -d: -f1)"
[ -n "${stop_line}" ] || fail "upgrade did not log the service stop"
[ -n "${backup_line}" ] || fail "upgrade did not back up config.toml"
[ "${stop_line}" -lt "${backup_line}" ] || fail "config backup ran before the service was stopped"
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
if compgen -G "${SANDBOX}/etc/sito/.sito-config-restore.*" >/dev/null; then
    fail "rollback leaked an atomic config-restore temp file"
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
# Database migration: fresh installs skip it, upgrades run it before start
# ---------------------------------------------------------------------------
reset_sandbox
write_fake_binary "${SANDBOX}/work/target/release/sito" "1.9.3"
# A fresh install has no previous binary. Even a leftover stats.db must not be
# migrated: there is no service to stop and no upgrade to sequence.
mkdir -p "${SANDBOX}/var/lib/sito"
printf 'legacy database placeholder\n' >"${SANDBOX}/var/lib/sito/stats.db"
printf 'config_version = 2\n[server]\ndata_dir = "%s"\n[dns]\nport = 0\n[web]\nenabled = false\n' \
    "${SANDBOX}/var/lib/sito" >"${SANDBOX}/etc/sito/config.toml"
: >"${SANDBOX}/logs/sito.log"
: >"${SANDBOX}/logs/events.log"
SITO_VERSION_FOR_TEST=1.9.3 run_installer >"${INSTALLER_OUT}" 2>&1 || fail "fresh install with a leftover database failed"
if grep -q '^sito db migrate' "${SANDBOX}/logs/sito.log"; then
    fail "fresh install ran a database migration"
fi
assert_eq "sito 1.9.3" "$(installed_version)" "fresh install binary version"

# Upgrade with an existing stats.db: the new binary's `db migrate --config`
# must run after the old service stopped and before the new one starts.
reset_sandbox
write_fake_binary "${SANDBOX}/work/target/release/sito" "1.9.3"
SITO_VERSION_FOR_TEST=1.9.3 run_installer >"${INSTALLER_OUT}" 2>&1 || fail "migration upgrade setup failed"
write_test_config 2
printf 'legacy database placeholder\n' >"${SANDBOX}/var/lib/sito/stats.db"
write_fake_binary "${SANDBOX}/work/target/release/sito" "2.0.0"
: >"${SANDBOX}/logs/sito.log"
: >"${SANDBOX}/logs/events.log"
SITO_VERSION_FOR_TEST=2.0.0 run_installer >"${INSTALLER_OUT}" 2>&1 || fail "upgrade with database migration failed"
assert_eq "sito 2.0.0" "$(installed_version)" "migrated upgrade binary version"
grep -Fq -- "sito db migrate --config ${SANDBOX}/etc/sito/config.toml" "${SANDBOX}/logs/sito.log" ||
    fail "upgrade did not run the new binary's db migrate with the installed config"
stop_line="$(grep -n 'systemctl stop sito' "${SANDBOX}/logs/events.log" | head -n 1 | cut -d: -f1)"
migrate_line="$(grep -n 'sito db migrate' "${SANDBOX}/logs/events.log" | head -n 1 | cut -d: -f1)"
start_line="$(grep -n 'systemctl start sito' "${SANDBOX}/logs/events.log" | head -n 1 | cut -d: -f1)"
[ -n "${stop_line}" ] || fail "upgrade did not log the service stop"
[ -n "${migrate_line}" ] || fail "upgrade did not log the database migration"
[ -n "${start_line}" ] || fail "upgrade did not log the service start"
[ "${stop_line}" -lt "${migrate_line}" ] || fail "database migration ran before the old service stopped"
[ "${migrate_line}" -lt "${start_line}" ] || fail "database migration did not run before the new server started"

# A 1.9.x -> 1.9.x update must not invoke the 2.0 migration path even when the
# data directory already has a stats.db.
reset_sandbox
write_fake_binary "${SANDBOX}/work/target/release/sito" "1.9.3"
SITO_VERSION_FOR_TEST=1.9.3 run_installer >"${INSTALLER_OUT}" 2>&1 || fail "1.9->1.9 setup failed"
write_test_config 1
printf 'legacy database placeholder\n' >"${SANDBOX}/var/lib/sito/stats.db"
write_fake_binary "${SANDBOX}/work/target/release/sito" "1.9.4"
: >"${SANDBOX}/logs/sito.log"
: >"${SANDBOX}/logs/events.log"
SITO_VERSION_FOR_TEST=1.9.4 run_installer >"${INSTALLER_OUT}" 2>&1 || fail "1.9.x -> 1.9.x update failed"
assert_eq "sito 1.9.4" "$(installed_version)" "1.9.x update binary version"
if grep -q 'sito db migrate' "${SANDBOX}/logs/sito.log" "${SANDBOX}/logs/events.log"; then
    fail "1.9.x -> 1.9.x update ran the 2.0 database migration"
fi
grep -q 'Target version 1.9.4 is pre-2.0; skipping' "${INSTALLER_OUT}" ||
    fail "1.9.x update did not explain why the migration was skipped"

# --no-migrate must skip the migration entirely and must win over a preserved
# SITO_DB_AUTO_MIGRATE=1 in the unit environment. A v1 config backup is kept so
# the fail-closed rollback restores a matching pre-2.0 binary/config pair.
reset_sandbox
write_fake_binary "${SANDBOX}/work/target/release/sito" "1.9.3"
SITO_VERSION_FOR_TEST=1.9.3 run_installer >"${INSTALLER_OUT}" 2>&1 || fail "--no-migrate setup failed"
write_test_config 2
printf 'config_version = 1\n[server]\ndata_dir = "%s"\n[dns]\nport = 0\n[web]\nenabled = false\n'     "${SANDBOX}/var/lib/sito" >"${SANDBOX}/etc/sito/config.toml.v1.bak"
printf 'RUST_LOG=info\nSITO_DB_AUTO_MIGRATE=1\n' >"${SANDBOX}/etc/sito/sito.env"
printf 'legacy database placeholder\n' >"${SANDBOX}/var/lib/sito/stats.db"
write_fake_binary "${SANDBOX}/work/target/release/sito" "2.0.0"
: >"${SANDBOX}/logs/sito.log"
: >"${SANDBOX}/logs/events.log"
if FAKE_SYSTEMCTL_ACTIVE=0 SITO_VERSION_FOR_TEST=2.0.0 \
    run_installer --no-migrate >"${INSTALLER_OUT}" 2>&1; then
    fail "installer reported success when --no-migrate left an old database for the fail-closed server"
fi
if grep -q 'sito db migrate' "${SANDBOX}/logs/sito.log" "${SANDBOX}/logs/events.log"; then
    fail "--no-migrate still ran a database migration"
fi
grep -q 'SITO_NO_MIGRATE/--no-migrate is set' "${INSTALLER_OUT}" ||
    fail "--no-migrate did not explain that the migration was skipped"
grep -q 'fail closed' "${INSTALLER_OUT}" ||
    fail "--no-migrate did not warn that the new server fails closed"
assert_eq "1" "$(grep -c '^SITO_DB_AUTO_MIGRATE=' "${SANDBOX}/etc/sito/sito.env")"     "--no-migrate must leave exactly one SITO_DB_AUTO_MIGRATE assignment"
grep -q '^SITO_DB_AUTO_MIGRATE=0$' "${SANDBOX}/etc/sito/sito.env" ||
    fail "--no-migrate did not force SITO_DB_AUTO_MIGRATE=0 in sito.env"
grep -q '^RUST_LOG=info$' "${SANDBOX}/etc/sito/sito.env" ||
    fail "--no-migrate clobbered an unrelated sito.env entry"
assert_eq "sito 1.9.3" "$(installed_version)" "--no-migrate rollback restored the previous binary"
cmp -s "${SANDBOX}/etc/sito/config.toml.v1.bak" "${SANDBOX}/etc/sito/config.toml" ||
    fail "--no-migrate rollback did not restore the matching v1 config backup"

# The environment equivalent is validated like the other installer switches.
if SITO_NO_MIGRATE_FOR_TEST=maybe SITO_VERSION_FOR_TEST=1.9.3 \
    run_installer >"${INSTALLER_OUT}" 2>&1; then
    fail "invalid SITO_NO_MIGRATE was accepted"
fi
grep -q 'SITO_NO_MIGRATE must be 0 or 1' "${INSTALLER_OUT}" ||
    fail "invalid SITO_NO_MIGRATE did not report the accepted values"
run_installer --help >"${INSTALLER_OUT}" 2>&1 || fail "installer --help failed"
grep -q -- '--no-migrate' "${INSTALLER_OUT}" || fail "installer help does not document --no-migrate"
grep -q 'SITO_NO_MIGRATE=1' "${INSTALLER_OUT}" || fail "installer help does not document SITO_NO_MIGRATE"

# A failed migration with no identifiable new backup leaves the 2.0 binary
# installed and the service stopped; it must not restart the old service
# against a database whose state cannot be proven.
reset_sandbox
write_fake_binary "${SANDBOX}/work/target/release/sito" "1.9.3"
SITO_VERSION_FOR_TEST=1.9.3 run_installer >"${INSTALLER_OUT}" 2>&1 || fail "migration-failure setup failed"
write_test_config 2
printf 'legacy database placeholder\n' >"${SANDBOX}/var/lib/sito/stats.db"
write_fake_binary "${SANDBOX}/work/target/release/sito" "2.0.0"
: >"${SANDBOX}/logs/sito.log"
: >"${SANDBOX}/logs/events.log"
if FAKE_DB_MIGRATE_RC=1 SITO_VERSION_FOR_TEST=2.0.0 \
    run_installer >"${INSTALLER_OUT}" 2>&1; then
    fail "installer succeeded despite a failed database migration"
fi
grep -q 'sito db migrate' "${SANDBOX}/logs/sito.log" || fail "failed migration was not attempted"
grep -q 'stats database migration failed' "${INSTALLER_OUT}" ||
    fail "migration failure did not produce a clear error"
grep -q 'no single new pre-migration backup' "${INSTALLER_OUT}" ||
    fail "missing-backup failure did not explain the safe stop"
grep -q 'service stays stopped' "${INSTALLER_OUT}" ||
    fail "missing-backup failure did not say the service stays stopped"
if grep -q 'systemctl start sito\|systemctl restart sito' "${SANDBOX}/logs/events.log"; then
    fail "installer started a service after a migration failure without a backup"
fi
assert_eq "sito 2.0.0" "$(installed_version)"     "missing-backup failure must leave the 2.0 binary installed for recovery"

# A partial migration failure that did write the B2 backup must restore that
# backup before the binary/config rollback restarts the old service.
reset_sandbox
write_fake_binary "${SANDBOX}/work/target/release/sito" "1.9.3"
SITO_VERSION_FOR_TEST=1.9.3 run_installer >"${INSTALLER_OUT}" 2>&1 || fail "partial-migration setup failed"
write_test_config 2
printf 'config_version = 1\n[server]\ndata_dir = "%s"\n[dns]\nport = 0\n[web]\nenabled = false\n'     "${SANDBOX}/var/lib/sito" >"${SANDBOX}/etc/sito/config.toml.v1.bak"
printf 'ORIGINAL DATABASE CONTENT\n' >"${SANDBOX}/var/lib/sito/stats.db"
cp "${SANDBOX}/var/lib/sito/stats.db" "${TMP}/db.before-partial"
write_fake_binary "${SANDBOX}/work/target/release/sito" "2.0.0"
: >"${SANDBOX}/logs/sito.log"
: >"${SANDBOX}/logs/events.log"
if FAKE_DB_MIGRATE_PARTIAL=1 SITO_VERSION_FOR_TEST=2.0.0 \
    run_installer >"${INSTALLER_OUT}" 2>&1; then
    fail "installer succeeded despite a partial database migration failure"
fi
grep -q 'Restored .*stats.db' "${INSTALLER_OUT}" ||
    fail "partial migration failure did not report the database restore"
cmp -s "${TMP}/db.before-partial" "${SANDBOX}/var/lib/sito/stats.db" ||
    fail "partial migration failure did not restore the pre-migration database"
grep -q 'systemctl restart sito' "${SANDBOX}/logs/events.log" ||
    fail "partial migration failure did not restart the previous service after the DB restore"
assert_eq "sito 1.9.3" "$(installed_version)" "partial migration failure restored the previous binary"
cmp -s "${SANDBOX}/etc/sito/config.toml.v1.bak" "${SANDBOX}/etc/sito/config.toml" ||
    fail "partial migration rollback did not restore the matching v1 config"

# A pre-2.0 rollback must never pair a 1.9.x binary with a v2 config. When the
# matching `<config>.v1.bak` is present it is restored and the old service works.
reset_sandbox
write_fake_binary "${SANDBOX}/work/target/release/sito" "1.9.3"
SITO_VERSION_FOR_TEST=1.9.3 run_installer >"${INSTALLER_OUT}" 2>&1 || fail "pre-2.0 rollback setup failed"
write_test_config 2
printf 'config_version = 1\n[server]\ndata_dir = "%s"\n[dns]\nport = 0\n[web]\nenabled = false\n'     "${SANDBOX}/var/lib/sito" >"${SANDBOX}/etc/sito/config.toml.v1.bak"
write_fake_binary "${SANDBOX}/work/target/release/sito" "2.0.0"
: >"${SANDBOX}/logs/events.log"
if FAKE_SYSTEMCTL_ACTIVE=0 SITO_VERSION_FOR_TEST=2.0.0 \
    run_installer >"${INSTALLER_OUT}" 2>&1; then
    fail "installer succeeded despite a failed health check"
fi
grep -q 'Restoring matching v1 configuration' "${INSTALLER_OUT}" ||
    fail "pre-2.0 rollback did not report restoring the v1 config pair"
assert_eq "sito 1.9.3" "$(installed_version)" "pre-2.0 rollback restored the previous binary"
cmp -s "${SANDBOX}/etc/sito/config.toml.v1.bak" "${SANDBOX}/etc/sito/config.toml" ||
    fail "pre-2.0 rollback left a v2 config for a 1.9.x binary"
grep -q 'systemctl restart sito' "${SANDBOX}/logs/events.log" ||
    fail "pre-2.0 rollback did not restart the paired old service"

# Without that backup the rollback must keep the 2.0 binary and leave the
# service stopped instead of starting a 1.9.x binary against config v2.
reset_sandbox
write_fake_binary "${SANDBOX}/work/target/release/sito" "1.9.3"
SITO_VERSION_FOR_TEST=1.9.3 run_installer >"${INSTALLER_OUT}" 2>&1 || fail "missing-v1-backup setup failed"
write_test_config 2
write_fake_binary "${SANDBOX}/work/target/release/sito" "2.0.0"
: >"${SANDBOX}/logs/events.log"
if FAKE_SYSTEMCTL_ACTIVE=0 SITO_VERSION_FOR_TEST=2.0.0 \
    run_installer >"${INSTALLER_OUT}" 2>&1; then
    fail "installer succeeded despite a failed health check"
fi
grep -q 'refusing to restart the pre-2.0 binary' "${INSTALLER_OUT}" ||
    fail "missing-v1-backup rollback did not refuse the incompatible pair"
assert_eq "sito 2.0.0" "$(installed_version)"     "missing-v1-backup rollback must keep the 2.0 binary installed"
if grep -q 'systemctl restart sito' "${SANDBOX}/logs/events.log"; then
    fail "missing-v1-backup rollback restarted a pre-2.0 binary against config v2"
fi

# A v1 config must leave the newly installed 2.0 binary in place so the exact
# config-migration command printed by the guard is runnable immediately.
reset_sandbox
write_fake_binary "${SANDBOX}/work/target/release/sito" "1.9.3"
SITO_VERSION_FOR_TEST=1.9.3 run_installer >"${INSTALLER_OUT}" 2>&1 || fail "v1-config guard setup failed"
write_test_config 1
printf 'legacy database placeholder\n' >"${SANDBOX}/var/lib/sito/stats.db"
write_fake_binary "${SANDBOX}/work/target/release/sito" "2.0.0"
: >"${SANDBOX}/logs/sito.log"
: >"${SANDBOX}/logs/events.log"
if SITO_VERSION_FOR_TEST=2.0.0 run_installer >"${INSTALLER_OUT}" 2>&1; then
    fail "installer upgraded a v1 config with an existing database"
fi
if grep -q 'sito db migrate' "${SANDBOX}/logs/sito.log"; then
    fail "installer ran db migrate before refusing a v1 config"
fi
grep -q 'is not config v2' "${INSTALLER_OUT}" ||
    fail "v1 config failure did not explain the config version requirement"
grep -Fq -- "${SANDBOX}/install/sito config migrate --from v1 --to v2 --backup --config ${SANDBOX}/etc/sito/config.toml" \
    "${INSTALLER_OUT}" || fail "v1 config guard did not print the runnable installed-binary command"
grep -q 'service is stopped' "${INSTALLER_OUT}" ||
    fail "v1 config guard did not say the service is stopped"
assert_eq "sito 2.0.0" "$(installed_version)"     "v1 config guard must keep the 2.0 binary installed for the recovery command"
if grep -q 'systemctl start sito\|systemctl restart sito' "${SANDBOX}/logs/events.log"; then
    fail "v1 config guard started a service before the config migration"
fi
if ! FAKE_SITO_LOG="${SANDBOX}/logs/sito.log" \
    "${SANDBOX}/install/sito" config migrate --from v1 --to v2 --backup \
    --config "${SANDBOX}/etc/sito/config.toml" >"${INSTALLER_OUT}" 2>&1; then
    fail "the v1 guard recovery command is not runnable after the guard"
fi
grep -q 'sito config migrate --from v1 --to v2 --backup' "${SANDBOX}/logs/sito.log" ||
    fail "the recovery command did not run the installed binary's config migrate"

# ---------------------------------------------------------------------------
# Uninstall keeps config and data
# ---------------------------------------------------------------------------
run_installer --uninstall >"${INSTALLER_OUT}" 2>&1 || fail "uninstall failed"
assert_file_missing "${SANDBOX}/install/sito"
assert_file_missing "${SANDBOX}/install/sito.bak"
assert_file_missing "${SANDBOX}/etc/sito/config.toml.bak"
assert_file_missing "${SANDBOX}/systemd/sito.service"
assert_file_exists "${SANDBOX}/etc/sito"
assert_file_exists "${SANDBOX}/etc/sito/sito.env"
assert_file_exists "${SANDBOX}/var/lib/sito"
grep -q 'stop sito' "${SANDBOX}/logs/systemctl.log" || fail "uninstall did not stop the service"
grep -q 'disable sito' "${SANDBOX}/logs/systemctl.log" || fail "uninstall did not disable the service"

# ---------------------------------------------------------------------------
# Capability failures are visible
# ---------------------------------------------------------------------------
reset_sandbox
write_fake_binary "${SANDBOX}/work/target/release/sito" "1.9.3"
if ! FAKE_SETCAP_RC=1 SITO_VERSION_FOR_TEST=1.9.3 run_installer >"${INSTALLER_OUT}" 2>&1; then
    fail "a setcap failure aborted the install instead of warning"
fi
grep -q 'failed to set cap_net_bind_service' "${INSTALLER_OUT}" || \
    fail "setcap failure did not produce a visible warning"

reset_sandbox
write_fake_binary "${SANDBOX}/work/target/release/sito" "1.9.3"
if ! FAKE_GETCAP_EMPTY=1 SITO_VERSION_FOR_TEST=1.9.3 run_installer >"${INSTALLER_OUT}" 2>&1; then
    fail "a getcap verification mismatch aborted the install instead of warning"
fi
grep -q 'getcap did not report cap_net_bind_service' "${INSTALLER_OUT}" || \
    fail "getcap verification mismatch did not produce a visible warning"

# ---------------------------------------------------------------------------
# No systemd: warn, and still remove the unit on uninstall
# ---------------------------------------------------------------------------
reset_sandbox
write_fake_binary "${SANDBOX}/work/target/release/sito" "1.9.3"
if ! SITO_SYSTEMCTL_FOR_TEST=/nonexistent/systemctl \
    SITO_VERSION_FOR_TEST=1.9.3 run_installer >"${INSTALLER_OUT}" 2>&1; then
    fail "install without systemd failed instead of warning"
fi
grep -q 'systemd is not available' "${INSTALLER_OUT}" || fail "missing systemd warning was not printed"
assert_file_exists "${SANDBOX}/install/sito"
# A stale unit must be removed even when systemctl cannot run.
: >"${SANDBOX}/systemd/sito.service"
SITO_SYSTEMCTL_FOR_TEST=/nonexistent/systemctl run_installer --uninstall >"${INSTALLER_OUT}" 2>&1 || \
    fail "uninstall without systemd failed"
assert_file_missing "${SANDBOX}/systemd/sito.service"

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
    cosign-linux-* | cosign_checksums.txt)
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

# ---------------------------------------------------------------------------
# cosign ownership marker
# ---------------------------------------------------------------------------
make_cosign_assets() {
    local arch asset
    arch="$(uname -m)"
    case "${arch}" in
        x86_64 | amd64) asset="cosign-linux-amd64" ;;
        aarch64 | arm64) asset="cosign-linux-arm64" ;;
        armv7* | armhf) asset="cosign-linux-arm" ;;
        *) fail "unsupported test architecture ${arch}" ;;
    esac
    printf '#!/bin/sh\nexit 0\n' >"${SANDBOX}/release/${asset}"
    chmod +x "${SANDBOX}/release/${asset}"
    (
        cd "${SANDBOX}/release"
        sha256sum "${asset}" >cosign_checksums.txt
    )
}

reset_sandbox
make_release_assets
make_cosign_assets
write_fake_curl
release_install_env
if ! SITO_INSTALL_COSIGN_FOR_TEST=1 FAKE_CURL_MISSING_SIG=1 SIGNATURE_POLICY=0 \
    run_installer >"${INSTALLER_OUT}" 2>&1; then
    fail "installer-managed cosign install failed"
fi
assert_file_exists "${SANDBOX}/install/cosign"
assert_file_exists "${SANDBOX}/install/cosign.installed-by-sito"
run_installer --uninstall >"${INSTALLER_OUT}" 2>&1 || fail "uninstall after cosign install failed"
assert_file_missing "${SANDBOX}/install/cosign"
assert_file_missing "${SANDBOX}/install/cosign.installed-by-sito"

# A pre-existing, unmarked cosign belongs to the user and must survive.
reset_sandbox
write_fake_binary "${SANDBOX}/work/target/release/sito" "1.9.3"
SITO_INSTALL_LOCAL_BINARY_FOR_TEST=1 SITO_VERSION_FOR_TEST=1.9.3 \
    run_installer >"${INSTALLER_OUT}" 2>&1 || fail "pre-existing cosign setup failed"
printf 'user cosign\n' >"${SANDBOX}/install/cosign"
chmod +x "${SANDBOX}/install/cosign"
run_installer --uninstall >"${INSTALLER_OUT}" 2>&1 || fail "uninstall with pre-existing cosign failed"
assert_file_exists "${SANDBOX}/install/cosign"
grep -q 'Keeping pre-existing cosign' "${INSTALLER_OUT}" || fail "uninstall did not report keeping a user cosign"

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
