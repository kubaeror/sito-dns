#!/usr/bin/env bash
# End-to-end Docker upgrade check for the 2.0 release candidate.
#
# Starts the previous 1.9.5 image with a v1 config and a real data directory,
# serves a local rewrite, stops it, migrates the config v1 -> v2 with the
# candidate image, starts the candidate, asserts DNS + Docker health, then
# rolls the data/config back and asserts the 1.9.5 image still serves.
#
# The candidate image entrypoint runs `sito db migrate` before the server when
# the stats database exists. When the candidate has the 2.0 entrypoint this
# script also proves SITO_NO_MIGRATE=1 leaves startup fail-closed and that the
# default start writes the 0600 stats.db.v1.bak. Older candidate images skip
# those two checks with a notice (their entrypoint has no migration flag).
#
# The images must exist locally:
#   docker build -t sito:1.9.5 <v1.9.5-worktree>
#   docker build -t sito:phase3 .
#
# Usage:
#   bash scripts/test-docker-upgrade.sh
#   OLD_IMAGE=sito:1.9.5 NEW_IMAGE=sito:phase3 HOST_PORT=15353 \
#     bash scripts/test-docker-upgrade.sh
set -euo pipefail

OLD_IMAGE="${OLD_IMAGE:-sito:1.9.5}"
NEW_IMAGE="${NEW_IMAGE:-sito:phase3}"
HOST_PORT="${HOST_PORT:-15353}"
TMP="$(mktemp -d)"
OLD_NAME="sito-upgrade-old"
NEW_NAME="sito-upgrade-new"
ADMIN_PASSWORD="upgrade-test-password"
ANSWER_HEX="192.0.2.9"

# The container writes users.toml, stats.db and HA keys as uid/gid 65532 mode
# 0600. The invoking user cannot read them directly; use passwordless sudo
# (the CI runner has it) for the snapshot and rollback copies.
as_root() {
    if [ "$(id -u)" -eq 0 ]; then
        "$@"
    else
        sudo -n "$@"
    fi
}

cleanup() {
    docker rm -f "${OLD_NAME}" "${NEW_NAME}" "${NEW_NAME}-nomigrate" >/dev/null 2>&1 || true
    as_root rm -rf "${TMP}"
}
trap cleanup EXIT

fail() {
    echo "FAIL: $*" >&2
    echo "--- old container logs ---" >&2
    docker logs "${OLD_NAME}" 2>&1 | tail -40 >&2 || true
    echo "--- new container logs ---" >&2
    docker logs "${NEW_NAME}" 2>&1 | tail -40 >&2 || true
    exit 1
}

query_rewrite() {
    local port="$1"
    python3 - "${port}" "${ANSWER_HEX}" <<'PY'
import socket
import struct
import sys

port = int(sys.argv[1])
expected = bytes(int(part) for part in sys.argv[2].split("."))
name = b"legacy.test"
qname = b"".join(bytes([len(label)]) + label for label in name.split(b".")) + b"\x00"
query = struct.pack("!HHHHHH", 0x4242, 0x0100, 1, 0, 0, 0) + qname + struct.pack("!HH", 1, 1)
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(1.0)
try:
    sock.sendto(query, ("127.0.0.1", port))
    data, _ = sock.recvfrom(4096)
except OSError:
    sys.exit(1)
if struct.unpack("!H", data[:2])[0] != 0x4242:
    sys.exit(1)
if expected not in data:
    sys.exit(1)
PY
}

wait_for_dns() {
    local name="$1" port="$2"
    for _ in $(seq 1 40); do
        if ! docker inspect -f '{{.State.Running}}' "${name}" 2>/dev/null | grep -qx true; then
            fail "container ${name} exited before answering"
        fi
        if query_rewrite "${port}"; then
            return 0
        fi
        sleep 0.5
    done
    fail "container ${name} did not answer legacy.test"
}

docker image inspect "${OLD_IMAGE}" >/dev/null 2>&1 || fail "missing image ${OLD_IMAGE}"
docker image inspect "${NEW_IMAGE}" >/dev/null 2>&1 || fail "missing image ${NEW_IMAGE}"

# Static contract: both shipped Dockerfiles must select the entrypoint mode that
# runs the explicit DB migration before the server, and document the opt-out.
for dockerfile in Dockerfile Dockerfile.release; do
    grep -Fq -- '--container-entrypoint' "${dockerfile}" ||
        fail "${dockerfile}: ENTRYPOINT must run the container entrypoint migration mode"
    grep -Fq -- 'SITO_NO_MIGRATE=1' "${dockerfile}" ||
        fail "${dockerfile}: the SITO_NO_MIGRATE opt-out must be documented"
done

NEW_ENTRYPOINT="$(docker image inspect "${NEW_IMAGE}" --format '{{json .Config.Entrypoint}}')"
HAS_CONTAINER_ENTRYPOINT=0
case "${NEW_ENTRYPOINT}" in
    *container-entrypoint*) HAS_CONTAINER_ENTRYPOINT=1 ;;
esac

mkdir -p "${TMP}/etc" "${TMP}/data"
# The distroless image runs as uid/gid 65532. Bind-mounted test directories must
# be writable by that user; production installs use named volumes or a one-time
# chown.
chmod 0777 "${TMP}/etc" "${TMP}/data"

cat >"${TMP}/etc/config.toml" <<'EOF'
config_version = 1

[server]
role = "master"
instance_name = "upgrade-test"
data_dir = "/var/lib/sito"
log_level = "info"
log_format = "json"

[dns]
bind = ["0.0.0.0"]
port = 5353
dot_port = 0
doh_port = 0
doq_port = 0
doh3_port = 0
allow_plaintext_doh = false
edns_udp_size = 1232
rate_limit_per_ip = 100
max_tcp_connections = 64

[upstream]
servers = ["1.1.1.1"]

[filtering]
enabled = false

[web]
enabled = false

[[rewrites.entries]]
domain = "legacy.test"
type = "A"
answer = "192.0.2.9"

# The image healthcheck probes a local name; answer it locally so the test does
# not depend on outbound DNS from the sandbox.
[[rewrites.entries]]
domain = "localhost"
type = "A"
answer = "127.0.0.1"
EOF

echo "==> seeding the v1 admin and starting ${OLD_IMAGE}"
docker run --rm \
    -v "${TMP}/etc:/etc/sito" \
    -v "${TMP}/data:/var/lib/sito" \
    "${OLD_IMAGE}" reset-admin --password "${ADMIN_PASSWORD}" >/dev/null

docker run -d --name "${OLD_NAME}" \
    -p "${HOST_PORT}:5353/udp" \
    -v "${TMP}/etc:/etc/sito" \
    -v "${TMP}/data:/var/lib/sito" \
    "${OLD_IMAGE}" >/dev/null

wait_for_dns "${OLD_NAME}" "${HOST_PORT}"
echo "    v1 rewrite answered"

docker stop -t 30 "${OLD_NAME}" >/dev/null
docker rm "${OLD_NAME}" >/dev/null
[ -s "${TMP}/data/stats.db" ] || fail "the v1 run did not create stats.db"
[ -s "${TMP}/data/users.toml" ] || fail "the v1 run did not create users.toml"

echo "==> snapshotting the v1 data dir for rollback"
mkdir -p "${TMP}/pre"
as_root cp -a "${TMP}/etc" "${TMP}/pre/etc"
as_root cp -a "${TMP}/data" "${TMP}/pre/data"

echo "==> migrating config v1 -> v2 with ${NEW_IMAGE}"
docker run --rm \
    -v "${TMP}/etc:/etc/sito" \
    -v "${TMP}/data:/var/lib/sito" \
    "${NEW_IMAGE}" config migrate --from v1 --to v2 --backup --json >/dev/null
as_root grep -q '^config_version = 2' "${TMP}/etc/config.toml" || fail "config was not migrated to v2"
[ -f "${TMP}/etc/config.toml.v1.bak" ] || fail "missing config.toml.v1.bak"
mode="$(stat -c '%a' "${TMP}/etc/config.toml.v1.bak")"
[ "${mode}" = "600" ] || fail "config backup mode is ${mode}, expected 600"
docker run --rm \
    -v "${TMP}/etc:/etc/sito" \
    -v "${TMP}/data:/var/lib/sito" \
    "${NEW_IMAGE}" check-config --config /etc/sito/config.toml >/dev/null
echo "    v2 config validates; v1 backup is 0600"

# Documented HA v2 upgrade step: v1 state/watermark files are refused by
# design. This test has HA disabled, but 1.9.5 still writes ha_state.toml.
# Move them aside (after the backup above) before the first v2 start.
for f in ha_state.toml ha_watermark.toml; do
    if as_root test -e "${TMP}/data/${f}"; then
        as_root mv "${TMP}/data/${f}" "${TMP}/data/${f}.v1.pre-2.0"
    fi
done

if [ "${HAS_CONTAINER_ENTRYPOINT}" = "1" ]; then
    echo "==> candidate with SITO_NO_MIGRATE=1 must fail closed on the v1 stats DB"
    as_root rm -f "${TMP}/data/stats.db.v1.bak"
    nomigrate_log="${TMP}/no-migrate.log"
    set +e
    timeout 90 docker run --rm --name "${NEW_NAME}-nomigrate" \
        -e SITO_NO_MIGRATE=1 \
        -v "${TMP}/etc:/etc/sito" \
        -v "${TMP}/data:/var/lib/sito" \
        "${NEW_IMAGE}" >"${nomigrate_log}" 2>&1
    nomigrate_rc=$?
    set -e
    [ "${nomigrate_rc}" -ne 0 ] || fail "SITO_NO_MIGRATE=1 started a server on the v1 stats DB"
    [ "${nomigrate_rc}" -ne 124 ] || fail "SITO_NO_MIGRATE=1 did not exit; it must fail closed"
    grep -q 'SITO_DB_AUTO_MIGRATE=1' "${nomigrate_log}" || \
        fail "SITO_NO_MIGRATE=1 did not print the B3 fail-closed guidance"
    grep -q 'sito db migrate' "${nomigrate_log}" || \
        fail "SITO_NO_MIGRATE=1 did not name the explicit migration command"
    if as_root test -e "${TMP}/data/stats.db.v1.bak"; then
        fail "SITO_NO_MIGRATE=1 created a migration backup"
    fi
    echo "    no-migrate stayed fail-closed and created no backup"

    echo "==> candidate with SITO_NO_MIGRATE=1 and SITO_DB_AUTO_MIGRATE=1 must fail closed"
    conflict_log="${TMP}/no-migrate-conflict.log"
    set +e
    timeout 90 docker run --rm --name "${NEW_NAME}-nomigrate" \
        -e SITO_NO_MIGRATE=1 \
        -e SITO_DB_AUTO_MIGRATE=1 \
        -v "${TMP}/etc:/etc/sito" \
        -v "${TMP}/data:/var/lib/sito" \
        "${NEW_IMAGE}" >"${conflict_log}" 2>&1
    conflict_rc=$?
    set -e
    [ "${conflict_rc}" -ne 0 ] || fail "the no-migrate/auto-migrate conflict started a server"
    [ "${conflict_rc}" -ne 124 ] || fail "the no-migrate/auto-migrate conflict did not exit"
    grep -q 'Conflicting migration policy' "${conflict_log}" || \
        fail "the conflicting switches did not produce an explicit policy error"
    if as_root test -e "${TMP}/data/stats.db.v1.bak"; then
        fail "the conflicting switches created a migration backup"
    fi
    echo "    conflicting switches failed closed without a backup"
else
    echo "notice: ${NEW_IMAGE} predates the 2.0 container entrypoint; skipping SITO_NO_MIGRATE checks" >&2
fi

echo "==> starting the candidate ${NEW_IMAGE} on the upgraded data dir"
docker run -d --name "${NEW_NAME}" \
    -p "${HOST_PORT}:5353/udp" \
    -v "${TMP}/etc:/etc/sito" \
    -v "${TMP}/data:/var/lib/sito" \
    "${NEW_IMAGE}" >/dev/null

wait_for_dns "${NEW_NAME}" "${HOST_PORT}"
[ -s "${TMP}/data/users.toml" ] || fail "users.toml disappeared during the upgrade"

if [ "${HAS_CONTAINER_ENTRYPOINT}" = "1" ]; then
    as_root test -f "${TMP}/data/stats.db.v1.bak" ||
        fail "the candidate entrypoint did not write stats.db.v1.bak"
    db_backup_mode="$(as_root stat -c '%a' "${TMP}/data/stats.db.v1.bak")"
    [ "${db_backup_mode}" = "600" ] ||
        fail "stats.db.v1.bak mode is ${db_backup_mode}, expected 600"
    echo "    candidate migrated the stats DB with a 0600 v1 backup"
fi

health="unknown"
for _ in $(seq 1 90); do
    health="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "${NEW_NAME}" 2>/dev/null || echo missing)"
    [ "${health}" = "healthy" ] && break
    [ "${health}" = "unhealthy" ] && fail "candidate container reported unhealthy"
    sleep 1
done
[ "${health}" = "healthy" ] || fail "candidate health status is ${health}, expected healthy"
echo "    candidate rewrite answered and healthcheck is healthy"

docker stop -t 30 "${NEW_NAME}" >/dev/null
docker rm "${NEW_NAME}" >/dev/null

echo "==> rolling back config/data and restarting ${OLD_IMAGE}"
as_root rm -rf "${TMP:?}/etc" "${TMP:?}/data"
as_root cp -a "${TMP}/pre/etc" "${TMP}/etc"
as_root cp -a "${TMP}/pre/data" "${TMP}/data"
docker run -d --name "${OLD_NAME}" \
    -p "${HOST_PORT}:5353/udp" \
    -v "${TMP}/etc:/etc/sito" \
    -v "${TMP}/data:/var/lib/sito" \
    "${OLD_IMAGE}" >/dev/null
wait_for_dns "${OLD_NAME}" "${HOST_PORT}"
echo "    rollback answered; the v1 binary still opens the additive DB"

echo "docker upgrade E2E OK (${OLD_IMAGE} -> ${NEW_IMAGE} -> rollback)"
