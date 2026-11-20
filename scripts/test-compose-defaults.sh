#!/usr/bin/env bash
# Static regression checks for the shipped Compose defaults.
#
# These files are user-facing deployment artifacts: a future edit must not
# re-expose the plain-HTTP admin UI on every interface, drop the named config
# volume, ship a local-only image tag, or emit invalid RouterOS DHCP hex.
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

assert_contains() {
    local file="$1" needle="$2" desc="$3"
    grep -Fq -- "$needle" "$file" || fail "$file: $desc (missing '$needle')"
}

assert_not_contains() {
    local file="$1" needle="$2" desc="$3"
    if grep -Fq -- "$needle" "$file"; then
        fail "$file: $desc (found '$needle')"
    fi
}

# --- Single-node compose -----------------------------------------------------
COMPOSE="docker-compose.yml"
assert_contains "$COMPOSE" '127.0.0.1:8080:8080/tcp' "admin UI must bind to loopback"
assert_contains "$COMPOSE" 'sito-config:/etc/sito' "configuration must use a named volume"
assert_contains "$COMPOSE" 'sito-config: {}' "the named config volume must be declared"
if grep -v '^[[:space:]]*#' "$COMPOSE" | grep -Fq -- './config:/etc/sito'; then
    fail "$COMPOSE: the shipped default must not bind-mount ./config"
fi
assert_not_contains "$COMPOSE" '- "8080:8080/tcp"' "the admin UI must not bind every host interface"

image="$(awk '/^[[:space:]]*image:/ { print $2; exit }' "$COMPOSE")"
case "$image" in
    ghcr.io/kubaeror/sito-dns:[0-9]*)
        ;;
    *)
        fail "$COMPOSE: default image must be a pinned release tag, got '${image}'"
        ;;
esac
case "$image" in
    *:latest | *:local)
        fail "$COMPOSE: default image must not be mutable or local-only, got '${image}'"
        ;;
esac
assert_not_contains "$COMPOSE" 'image: sito:local' "local builds belong in the build override"

# The development override is optional, but if present it must not leak into
# the shipped default file above.
if [ -f docker-compose.build.yml ]; then
    assert_contains docker-compose.build.yml 'image: sito:local' "build override should tag the local image"
    assert_contains docker-compose.build.yml 'dockerfile: Dockerfile' "build override should build the local Dockerfile"
fi

# --- HA compose --------------------------------------------------------------
HA="docker-compose.ha.yml"
assert_contains "$HA" '0xc0a8010ac0a8010b' "DHCP Option 6 must use the fixed even-length hex value"
dhcp_hex="$(sed -n 's/.*value="0x\([0-9a-fA-F]*\)".*/\1/p' "$HA" | head -n 1)"
[ -n "$dhcp_hex" ] || fail "$HA: DHCP Option 6 value was not found"
case "$dhcp_hex" in
    *[!0-9a-fA-F]*) fail "$HA: DHCP Option 6 must be hexadecimal, got '${dhcp_hex}'" ;;
esac
if [ $(( ${#dhcp_hex} % 2 )) -ne 0 ]; then
    fail "$HA: DHCP Option 6 must contain whole bytes (even hex length), got ${#dhcp_hex} digits"
fi
[ "$dhcp_hex" = "c0a8010ac0a8010b" ] || fail "$HA: unexpected DHCP Option 6 value '0x${dhcp_hex}'"

for var in SITO_HA_PARENT SITO_HA_SUBNET SITO_HA_GATEWAY SITO_HA_MASTER_IP SITO_HA_SLAVE_IP SITO_HA_SLAVE2_IP; do
    assert_contains "$HA" "${var}" "HA topology must be parameterized with ${var}"
done
assert_contains "$HA" 'driver_opts:' "macvlan parent must stay configurable"
assert_contains "$HA" 'chown -R 65532:65532' "HA config/cert chown requirement must stay explicit"
assert_contains "$HA" 'chmod 0600' "HA certificate key permissions must stay explicit"
assert_not_contains "$HA" 'value="0xc0a8010a0c0a8010b"' "the 18-digit DHCP hex value is invalid"

ha_images="$(grep -Ec '^[[:space:]]*image:[[:space:]]*ghcr\.io/kubaeror/sito-dns:[0-9]' "$HA")"
[ "$ha_images" -ge 2 ] || fail "$HA: master and slave must use a pinned release image"
assert_not_contains "$HA" 'image: sito:local' "HA must not default to a local-only image"

# --- Build context -----------------------------------------------------------
assert_contains .dockerignore 'fuzz/target/' "fuzz build artifacts must stay out of the context"
assert_contains .dockerignore '**/target/' "nested Cargo target directories must stay out of the context"

# --- Optional Compose schema validation -------------------------------------
if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    docker compose -f "$COMPOSE" config >/dev/null || fail "docker compose could not parse ${COMPOSE}"
    docker compose -f "$HA" config >/dev/null || fail "docker compose could not parse ${HA}"
    if [ -f docker-compose.build.yml ]; then
        docker compose -f "$COMPOSE" -f docker-compose.build.yml config >/dev/null ||
            fail "docker compose could not parse the build override"
    fi
else
    echo "notice: docker compose unavailable; skipped schema validation" >&2
fi

echo "compose defaults: OK"
