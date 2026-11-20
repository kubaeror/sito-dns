#!/usr/bin/env bash
# Static regression checks for the packaged systemd unit, the installer's
# embedded fallback unit, and the documented snippet.
#
# All three copies are edited by hand, so this test keeps them from drifting and
# keeps the installer's optional /etc/sito/sito.env handling in place.
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

UNIT="contrib/systemd/sito.service"
INSTALLER="contrib/install.sh"
DOCS="docs/installation.md"

DIRECTIVES=(
    "EnvironmentFile=-/etc/sito/sito.env"
    "UMask=0077"
    "PrivateTmp=true"
    "ProtectProc=invisible"
    "RestrictNamespaces=true"
    "RestrictSUIDSGID=true"
    "LockPersonality=true"
    "SystemCallArchitectures=native"
    "TimeoutStopSec=180"
)

for file in "$UNIT" "$INSTALLER" "$DOCS"; do
    [ -f "$file" ] || fail "$file is missing"
    for directive in "${DIRECTIVES[@]}"; do
        assert_contains "$file" "$directive" "hardening directive must be present"
    done
done

# The installer must keep the fallback unit's ExecStart and service identity
# aligned with the packaged unit.
for file in "$UNIT" "$INSTALLER"; do
    assert_contains "$file" "User=sito" "unit must run as the dedicated user"
    assert_contains "$file" "Group=sito" "unit must run as the dedicated group"
    assert_contains "$file" "ExecStart=/usr/local/bin/sito --config /etc/sito/config.toml" "unit must use the installed binary"
done

# /etc/sito/sito.env: create only when absent, mode 0600, preserve on upgrade
# and keep on uninstall (the installer never removes CONFIG_DIR).
assert_contains "$INSTALLER" 'ENV_FILE="${CONFIG_DIR}/sito.env"' "installer must define the env file path"
assert_contains "$INSTALLER" '[ ! -e "${ENV_FILE}" ] && [ ! -L "${ENV_FILE}" ]' "installer must not overwrite an existing env file or follow a symlink"
assert_contains "$INSTALLER" 'umask 077' "installer must create the env file privately"
assert_contains "$INSTALLER" 'chmod 0600 "${ENV_FILE}"' "installer must enforce mode 0600 on the env file"
if grep -Fq 'rm -f "${ENV_FILE}"' "$INSTALLER"; then
    fail "$INSTALLER: uninstall must keep ${ENV_FILE}"
fi

echo "systemd hardening: OK"
