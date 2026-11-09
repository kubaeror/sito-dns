#!/usr/bin/env bash
# sito automated installer for Linux (x86_64, aarch64, armv7)
set -euo pipefail

REPO="kubaeror/sito-dns"
SITO_VERSION="${SITO_VERSION:-latest}"
COSIGN_VERSION="${COSIGN_VERSION:-v2.6.5}"
# Release signatures are required by default. Set SITO_REQUIRE_SIGNATURE=0 only
# when a SHA-256-only install is explicitly intended (for example in an offline
# mirror that cannot publish cosign assets).
SITO_REQUIRE_SIGNATURE="${SITO_REQUIRE_SIGNATURE:-1}"
# Production defaults. Tests override these paths and the systemctl binary so
# the installer E2E can run unprivileged without touching the real system.
INSTALL_BIN="${SITO_INSTALL_BIN:-/usr/local/bin/sito}"
COSIGN_INSTALL_BIN="${SITO_INSTALL_COSIGN_BIN:-/usr/local/bin/cosign}"
CONFIG_DIR="${SITO_CONFIG_DIR:-/etc/sito}"
DATA_DIR="${SITO_DATA_DIR:-/var/lib/sito}"
SERVICE_PATH="${SITO_SERVICE_PATH:-/etc/systemd/system/sito.service}"
SYSTEMCTL="${SITO_SYSTEMCTL:-systemctl}"
CONFIG_FILE="${CONFIG_DIR}/config.toml"
BACKUP_BIN="${INSTALL_BIN}.bak"
CONFIG_BACKUP="${CONFIG_FILE}.bak"

UNINSTALL=0
for arg in "$@"; do
    case "${arg}" in
        --uninstall)
            UNINSTALL=1
            ;;
        -h|--help)
            echo "Usage: install.sh [--uninstall]"
            echo "  --uninstall  Remove the sito binary and systemd unit (keeps config/data)"
            echo "  SITO_VERSION=<version>  Pin a specific release version (default: latest)"
            echo "  SITO_INSTALL_COSIGN=0   Skip automatic cosign installation"
            echo "  COSIGN_VERSION=<tag>    Pin the cosign release (default: v2.6.5)"
            echo "  SITO_REQUIRE_SIGNATURE=0  Allow an unsigned (SHA-256 only) release"
            exit 0
            ;;
    esac
done

# systemctl is resolved through SITO_SYSTEMCTL so tests can substitute a fake
# implementation. Production leaves it at the PATH entry `systemctl`.
have_systemctl() {
    command -v "${SYSTEMCTL}" >/dev/null 2>&1
}

run_systemctl() {
    "${SYSTEMCTL}" "$@"
}

# 1. Root check. SITO_ALLOW_NON_ROOT exists only for the behavioral installer
# tests; production installs still require root.
if [ "$(id -u)" -ne 0 ] && [ "${SITO_ALLOW_NON_ROOT:-0}" != "1" ]; then
    echo "Error: This installer must be run as root (use sudo)." >&2
    exit 1
fi

if [ "${UNINSTALL}" -eq 1 ]; then
    echo "Uninstalling sito..."
    if have_systemctl; then
        run_systemctl stop sito || true
        run_systemctl disable sito || true
        rm -f "${SERVICE_PATH}"
        run_systemctl daemon-reload || true
        run_systemctl reset-failed sito 2>/dev/null || true
    fi
    rm -f "${INSTALL_BIN}" "${BACKUP_BIN}" "${CONFIG_BACKUP}"
    echo "Removed ${INSTALL_BIN} and ${SERVICE_PATH}."

    # Remove the dedicated system user/group when possible. Config and data are
    # kept on purpose, so this never uses `userdel -r`; if the account is still
    # running processes the cleanup is skipped with a warning.
    if id -u sito >/dev/null 2>&1; then
        if command -v pgrep >/dev/null 2>&1 && pgrep -u sito >/dev/null 2>&1; then
            echo "Warning: user 'sito' still has running processes; leaving the account in place." >&2
        elif userdel sito 2>/dev/null; then
            echo "Removed system user 'sito'."
        else
            echo "Warning: could not remove system user 'sito'." >&2
        fi
    fi
    if getent group sito >/dev/null 2>&1; then
        if groupdel sito 2>/dev/null; then
            echo "Removed system group 'sito'."
        else
            echo "Warning: could not remove system group 'sito' (it may still be in use)." >&2
        fi
    fi

    echo "Configuration (${CONFIG_DIR}) and data (${DATA_DIR}) were kept."
    exit 0
fi

# Resolve the concrete release version. `latest` is resolved through the
# GitHub releases API so the installer never pins a stale hardcoded version.
resolve_latest_version() {
    local api_url="https://api.github.com/repos/${REPO}/releases/latest"
    local response tag

    if command -v curl >/dev/null 2>&1; then
        response="$(curl -fsSL -H 'Accept: application/vnd.github+json' "${api_url}")" || {
            echo "Error: Failed to resolve the latest release from ${api_url}." >&2
            echo "Check network connectivity or set SITO_VERSION=<version> to install a specific release." >&2
            exit 1
        }
    elif command -v wget >/dev/null 2>&1; then
        response="$(wget -q -O - --header='Accept: application/vnd.github+json' "${api_url}")" || {
            echo "Error: Failed to resolve the latest release from ${api_url}." >&2
            echo "Check network connectivity or set SITO_VERSION=<version> to install a specific release." >&2
            exit 1
        }
    else
        echo "Error: Neither curl nor wget was found; cannot resolve the latest release." >&2
        echo "Set SITO_VERSION=<version> to install a specific release without tag resolution." >&2
        exit 1
    fi

    tag="$(printf '%s\n' "${response}" | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)"
    if [ -z "${tag}" ]; then
        echo "Error: Could not determine the latest release tag from ${api_url}." >&2
        echo "Set SITO_VERSION=<version> to install a specific release." >&2
        exit 1
    fi
    printf '%s\n' "${tag#v}"
}

# Restores executable permissions and file capabilities. Called after every
# install (fresh, upgrade and rollback) so a replacement never loses the
# capability needed to bind privileged DNS ports.
apply_capabilities() {
    chmod 755 "${INSTALL_BIN}"
    # Grant ambient capabilities to bind privileged ports (53, 443, 853)
    if command -v setcap >/dev/null 2>&1; then
        setcap 'cap_net_bind_service=+ep' "${INSTALL_BIN}" || true
    fi
}

# Installs `src` as `${INSTALL_BIN}` atomically. A temp file is created in the
# destination directory, flushed, then renamed over the target. Never writes
# through the destination inode: `cp -f` over a running executable fails with
# ETXTBSY on Linux, while rename replaces the directory entry atomically.
install_binary_atomic() {
    local src="$1"
    local dest="${2:-${INSTALL_BIN}}"
    local dir tmp

    if [ ! -f "${src}" ]; then
        echo "Error: binary '${src}' does not exist." >&2
        return 1
    fi

    dir="$(dirname -- "${dest}")"
    mkdir -p "${dir}" || return 1
    tmp="$(mktemp "${dir}/.sito-install.XXXXXX")" || return 1
    if ! install -m 0755 "${src}" "${tmp}"; then
        rm -f "${tmp}"
        return 1
    fi
    # Flush the file contents before the rename makes it visible.
    if command -v sync >/dev/null 2>&1; then
        sync -- "${tmp}" 2>/dev/null || sync || true
    fi
    if ! mv -f -- "${tmp}" "${dest}"; then
        rm -f "${tmp}"
        return 1
    fi
}

# Stops the service (best effort) before the binary is replaced. If systemd is
# unavailable the caller still installs the binary; there is no running unit to
# stop in that case.
stop_service_for_install() {
    if have_systemctl; then
        run_systemctl stop sito >/dev/null 2>&1 || true
    fi
}

backup_config_if_present() {
    if [ -f "${CONFIG_FILE}" ]; then
        cp -pf "${CONFIG_FILE}" "${CONFIG_BACKUP}" || true
    fi
}

# Restores the previous binary and configuration backup after a failed health
# check. The restore itself is atomic so the service can be started again even
# if the new binary is still executing.
rollback_install() {
    if [ -f "${BACKUP_BIN}" ]; then
        echo "Restoring previous binary from ${BACKUP_BIN}..." >&2
        if install_binary_atomic "${BACKUP_BIN}"; then
            apply_capabilities
        else
            echo "Error: failed to restore ${BACKUP_BIN}." >&2
        fi
    fi
    if [ -f "${CONFIG_BACKUP}" ]; then
        echo "Restoring previous configuration from ${CONFIG_BACKUP}..." >&2
        cp -pf "${CONFIG_BACKUP}" "${CONFIG_FILE}" || true
    fi
    if have_systemctl; then
        run_systemctl restart sito || true
    fi
}

# A locally built binary can be installed without any network access, in which
# case the version is read from the binary itself.
USE_LOCAL_BINARY=0
if [ "${SITO_INSTALL_LOCAL_BINARY:-0}" = "1" ] && [ -f "target/release/sito" ]; then
    USE_LOCAL_BINARY=1
fi

if [ "${SITO_VERSION}" = "latest" ]; then
    if [ "${USE_LOCAL_BINARY}" -eq 1 ]; then
        LOCAL_VERSION="$(./target/release/sito --version 2>/dev/null | awk '{print $2}' || true)"
        SITO_VERSION="${LOCAL_VERSION:-local}"
    else
        SITO_VERSION="$(resolve_latest_version)"
    fi
fi
SITO_VERSION="${SITO_VERSION#v}"

# Reject characters that could escape the release URL paths.
case "${SITO_VERSION}" in
    ""|*[!0-9A-Za-z._+-]*)
        echo "Error: Invalid release version '${SITO_VERSION}'." >&2
        exit 1
        ;;
esac

# Directory containing this script, when executed from a real file (e.g. an
# extracted release archive). Used to install the packaged systemd unit instead
# of the embedded fallback. Piped execution (`curl | bash`) has no script file
# and uses the fallback.
if [ -n "${BASH_SOURCE[0]:-}" ] && [ -f "${BASH_SOURCE[0]}" ]; then
    SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" 2>/dev/null && pwd)" || SCRIPT_DIR=""
else
    SCRIPT_DIR=""
fi

echo "=================================================="
echo "    sito DNS Server Installer — v${SITO_VERSION}"
echo "=================================================="

# 2. Architecture detection
ARCH="$(uname -m)"
case "${ARCH}" in
    x86_64|amd64)
        TARGET="x86_64-unknown-linux-gnu"
        ;;
    aarch64|arm64)
        TARGET="aarch64-unknown-linux-gnu"
        ;;
    armv7*|armhf)
        TARGET="armv7-unknown-linux-gnueabihf"
        ;;
    *)
        echo "Error: Unsupported CPU architecture: ${ARCH}" >&2
        exit 1
        ;;
esac
echo "Detected architecture: ${ARCH} (target: ${TARGET})"

# 3. Create dedicated system user and group if missing. Test runs are
# unprivileged and use paths owned by the invoking user.
if [ "$(id -u)" -eq 0 ]; then
    if ! getent group sito >/dev/null 2>&1; then
        echo "Creating system group 'sito'..."
        groupadd --system sito
    fi

    if ! id -u sito >/dev/null 2>&1; then
        echo "Creating system user 'sito'..."
        useradd --system -g sito -d "${DATA_DIR}" -s /usr/sbin/nologin sito
    fi
fi

# 4. Create directories
mkdir -p "${CONFIG_DIR}" "${DATA_DIR}"
if [ "$(id -u)" -eq 0 ]; then
    chown -R sito:sito "${CONFIG_DIR}" "${DATA_DIR}"
fi
chmod 750 "${CONFIG_DIR}" "${DATA_DIR}"

# 5. Detect upgrade vs fresh install and backup existing binary
IS_UPGRADE=0
if [ -x "${INSTALL_BIN}" ]; then
    PREV_VERSION="$("${INSTALL_BIN}" --version 2>/dev/null || true)"
    if [ -n "${PREV_VERSION}" ]; then
        IS_UPGRADE=1
        echo "Detected existing installation: ${PREV_VERSION}"
        echo "Backing up existing binary to ${BACKUP_BIN}..."
        cp -pf "${INSTALL_BIN}" "${BACKUP_BIN}"
        backup_config_if_present
        echo "Upgrading sito ${PREV_VERSION} → v${SITO_VERSION}..."
    fi
fi
if [ "${IS_UPGRADE}" -eq 0 ]; then
    echo "Fresh install of sito v${SITO_VERSION}..."
    backup_config_if_present
fi

# 6. Obtain and verify binary
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

TARBALL_NAME="sito-v${SITO_VERSION}-${TARGET}.tar.gz"
DOWNLOAD_URL="https://github.com/${REPO}/releases/download/v${SITO_VERSION}/${TARBALL_NAME}"
CHECKSUMS_URL="https://github.com/${REPO}/releases/download/v${SITO_VERSION}/SHA256SUMS"
SIG_NAME="${TARBALL_NAME}.sig"
CERT_NAME="${TARBALL_NAME}.pem"
SIG_URL="https://github.com/${REPO}/releases/download/v${SITO_VERSION}/${SIG_NAME}"
CERT_URL="https://github.com/${REPO}/releases/download/v${SITO_VERSION}/${CERT_NAME}"

download_file() {
    local url="$1"
    local output="$2"
    local max_attempts=3
    local attempt=1
    local delay=2

    while [ "${attempt}" -le "${max_attempts}" ]; do
        echo "Downloading ${url} (attempt ${attempt}/${max_attempts})..."
        if command -v curl >/dev/null 2>&1; then
            if curl -fsSL "${url}" -o "${output}"; then
                return 0
            fi
        elif command -v wget >/dev/null 2>&1; then
            if wget -q "${url}" -O "${output}"; then
                return 0
            fi
        else
            echo "Error: Neither curl nor wget was found on the system." >&2
            exit 1
        fi

        echo "Download attempt ${attempt} failed. Retrying in ${delay}s..." >&2
        sleep "${delay}"
        attempt=$((attempt + 1))
        delay=$((delay * 2))
    done

    echo "Error: Failed to download ${url} after ${max_attempts} attempts." >&2
    return 1
}

# Installs a checksum-verified cosign binary when the host has none. The
# updater requires cosign while server.update_require_signature keeps its
# default (true), so a fresh systemd install must ship the verifier or the
# documented `sito update` command cannot run.
install_cosign_if_missing() {
    if command -v cosign >/dev/null 2>&1; then
        echo "cosign already installed: $(command -v cosign)"
        return 0
    fi

    if [ "${SITO_INSTALL_COSIGN:-1}" != "1" ]; then
        echo "Warning: 'cosign' is not installed and SITO_INSTALL_COSIGN=${SITO_INSTALL_COSIGN:-1}." >&2
        echo "Warning: 'sito update' will refuse to run until cosign is installed or" >&2
        echo "Warning: server.update_require_signature is set to false." >&2
        return 0
    fi

    case "${COSIGN_VERSION}" in
        v[0-9]* ) ;;
        *)
            echo "Error: COSIGN_VERSION must look like v2.6.5 (got '${COSIGN_VERSION}')." >&2
            exit 1
            ;;
    esac
    case "${COSIGN_VERSION}" in
        *[!0-9A-Za-z._-]* )
            echo "Error: Invalid COSIGN_VERSION '${COSIGN_VERSION}'." >&2
            exit 1
            ;;
    esac

    local asset
    case "${TARGET}" in
        x86_64-unknown-linux-gnu)
            asset="cosign-linux-amd64"
            ;;
        aarch64-unknown-linux-gnu)
            asset="cosign-linux-arm64"
            ;;
        armv7-unknown-linux-gnueabihf)
            asset="cosign-linux-arm"
            ;;
        *)
            echo "Error: No cosign release asset for target ${TARGET}." >&2
            exit 1
            ;;
    esac

    local base_url="https://github.com/sigstore/cosign/releases/download/${COSIGN_VERSION}"
    echo "Installing cosign ${COSIGN_VERSION} (${asset}) for self-update verification..."
    download_file "${base_url}/${asset}" "${TMP_DIR}/${asset}"
    download_file "${base_url}/cosign_checksums.txt" "${TMP_DIR}/cosign_checksums.txt"

    (
        cd "${TMP_DIR}"
        if ! awk -v asset="${asset}" '$2 == asset { found = 1 } END { exit found ? 0 : 1 }' cosign_checksums.txt; then
            echo "Error: cosign checksum entry for ${asset} was not found." >&2
            exit 1
        fi
        if ! awk -v asset="${asset}" '$2 == asset' cosign_checksums.txt | sha256sum -c -; then
            echo "Error: cosign checksum verification failed for ${asset}!" >&2
            exit 1
        fi
    )

    install -m 0755 "${TMP_DIR}/${asset}" "${COSIGN_INSTALL_BIN}"
    echo "Installed cosign to ${COSIGN_INSTALL_BIN}."
}

# Best-effort download of an optional artifact. Unlike download_file it does
# not retry or print noisy progress: a missing signature must fail closed.
try_download_file() {
    local url="$1"
    local output="$2"
    rm -f "${output}"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "${url}" -o "${output}" 2>/dev/null
    elif command -v wget >/dev/null 2>&1; then
        wget -q "${url}" -O "${output}" 2>/dev/null
    else
        return 1
    fi
}

# Support installing a locally built binary only when explicitly requested
# (verification cannot be performed for local builds).
if [ "${USE_LOCAL_BINARY}" -eq 1 ]; then
    echo "Using existing local release binary target/release/sito (verification skipped)..."
    stop_service_for_install
    install_binary_atomic "target/release/sito"
else
    install_cosign_if_missing

    if [ "${SITO_REQUIRE_SIGNATURE}" = "1" ] && ! command -v cosign >/dev/null 2>&1; then
        echo "Error: release signatures are required but 'cosign' is not installed." >&2
        echo "Install cosign, allow the installer to install it (SITO_INSTALL_COSIGN=1)," >&2
        echo "or opt out explicitly with SITO_REQUIRE_SIGNATURE=0." >&2
        exit 1
    fi

    download_file "${DOWNLOAD_URL}" "${TMP_DIR}/${TARBALL_NAME}"
    download_file "${CHECKSUMS_URL}" "${TMP_DIR}/SHA256SUMS"

    HAVE_SIG=0
    if try_download_file "${SIG_URL}" "${TMP_DIR}/${SIG_NAME}" && \
       try_download_file "${CERT_URL}" "${TMP_DIR}/${CERT_NAME}"; then
        HAVE_SIG=1
    fi

    if [ "${SITO_REQUIRE_SIGNATURE}" = "1" ] && [ "${HAVE_SIG}" -eq 0 ]; then
        echo "Error: release signatures are required but ${SIG_NAME} and/or ${CERT_NAME}" >&2
        echo "were not found for v${SITO_VERSION}." >&2
        echo "Refusing to install from a release channel without cosign assets." >&2
        echo "Set SITO_REQUIRE_SIGNATURE=0 only if you intentionally accept SHA-256-only integrity." >&2
        exit 1
    fi

    if [ "${HAVE_SIG}" -eq 1 ] && command -v cosign >/dev/null 2>&1; then
        echo "Verifying cosign keyless signature..."
        if cosign verify-blob \
            --certificate "${TMP_DIR}/${CERT_NAME}" \
            --signature "${TMP_DIR}/${SIG_NAME}" \
            --certificate-identity-regexp "^https://github.com/${REPO}/\.github/workflows/release\.yml@refs/tags/.*$" \
            --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
            "${TMP_DIR}/${TARBALL_NAME}"; then
            echo "Cosign keyless signature verified successfully."
        else
            echo "Error: Cosign signature verification failed for ${TARBALL_NAME}!" >&2
            exit 1
        fi
    else
        if [ "${HAVE_SIG}" -eq 0 ]; then
            echo "Warning: SITO_REQUIRE_SIGNATURE=0: no cosign signature artifacts found for release v${SITO_VERSION}." >&2
            echo "Warning: Relying solely on SHA-256 checksum verification." >&2
        elif ! command -v cosign >/dev/null 2>&1; then
            echo "Warning: SITO_REQUIRE_SIGNATURE=0: release ships cosign signatures, but 'cosign' is not installed." >&2
            echo "Warning: Relying solely on SHA-256 checksum verification." >&2
            echo "Warning: 'sito update' will refuse to run until cosign is installed or" >&2
            echo "Warning: server.update_require_signature is set to false." >&2
        fi
    fi

    echo "Verifying SHA256 checksum..."
    (
        cd "${TMP_DIR}"
        if ! grep -F "${TARBALL_NAME}" SHA256SUMS >/dev/null 2>&1; then
            echo "Error: Checksum entry for ${TARBALL_NAME} was not found in SHA256SUMS." >&2
            exit 1
        fi

        if ! grep -F "${TARBALL_NAME}" SHA256SUMS | sha256sum -c -; then
            echo "Error: SHA256 checksum verification failed for ${TARBALL_NAME}!" >&2
            echo "The downloaded archive does not match the published release checksum." >&2
            echo "This could indicate a corrupted download or security tampering." >&2
            exit 1
        fi
    )

    # The release archive contains a top-level directory; strip it so the binary
    # lands directly in TMP_DIR.
    tar -xzf "${TMP_DIR}/${TARBALL_NAME}" --strip-components=1 -C "${TMP_DIR}"
    if [ ! -f "${TMP_DIR}/sito" ]; then
        echo "Error: 'sito' binary not found inside ${TARBALL_NAME}." >&2
        exit 1
    fi
    stop_service_for_install
    install_binary_atomic "${TMP_DIR}/sito"
fi

if [ -f "${INSTALL_BIN}" ]; then
    apply_capabilities
fi

# 7. Install systemd service. Prefer the unit shipped in the release archive
# (contrib/systemd/sito.service) so it cannot drift from the source of truth;
# fall back to the embedded copy below when running via `curl | bash`.
if have_systemctl; then
    UNIT_SRC=""
    if [ -n "${SCRIPT_DIR}" ]; then
        for candidate in "${SCRIPT_DIR}/systemd/sito.service" "${SCRIPT_DIR}/contrib/systemd/sito.service"; do
            if [ -f "${candidate}" ]; then
                UNIT_SRC="${candidate}"
                break
            fi
        done
    fi

    mkdir -p "$(dirname -- "${SERVICE_PATH}")"
    if [ -n "${UNIT_SRC}" ]; then
        echo "Installing packaged systemd service unit from ${UNIT_SRC}..."
        install -m 0644 "${UNIT_SRC}" "${SERVICE_PATH}"
    else
        echo "Installing embedded systemd service unit to ${SERVICE_PATH}..."
        cat > "${SERVICE_PATH}" << 'EOF'
[Unit]
Description=sito high-performance filtering DNS server
Documentation=https://github.com/kubaeror/sito-dns
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=sito
Group=sito
ExecStart=/usr/local/bin/sito --config /etc/sito/config.toml
# The service runs unprivileged with ProtectSystem=strict, so in-app updates
# cannot replace the binary in /usr/local/bin. Updates must be applied as root
# while the service is stopped: sudo systemctl stop sito && sudo sito update
# (or re-run this installer). The installer also installs cosign because
# server.update_require_signature defaults to true. See docs/installation.md
# "Updating sito".
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
MemoryDenyWriteExecute=true
SystemCallFilter=@system-service
ReadWritePaths=/var/lib/sito /etc/sito
LimitNOFILE=1048576
Restart=on-failure
RestartSec=2s

[Install]
WantedBy=multi-user.target
EOF
    fi

    run_systemctl daemon-reload
    run_systemctl enable sito || true
    echo "Starting sito service..."
    run_systemctl start sito || true

    # Post-install health check. The systemd service and the DNS listener are
    # the primary checks; the HTTP probe is advisory because the web UI can be
    # disabled (`web.enabled = false`) or bound to a non-loopback address.
    echo "Performing post-install health check..."
    sleep 2

    # Prints "dns_port|web_enabled|web_bind|web_port" for the [dns]/[web]
    # sections, with the documented defaults when a key or file is missing.
    read_service_config() {
        awk '
            function strip(line) {
                sub(/#.*/, "", line)
                return line
            }
            function value(line) {
                sub(/^[^=]*=[[:space:]]*/, "", line)
                gsub(/["[:space:]]/, "", line)
                return line
            }
            /^\[dns\][[:space:]]*(#.*)?$/ { section="dns"; next }
            /^\[web\][[:space:]]*(#.*)?$/ { section="web"; next }
            /^\[/ { section="" }
            section == "dns" && strip($0) ~ /^[[:space:]]*port[[:space:]]*=/ {
                dns_port=value(strip($0))
            }
            section == "web" && strip($0) ~ /^[[:space:]]*enabled[[:space:]]*=/ {
                web_enabled=value(strip($0))
            }
            section == "web" && strip($0) ~ /^[[:space:]]*bind[[:space:]]*=/ {
                web_bind=value(strip($0))
            }
            section == "web" && strip($0) ~ /^[[:space:]]*port[[:space:]]*=/ {
                web_port=value(strip($0))
            }
            END {
                if (dns_port == "") dns_port=53
                if (web_enabled == "") web_enabled="true"
                if (web_bind == "") web_bind="0.0.0.0"
                if (web_port == "") web_port=8080
                print dns_port "|" web_enabled "|" web_bind "|" web_port
            }
        ' "$1"
    }

    DNS_PORT=53
    WEB_ENABLED="true"
    WEB_BIND="0.0.0.0"
    CONFIG_WEB_PORT=""
    if [ -f "${CONFIG_FILE}" ]; then
        IFS='|' read -r DNS_PORT WEB_ENABLED WEB_BIND CONFIG_WEB_PORT <<< "$(read_service_config "${CONFIG_FILE}")"
    fi
    WEB_PORT="${SITO_WEB_PORT:-${CONFIG_WEB_PORT:-8080}}"

    HEALTH_OK=1
    if ! run_systemctl is-active --quiet sito 2>/dev/null; then
        HEALTH_OK=0
        echo "Error: sito service failed to start or is not active!" >&2
    fi

    # DNS port check (primary): a config file means setup is complete and the
    # DNS listeners must be up. Fresh installs have no config yet - listeners
    # start after the wizard - so the check is skipped there.
    if [ -f "${CONFIG_FILE}" ] && [ "${DNS_PORT}" != "0" ]; then
        if command -v ss >/dev/null 2>&1; then
            # Capture the listener rows instead of piping into `grep -q`:
            # with `set -o pipefail`, grep exiting early can make the pipeline
            # fail even when the port is bound (SIGPIPE on ss).
            DNS_UDP_LISTENERS="$(ss -H -lun "sport = :${DNS_PORT}" 2>/dev/null || true)"
            DNS_TCP_LISTENERS="$(ss -H -ltn "sport = :${DNS_PORT}" 2>/dev/null || true)"
            if [ -z "${DNS_UDP_LISTENERS}" ] || [ -z "${DNS_TCP_LISTENERS}" ]; then
                HEALTH_OK=0
                echo "Error: sito is not listening on DNS port ${DNS_PORT} (UDP/TCP)!" >&2
            fi
        else
            echo "Notice: 'ss' not found; skipping the DNS port check." >&2
        fi
    fi

    # HTTP probe (advisory only): probe the configured bind, mapping wildcard
    # addresses to loopback because the unspecified address is not routable.
    if [ "${WEB_ENABLED}" = "false" ]; then
        echo "Notice: web UI is disabled (web.enabled = false); skipping the HTTP probe."
    elif command -v curl >/dev/null 2>&1; then
        case "${WEB_BIND}" in
            0.0.0.0) WEB_PROBE_HOST="127.0.0.1" ;;
            ::) WEB_PROBE_HOST="[::1]" ;;
            *:*) WEB_PROBE_HOST="[${WEB_BIND}]" ;;
            *) WEB_PROBE_HOST="${WEB_BIND}" ;;
        esac
        if ! curl -fsS "http://${WEB_PROBE_HOST}:${WEB_PORT}/" >/dev/null 2>&1 && \
           ! curl -fsS "http://${WEB_PROBE_HOST}:${WEB_PORT}/wizard" >/dev/null 2>&1; then
            echo "Warning: sito web server did not respond on http://${WEB_PROBE_HOST}:${WEB_PORT} (web.enabled=${WEB_ENABLED}, web.bind=${WEB_BIND})." >&2
            echo "Warning: DNS service checks passed; verify the web bind/port if the panel is needed." >&2
        fi
    else
        echo "Notice: curl not found; skipping the HTTP probe." >&2
    fi

    if [ "${HEALTH_OK}" -eq 0 ]; then
        echo "==================================================" >&2
        echo "Service startup diagnostics (journalctl -u sito):" >&2
        echo "==================================================" >&2
        journalctl -u sito -n 50 --no-pager >&2 || true
        echo "" >&2
        echo "Troubleshooting hints:" >&2
        echo " - Check if port ${DNS_PORT} or port ${WEB_PORT} is already in use: ss -tulpn | grep -E ':(${DNS_PORT}|${WEB_PORT})'" >&2
        echo " - Check system logs: journalctl -u sito -e" >&2
        echo " - Restoring previous binary and configuration backup (if present)..." >&2
        rollback_install
        exit 1
    else
        echo "sito service is active and responding."
    fi
fi

HOST_IP="$(hostname -I 2>/dev/null | awk '{print $1}' || echo "localhost")"
if [ -z "${HOST_IP}" ]; then
    HOST_IP="localhost"
fi

echo ""
echo "=================================================="
echo " sito v${SITO_VERSION} installed successfully!"
echo ""
echo " Complete First-Time Setup:"
echo "   Open http://${HOST_IP}:8080 from the server or your LAN"
echo "   to configure administrator credentials, upstreams,"
echo "   blocklists, and DNS listeners."
echo "   The admin UI is plain HTTP. Do not expose port 8080 to the internet."
echo ""
echo " Firewall guidance (LAN-only by default):"
echo "   sito binds DNS on all interfaces and the admin UI on 0.0.0.0:8080."
echo "   Allow only your LAN; replace 192.168.0.0/24 with your subnet."
echo "   UFW (allow SSH first so a remote session survives enabling the firewall):"
echo "     ufw allow OpenSSH"
echo "     ufw default deny incoming"
echo "     ufw allow from 192.168.0.0/24 to any port 53 proto udp comment 'sito DNS (UDP, LAN)'"
echo "     ufw allow from 192.168.0.0/24 to any port 53 proto tcp comment 'sito DNS (TCP, LAN)'"
echo "   firewalld:"
echo "     firewall-cmd --permanent --add-rich-rule='rule family=\"ipv4\" source address=\"192.168.0.0/24\" port port=\"53\" protocol=\"udp\" accept'"
echo "     firewall-cmd --permanent --add-rich-rule='rule family=\"ipv4\" source address=\"192.168.0.0/24\" port port=\"53\" protocol=\"tcp\" accept'"
echo "     firewall-cmd --reload"
echo "   The rules above do not open 8080. After 'ufw enable', use the SSH"
echo "   tunnel below, or add this temporary LAN-only rule for setup and"
echo "   remove it once setup is complete:"
echo "     ufw allow from 192.168.0.0/24 to any port 8080 proto tcp"
echo "   Admin access: do not open 8080 publicly. Use an SSH tunnel:"
echo "     ssh -L 8080:127.0.0.1:8080 user@server"
echo "   then browse http://127.0.0.1:8080. For remote access, put a"
echo "   reverse proxy with TLS in front and set web.bind = \"127.0.0.1\"."
echo "   DoT/DoH/DoH3 (853/443) are optional; if enabled, restrict them"
echo "   to the clients that need them instead of opening them to everyone."
echo ""
echo " Service Management:"
echo "   Status:  systemctl status sito"
echo "   Logs:    journalctl -u sito -f"
echo "   Restart: systemctl restart sito"
echo "=================================================="
