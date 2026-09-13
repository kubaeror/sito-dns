#!/usr/bin/env bash
# sito automated installer for Linux (x86_64, aarch64, armv7)
set -euo pipefail

REPO="kubaeror/sito-dns"
SITO_VERSION="${SITO_VERSION:-latest}"
INSTALL_BIN="/usr/local/bin/sito"
CONFIG_DIR="/etc/sito"
DATA_DIR="/var/lib/sito"
SERVICE_PATH="/etc/systemd/system/sito.service"

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
            exit 0
            ;;
    esac
done

# 1. Root check
if [ "$(id -u)" -ne 0 ]; then
    echo "Error: This installer must be run as root (use sudo)." >&2
    exit 1
fi

if [ "${UNINSTALL}" -eq 1 ]; then
    echo "Uninstalling sito..."
    if command -v systemctl >/dev/null 2>&1; then
        systemctl stop sito || true
        systemctl disable sito || true
        rm -f "${SERVICE_PATH}"
        systemctl daemon-reload || true
    fi
    rm -f "${INSTALL_BIN}" "${INSTALL_BIN}.bak"
    echo "Removed ${INSTALL_BIN} and ${SERVICE_PATH}."
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

# 3. Create dedicated system user and group if missing
if ! getent group sito >/dev/null 2>&1; then
    echo "Creating system group 'sito'..."
    groupadd --system sito
fi

if ! id -u sito >/dev/null 2>&1; then
    echo "Creating system user 'sito'..."
    useradd --system -g sito -d "${DATA_DIR}" -s /usr/sbin/nologin sito
fi

# 4. Create directories
mkdir -p "${CONFIG_DIR}" "${DATA_DIR}"
chown -R sito:sito "${CONFIG_DIR}" "${DATA_DIR}"
chmod 750 "${CONFIG_DIR}" "${DATA_DIR}"

# 5. Detect upgrade vs fresh install and backup existing binary
IS_UPGRADE=0
if [ -x "${INSTALL_BIN}" ]; then
    PREV_VERSION="$("${INSTALL_BIN}" --version 2>/dev/null || true)"
    if [ -n "${PREV_VERSION}" ]; then
        IS_UPGRADE=1
        echo "Detected existing installation: ${PREV_VERSION}"
        echo "Backing up existing binary to ${INSTALL_BIN}.bak..."
        cp -f "${INSTALL_BIN}" "${INSTALL_BIN}.bak"
        echo "Upgrading sito ${PREV_VERSION} → v${SITO_VERSION}..."
    fi
fi
if [ "${IS_UPGRADE}" -eq 0 ]; then
    echo "Fresh install of sito v${SITO_VERSION}..."
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

# Support installing a locally built binary only when explicitly requested
# (verification cannot be performed for local builds).
if [ "${USE_LOCAL_BINARY}" -eq 1 ]; then
    echo "Using existing local release binary target/release/sito (verification skipped)..."
    cp -f "target/release/sito" "${INSTALL_BIN}"
else
    download_file "${DOWNLOAD_URL}" "${TMP_DIR}/${TARBALL_NAME}"
    download_file "${CHECKSUMS_URL}" "${TMP_DIR}/SHA256SUMS"

    # Optional keyless signature verification with cosign
    HAVE_SIG=0
    if command -v curl >/dev/null 2>&1; then
        if curl -fsSL "${SIG_URL}" -o "${TMP_DIR}/${SIG_NAME}" 2>/dev/null && \
           curl -fsSL "${CERT_URL}" -o "${TMP_DIR}/${CERT_NAME}" 2>/dev/null; then
            HAVE_SIG=1
        fi
    elif command -v wget >/dev/null 2>&1; then
        if wget -q "${SIG_URL}" -O "${TMP_DIR}/${SIG_NAME}" 2>/dev/null && \
           wget -q "${CERT_URL}" -O "${TMP_DIR}/${CERT_NAME}" 2>/dev/null; then
            HAVE_SIG=1
        fi
    fi

    # Optional strict signature enforcement
    if [ "${SITO_REQUIRE_SIGNATURE:-0}" = "1" ]; then
        if [ "${HAVE_SIG}" -eq 0 ]; then
            echo "Error: SITO_REQUIRE_SIGNATURE=1 but no cosign signature artifacts were found." >&2
            exit 1
        fi
        if ! command -v cosign >/dev/null 2>&1; then
            echo "Error: SITO_REQUIRE_SIGNATURE=1 but 'cosign' is not installed." >&2
            exit 1
        fi
    fi

    if [ "${HAVE_SIG}" -eq 1 ] && command -v cosign >/dev/null 2>&1; then
        echo "Verifying cosign keyless signature..."
        if cosign verify-blob \
            --certificate "${TMP_DIR}/${CERT_NAME}" \
            --signature "${TMP_DIR}/${SIG_NAME}" \
            --certificate-identity-regexp "https://github.com/${REPO}/.*" \
            --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
            "${TMP_DIR}/${TARBALL_NAME}"; then
            echo "Cosign keyless signature verified successfully."
        else
            echo "Error: Cosign signature verification failed for ${TARBALL_NAME}!" >&2
            exit 1
        fi
    else
        if [ "${HAVE_SIG}" -eq 0 ]; then
            echo "Notice: No cosign signature artifacts found for release v${SITO_VERSION}."
            echo "Warning: Relying solely on SHA-256 checksum verification. Releases with signatures are strongly recommended."
        elif ! command -v cosign >/dev/null 2>&1; then
            echo "Notice: Release ships cosign signatures, but 'cosign' tool is not installed."
            echo "Warning: Relying solely on SHA-256 checksum verification. Consider installing cosign for supply chain security."
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
    cp -f "${TMP_DIR}/sito" "${INSTALL_BIN}"
fi

if [ -f "${INSTALL_BIN}" ]; then
    chmod 755 "${INSTALL_BIN}"
    # Grant ambient capabilities to bind privileged ports (53, 443, 853)
    if command -v setcap >/dev/null 2>&1; then
        setcap 'cap_net_bind_service=+ep' "${INSTALL_BIN}" || true
    fi
fi

# 7. Install systemd service. Prefer the unit shipped in the release archive
# (contrib/systemd/sito.service) so it cannot drift from the source of truth;
# fall back to the embedded copy below when running via `curl | bash`.
if command -v systemctl >/dev/null 2>&1; then
    UNIT_SRC=""
    if [ -n "${SCRIPT_DIR}" ]; then
        for candidate in "${SCRIPT_DIR}/systemd/sito.service" "${SCRIPT_DIR}/contrib/systemd/sito.service"; do
            if [ -f "${candidate}" ]; then
                UNIT_SRC="${candidate}"
                break
            fi
        done
    fi

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
# (or re-run this installer). See docs/installation.md "Updating sito".
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

    systemctl daemon-reload
    systemctl enable sito || true
    echo "Starting sito service..."
    systemctl restart sito || true

    # Post-install health check
    echo "Performing post-install health check..."
    sleep 2

    WEB_PORT="${SITO_WEB_PORT:-}"
    if [ -z "${WEB_PORT}" ] && [ -f "${CONFIG_DIR}/config.toml" ]; then
        WEB_PORT="$(awk '
            /^\[web\]/ { in_web=1; next }
            /^\[/ { in_web=0 }
            in_web && $1 == "port" { gsub(/[^0-9]/, "", $0); print; exit }
        ' "${CONFIG_DIR}/config.toml")"
    fi
    WEB_PORT="${WEB_PORT:-8080}"

    HEALTH_OK=1
    if ! systemctl is-active --quiet sito 2>/dev/null; then
        HEALTH_OK=0
        echo "Error: sito service failed to start or is not active!" >&2
    fi

    if command -v curl >/dev/null 2>&1; then
        if ! curl -fsS "http://localhost:${WEB_PORT}/" >/dev/null 2>&1 && \
           ! curl -fsS "http://localhost:${WEB_PORT}/wizard" >/dev/null 2>&1; then
            HEALTH_OK=0
            echo "Error: sito web server did not respond on http://localhost:${WEB_PORT}" >&2
        fi
    fi

    if [ "${HEALTH_OK}" -eq 0 ]; then
        echo "==================================================" >&2
        echo "Service startup diagnostics (journalctl -u sito):" >&2
        echo "==================================================" >&2
        journalctl -u sito -n 50 --no-pager >&2 || true
        echo "" >&2
        echo "Troubleshooting hints:" >&2
        echo " - Check if port ${WEB_PORT} or port 53 is already in use: ss -tulpn | grep -E ':(${WEB_PORT}|53)'" >&2
        echo " - Check system logs: journalctl -u sito -e" >&2
        echo " - Restoring previous binary from ${INSTALL_BIN}.bak (if present)..." >&2
        if [ -f "${INSTALL_BIN}.bak" ]; then
            cp -f "${INSTALL_BIN}.bak" "${INSTALL_BIN}"
            systemctl restart sito || true
        fi
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
echo "   Open http://${HOST_IP}:8080 in your browser"
echo "   to configure administrator credentials, upstreams,"
echo "   blocklists, and DNS listeners."
echo ""
echo " Firewall Configuration (allow required ports):"
echo "   UFW:"
echo "     ufw allow 53/tcp comment 'sito DNS (TCP)'"
echo "     ufw allow 53/udp comment 'sito DNS (UDP)'"
echo "     ufw allow 853/tcp comment 'sito DNS-over-TLS'"
echo "     ufw allow 443/tcp comment 'sito DNS-over-HTTPS'"
echo "     ufw allow 8080/tcp comment 'sito Admin Panel'"
echo "   firewalld:"
echo "     firewall-cmd --add-port={53/tcp,53/udp,853/tcp,443/tcp,8080/tcp} --permanent"
echo "     firewall-cmd --reload"
echo ""
echo " Service Management:"
echo "   Status:  systemctl status sito"
echo "   Logs:    journalctl -u sito -f"
echo "   Restart: systemctl restart sito"
echo "=================================================="
