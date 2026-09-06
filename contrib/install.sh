#!/usr/bin/env bash
# sito automated installer for Linux (x86_64, aarch64, armv7)
set -euo pipefail

REPO="kubaeror/sito-dns"
SITO_VERSION="${SITO_VERSION:-1.4.0}"
INSTALL_BIN="/usr/local/bin/sito"
CONFIG_DIR="/etc/sito"
DATA_DIR="/var/lib/sito"
SERVICE_PATH="/etc/systemd/system/sito.service"

echo "=================================================="
echo "    sito DNS Server Installer — v${SITO_VERSION}"
echo "=================================================="

# 1. Root check
if [ "$(id -u)" -ne 0 ]; then
    echo "Error: This installer must be run as root (use sudo)." >&2
    exit 1
fi

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

# If local binary exists in build path, prefer local install
if [ -f "target/release/sito" ]; then
    echo "Using existing local release binary target/release/sito..."
    cp -f "target/release/sito" "${INSTALL_BIN}"
elif [ -f "${TMP_DIR}/sito" ]; then
    cp -f "${TMP_DIR}/sito" "${INSTALL_BIN}"
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

    tar -xzf "${TMP_DIR}/${TARBALL_NAME}" -C "${TMP_DIR}"
    cp -f "${TMP_DIR}/sito" "${INSTALL_BIN}"
fi

if [ -f "${INSTALL_BIN}" ]; then
    chmod 755 "${INSTALL_BIN}"
    # Grant ambient capabilities to bind privileged ports (53, 443, 853)
    if command -v setcap >/dev/null 2>&1; then
        setcap 'cap_net_bind_service=+ep' "${INSTALL_BIN}" || true
    fi
fi

# 7. Install systemd service
if command -v systemctl >/dev/null 2>&1; then
    echo "Installing systemd service unit to ${SERVICE_PATH}..."
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

    systemctl daemon-reload
    systemctl enable sito || true
    echo "Starting sito service..."
    systemctl restart sito || true

    # Post-install health check
    echo "Performing post-install health check..."
    sleep 2
    HEALTH_OK=1
    if ! systemctl is-active --quiet sito 2>/dev/null; then
        HEALTH_OK=0
        echo "Error: sito service failed to start or is not active!" >&2
    fi

    if command -v curl >/dev/null 2>&1; then
        if ! curl -fsS http://localhost:8080/ >/dev/null 2>&1 && \
           ! curl -fsS http://localhost:8080/wizard >/dev/null 2>&1; then
            HEALTH_OK=0
            echo "Error: sito web server did not respond on http://localhost:8080" >&2
        fi
    fi

    if [ "${HEALTH_OK}" -eq 0 ]; then
        echo "==================================================" >&2
        echo "Service startup diagnostics (journalctl -u sito):" >&2
        echo "==================================================" >&2
        journalctl -u sito -n 50 --no-pager >&2 || true
        echo "" >&2
        echo "Troubleshooting hints:" >&2
        echo " - Check if port 8080 or port 53 is already in use: ss -tulpn | grep -E ':(53|8080)'" >&2
        echo " - Check system logs: journalctl -u sito -e" >&2
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
