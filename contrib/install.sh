#!/usr/bin/env bash
# sito automated installer for Linux (x86_64, aarch64, armv7)
set -euo pipefail

REPO="kubaeror/sito-dns"
SITO_VERSION="${SITO_VERSION:-1.1.0}"
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

# 5. Obtain and verify binary
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

TARBALL_NAME="sito-v${SITO_VERSION}-${TARGET}.tar.gz"
DOWNLOAD_URL="https://github.com/${REPO}/releases/download/v${SITO_VERSION}/${TARBALL_NAME}"
CHECKSUMS_URL="https://github.com/${REPO}/releases/download/v${SITO_VERSION}/SHA256SUMS"

# If local binary exists in build path, prefer local install
if [ -f "target/release/sito" ]; then
    echo "Using existing local release binary target/release/sito..."
    cp -f "target/release/sito" "${INSTALL_BIN}"
elif [ -f "${TMP_DIR}/sito" ]; then
    cp -f "${TMP_DIR}/sito" "${INSTALL_BIN}"
else
    echo "Downloading ${TARBALL_NAME}..."
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "${DOWNLOAD_URL}" -o "${TMP_DIR}/${TARBALL_NAME}" || true
        curl -fsSL "${CHECKSUMS_URL}" -o "${TMP_DIR}/SHA256SUMS" || true
    elif command -v wget >/dev/null 2>&1; then
        wget -q "${DOWNLOAD_URL}" -O "${TMP_DIR}/${TARBALL_NAME}" || true
        wget -q "${CHECKSUMS_URL}" -O "${TMP_DIR}/SHA256SUMS" || true
    fi

    if [ -f "${TMP_DIR}/${TARBALL_NAME}" ]; then
        if [ -f "${TMP_DIR}/SHA256SUMS" ]; then
            echo "Verifying SHA256 checksum..."
            cd "${TMP_DIR}"
            grep "${TARBALL_NAME}" SHA256SUMS | sha256sum -c -
            cd - >/dev/null
        fi
        tar -xzf "${TMP_DIR}/${TARBALL_NAME}" -C "${TMP_DIR}"
        cp -f "${TMP_DIR}/sito" "${INSTALL_BIN}"
    else
        echo "Warning: Prebuilt binary archive not available online, falling back to local binary copy if present."
        if [ -f "./sito" ]; then
            cp -f "./sito" "${INSTALL_BIN}"
        else
            echo "Binary placement: please ensure 'sito' binary is copied to ${INSTALL_BIN}."
        fi
    fi
fi

if [ -f "${INSTALL_BIN}" ]; then
    chmod 755 "${INSTALL_BIN}"
    # Grant ambient capabilities to bind ports 53 and 443
    if command -v setcap >/dev/null 2>&1; then
        setcap 'cap_net_bind_service=+ep' "${INSTALL_BIN}" || true
    fi
fi

# 6. Deploy configuration skeleton if not present
CONFIG_FILE="${CONFIG_DIR}/config.toml"
if [ ! -f "${CONFIG_FILE}" ]; then
    echo "Creating default configuration at ${CONFIG_FILE}..."
    cat > "${CONFIG_FILE}" << 'EOF'
config_version = 1

[server]
role = "master"
instance_name = "sito-main"
data_dir = "/var/lib/sito"
log_level = "info"
log_format = "pretty"

[dns]
bind = ["0.0.0.0", "::"]
port = 53
dot_port = 853
doh_port = 443
doq_port = 853
rate_limit_per_ip = 20
max_tcp_connections = 256

[dns.cache]
enabled = true
size_mb = 64
min_ttl = 60
max_ttl = 86400
negative_ttl_max = 3600
prefetch = true
serve_stale_hours = 12

[dns.dnssec]
mode = "validate"
validate = true

[upstream]
servers = [
    "tls://dns.quad9.net",
    "https://cloudflare-dns.com/dns-query"
]
bootstrap = ["9.9.9.9", "1.1.1.1"]
strategy = "parallel"
timeout_ms = 5000

[filtering]
enabled = true
blocking_mode = "zero_ip"
blocking_ttl = 10
cname_cloaking = true
anti_doh_bypass = "off"
custom_rules = []

[[filtering.lists]]
name = "OISD Big"
url = "https://big.oisd.nl"
enabled = true
refresh_hours = 24

[rewrites]
auto_ptr = true

[web]
port = 8080
bind = ["0.0.0.0"]
https = false

[auth]
session_ttl_hours = 24
login_rate_limit = 5

[stats]
query_log_enabled = true
query_log_retention_days = 90
anonymize_client_ip = false
prometheus_enabled = true
EOF
    chown sito:sito "${CONFIG_FILE}"
    chmod 640 "${CONFIG_FILE}"
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
fi

echo ""
echo "=================================================="
echo " sito v${SITO_VERSION} installed successfully!"
echo " Web Dashboard: http://localhost:8080"
echo " Initial credentials: admin / adminadmin"
echo " Configuration: ${CONFIG_FILE}"
echo " Service Status: systemctl status sito"
echo "=================================================="
