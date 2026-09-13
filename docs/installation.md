# Installation and Deployment Guide

This guide covers deploying **sito** on Linux hosts using the automated one-line installer, manual systemd service configuration, Docker, or Docker Compose.

---

## 1. Quick Install (Automated Shell Script)

For systemd-based distributions (Debian/Ubuntu, Arch, RHEL/Fedora). Alpine
and other non-systemd systems are not covered by the automated installer
(it requires `useradd`/`groupadd` and systemd); install the release binary
manually and supervise it with your init system.

```bash
curl -fsSL https://raw.githubusercontent.com/kubaeror/sito-dns/main/contrib/install.sh | sudo bash
```

The installer automatically:
1. Detects your CPU architecture (`x86_64`, `aarch64`, or `armv7`).
2. Fetches the latest signed release binary and verifies SHA256 checksums.
3. Creates the unprivileged system user `sito`.
4. Grants `CAP_NET_BIND_SERVICE` capability to bind ports 53 and 443 without root.
5. Deploys the hardened systemd unit, enables, and starts the service.
6. Runs post-install health verification (`systemctl is-active` and HTTP check).
7. Prompts you to complete setup via the web wizard at `http://<server-ip>:8080`.

---

## 2. Linux Bare-Metal Installation (systemd)

### 2.1 Resolving `systemd-resolved` Port 53 Conflicts
By default, modern Ubuntu and Debian distributions run `systemd-resolved` listening on `127.0.0.53:53`, which blocks port 53:

1. Disable the local DNS stub listener:
   ```bash
   sudo mkdir -p /etc/systemd/resolved.conf.d
   echo -e "[Resolve]\nDNSStubListener=no" | sudo tee /etc/systemd/resolved.conf.d/disable-stub.conf
   ```
2. Symlink resolv.conf to upstream nameservers and restart:
   ```bash
   sudo ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
   sudo systemctl restart systemd-resolved
   ```

### 2.2 User and Directory Setup
```bash
# Create dedicated system group and user
sudo groupadd --system sito
sudo useradd --system -g sito -d /var/lib/sito -s /usr/sbin/nologin sito

# Create configuration and data directories
sudo mkdir -p /etc/sito /var/lib/sito
sudo chown -R sito:sito /etc/sito /var/lib/sito
sudo chmod 750 /var/lib/sito /etc/sito
```

### 2.3 Binary Placement & Capabilities
```bash
sudo cp target/release/sito /usr/local/bin/sito
sudo chmod 755 /usr/local/bin/sito
sudo setcap 'cap_net_bind_service=+ep' /usr/local/bin/sito
```

### 2.4 Configuration Skeleton (Optional)
> [!NOTE]
> On a clean boot without an existing `config.toml`, **sito** starts in **setup-pending mode** serving only the web panel on port 8080. You can simply open `http://<server-ip>:8080` to generate your configuration via the web wizard, or pass `--no-setup` to boot immediately with built-in defaults.
>
> If you prefer to supply configuration up-front, create `/etc/sito/config.toml`:

```toml
config_version = 1

[server]
role = "master"
instance_name = "sito-main"
data_dir = "/var/lib/sito"
log_level = "info"

[dns]
bind = ["0.0.0.0", "::"]
port = 53
dot_port = 853
doh_port = 443
doq_port = 0

[upstream]
servers = ["tls://dns.quad9.net", "1.1.1.1:53"]
bootstrap = ["9.9.9.9", "1.1.1.1"]
strategy = "parallel"

[filtering]
enabled = true
blocking_mode = "zero_ip"

[[filtering.lists]]
name = "OISD Big"
url = "https://big.oisd.nl"
enabled = true

[web]
port = 8080
bind = "0.0.0.0"
```

### 2.5 Install Systemd Unit
Copy `contrib/systemd/sito.service` to `/etc/systemd/system/sito.service`:
```ini
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
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now sito
```

### 2.6 Updating sito

The hardened unit runs as the unprivileged `sito` user with
`ProtectSystem=strict`, and `/usr/local/bin/sito` is root-owned. The in-process
self-update therefore cannot replace its own binary while the service is
running (the write returns `EACCES`). Apply updates as root with the service
stopped:

```bash
# Option A: built-in updater
sudo systemctl stop sito
sudo sito update --check   # optional: preview the release first
sudo sito update
sudo systemctl start sito

# Option B: re-run the installer (SITO_VERSION pins a release)
sudo systemctl stop sito
sudo SITO_VERSION=1.7.0 bash contrib/install.sh
```

The installer backs up the previous binary to `/usr/local/bin/sito.bak` and
restores it automatically if the post-install health check fails. If you manage
the binary manually, stop the service, replace `/usr/local/bin/sito`, re-apply
the bind capability (`sudo setcap 'cap_net_bind_service=+ep' /usr/local/bin/sito`),
then start the service again. Docker deployments are updated by pulling the new
image tag, not from inside the container.

---

## 3. Docker Deployment

### 3.1 Standard Container (`docker run`)
```bash
docker run -d \
  --name sito \
  --restart unless-stopped \
  --cap-add=NET_BIND_SERVICE \
  -p 53:53/udp \
  -p 53:53/tcp \
  -p 853:853/tcp \
  -p 853:853/udp \
  -p 443:443/tcp \
  -p 443:443/udp \
  -p 8080:8080 \
  -v /opt/sito/config:/etc/sito \
  -v sito-data:/var/lib/sito \
  ghcr.io/kubaeror/sito-dns:latest
```

The image defines a healthcheck that probes DNS on the configured port and only
accepts the admin web interface while the API reports first-boot setup pending
(`sito healthcheck --setup-fallback`).

> **Config directory permissions.** The image runs as UID/GID `65532`
> (non-root). When bind-mounting a host directory for `/etc/sito`, hand it to
> that user once: `sudo chown -R 65532:65532 /opt/sito/config`. Alternatively
> keep configuration in a named volume mounted at `/etc/sito` (the image
> ships that path owned by `65532:65532`, and Docker initialises fresh named
> volumes from the image path), though the Compose example below bind-mounts
> `./config` for convenience.

> **Data directory permissions.** Fresh named volumes (such as `sito-data`)
> inherit the `65532:65532` ownership created in the image, so no manual step
> is needed. If you bind-mount a host directory at `/var/lib/sito` instead,
> hand it to the same user once: `sudo chown -R 65532:65532 /opt/sito/data`.
> Volumes created by images older than 1.6.0 may already be root-owned; fix
> them once with
> `docker run --rm -v sito-data:/data busybox chown -R 65532:65532 /data`.

---

## 4. Docker Compose Deployment

### 4.1 Single Node (`docker-compose.yml`)
```yaml
services:
  sito:
    image: ghcr.io/kubaeror/sito-dns:latest
    container_name: sito
    restart: unless-stopped
    cap_add:
      - NET_BIND_SERVICE
    ports:
      - "53:53/udp"
      - "53:53/tcp"
      - "853:853/tcp"
      - "853:853/udp"
      - "443:443/tcp"
      - "443:443/udp"
      - "8080:8080"
    volumes:
      - ./config:/etc/sito
      - sito-data:/var/lib/sito
    healthcheck:
      test: ["CMD", "/usr/bin/sito", "--config", "/etc/sito/config.toml", "healthcheck", "--setup-fallback"]
      interval: 30s
      timeout: 5s
      retries: 3

volumes:
  sito-data:
```

The `--setup-fallback` healthcheck flag keeps the container healthy while the
first-boot wizard is active; once setup completes the DNS probe must succeed, so
a broken DNS listener still turns the container unhealthy.

### 4.2 High-Availability Master/Slave on LAN (`macvlan`)
Run redundant master and slave instances on separate dedicated LAN IPs on a single server:

```yaml
networks:
  lan:
    driver: macvlan
    driver_opts:
      parent: eth0
    ipam:
      config:
        - subnet: 192.168.1.0/24
          gateway: 192.168.1.1

services:
  sito-master:
    image: ghcr.io/kubaeror/sito-dns:latest
    container_name: sito-master
    cap_add: [NET_BIND_SERVICE]
    networks:
      lan:
        ipv4_address: 192.168.1.10
    volumes:
      - ./master-config:/etc/sito
      - master-data:/var/lib/sito
    healthcheck:
      test: ["CMD", "/usr/bin/sito", "--config", "/etc/sito/config.toml", "healthcheck", "--setup-fallback"]
      interval: 15s
      timeout: 5s
      retries: 3

  sito-slave:
    image: ghcr.io/kubaeror/sito-dns:latest
    container_name: sito-slave
    cap_add: [NET_BIND_SERVICE]
    networks:
      lan:
        ipv4_address: 192.168.1.11
    volumes:
      - ./slave-config:/etc/sito
      - slave-data:/var/lib/sito
    healthcheck:
      test: ["CMD", "/usr/bin/sito", "--config", "/etc/sito/config.toml", "healthcheck", "--setup-fallback"]
      interval: 15s
      timeout: 5s
      retries: 3
```

> [!NOTE]
> Configuration, including `[ha] master_url`, is read exclusively from the
> mounted `config.toml`; environment overrides (for example
> `DNSD__HA__MASTER_URL`) are not supported. Make the host config directories
> writable by uid/gid 65532 once:
> `sudo chown -R 65532:65532 ./master-config ./slave-config`. The full macvlan
> reference deployment, including certificate handling and the RouterOS DHCP
> hints, is in `docker-compose.ha.yml`.

---

## 5. Post-Installation Verification

### 5.1 Test DNS Resolution
```bash
# Verify plain UDP resolution
dig @127.0.0.1 -p 53 example.com +short

# Verify ad-blocking
dig @127.0.0.1 -p 53 doubleclick.net +short
# Expected output: 0.0.0.0
```

### 5.2 Verify API and Web Panel
```bash
curl -fsSL http://127.0.0.1:8080/api/v1/status | jq .
```

The CLI health probe requires a matching DNS response with a `NOERROR` rcode:

```bash
sito --config /etc/sito/config.toml healthcheck

# First-boot window only: accept the admin web interface while the API reports
# setup pending (DNS listeners are not bound until setup completes).
sito --config /etc/sito/config.toml healthcheck --setup-fallback
```

Open `http://<host-ip>:8080` in your browser to run the first-time setup wizard. If the wizard is skipped with `--no-setup`, the bootstrap credentials are `admin` / `adminadmin` and **must be changed immediately** (Settings -> Administrator).

---

## 6. Verifying Releases

Every release archive is published with a `.sha256` checksum, a cosign keyless
signature (`.sig` + `.pem`), and a `SHA256SUMS` file covering the archives and
the SPDX SBOM (`sito.spdx.json`).

### 6.1 Checksums

```bash
sha256sum -c SHA256SUMS
```

### 6.2 cosign signature (keyless)

```bash
cosign verify-blob \
  --certificate sito-v1.7.0-x86_64-unknown-linux-gnu.tar.gz.pem \
  --signature   sito-v1.7.0-x86_64-unknown-linux-gnu.tar.gz.sig \
  --certificate-identity-regexp \
      '^https://github.com/kubaeror/sito-dns/.github/workflows/release.yml@refs/.*$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  sito-v1.7.0-x86_64-unknown-linux-gnu.tar.gz
```

The identity pins the artifact to this repository's release workflow and the
OIDC issuer pins it to GitHub Actions. `SITO_REQUIRE_SIGNATURE=1|0` controls
whether `install.sh` enforces signature verification.

### 6.3 SBOM

The SPDX 2.3 document `sito.spdx.json` is attached to every release and is
covered by `SHA256SUMS`.

### 6.4 Reproducibility

Release binaries are built in GitHub Actions with `cargo build --release
--locked`, so the dependency graph is exactly the committed `Cargo.lock`,
using the pinned Rust toolchain in `rust-toolchain.toml` and the release
profile (`lto = "fat"`, `codegen-units = 1`, `strip = true`). Rebuilding the
same tag locally with the same toolchain produces a functionally identical
binary; bit-for-bit identity is not guaranteed across host toolchains or
archive timestamps.
