# Installation and Deployment Guide

This guide covers deploying **sito** on Linux hosts using the automated one-line installer, manual systemd service configuration, Docker, or Docker Compose.

---

## 1. Quick Install (Automated Shell Script)

For Debian/Ubuntu, Arch, RHEL/Fedora, and Alpine Linux:

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
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now sito
```

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
  -p 853:853 \
  -p 443:443 \
  -p 8080:8080 \
  -v /opt/sito/config:/etc/sito \
  -v sito-data:/var/lib/sito \
  ghcr.io/kubaeror/sito:latest
```

---

## 4. Docker Compose Deployment

### 4.1 Single Node (`docker-compose.yml`)
```yaml
services:
  sito:
    image: ghcr.io/kubaeror/sito:latest
    container_name: sito
    restart: unless-stopped
    cap_add:
      - NET_BIND_SERVICE
    ports:
      - "53:53/udp"
      - "53:53/tcp"
      - "853:853"
      - "443:443"
      - "8080:8080"
    volumes:
      - ./config:/etc/sito
      - sito-data:/var/lib/sito
    healthcheck:
      test: ["CMD", "/usr/local/bin/sito", "healthcheck", "--address", "127.0.0.1:53"]
      interval: 30s
      timeout: 5s
      retries: 3

volumes:
  sito-data:
```

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
    image: ghcr.io/kubaeror/sito:latest
    container_name: sito-master
    cap_add: [NET_BIND_SERVICE]
    networks:
      lan:
        ipv4_address: 192.168.1.10
    volumes:
      - ./master-config:/etc/sito
      - master-data:/var/lib/sito

  sito-slave:
    image: ghcr.io/kubaeror/sito:latest
    container_name: sito-slave
    cap_add: [NET_BIND_SERVICE]
    networks:
      lan:
        ipv4_address: 192.168.1.11
    volumes:
      - ./slave-config:/etc/sito
      - slave-data:/var/lib/sito
    environment:
      - DNSD__HA__MASTER_URL=wss://192.168.1.10:8953
```

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

Open `http://<host-ip>:8080` in your web browser to access the dashboard. Default credentials on initial run: `admin` / `adminadmin` (system prompts for immediate password change and optional TOTP enrollment on first login).
