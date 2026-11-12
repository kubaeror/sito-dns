# sito 🛡️

[![CI](https://github.com/kubaeror/sito-dns/actions/workflows/ci.yml/badge.svg)](https://github.com/kubaeror/sito-dns/actions/workflows/ci.yml)
[![Weekly Quality](https://github.com/kubaeror/sito-dns/actions/workflows/weekly.yml/badge.svg)](https://github.com/kubaeror/sito-dns/actions/workflows/weekly.yml)
[![Release](https://img.shields.io/github/v/release/kubaeror/sito-dns?include_prereleases&color=brightgreen)](https://github.com/kubaeror/sito-dns/releases)
[![License: GPL-3.0](https://img.shields.io/badge/License-GPL--3.0-blue.svg)](LICENSE)
[![MSRV: 1.99.1](https://img.shields.io/badge/MSRV-1.99.1-orange.svg)](rust-toolchain.toml)
[![Rust Edition 2024](https://img.shields.io/badge/Edition-2024-purple.svg)](Cargo.toml)

CI lanes, the required `ci-gate` check, the release pipeline, and the current
runner-minute budget are documented in **[docs/ci.md](docs/ci.md)**.

> **sito** (noun, Polish for *sieve* / *strainer*) — A high-performance, memory-safe, self-hosted filtering DNS server written in Rust.

`sito` is designed as a modern, rock-solid alternative to AdGuard Home and Pi-hole. Engineered in Rust (edition 2024), it combines sub-millisecond p99 latency, comprehensive ad/tracker/malware blocking (using AdGuard/ABP rule syntax), multi-protocol encryption (DoT, DoH H2, DoQ, DoH3), and automated master/slave high availability.

> **Development status:** the `main` line is currently **2.0.0-alpha.1**
> (Phase 1 refactor foundations). The latest stable release remains **1.9.5**;
> the quickstart below intentionally pins the published stable installer and
> container image. Alpha builds are not published as stable artifacts.

---

## 📊 Feature Comparison: sito vs. AdGuard Home vs. Pi-hole

| Feature / Capability | **sito** (2.0 alpha) | **AdGuard Home** | **Pi-hole (FTL)** |
|---|---|---|---|
| **Language & Runtime** | **Rust (edition 2024, zero GC, zero Node.js)** | Go (GC overhead under load) | C (FTL) + PHP Web UI |
| **Max Cache Throughput** | **≥ 500,000 QPS** (v1.0 reference run: 584k) | ~100,000 QPS | ~50,000 QPS |
| **Cache Hit Latency (p99)** | **< 1.0 ms** (v1.0 reference run: 0.34 ms) | 2 – 5 ms | 2 – 5 ms |
| **Memory @ 1M Rules** | **~ 285 MB RSS** (v1.0 reference run; Trie + Interning) | 400 – 800 MB RSS | ~ 350 MB RSS |
| **Encrypted Transports** | **DoT, DoH (H2), DoQ, DoH3** | DoT, DoH, DoQ | Plain only (requires proxy) |
| **High Availability (HA)** | **Native mTLS WebSocket Push (<2s)** | External tool (adguardhome-sync) | External tool (gravity-sync) |
| **Filter Rule Engine** | **ABP/AdGuard syntax (see [compatibility matrix](docs/compatibility.md); qtype-aware `$dnsrewrite`)** | Full ABP + modifiers | Domain regex & wildcards |
| **ReDoS Defense** | **Pure Dense DFA (no backtracking)** | RE2 linear time | POSIX regex (risk of backtrack) |
| **ACME Certificates** | **Native TLS-ALPN-01 & HTTP-01** | Built-in ACME | External (Certbot) |
| **RouterOS Integration** | **Optional experimental DHCP Lease Sync** (build with `cargo build -p sito --features routeros`; not in the default build) | None | None |
| **Distribution** | **Single standalone binary (HTMX + Askama UI embedded)** | Single standalone binary | Multiple packages / lighttpd |
| **Config Format** | **Single TOML (`config.toml`)** | Single YAML | Multiple conf files + SQLite |

> Throughput, latency, and memory figures are from the **v1.0.0**
> reference-hardware run recorded in [docs/benchmarks.md](docs/benchmarks.md).
> They are historical reference numbers, not a measurement of the 2.0 alpha
> line. Pull requests only compile the Criterion benches; the nightly
> `bench.yml` comparison fails above its tolerance once a dedicated
> `BENCH_RUNNER_LABEL` runner and a baseline generated on it are provisioned.
> The committed baseline is a development-host baseline, so that nightly gate
> is currently inactive — see
> [docs/ci.md](docs/ci.md#benchmark-baseline).

---

## ⚡ Key Highlights

- **Blazing Fast Hot Path:** Zero garbage collection pauses, multi-socket `SO_REUSEPORT` listeners, concurrent UDP query workers, single-pass candidate filter evaluation, and concurrent `moka` caching delivering **> 580k QPS** with **0.34 ms p99 latency** on reference hardware at v1.0.0 ([ADR-008](docs/adr/0008-performance-budget.md); see [benchmarks](docs/benchmarks.md)).
- **Zero-Downtime Hot Reloading:** ArcSwap-backed query pipeline and live upstream reloading pick up hot-applied configuration, upstream resolvers, local rewrites, and client group changes without dropping persistent transport connections or restarting the daemon. Process identity, the admin listener, TLS/ACME, auth and HA/integration settings are restart-only (DNS listeners are hot-rebound); the [hot-reload matrix](docs/configuration-reference.md#16-hot-reload-matrix) lists the exact split.
- **Zero-Node.js Embedded Web Console:** Lightweight, reactive admin panel powered by Axum, Askama compile-time templates, HTMX, and Alpine.js embedded directly into the standalone binary via `rust-embed` (zero npm/Node.js build or runtime dependencies, <1 MB footprint).
- **AdGuard / ABP Syntax Compatibility:** High-throughput `SuffixTrie` with string interning, Aho-Corasick substring matching, and backtracking-free regex DFAs.
- **Modern Encryption:** Native support for plain UDP/TCP, DNS-over-TLS (DoT/853), DNS-over-HTTPS (DoH/443, H2), DNS-over-QUIC (DoQ/853), and DNS-over-HTTP/3 (DoH3/443).
- **Zero-Consensus High Availability:** Real-time master/slave push replication over mTLS WebSockets with Ed25519 cryptographic signatures, certificate pinning by default (`allow_unpinned_tls` is an explicit insecure opt-out), shared token authentication, master-loss heartbeat detection, and instant mutation push.
- **Hardened Security & RBAC:** Audited security posture including setup wizard credential validation, default-authenticated Prometheus `/metrics` (`metrics_auth = true`), trusted proxy X-Forwarded-For verification, Argon2id passwords with BLAKE3-hashed TOTP backup codes and bounded auth maps with active background pruners, cosign-verified self-updates (`update_require_signature = true` by default; SHA-256 archives are still checked), constant-time authentication via `subtle`, parameterized SQL query builders, SSRF protection, ReDoS protection via dense DFA compilation bounds, and systemd sandbox directives.
- **Robust Telemetry:** Non-blocking query logging to SQLite in WAL mode with real upstream identification and querylog privacy anonymization, Prometheus metrics exposition ([ADR-003](docs/adr/0003-log-store-sqlite-wal.md)), and Grafana dashboard.
- **Unix & Linux Platform Support:** Engineered for Unix-based operating systems (Linux kernel 5.4+ strongly recommended for production; macOS supported for development) utilizing `SO_REUSEPORT`, `IP_PKTINFO`, and raw POSIX socket file descriptors. Windows is not supported natively.

---

## 🏗️ Architecture & Query Pipeline

```
Client Query ──▶ [sito-transport] (UDP / TCP / DoT / DoH / DoQ / DoH3)
                        │
                        ▼
                 [sito-clients] (identify client IP, CIDR, MAC, SNI, DoH path)
                        │
                        ▼
                 [sito-rewrites] (check local records, wildcard *.home.arpa, auto-PTR)
                        │
                        ▼
                 [sito-filter] (compacted SuffixTrie + Aho-Corasick + regex DFA)
                        │
                  ┌─────┴─────┐
            Verdict: Block  Verdict: Allow
                  │           │
                  ▼           ▼
             [0.0.0.0/::] [sito-cache] (check moka cache)
                              │
                        ┌─────┴─────┐
                     Cache Hit   Cache Miss
                        │           │
                        ▼           ▼
                    Respond    [sito-upstream] (forward query to encrypted upstreams)
                                    │
                                    ▼
                               [sito-dnssec] (RFC 4035 validation against root trust)
                                    │
                                    ▼
                                Store & Return
```

---

## 🚀 Quickstart

### Option 1: Automated One-Line Installer (Linux)
The examples below install the latest **stable** release (1.9.5). The
`2.0.0-alpha.1` development line is not published as a stable artifact yet.
```bash
# Download and inspect the pinned installer, then run it for the same version.
curl -fsSL https://raw.githubusercontent.com/kubaeror/sito-dns/v1.9.5/contrib/install.sh -o sito-install.sh
sed -n '1,120p' sito-install.sh
sudo SITO_VERSION=1.9.5 bash sito-install.sh
```

The installer verifies the cosign signature of the release assets by default;
a missing signature or cosign binary fails closed. See
[the installation guide](docs/installation.md#6-verifying-releases) and
[release verification](docs/release-verification.md). Replace `v1.9.5` with a
newer tag deliberately instead of piping a mutable `main` script.

### Network exposure (read before exposing the host)

The pinned **1.9.5** defaults are intended for a trusted LAN: the admin UI
listens on `0.0.0.0:8080` over plain HTTP, and DNS listens on `0.0.0.0`/`::`
with no client allow-list. **Do not expose port 8080 to the internet.**
Restrict DNS to your LAN with a host firewall, or bind `dns.bind` to your LAN
address. For remote admin access, bind `web.bind = "127.0.0.1"` and use an SSH
tunnel or a TLS reverse proxy. The server logs a startup warning for each
exposed listener.

The **2.0 line** already defaults `web.bind` to `127.0.0.1` (config v2 safe
defaults), but still has no default-deny DNS client ACL: `dns.bind` remains
`["0.0.0.0", "::"]`. A DNS client ACL remains future work. New 2.0 installs
should keep the loopback admin bind; upgraded v1 files keep their old bind
unless `--adopt-safe-defaults` is used. See the
[2.0 migration guide](docs/2.0-migration.md).

### Option 2: Docker / Docker Compose
```yaml
services:
  sito:
    image: ghcr.io/kubaeror/sito-dns:1.9.5
    container_name: sito
    restart: unless-stopped
    cap_add:
      - NET_BIND_SERVICE
    ports:
      - "53:53/udp"       # DNS (UDP)
      - "53:53/tcp"       # DNS (TCP)
      - "853:853/tcp"     # DoT (dns.dot_port, default 853)
      - "853:853/udp"     # DoQ (dns.doq_port, default 0 = disabled)
      - "443:443/tcp"     # DoH (dns.doh_port, default 443)
      - "443:443/udp"     # DoH3 (dns.doh3_port, default 443)
      - "127.0.0.1:8080:8080/tcp"   # Web UI / REST API (loopback; use SSH tunnel/TLS proxy)
    volumes:
      # Host bind mounts must be handed to the container user once:
      #   sudo chown -R 65532:65532 ./config
      - ./config:/etc/sito
      - sito-data:/var/lib/sito
    healthcheck:
      test: ["CMD", "/usr/bin/sito", "--config", "/etc/sito/config.toml", "healthcheck", "--setup-fallback"]
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 10s

volumes:
  sito-data:
```

Pin an explicit image tag in production; `latest` is mutable. The `ports`
mapping controls **host** exposure while `web.bind` controls the listener
**inside** the container. Keep `web.bind = "0.0.0.0"` inside the container so
Docker can forward the port, and publish it only on loopback:
`-p 127.0.0.1:8080:8080`. Use an SSH tunnel or a TLS reverse proxy for remote
access. See [Docker Compose deployment](docs/installation.md#4-docker-compose-deployment).

### Option 3: Manual Binary Build (2.0 alpha)
This builds the current `2.0.0-alpha.1` development line, which uses config v2
and rejects a v1 `config.toml` until it is migrated. For a stable production
install, use the pinned 1.9.5 installer or image above and follow the
[2.0 migration guide](docs/2.0-migration.md) when moving to 2.0.

```bash
# Build release binary with embedded Web UI and mimalloc allocator
cargo build --release --locked --features "embed-ui,mimalloc"

# Verify configuration (if an existing config.toml is provided)
./target/release/sito check-config --config /etc/sito/config.toml

# Start daemon (if config is missing, boots into setup wizard mode on port 8080)
./target/release/sito --config /etc/sito/config.toml

# For headless environments on a first boot with no config.toml, skip the
# wizard and boot immediately. This generates a random admin password (printed
# once), binds the panel to loopback, and does not enable admin/adminadmin:
./target/release/sito --no-setup
```

### 🧙 First-Time Setup Wizard
On a fresh installation without a configuration file, **sito** starts in **setup-pending mode** on port `8080` (DNS listener ports 53/853/443 remain closed until initial setup is confirmed).

Open **`http://<server-ip>:8080`** from a trusted LAN host (or through an SSH tunnel; the LAN-only firewall in the installation guide does not open 8080) to launch the 6-section configuration wizard:
* **Administrator Account:** Set a custom admin username and a password. The wizard rejects the bootstrap password `adminadmin`, passwords shorter than 8 characters, and passwords containing whitespace or control characters. The bootstrap account cannot log in while setup is pending.
* **DNS Listeners:** Configure IPv4/IPv6 bindings, UDP/TCP, DoT, and DoH ports.
* **Upstream Resolvers:** Select presets (Cloudflare, Quad9, Google) with live latency testing.
* **Cache & DNSSEC:** Tune in-memory cache and cryptographic DNSSEC validation.
* **Filtering:** Choose blocking modes, enable CNAME cloaking defense, and subscribe to popular blocklists (OISD, StevenBlack, HaGeZi).
* **Web Panel & Statistics:** Configure web bind and retention policies.

While setup is pending, the server prints a one-time setup token to the console. Open `/wizard?setup_token=<token>` (or send the `X-Setup-Token` header). Login, API tokens and every non-wizard route stay disabled until setup completes, including when `config.toml` exists but `users.toml` still contains the bootstrap `admin` / `adminadmin` credential.

If credentials are lost, stop the service, reset the admin account, then start it
again:

```bash
sudo systemctl stop sito
sudo sito reset-admin --config /etc/sito/config.toml   # prints a generated password once
sudo systemctl start sito
```

`reset-admin` preserves non-admin accounts unless `--reset-all` is passed. The
reset commands refuse to run while a server holds the data directory. `--force`
writes the change to disk anyway, but the running server keeps its in-memory
state: existing sessions/tokens stay valid and the new admin password does not
take effect until the service is restarted.

Once setup is submitted, DNS listeners are bound in-process without needing a server restart.

Swagger UI / OpenAPI documentation is available at `http://localhost:8080/api/docs`.

---

## 📖 Comprehensive Documentation

* **[2.0 Migration Guide](docs/2.0-migration.md):** Stable 1.9.5 → 2.0 alpha upgrade, breaking-change IDs, config/API/DB/HA boundary, and rollback.
* **[Installation Guide](docs/installation.md):** Step-by-step setup for Linux systemd, Docker, Docker Compose, and HA macvlan.
* **[Configuration Reference](docs/configuration-reference.md):** Exhaustive documentation of every TOML configuration key, default and hot-reload/restart behavior. See also [Config v2](docs/config-v2.md) and the [2.0 public API diff](docs/2.0-public-api-diff.md).
* **[Benchmarking Report](docs/benchmarks.md):** Empirical benchmark results vs. Plan Section 16.1 and ADR-0008 contracts.
* **[Performance Tuning Guide](docs/performance.md):** Kernel sysctl parameters, NIC RSS hashing, and PGO instructions.
* **[Security Review & Threat Model](docs/security-audit.md):** Security vectors, SSRF allowlists, ReDoS DFA bounds, and constant-time auth.
* **[User Management & Authentication](docs/user-management.md):** Accounts, roles/RBAC, password changes, API tokens, TOTP 2FA, last-admin protection, and recovery — including the Admin **Users** page (`/users`), the per-user **Account** page (`/account`), and the Operator-only unidentified-clients table in the web panel.
* **[Migrating from AdGuard Home](docs/migration-adguard.md):** Migration instructions and automated converter script (`contrib/adguard_to_sito.py`).
* **[High-Availability Runbook](docs/runbook-ha.md):** Deployment architectures, mTLS certificates, failover, and slave promotion.
* **[1.9.5 Release Notes](docs/release-notes-1.9.5.md):** Release-engineering patch: multi-platform artifact E2E and container image publication. See the [1.9.4 release notes](docs/release-notes-1.9.4.md#known-issues) for known issues.
* **[Changelog](CHANGELOG.md):** Release notes for v1.9.5 and complete history of phases M0 through M9.
* **[Historical documentation index](docs/history/README.md):** Which audits/plans are historical leads versus current evidence.

---

## ⚖️ License

`sito` is licensed under the **GNU General Public License v3.0** (`GPL-3.0-only`). See [LICENSE](LICENSE) for details.
