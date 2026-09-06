# sito 🛡️

[![CI](https://github.com/kubaeror/sito-dns/actions/workflows/ci.yml/badge.svg)](https://github.com/kubaeror/sito-dns/actions/workflows/ci.yml)
[![Nightly Fuzzing](https://github.com/kubaeror/sito-dns/actions/workflows/nightly-fuzz.yml/badge.svg)](https://github.com/kubaeror/sito-dns/actions/workflows/nightly-fuzz.yml)
[![Release](https://img.shields.io/github/v/release/kubaeror/sito-dns?include_prereleases&color=brightgreen)](https://github.com/kubaeror/sito-dns/releases)
[![License: GPL-3.0](https://img.shields.io/badge/License-GPL--3.0-blue.svg)](LICENSE)
[![MSRV: 1.98.1](https://img.shields.io/badge/MSRV-1.98.1-orange.svg)](rust-toolchain.toml)
[![Rust Edition 2024](https://img.shields.io/badge/Edition-2024-purple.svg)](Cargo.toml)

> **sito** (noun, Polish for *sieve* / *strainer*) — A high-performance, memory-safe, self-hosted filtering DNS server written in Rust.

`sito` is designed as a modern, rock-solid alternative to AdGuard Home and Pi-hole. Engineered in Rust (edition 2024), it combines sub-millisecond p99 latency, comprehensive ad/tracker/malware blocking (using AdGuard/ABP rule syntax), multi-protocol encryption (DoT, DoH H2, DoQ, DoH3), and automated master/slave high availability.

---

## 📊 Feature Comparison: sito vs. AdGuard Home vs. Pi-hole

| Feature / Capability | **sito** (v1.3) | **AdGuard Home** | **Pi-hole (FTL)** |
|---|---|---|---|
| **Language & Runtime** | **Rust (edition 2024, zero GC, zero Node.js)** | Go (GC overhead under load) | C (FTL) + PHP Web UI |
| **Max Cache Throughput** | **≥ 500,000 QPS** (measured 584k) | ~100,000 QPS | ~50,000 QPS |
| **Cache Hit Latency (p99)** | **< 1.0 ms** (measured 0.34 ms) | 2 – 5 ms | 2 – 5 ms |
| **Memory @ 1M Rules** | **~ 285 MB RSS** (Trie + Interning) | 400 – 800 MB RSS | ~ 350 MB RSS |
| **Encrypted Transports** | **DoT, DoH (H2), DoQ, DoH3** | DoT, DoH, DoQ | Plain only (requires proxy) |
| **High Availability (HA)** | **Native mTLS WebSocket Push (<2s)** | External tool (adguardhome-sync) | External tool (gravity-sync) |
| **Filter Rule Engine** | **Full ABP + all modifiers** | Full ABP + modifiers | Domain regex & wildcards |
| **ReDoS Defense** | **Pure Dense DFA (no backtracking)** | RE2 linear time | POSIX regex (risk of backtrack) |
| **ACME Certificates** | **Native TLS-ALPN-01 & HTTP-01** | Built-in ACME | External (Certbot) |
| **RouterOS Integration** | **Native DHCP Lease Sync** | None | None |
| **Distribution** | **Single standalone binary (HTMX + Askama UI embedded)** | Single standalone binary | Multiple packages / lighttpd |
| **Config Format** | **Single TOML (`config.toml`)** | Single YAML | Multiple conf files + SQLite |

---

## ⚡ Key Highlights

- **Blazing Fast Hot Path:** Zero garbage collection pauses, multi-socket `SO_REUSEPORT` listeners, concurrent UDP query workers, single-pass candidate filter evaluation, and concurrent `moka` caching delivering **> 580k QPS** with **0.34 ms p99 latency** on reference hardware ([ADR-008](docs/adr/0008-performance-budget.md)).
- **Zero-Downtime Hot Reloading:** ArcSwap-backed query pipeline and live upstream reloading pick up configuration, upstream resolvers, local rewrites, and client group changes immediately without dropping persistent transport connections or restarting the daemon.
- **Zero-Node.js Embedded Web Console:** Lightweight, reactive admin panel powered by Axum, Askama compile-time templates, HTMX, and Alpine.js embedded directly into the standalone binary via `rust-embed` (zero npm/Node.js build or runtime dependencies, <1 MB footprint).
- **AdGuard / ABP Syntax Compatibility:** High-throughput `SuffixTrie` with string interning, Aho-Corasick substring matching, and backtracking-free regex DFAs.
- **Modern Encryption:** Native support for plain UDP/TCP, DNS-over-TLS (DoT/853), DNS-over-HTTPS (DoH/443, H2), DNS-over-QUIC (DoQ/853), and DNS-over-HTTP/3 (DoH3/443).
- **Zero-Consensus High Availability:** Real-time master/slave push replication over mTLS WebSockets with Ed25519 cryptographic signatures, mandatory certificate pinning, shared token authentication, and instant mutation push.
- **Hardened Security & RBAC:** Audited security posture including setup wizard credential validation, default-authenticated Prometheus `/metrics` (`metrics_auth = true`), trusted proxy X-Forwarded-For verification, Argon2id/TOTP bounded auth maps with active background pruners, strict SHA-256 self-updater verification, constant-time authentication via `subtle`, parameterized SQL query builders, SSRF protection, ReDoS protection via dense DFA compilation bounds, and systemd sandbox directives.
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
```bash
curl -fsSL https://raw.githubusercontent.com/kubaeror/sito-dns/main/contrib/install.sh | sudo bash
```

### Option 2: Docker / Docker Compose
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
      - "853:853/tcp"
      - "853:853/udp"
      - "443:443/tcp"
      - "8080:8080/tcp"
    volumes:
      - ./config:/etc/sito
      - sito-data:/var/lib/sito

volumes:
  sito-data:
```

### Option 3: Manual Binary Build
```bash
# Build release binary with embedded Web UI and mimalloc allocator
cargo build --release --locked --features "embed-ui,mimalloc"

# Verify configuration (if an existing config.toml is provided)
./target/release/sito check-config --config /etc/sito/config.toml

# Start daemon (if config is missing, boots into setup wizard mode on port 8080)
./target/release/sito --config /etc/sito/config.toml

# For headless environments, skip the wizard and boot immediately with secure defaults:
./target/release/sito --no-setup
```

### 🧙 First-Time Setup Wizard
On a fresh installation without a configuration file, **sito** starts in **setup-pending mode** on port `8080` (DNS listener ports 53/853/443 remain closed until initial setup is confirmed).

Open **`http://<server-ip>:8080`** in any browser to launch the 6-section configuration wizard:
* **Administrator Account:** Set custom admin username and password (or defaults).
* **DNS Listeners:** Configure IPv4/IPv6 bindings, UDP/TCP, DoT, and DoH ports.
* **Upstream Resolvers:** Select presets (Cloudflare, Quad9, Google) with live latency testing.
* **Cache & DNSSEC:** Tune in-memory cache and cryptographic DNSSEC validation.
* **Filtering:** Choose blocking modes, enable CNAME cloaking defense, and subscribe to popular blocklists (OISD, StevenBlack, HaGeZi).
* **Web Panel & Statistics:** Configure web bind and retention policies.

Once setup is submitted, DNS listeners are bound in-process without needing a server restart.

Swagger UI / OpenAPI documentation is available at `http://localhost:8080/swagger-ui`.

---

## 📖 Comprehensive Documentation

* **[Installation Guide](docs/installation.md):** Step-by-step setup for Linux systemd, Docker, Docker Compose, and HA macvlan.
* **[Configuration Reference](docs/configuration-reference.md):** Exhaustive documentation of every TOML configuration key.
* **[Benchmarking Report](docs/benchmarks.md):** Empirical benchmark results vs. Plan Section 16.1 and ADR-0008 contracts.
* **[Performance Tuning Guide](docs/performance.md):** Kernel sysctl parameters, NIC RSS hashing, and PGO instructions.
* **[Security Review & Threat Model](docs/security-audit.md):** Security vectors, SSRF allowlists, ReDoS DFA bounds, and constant-time auth.
* **[Migrating from AdGuard Home](docs/migration-adguard.md):** Migration instructions and automated converter script (`contrib/adguard_to_sito.py`).
* **[High-Availability Runbook](docs/runbook-ha.md):** Deployment architectures, mTLS certificates, failover, and slave promotion.
* **[Changelog](CHANGELOG.md):** Release notes for v1.0.0 and complete history of phases M0 through M9.

---

## ⚖️ License

`sito` is licensed under the **GNU General Public License v3.0** (`GPL-3.0-only`). See [LICENSE](LICENSE) for details.
