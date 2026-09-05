# sito 🛡️

[![CI](https://github.com/kubaeror/sito-dns/actions/workflows/ci.yml/badge.svg)](https://github.com/kubaeror/sito-dns/actions/workflows/ci.yml)
[![Nightly Fuzzing](https://github.com/kubaeror/sito-dns/actions/workflows/nightly-fuzz.yml/badge.svg)](https://github.com/kubaeror/sito-dns/actions/workflows/nightly-fuzz.yml)
[![Release](https://img.shields.io/github/v/release/kubaeror/sito-dns?include_prereleases&color=brightgreen)](https://github.com/kubaeror/sito-dns/releases)
[![License: GPL-3.0](https://img.shields.io/badge/License-GPL--3.0-blue.svg)](LICENSE)
[![MSRV: 1.85.0](https://img.shields.io/badge/MSRV-1.85.0-orange.svg)](rust-toolchain.toml)
[![Rust Edition 2024](https://img.shields.io/badge/Edition-2024-purple.svg)](Cargo.toml)

> **sito** (noun, Polish for *sieve* / *strainer*) — A high-performance, memory-safe, self-hosted filtering DNS server written in Rust.

`sito` is designed as a modern, rock-solid alternative to AdGuard Home and Pi-hole. Engineered in Rust (edition 2024), it combines sub-millisecond p99 latency, comprehensive ad/tracker/malware blocking (using AdGuard/ABP rule syntax), multi-protocol encryption (DoT, DoH H2, DoQ, DoH3), and automated master/slave high availability.

---

## 📊 Feature Comparison: sito vs. AdGuard Home vs. Pi-hole

| Feature / Capability | **sito** (v1.0) | **AdGuard Home** | **Pi-hole (FTL)** |
|---|---|---|---|
| **Language & Runtime** | **Rust (edition 2024, zero GC)** | Go (GC overhead under load) | C (FTL) + PHP Web UI |
| **Max Cache Throughput** | **≥ 500,000 QPS** (measured 584k) | ~100,000 QPS | ~50,000 QPS |
| **Cache Hit Latency (p99)** | **< 1.0 ms** (measured 0.34 ms) | 2 – 5 ms | 2 – 5 ms |
| **Memory @ 1M Rules** | **~ 285 MB RSS** (Trie + Interning) | 400 – 800 MB RSS | ~ 350 MB RSS |
| **Encrypted Transports** | **DoT, DoH (H2), DoQ, DoH3** | DoT, DoH, DoQ | Plain only (requires proxy) |
| **High Availability (HA)** | **Native mTLS WebSocket Push (<2s)** | External tool (adguardhome-sync) | External tool (gravity-sync) |
| **Filter Rule Engine** | **Full ABP + all modifiers** | Full ABP + modifiers | Domain regex & wildcards |
| **ReDoS Defense** | **Pure Dense DFA (no backtracking)** | RE2 linear time | POSIX regex (risk of backtrack) |
| **ACME Certificates** | **Native TLS-ALPN-01 & HTTP-01** | Built-in ACME | External (Certbot) |
| **RouterOS Integration** | **Native DHCP Lease Sync** | None | None |
| **Distribution** | **Single standalone binary (UI embedded)** | Single standalone binary | Multiple packages / lighttpd |
| **Config Format** | **Single TOML (`config.toml`)** | Single YAML | Multiple conf files + SQLite |

---

## ⚡ Key Highlights

- **Blazing Fast Hot Path:** Zero garbage collection pauses, multi-socket `SO_REUSEPORT` listeners, and concurrent `moka` caching delivering **> 580k QPS** with **0.34 ms p99 latency** on reference hardware ([ADR-008](docs/adr/0008-performance-budget.md)).
- **AdGuard / ABP Syntax Compatibility:** High-throughput `SuffixTrie` with string interning, Aho-Corasick substring matching, and backtracking-free regex DFAs.
- **Modern Encryption:** Native support for plain UDP/TCP, DNS-over-TLS (DoT/853), DNS-over-HTTPS (DoH/443, H2), DNS-over-QUIC (DoQ/853), and DNS-over-HTTP/3 (DoH3/443).
- **Zero-Consensus High Availability:** Real-time master/slave push replication over mTLS WebSockets with Ed25519 cryptographic signatures and atomic snapshot updates ([ADR-002](docs/adr/0002-ha-master-slave-push.md)).
- **Hardened Security:** Constant-time authentication with `subtle`, SSRF protection on list subscriptions, ReDoS protection via dense DFA compilation bounds, and minimum TLS 1.2 enforcement.
- **Robust Telemetry:** Non-blocking query logging to SQLite in WAL mode with Prometheus metrics exposition ([ADR-003](docs/adr/0003-log-store-sqlite-wal.md)) and Grafana dashboard.

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
      - "853:853"
      - "443:443"
      - "8080:8080"
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

# Verify configuration
./target/release/sito check-config --config /etc/sito/config.toml

# Start daemon
./target/release/sito --config /etc/sito/config.toml
```

Once started, navigate to `http://localhost:8080` to access the administration web panel. Initial credentials: `admin` / `adminadmin`.

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
