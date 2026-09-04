# sito 🛡️

[![CI](https://github.com/kubaeror/sito-dns/actions/workflows/ci.yml/badge.svg)](https://github.com/kubaeror/sito-dns/actions/workflows/ci.yml)
[![License: GPL-3.0](https://img.shields.io/badge/License-GPL--3.0-blue.svg)](LICENSE)
[![MSRV: 1.85.0](https://img.shields.io/badge/MSRV-1.85.0-orange.svg)](rust-toolchain.toml)
[![Rust Edition 2024](https://img.shields.io/badge/Edition-2024-purple.svg)](Cargo.toml)

> **sito** (noun, Polish for *sieve* / *strainer*) — A high-performance, memory-safe, self-hosted filtering DNS server written in Rust.

`sito` is designed as a modern, rock-solid alternative to AdGuard Home and Pi-hole. Engineered in Rust (edition 2024), it combines sub-millisecond p99 latency, comprehensive ad/tracker/malware blocking (using AdGuard/ABP rule syntax), multi-protocol encryption (DoT, DoH, DoQ, DoH3), and automated master/slave high availability.

---

## ⚡ Highlights

- **Blazing Fast Hot Path:** Zero garbage collection pauses, multi-socket `SO_REUSEPORT` listeners, and concurrent `moka` caching targeting **≥ 500k QPS** with **< 1 ms p99 latency** on reference hardware ([ADR-008](docs/adr/0008-performance-budget.md)).
- **AdGuard / ABP Syntax Compatibility:** High-throughput `SuffixTrie` with string interning, Aho-Corasick substring matching, and backtracking-free regex DFAs.
- **Modern Encryption:** Native support for plain UDP/TCP, DNS-over-TLS (DoT/853), DNS-over-HTTPS (DoH/443, H2), and DNS-over-QUIC (DoQ/853) powered by pure-Rust `rustls`.
- **Zero-Consensus High Availability:** Master/slave push replication over mTLS WebSockets with Ed25519 cryptographic signatures and atomic snapshot updates ([ADR-002](docs/adr/0002-ha-master-slave-push.md)).
- **Robust Telemetry:** Non-blocking query logging to SQLite in WAL mode with Prometheus metrics exposition ([ADR-003](docs/adr/0003-log-store-sqlite-wal.md)).
- **Lightweight Footprint:** Strict memory budgets (< 512 MB RSS with 1,000,000 rules), ideal for Raspberry Pi, home routers, and homelab servers.

---

## 🏗️ Architecture Overview

The `sito` workspace is structured into 13 modular crates:

```
sito
├── crates/sito              # Binary entry point, CLI args (clap), daemon orchestration
├── crates/sito-core         # Core contracts, verdicts, shared data structures, traits
├── crates/sito-proto        # Wire-format encoding/decoding (hickory-proto), normalization
├── crates/sito-transport    # Multi-protocol listeners (UDP SO_REUSEPORT, TCP, DoT, DoH, DoQ)
├── crates/sito-upstream     # Upstream resolver pooling, health checking, failover
├── crates/sito-cache        # High-performance moka DNS cache, TTL clamping, serve-stale
├── crates/sito-filter       # Rule parser, SuffixTrie, Aho-Corasick, regex DFA engine
├── crates/sito-dnssec       # DNSSEC validation, cryptographic trust anchor tracking
├── crates/sito-clients      # Client registry, multi-method identification, group policies
├── crates/sito-rewrites     # DNS rewrite table, wildcard host mapping, auto-PTR
├── crates/sito-api          # Management REST API (axum), OpenAPI/Swagger (utoipa), auth
├── crates/sito-stats        # Query log processing, SQLite WAL storage, Prometheus metrics
└── crates/sito-ha           # HA replication, WebSocket mTLS, signed config bundles
```

### Query Pipeline Flow

```
Client Query ──▶ [sito-transport] (UDP / TCP / DoT / DoH / DoQ)
                        │
                        ▼
                 [sito-clients] (identify client IP, subnet, MAC, DoH path)
                        │
                        ▼
                 [sito-rewrites] (check local /etc/hosts & custom overrides)
                        │
                        ▼
                 [sito-filter] (SuffixTrie + Aho-Corasick + regex DFA)
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
                    Respond    [sito-upstream] (forward query)
                                    │
                                    ▼
                               [sito-dnssec] (verify signatures)
                                    │
                                    ▼
                                Store & Return
```

---

## 🚀 Quickstart

### Prerequisites

- **Rust:** 1.85.0 or later (Rust edition 2024)
- **Target OS:** Linux (x86_64, aarch64, armv7)

### Build and Run

```bash
# Clone the repository
git clone https://github.com/kubaeror/sito-dns.git
cd sito-dns

# Verify toolchain and run checks
cargo test --workspace

# Inspect binary version
cargo run -p sito -- --version
```

### Git Hooks

Install pre-commit and conventional commit git hooks:

```bash
./scripts/setup-hooks.sh
```

---

## 📖 Documentation & Roadmap

- **Master Plan:** [docs/dns-server-plan-detailed.md](docs/dns-server-plan-detailed.md)
- **Phase Roadmap:** [docs/phases/README.md](docs/phases/README.md)
  - [Phase M0 — Foundation](docs/phases/m0-foundation.md) *(Current)*
  - [Phase M1 — MVP](docs/phases/m1-mvp.md)
  - [Phase M2 — Filtering Engine](docs/phases/m2-filtering-engine.md)
  - [Phase M3 — Encryption + DNSSEC](docs/phases/m3-dot-doh-dnssec.md)
  - [Phase M4 — Clients & Rewrites](docs/phases/m4-clients-rewrites.md)
  - [Phase M5 — API & Data](docs/phases/m5-api-data.md)
  - [Phase M6 — UI](docs/phases/m6-ui.md)
  - [Phase M7 — DoQ & Extras](docs/phases/m7-doq-doh3-extras.md)
  - [Phase M8 — High Availability](docs/phases/m8-ha.md)
  - [Phase M9 — Hardening & 1.0](docs/phases/m9-hardening-1-0.md)
- **Architecture Decision Records (ADRs):**
  - [ADR-0001: Technology Stack (Rust + Hickory)](docs/adr/0001-stack-rust-hickory.md)
  - [ADR-0002: High Availability Architecture](docs/adr/0002-ha-master-slave-push.md)
  - [ADR-0003: Query Log Storage Engine (SQLite WAL)](docs/adr/0003-log-store-sqlite-wal.md)
  - [ADR-0004: Configuration System (Single TOML)](docs/adr/0004-configuration-single-toml.md)
  - [ADR-0005: Default Block Response Mode (Zero IP)](docs/adr/0005-blocking-zero-ip.md)
  - [ADR-0006: Protocol Prioritization — DNSCrypt Stretch Goal](docs/adr/0006-dnscrypt-stretch-goal.md)
  - [ADR-0007: Rule Precedence Architecture](docs/adr/0007-precedence-rewrites-vs-important.md)
  - [ADR-0008: Performance Budget and Resource Constraints](docs/adr/0008-performance-budget.md)
  - [ADR-0009: Project Open-Source License (GPL-3.0)](docs/adr/0009-license-gplv3.md)

---

## 🤝 Contributing

Contributions are welcomed under the **Developer Certificate of Origin (DCO)**. Please see [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines on Test-Driven Development (TDD), PR line limits, benchmark requirements, and code style.

---

## ⚖️ License

`sito` is licensed under the **GNU General Public License v3.0** ([LICENSE](LICENSE)).
