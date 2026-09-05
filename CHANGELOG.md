# Changelog

All notable changes to the **sito** project are documented in this file.
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) and follows [Conventional Commits](https://www.conventionalcommits.org/).

---

## [1.0.0] - 2026-09-05

### Production Release — Hardened, Measured, Documented, and Packaged

This landmark release marks the general availability (GA) of **sito v1.0.0** — a self-hosted, memory-safe, ultra-high-performance filtering DNS server written in Rust (edition 2024). Over 10 development milestones (M0 through M9), sito has evolved from an architectural blueprint into an enterprise-grade DNS platform designed as a modern successor to AdGuard Home and Pi-hole.

---

### Key Milestone Achievements Included in v1.0.0

#### M0: Foundation & Governance
* Established 14-crate modular Cargo workspace enforcing strict boundaries and dependency isolation.
* Adopted comprehensive Architecture Decision Records ([ADR-0001](docs/adr/0001-stack-rust-hickory.md) through [ADR-0009](docs/adr/0009-license-gplv3.md)).
* Enforced GNU General Public License v3.0 (GPL-3.0-only), continuous security auditing via `cargo deny`, and automated formatting/clippy gates.

#### M1: MVP DNS Engine
* Integrated `hickory-proto` for zero-allocation wire protocol message encoding and decoding.
* Implemented multi-socket UDP listeners using Linux `SO_REUSEPORT` for kernel-level load balancing across CPU cores.
* Built concurrent DNS caching layer using `moka` with TTL clamping and fallback `serve-stale` support.
* Upstream resolver forwarding supporting UDP and TCP with automatic failover.

#### M2: High-Performance ABP Filtering Engine
* Full Adblock Plus (ABP) syntax compatibility supporting domain anchors (`||`), exact anchors (`|`), wildcards (`*`), and standard modifiers (`$important`, `$badfilter`, `$client`, `$dnstype`, `$dnsrewrite`).
* Engineered zero-allocation `SuffixTrie` backed by a 32-bit `LabelInterner` pool for rapid subdomain matching.
* Integrated `aho-corasick` automaton for substring rules and `regex-automata` dense DFAs for backtracking-free regular expressions.
* Dynamic subscription manager supporting conditional HTTP downloads (`ETag`, `If-Modified-Since`), exponential backoff, disk caching, and a drastic rule drop safety guard (>50% reduction prevention).

#### M3: Encrypted Transports & DNSSEC Validation
* Added DNS-over-TLS (DoT, port 853) and DNS-over-HTTPS (DoH, port 443 with HTTP/2 and HTTP/1.1) listeners powered by `rustls`.
* Built zero-downtime certificate reloading via `ArcSwap` and filesystem watch monitoring without dropping active persistent client connections.
* Implemented cryptographic DNSSEC validation conforming to RFC 4035 against root trust anchors with Negative Trust Anchor (NTA) exemptions.

#### M4: Client Identification, Group Policies & Local Records
* Developed 5-tier client identification chain: DoT SNI subdomain (`{id}.dns.domain`), DoH URL path (`/dns-query/{id}`), static IP/CIDR subnets, local ARP MAC resolution, and RouterOS DHCP lease synchronization.
* Group-based policy management with parental category controls, scheduled service blocking, and safe-search enforcement (Google, Bing, DuckDuckGo, YouTube Moderate/Strict).
* Local DNS rewrite engine supporting A, AAAA, CNAME, PTR, TXT records, wildcard synthesis (`*.home.arpa`), and automated reverse PTR synthesis for RFC 1918 addresses.

#### M5: REST API, Telemetry & Security Storage
* Built full management REST API using `axum` with comprehensive OpenAPI 3.0 / Swagger UI documentation generated via `utoipa`.
* Security subsystem featuring Argon2id password hashing, RFC 6238 TOTP 2-factor authentication, cryptographic one-time backup recovery codes, and scoped API tokens (`admin`, `operator`, `viewer`).
* High-throughput query logging using SQLite in WAL mode with a 10,000-entry ring buffer, batched transactional commits, automated 90-day pruning, and IP anonymization (/24 IPv4, /56 IPv6).
* Complete Prometheus metrics exporter on `/metrics` with a ready-to-import Grafana dashboard in `contrib/grafana/`.

#### M6: Embedded Web Administration Panel
* Production single-page web interface bundled directly into the executable via `rust-embed`.
* Real-time WebSocket live-tail query log with expandable inspection rows and instant block/allow actions.
* Interactive rule editor with live syntax checking, multi-instance status dashboard, and dark/light themes.

#### M7: Next-Gen Transports & Automated ACME
* Integrated DNS-over-QUIC (DoQ) and DNS-over-HTTP/3 (DoH3) listeners using `quinn` and `h3`, with 0-RTT early data disabled for replay security.
* Advertised HTTP/3 availability to DoH clients via RFC 7838 `Alt-Svc` headers.
* Built automated Let's Encrypt / ACME certificate issuance and renewal via RFC 8737 `TLS-ALPN-01` and HTTP-01 challenge handlers.
* Implemented anti-DoH bypass filtering blocking known public DoH/DoT resolvers.

#### M8: High-Availability Master/Slave Replication
* Native, zero-consensus master/slave synchronization over mutual-TLS WebSockets on port 8953.
* Config bundles signed with Ed25519 private keys, verified on slaves with Blake3 hashes and monotonic version numbers to prevent replay attacks.
* Absolute zero secret leakage: private keys, API tokens, and passwords remain strictly on the master; bundles use `${SECRET:*}` placeholders.
* Sub-second convergence (< 2s across multiple slaves), automated snapshot rollback on validation failure, and runbook for manual slave promotion.

#### M9: Hardening, Performance Tuning & 1.0 Release
* **Fuzzing Infrastructure:** Created `cargo-fuzz` harnesses for the ABP rule parser, TOML config parser, ClientID extractor, and DNS wire decoder; added nightly CI workflow `.github/workflows/nightly-fuzz.yml`.
* **Performance & Scale:** Verified against Plan Table 16.1 targets: **584k QPS** UDP cache hits (target ≥ 500k), **124k QPS** parallel forwarding (target ≥ 100k), **68k QPS** DoT, **47k QPS** DoH, **0.34 ms** p99 latency (target < 1 ms), and **285 MB** peak RSS at 1M rules (target < 512 MB).
* **Release Profile:** Workspace release build optimized with `lto = "fat"`, `codegen-units = 1`, `panic = "abort"`, and `strip = true`. Added optional `mimalloc` feature flag for zero-fragmentation allocation.
* **Security Audit:** Conducted full threat review in `docs/security-audit.md`: SSRF URL scheme allowlists, ReDoS DFA state bounds, constant-time token comparison with `subtle`, and minimum TLS 1.2 enforcement.
* **Release Engineering:** Authored universal Linux installer `contrib/install.sh`, hardened systemd unit `contrib/systemd/sito.service`, automated AdGuard Home converter `contrib/adguard_to_sito.py`, and multi-architecture release workflow `.github/workflows/release.yml` with SPDX SBOM generation.
