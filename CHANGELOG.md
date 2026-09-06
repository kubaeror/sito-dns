# Changelog

All notable changes to the **sito** project are documented in this file.
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) and follows [Conventional Commits](https://www.conventionalcommits.org/).

---

## [1.4.0] - 2026-09-06

### First-Time Setup Wizard & Installer Hardening

#### First-Time Setup & Bootstrap Mode
- **Web-Based First-Time Setup Wizard**: When `config.toml` is missing at startup, the server boots into an in-memory bootstrap `setup_pending` mode, serving only the web panel on port 8080 and delaying DNS listener port bindings until setup is finished.
- **Route Gating Middleware**: While in `setup_pending` mode, all UI requests redirect (HTTP 302) to `/wizard`, API v1 endpoints return HTTP 503 `Setup not completed`, while `/wizard`, static assets, and upstream testing are permitted.
- **Expanded 6-Section Setup Wizard**: Implemented a comprehensive single-page wizard with pre-filled defaults covering:
  1. Administrator Account (username, password, confirm password)
  2. DNS Listeners & Protocols (IPv4/IPv6 bindings, UDP/TCP 53, DoT 853, DoH 443, DoQ disabled by default)
  3. Upstream Resolvers (presets for Cloudflare, Quad9, Google, resolution strategies, bootstrap IPs, and live HTMX latency testing)
  4. Cache & DNSSEC (local cache toggle, cache size, DNSSEC modes and validation)
  5. Filtering & Protection (blocking modes, CNAME cloaking defense, and one-click presets for OISD Big, OISD Small, StevenBlack, and HaGeZi Pro)
  6. Web Panel & Statistics (binding address, port, and query log retention days)
- **Headless Mode (`--no-setup`)**: Added `--no-setup` CLI flag to bypass wizard gating and immediately initialize all services with default configuration for automated or headless deployments.
- **In-Process DNS Listener Startup**: DNS listener pipelines are spawned in-process upon wizard completion without requiring a daemon restart.

#### Installer Hardening & Supply Chain Security
- **Config Generation Removed**: `contrib/install.sh` no longer writes a static `config.toml` or prints default credentials, directing operators to complete setup via the web wizard.
- **Download Retries & Backoff**: Added retry logic (up to 3 attempts with exponential backoff) and removed error swallowing.
- **Cosign Verification**: Added optional Cosign keyless signature verification for release archives with fallback to SHA-256 checksum validation.
- **Upgrade Detection & Backup**: Automatically detects existing installations and backs up the existing binary to `/usr/local/bin/sito.bak`.
- **Post-Install Health Check**: Added automated post-install health checks verifying `systemctl is-active` and HTTP server response, printing journal diagnostics on failure.
- **Firewall Guidance**: Added UFW and firewalld rule instructions to the installation summary.
- **CI ShellCheck Job**: Integrated automated shellcheck validation in both `.github/workflows/ci.yml` and `.github/workflows/release.yml`.
- **Port Conflict Fix**: Disabled DoQ by default (`doq_port = 0`) to eliminate default port collision with DoT on port 853.

---

## [1.3.0] - 2026-09-06

### Security, Performance & Operational Audit Remediation (Audit 2)
Comprehensive remediation of all findings identified in `/docs/audit2.md`:

#### Phase 1: Critical Security (P1)
- **HA Master Replication Hardening (P1-1)**: Enforced strict TLS certificate pinning (`expected_slave_pins`), rejected plaintext WebSocket replication by default, and required non-empty authentication tokens (`auth_token`) on the replication listener, preventing unauthorized configuration extraction and eavesdropping.
- **Setup Wizard Credential Validation (P1-2)**: Validated existing admin credentials if an admin user already exists, auto-created the admin account if missing, and surfaced configuration persistence errors to prevent runtime/disk drift.
- **Default Metrics Authentication (P1-3 - Breaking Change)**: Changed `metrics_auth` default from `false` to `true`, requiring authentication for `/metrics` by default.

#### Phase 2: Resilience & Integrity (P2)
- **Immediate HA Replication on Mutations (P2-1)**: Wired automatic bundle publishing to connected slave nodes immediately upon mutating API and UI configuration changes.
- **Negative Caching for NXDOMAIN Responses (P2-2)**: Enabled caching of NXDOMAIN responses using the minimum TTL from the SOA record and RFC 2308 compliance.
- **Upstream ID & Query Log Anonymization (P2-3)**: Propagated real upstream names into SQLite query log entries and wired querylog IP anonymization per configuration.
- **Filter Reload Join Error Handling (P2-4)**: Gracefully handled Tokio join errors during filter engine reloads without clearing or wiping existing filter rules.
- **HA Slave Telemetry (P2-5)**: Transmitted real query counts, block rates, and upstream performance in slave heartbeat reports to the HA master coordinator.
- **User Account File Corruption Protection (P2-6)**: Created automatic timestamped backups (`users.toml.corrupt.<ts>`) on unparseable user files and aborted startup rather than silently overwriting credentials with defaults.
- **Trusted Reverse Proxy Client IP Protection (P2-7)**: Used rightmost client IP from `X-Forwarded-For` when behind trusted reverse proxies to eliminate header spoofing.
- **Atomic UI Configuration Persistence (P2-8)**: Enforced atomic file persistence (`save_config_atomic`) before updating in-memory state across all UI handlers, returning HTTP 500 on disk failures.

#### Phase 3: Performance, Infrastructure & Polish (P3)
- **Single-Pass Filter Candidate Collection (P3-1)**: Refactored `evaluate()` in `sito-filter` to collect rule candidates once and pass them through `evaluate_important` and `evaluate_standard`, eliminating double traversal on the hot path.
- **Live Upstream Hot-Reloading (P3-2)**: Dynamically reloaded `UpstreamManager` servers, strategies, and per-domain rules on `PUT /api/v1/upstream` and UI upstream edits without requiring daemon restart.
- **Reduced Pipeline Log Level (P3-3)**: Lowered routine cache hits, safe search rewrites, and stale cache serves to `debug` level, keeping `info` exclusively for block verdicts.
- **Docker Port Exposures & Documentation (P3-4)**: Added DoT (853), DoH (443), and Web (8080) ports to Dockerfile and compose, documented `NET_BIND_SERVICE` capability requirements, and added workflow dispatch tags to container image metadata.
- **CI Release Smoke Build (P3-5)**: Added an x86_64 `--release` smoke build step to the continuous integration workflow.
- **Unix Compile Guard & Platform Support (P3-6)**: Added `#[cfg(not(unix))]` compile error guard to `sito-transport` and documented Unix/Linux platform requirements in documentation.

---

## [1.2.1] - 2026-09-06

### Security & Robustness Audit Remediation
Comprehensive remediation of all 24 security, stability, architecture, and correctness findings identified in `/docs/audit.md`:

#### Phase 1: Critical Security (P0)
- **Setup Wizard Gating**: Restricted `/ui/wizard` and `/ui/wizard/complete` endpoints so they can only be executed during initial first-run (when no users are registered) or by an authenticated admin session, returning HTTP 403 Forbidden once initialized.
- **User Account Persistence & Configuration Wiring**: Wired `auth.user` and `auth.role` configuration options, persisted user accounts to `<data_dir>/users.toml`, and restored them automatically on daemon startup.
- **Updater Integrity & Enforcement**: Enforced strict SHA256 checksum verification from `SHA256SUMS` during self-updates, protected the update check endpoint with authentication, and pinned GitHub update queries to `kubaeror/sito-dns`.
- **Installer Configuration Hardening**: Fixed missing default tables in installer config generation and added warnings when configuration sections fail to parse.
- **Hot-Reload Dynamic Pipeline**: Wired `ArcSwap` handles into the DNS processing pipeline to enable zero-downtime, restart-free updates of configuration, local rewrites, and client definitions.

#### Phase 2: High Priority Robustness (P1)
- **Defensive Cache TTL Clamping**: Defensively clamped TTL bounds and validated that `negative_ttl_max >= min_ttl` at configuration validation time.
- **UDP Concurrency & Head-of-Line Blocking**: Resolved UDP head-of-line blocking by spawning concurrent Tokio worker tasks per received query bounded by a high-capacity semaphore.
- **High-Availability Security**: Mandated TLS certificate pinning for HA replication, rejected plain WebSockets by default unless explicitly allowed, and required pre-shared token authentication for replica nodes.
- **Session Cookie Security**: Conditionally set the `Secure` flag on session cookies based on TLS status and issued clear warnings when serving over plain HTTP on non-loopback network interfaces.
- **Bounded State & Proactive Pruners**: Bounded lockout, session, and TOTP authentication maps with LRU eviction and spawned a dedicated background pruner task to purge expired entries every 5 minutes.
- **Comprehensive RBAC Enforcement**: Enforced role-based access control across all mutating UI routes and the `/metrics` endpoint; exposed OpenAPI docs endpoint in documentation.

#### Phase 3: Correctness & Configuration (P2)
- **Hourly Statistics Watermark**: Implemented a persistent high-water mark for stats rollups to prevent double-counting queries in `stats_hourly`.
- **Parameterized Query Logs**: Refactored query log filtering to use `sqlx::QueryBuilder` with strict parameterized `push_bind` expressions.
- **Installer Checksum Verification**: Hardened `contrib/install.sh` to require valid SHA-256 checksums from `SHA256SUMS` and fail loudly on mismatches.
- **Dead Configuration Pruning**: Removed deprecated `refresh_hours` settings from UI forms and sample configurations.
- **DNSSEC Validation Logging**: Added configuration validation for DNSSEC modes (`off`, `process`, `log_fail`) and recorded validation outcomes in query logs.
- **Query Log Graceful Shutdown**: Ensured the query log writer channel is flushed and awaited during graceful daemon shutdown.
- **Filter Rule Drop Guard**: Restricted rule-count drop protection to scheduled background refreshes to avoid blocking intentional user rule deletions.
- **Upstream Bootstrap Safety**: Guarded upstream bootstrap resolution against empty address lists using `.first()`.
- **Protocol Documentation Alignment**: Corrected upstream protocol labels and examples to `tls://` and UDP, reflecting implemented upstream protocols.

#### Phase 4: Low Priority & Code Polish (P3)
- **Pipeline QueryOutcome Refactoring**: Introduced private `QueryOutcome` struct, unified anti-bypass checks and blocked-response builders, bounded cache prefetching tasks with a semaphore, updated cache size metrics gauge, consolidated HTML escapers, and routed missing client/rewrite endpoints.
- **Atomic Config Persistence Documentation**: Clarified that atomic config saves preserve modeled fields and omit unknown top-level keys.
- **Systemd Unit Hardening**: Added `MemoryDenyWriteExecute`, `ProtectKernelTunables`, `ProtectKernelModules`, `ProtectControlGroups`, and `SystemCallFilter=@system-service` directives to systemd service units, and added default password change alerts.
- **Axum Explicit JSON Feature**: Explicitly declared `"json"` feature on `axum` workspace dependency.

---

## [1.2.0] - 2026-09-05

### Added
- **In-App Self-Updater**:
  - Direct software updates from web console and CLI (`sito update`).
  - Automatic query of GitHub Releases API, parsing semantic versions and release notes.
  - SHA256 checksum verification against published `SHA256SUMS`.
  - Docker/OCI container detection with non-destructive container upgrade guidance.
  - Safe, atomic self-replacement of the running executable on Linux (x86_64, aarch64, armv7).
  - Admin REST API endpoints: `GET /api/v1/system/update/check` and `POST /api/v1/system/update/apply`.
  - OpenAPI 3.0 specification updated in `docs/openapi.json`.
- **Advanced Upstream Strategies & Caching**:
  - `Parallel` upstream racing: concurrent query dispatch to all healthy upstreams; fastest valid answer wins.
  - `LoadBalance` round-robin: distributed query forwarding across upstream resolvers.
  - `[[upstream.per_domain]]`: domain-based routing for split-horizon or internal DNS zones.
  - RFC 8767 `serve_stale`: stale cache entry fallback during upstream network outages.

### Fixed
- **RouterOS Auth Fallback**: Automatically fall back to native RouterOS API (port 8728) if REST login fails.
- **SafeSearch Normalization**: Fixed domain matching bypasses with consistent trailing-dot FQDN normalization.
- **HA Redaction Loop**: Guarded against recursive cycle traversal in High Availability secret sanitization.
- **Auth IP Resolution**: Secured peer IP extraction against reverse proxy spoofing when proxies are untrusted.
- **Web Port Configuration**: Fixed web server listener to respect `config.web.port` (default `8080`).
- **Telemetry Retention Cleanup**: Added 24-hour background task to prune old query logs and keep SQLite storage bounded.
- **Test Harness Reliability**: Eliminated ephemeral port probe races in parallel acceptance test execution with automated retry.

### Changed
- **Workspace Version**: Bumped workspace package and all internal crates to `1.2.0`.
- **Configuration Persistence**: Persisting configuration changes via the Web UI or REST API round-trips modeled fields; unmodeled or unknown keys and custom comments are not preserved on save.

---

## [1.1.1] - 2026-09-05

### Maintenance & Rust 1.98.1 Toolchain Modernization
- **Rust Toolchain Bump**: Bumped toolchain and MSRV to `1.98.1` (`rust-toolchain.toml` and `Cargo.toml`). Adopted Rust 2024 let-chain idioms across codebase.
- **Transitive Dependency Refresh**: Updated 31 SemVer-compatible crates via `cargo update` previously blocked by older MSRV.
- **Major Dependency Upgrades**:
  - `totp-rs`: Upgraded from `5.6` to `6.0` (migrated to `TOTP::builder()` API, `try_from_base32`, and URL generation).
  - `sqlx`: Upgraded from `0.8` to `0.9` (adopted `sqlx::AssertSqlSafe` for dynamic batch telemetry queries).
  - `reqwest`: Upgraded from `0.12` to `0.13` (migrated TLS configuration to `rustls` feature).
  - `tower-http`: Upgraded from `0.6` to `0.7`.
  - `tokio-tungstenite`: Upgraded from `0.26` to `0.30`.
  - `askama`: Upgraded from `0.14` to `0.16`.
  - `toml`: Upgraded from `0.8` to `1.1` (using `toml-write` engine).
  - `base64`: Upgraded from `0.22` to `0.23`.
  - `criterion`: Upgraded from `0.5` to `0.8` (benchmarks modernized with `std::hint::black_box`).
  - `argon2`: Upgraded from `0.5` to `0.6` (migrated to `password-hash 0.6`, `phc::PasswordHash`, and automatic secure salt generation).
  - `rand`: Upgraded from `0.8` to `0.10` (unified RNG engine across entire workspace, migrated to `rand::rng()` and `rand::RngExt`).
- **Workspace Version**: Bumped workspace and crate versions to `1.1.1`.

---

## [1.1.0] - 2026-09-05

### Major Architecture Change — Web Framework Migration to HTMX + Askama + Alpine.js
- **Eliminated Node.js and npm**: Completely removed the Node.js / Vite / React 18 / Mantine UI frontend toolchain, eliminating 351 MB of `node_modules` and 100+ npm dependencies.
- **Server-Side Rendered Hypermedia**: Migrated web dashboard and administration views to **Askama** type-safe compile-time templates in `crates/sito-api` with **HTMX** for dynamic partial swaps and **Alpine.js** for client-side state.
- **Microsecond Rendering & Minimal Footprint**: Client bundle reduced by >95% (from 1.6 MB to ~70 kB total JS/CSS), browser memory footprint reduced from ~150 MB to ~20 MB.
- **Real-Time DNS Query Log**: Live WebSocket streaming directly into HTMX table rows for zero-delay query inspection.
- **High-Performance Charts**: Integrated **uPlot** (~35 kB) for fast 24h query analytics.
- **Unified Rust Toolchain**: Entire repository and web UI now compiles with standard `cargo build`.
- Bumped workspace version to `1.1.0`.

---

## [1.0.1] - 2026-09-05

### Maintenance & Dependency Upgrades
- Upgraded workspace dependencies: `socket2` unified on `0.6.5` (eliminating duplicate versions in dependency graph), `tokio` to `1.53.1`, `clap` to `4.6.6`, `arc-swap` to `1.9.2`, `dashmap` to `6.2.1`, `bytes` to `1.12.1`, `http` to `1.5.0`, `hyper` to `1.11.1`, `idna` to `1.1.0`, `notify` to `8.2.0`, and `rust-embed` to `8.12.0`.
- Unified workspace dependencies (`flate2`, `tar`, `utoipa`, `blake3`) in `sito-api`.
- Upgraded frontend API client `openapi-fetch` to `^0.17.0` with strict tuple type conversions in dashboard top domains and clients.
- Bumped application and crate versions across the workspace to `1.0.1`.

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
