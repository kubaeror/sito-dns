# ADR-0001: Technology Stack (Rust + Hickory DNS)

* **Status:** Accepted
* **Date:** 2026-09-04
* **Deciders:** sito core team
* **Consulted:** Architecture and security review
* **Informed:** All contributors

## Context

A self-hosted, network-wide filtering DNS server operates directly on the critical path of all network devices. The server must satisfy stringent operational criteria:
- **Low latency and jitter:** p99 latency under 1 ms for cached queries and throughput exceeding 500,000 QPS on standard hardware (plan section 16.1).
- **Absolute memory safety:** DNS parsers are frequent targets for remote exploit vulnerabilities (buffer overflows, use-after-free, memory corruption).
- **Broad protocol support:** Plain UDP/TCP (RFC 1035), EDNS0 (RFC 6891), DNSSEC (RFC 4033-4035), DNS-over-TLS (DoT, RFC 7858), DNS-over-HTTPS (DoH, RFC 8484), DNS-over-QUIC (DoQ, RFC 9250), and DNS-over-HTTP/3 (RFC 9250/RFC 9114).
- **Concurrency model:** Non-blocking asynchronous I/O across multi-core architectures without garbage collection pauses.

## Decision

We select **Rust (edition 2024, stable channel)** as the implementation language and **`hickory-proto` / `hickory`** as the foundational DNS protocol layer.

The core technology stack includes:
- **Runtime:** `tokio` (multi-threaded async runtime with native epoll/kqueue integration).
- **Protocol layer:** `hickory-proto` for wire-format serialization, deserialization, EDNS0 handling, and DNSSEC records.
- **TLS / Crypto:** `rustls` (pure Rust TLS, ring/aws-lc-rs backend) shared across DoT, DoH, DoQ, management API, and HA clustering.
- **Web / API:** `axum` (Tower-compatible, lightweight, native tokio ecosystem) with `utoipa` for OpenAPI 3.0 generation.
- **Cache:** `moka` (concurrent, lock-free TinyLFU cache with weighted byte accounting and per-entry TTL).
- **Filter matching:** Custom `SuffixTrie` with label interning, `aho-corasick` for substring search, and `regex-automata` for backtracking-free regex DFAs.
- **Storage:** `sqlx` + SQLite with Write-Ahead Logging (WAL) for persistent query telemetry.

## Consequences

### Positive
- Zero garbage collection pauses, guaranteeing predictable sub-millisecond p99 latency under heavy load.
- Memory safety and thread safety guaranteed by the Rust compiler.
- `hickory-proto` provides battle-tested compliance with core DNS RFCs, eliminating the need to maintain hundreds of custom record types.
- Pure-Rust TLS (`rustls`) removes dependency on OpenSSL C libraries, simplifying cross-compilation and container deployment.

### Negative
- Steeper learning curve for contributors compared to languages like Go or Python.
- Longer compile and link times in CI, mitigated by `rust-cache` and modular multi-crate workspace design.
- Dependency on `hickory` release cycles for new draft RFCs; if deep wire customizations are required in M9, custom adapters may be needed.

### Neutral / Operational
- MSRV is pinned in `rust-toolchain.toml` and tracked in `README.md`.
- Cargo workspace split into 13 crates isolates compilation units and boundary contracts.

## Alternatives Considered

### Alternative 1: Go (miekg/dns) — AdGuard Home approach
- **Pros:** Fast development cycle, large ecosystem, mature prior art in AdGuard Home.
- **Cons:** Garbage collector pauses degrade tail latency (p99); higher per-goroutine memory footprint under massive concurrent connections.
- **Why not chosen:** Sub-millisecond p99 latency targets and strict resource limits (< 512 MB under 1M rules) are better met with Rust.

### Alternative 2: C / C++ (Unbound, BIND, dnsmasq)
- **Pros:** Extreme low-level control, historically standard for DNS servers.
- **Cons:** High risk of memory safety bugs (CVE history in legacy DNS servers); lack of modern ergonomic concurrency and package management.
- **Why not chosen:** Memory safety in an untrusted network protocol parser is paramount.

### Alternative 3: Custom Hand-Written DNS Parser in Rust
- **Pros:** Zero third-party dependencies, fine-tuned micro-optimizations.
- **Cons:** Enormous maintenance burden to cover all standard and experimental RR types, EDNS0 extensions, and DNSSEC canonical wire encodings.
- **Why not chosen:** Premature optimization. As stated in plan section 2.1, a custom parser will only be considered in M9 if profiling demonstrates that `hickory-proto` is an insurmountable bottleneck.
