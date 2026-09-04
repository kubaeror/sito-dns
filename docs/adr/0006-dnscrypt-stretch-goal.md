# ADR-0006: Protocol Prioritization — DNSCrypt as a Stretch Goal

* **Status:** Accepted
* **Date:** 2026-09-04
* **Deciders:** sito core team
* **Consulted:** Protocol and security review
* **Informed:** All contributors

## Context

DNSCrypt was an early encrypted DNS protocol developed prior to standardized IETF protocols. It utilizes public-key cryptography (Curve25519, XSalsa20-Poly1305) to authenticate and encrypt DNS traffic between client and resolver.

Current ecosystem realities:
1. **Industry Standards:** The IETF has formally standardized modern encrypted DNS protocols: DNS-over-TLS (DoT, RFC 7858), DNS-over-HTTPS (DoH, RFC 8484), DNS-over-QUIC (DoQ, RFC 9250), and DNS-over-HTTP/3 (RFC 9250 / RFC 9114). Major operating systems (Android, iOS, macOS, Windows 11) natively support DoT or DoH without third-party client software.
2. **Rust Ecosystem:** No mature, actively maintained, production-grade DNSCrypt server library exists in the Rust ecosystem. Existing crates are either unmaintained prototypes or abandoned forks. Implementing a custom DNSCrypt server engine would require significant development, maintenance, and cryptographic audit investment.

## Decision

We designate DNSCrypt support as an **optional stretch goal scheduled for Phase M7**, rather than a core requirement in the initial delivery phases (M0–M3).

Primary development will focus strictly on IETF standard protocols:
- Plain UDP/TCP (RFC 1035) — Phase M1
- DNS-over-TLS (RFC 7858) — Phase M3
- DNS-over-HTTPS / H2 (RFC 8484) — Phase M3
- DNS-over-QUIC (RFC 9250) and DoH3 — Phase M7

In M7, DNSCrypt will be revisited. If no high-quality crate emerges, users requiring DNSCrypt upstream or downstream compatibility will be directed to upstream proxy bridges (such as `dnscrypt-wrapper` or `dnscrypt-proxy`) terminating traffic to `sito`'s local UDP/TCP listener.

## Consequences

### Positive
- Concentrates engineering resources on modern standard protocols utilized by modern client operating systems.
- Avoids introducing unvetted, experimental, or unmaintained cryptographic dependencies into the core workspace.
- Simplifies the transport layer architecture during initial milestones (M1–M3).

### Negative
- Users running legacy hardware or firmware strictly relying on DNSCrypt client daemons cannot connect directly to `sito`'s encrypted listener without an intermediate proxy until/unless M7 stretch goal is completed.

### Neutral / Operational
- Upstream resolution to DNSCrypt-only resolvers is similarly treated as an optional extension.

## Alternatives Considered

### Alternative 1: Implement DNSCrypt in Phase M1/M3
- **Pros:** Full backward parity with all legacy tools.
- **Cons:** Major delay in delivering the MVP and standard DoT/DoH capabilities; burden of writing and securing custom Curve25519 packet exchange logic.
- **Why not chosen:** Poor ROI compared to native DoT/DoH/DoQ protocols supported by millions of client devices.

### Alternative 2: Permanently Exclude DNSCrypt (Non-Goal)
- **Pros:** Clean scope reduction with no open questions.
- **Cons:** Forecloses compatibility if a well-maintained community crate appears or if a contributor volunteers an isolated implementation.
- **Why not chosen:** Keeping it as a stretch goal in M7 preserves flexibility without compromising near-term roadmap discipline.
