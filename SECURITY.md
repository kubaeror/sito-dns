# Security Policy

The `sito` security team takes vulnerabilities in network services seriously. Because `sito` operates directly on network query paths and handles sensitive DNS traffic, security, memory integrity, and prompt vulnerability resolution are paramount.

---

## 1. Supported Versions

We release security patches and vulnerability fixes for the **current minor release** and the **preceding minor release**:

| Release Line | Supported Status | Notes |
|---|---|---|
| `1.6.x` (current) | :white_check_mark: Supported | Active development |
| Prior minor release (`1.5.x`) | :white_check_mark: Supported | Critical security fixes only |
| Older releases | :x: Unsupported | Upgrade recommended |

Patch releases within a supported line are published from `main` and tagged
`vX.Y.Z`; see [CHANGELOG.md](CHANGELOG.md) for the current release.

---

## 2. Reporting a Vulnerability

**Please DO NOT report security vulnerabilities via public GitHub issues, discussions, or social media channels.**

To report a vulnerability:
1. **GitHub Private Security Advisory (Preferred):** Open a draft advisory through the repository's [Security Advisories tab](https://github.com/kubaeror/sito-dns/security/advisories/new).
2. **Email (Alternative):** Contact the maintainer listed on the GitHub profile for the repository with detailed disclosure and reproduction steps. Public issues are not an acceptable channel for vulnerability reports.

### Report Contents
To assist in rapid triage, please include:
- A descriptive summary of the vulnerability and attack vector.
- Affected component(s) (e.g. `sito-proto`, `sito-transport`, `sito-filter`, `sito-api`).
- Proof-of-concept (PoC) code, packet captures (`.pcap`), or step-by-step reproduction instructions.
- Potential impact (e.g. denial of service, memory exhaustion, filter bypass, authorization bypass).
- Any proposed remediation or patch if available.

---

## 3. Response SLA and Disclosure Process

We commit to the following Service Level Agreement (SLA) for confirmed reports:

- **Initial Response / Acknowledgment:** Within **72 hours** of receipt.
- **Triage & Severity Assessment:** Within **5 business days**, including CVSS score assignment.
- **Fix & Patch Development:** High/Critical severity issues are prioritized for rapid resolution and backporting.
- **Coordinated Disclosure:** We adhere to responsible coordinated disclosure. Public advisories and releases will be coordinated with the reporter, allowing a reasonable embargo period (typically 30–90 days depending on complexity) for downstream users to update.

---

## 4. Security Philosophy and Hardening

`sito` is engineered from the ground up for resilience against network-borne attacks:
- **Memory Safety:** Implemented in pure Rust with strict compile-time checks, eliminating memory corruption risks (buffer overflows, use-after-free).
- **ReDoS Prevention:** Rule parsing DFA engines (`regex-automata`) are guaranteed linear-time and non-backtracking.
- **Backpressure Protection:** Unbounded queues and channel buffers are strictly prohibited on the DNS query hot path to protect against DoS-induced resource exhaustion.
- **Dependency Audits:** Automated `cargo-deny` checks run on every PR to prevent vulnerable or banned crates from entering the dependency tree.
- **Continuous Fuzzing:** Nightly `cargo-fuzz` targets test wire-format decoders, client ID extractors, and configuration parsers.
