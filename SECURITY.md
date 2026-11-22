# Security Policy

The `sito` security team takes vulnerabilities in network services seriously. Because `sito` operates directly on network query paths and handles sensitive DNS traffic, security, memory integrity, and prompt vulnerability resolution are paramount.

---

## 1. Supported Versions

We release security patches and vulnerability fixes for the **current minor release** and the **preceding minor release**:

| Release Line | Supported Status | Notes |
|---|---|---|
| `1.9.x` (1.9.5 stable) | :white_check_mark: Supported | Published stable release; security fixes and critical backports |
| `2.0.0-rc.2` (release candidate, tag pending) | :construction: Release candidate | Phase 3 verification at the rc.1 candidate; the workspace version is `2.0.0-rc.2`. Not a published stable artifact until the tag/release workflow completes. Security reports are triaged against this line. |
| Prior minor release (`1.8.x`) | :white_check_mark: Supported | Critical security fixes only |
| Older releases | :x: Unsupported | Upgrade recommended |

Patch releases within a supported stable line are published from the matching
release branch and tagged `vX.Y.Z`; see [CHANGELOG.md](CHANGELOG.md) for the
current release. The 2.0 line uses config v2 and is a deliberate breaking
change; see [docs/2.0-migration.md](docs/2.0-migration.md). The current threat
model, control summary and Phase 3 review are in
[docs/security-audit.md](docs/security-audit.md) and
[docs/phase3-security-review.md](docs/phase3-security-review.md).

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
- **Dependency Audits:** Automated `cargo-deny` checks run on **every pull request** (including docs-only changes), on `main`, and in the weekly quality workflow, so a new advisory is caught even when the dependency set is unchanged. Two unmaintained-crate advisories are reviewed and suppressed in `deny.toml`: `RUSTSEC-2026-0374` (`basic-toml`, build-time via `askama_derive`) and `RUSTSEC-2026-0543` (`chrono`, reachable in production; no safe upgrade yet). Impact, reachability and the 2027-01-31 review date are recorded in [docs/phase3-security-review.md](docs/phase3-security-review.md#11-denytoml-suppression-review).
- **Fuzzing:** The 2.0 branch has a five-target cargo-fuzz workspace. Pull requests build the targets. Before Phase 3 the scheduled workflow produced an invalid job matrix and did not run; the Phase 3 workflow builds a valid target × shard matrix in a `prepare` job, and the nightly smoke runs 600 s per target with corpus, dictionary and a 10 s per-input timeout. The 24-hour campaign (four 6-hour shards per target) remains a **deferred release-checklist item** and has not been run for rc.1. Fuzzing is not a pull-request execution gate. See [docs/ci.md](docs/ci.md#fuzzing-is-nightlyrelease-not-a-pr-gate) and [fuzz/README.md](fuzz/README.md).
- **Benchmarks:** The nightly `bench.yml` comparison is **active**. It runs on GitHub-hosted `ubuntu-24.04`, compares against the committed `benches/baseline.json` (`environment: github-ubuntu-24.04`), and fails on a >10% regression. A local comparison on different hardware must use `--reference-only` and is not the release gate; regenerate the baseline only through the GitHub-hosted `update_baseline=true` workflow. See [docs/ci.md](docs/ci.md#benchmark-baseline).
- **Health endpoint:** `/health` is an intentionally generic `200 {"status":"ok"}`/`503 {"status":"unavailable"}` probe. It exposes no setup state, component names, reasons, paths or configuration values; authenticated detail is on `/api/v2/status` and `/api/v2/ha/status`. ACME/TLS readiness distinguishes a current certificate with a failed renewal (degraded), an expiring certificate (degraded) and an expired/unparseable certificate (not ready). See [docs/runbook-ha.md](docs/runbook-ha.md#health-and-status-endpoint-semantics-wp-17).
