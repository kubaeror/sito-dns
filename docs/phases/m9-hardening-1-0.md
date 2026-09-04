# Phase M9 — Hardening, Performance and the 1.0 Release (4 weeks)

Goal: from a working server to a product: measured, fuzzed, documented, packaged. References: plan sections 16, 18, 19.

## Scope

**In:** fuzzing, regression benchmarks, PGO, tuning, security review, complete documentation, release pipeline with signatures and SBOM, tag v1.0.0.
**Out:** new features (feature freeze from day one of the phase).

## Tasks

### 1. Fuzzing

- cargo-fuzz targets: ABP rule parser, TOML-config parser, ClientID extraction (URL/SNI), DNS message parser if a custom one ever appears
- Nightly CI: 10 min/target; corpus in a separate repo; every crash → issue with a reproducer within 24 h

### 2. Performance

- dnsperf/resperf infrastructure in CI: 1M-domain corpus (Tranco), 3×5 min, results as an artifact + entry in `docs/benchmarks.md`
- Scenarios from table 16.1: UDP cache, UDP parallel forwarding, DoT, DoH; measure added-latency p99
- PGO in the release pipeline; A/B `mimalloc` vs system allocator — decide with data, not opinion
- Profile with `flamegraph` + `tokio-console`; every hotspot >5% CPU on the hot path gets an ADR-008 comment (budget) or a fix
- `docs/performance.md`: kernel tuning from section 16.3 + rationale

### 3. Security review (checklist)

- [ ] `cargo audit` + `cargo deny` clean; review of the TLS/crypto dependency tree
- [ ] SSRF in list fetching: scheme allowlist (https), optional RFC1918 block in the fetcher's resolver (documented — lists may live on the LAN)
- [ ] ReDoS: user regexes only through the `regex-automata` DFA (no backtracking) — malicious-pattern test
- [ ] DoS: per-transport connection/query limits active and documented; flood test (hping3/QUIC retry)
- [ ] Auth: timing attack on login (constant-time comparison), lockout, secure cookie flags
- [ ] Secrets: grep tests over configs/logs/HA bundles (zero secrets)
- [ ] TLS: ssllabs test on DoH; TLS <1.2 ban confirmed by scan
- [ ] Optional: external review (budget/community)

### 4. Documentation

- `docs/`: installation (docker/bare-metal/installer), configuration reference (every TOML key), performance, HA runbook (from M8), compatibility (from M2), security, troubleshooting
- README: UI screenshots, quickstart, honest comparison table with AdGuard Home/Pi-hole — what works, what's in the backlog
- CHANGELOG from conventional commits; "migrate from AdGuard Home" guide (export lists/rules/clients → sito TOML, converter script in `contrib/`)

### 5. Release engineering

- cargo-dist: binaries x86_64/aarch64/armv7, `.deb`/`.rpm`, `install.sh` (section 17.5)
- Multi-arch images; cosign signatures (keyless); SBOM (`cargo-sbom`) as an artifact
- RC process: v1.0.0-rc.1 → a week of soak testing on your own homelab (dogfooding: your MikroTik + family as the quality clause) → v1.0.0

## Agent prompts

```
M9.1 fuzz-infra  → task 1; DoD: nightly job green; an injected bug (test) caught
                   by the fuzzer in <5 min
M9.2 perf        → task 2; DoD: docs/benchmarks.md with numbers vs targets 16.1;
                   deviations come with a root-cause analysis
M9.3 sec-review  → task 3; DoD: checklist 100% ticked or has an issue labeled
                   security with a deadline
M9.4 docs        → task 4; DoD: a new user goes from zero to working in <15 min
                   following the docs ("fresh eyes" test)
M9.5 release     → task 5; DoD: RC tag dry run produces all artifacts with
                   signatures; install.sh works on a clean VM
```

## Exit criteria — v1.0.0

- [ ] Section 16.1 targets measured and published (or deviations planned in ADR-008)
- [ ] Zero known fuzzing crashes; zero advisories in audit
- [ ] Security checklist complete
- [ ] Dogfooding: ≥1 week as the only DNS in your network, including the HA pair
- [ ] v1.0.0 tagged with signed artifacts and SBOM

## Risks

| Risk | Mitigation |
|---|---|
| Performance targets unreachable without a rewrite | Measure early (per-phase benchmarks in M2/M3) — M9 only fine-tunes; ADR-008 updated with data |
| Scope creep ("just one more feature for 1.0") | Feature freeze; everything new → milestone v1.1 |
| Burnout on the home stretch | Dogfooding as motivation; v1.1 roadmap (HA query-log aggregation, Helm, APT repo) as a promise of continuation |

## Deliverables

v1.0.0: binaries, packages, images, signatures, SBOM, docs, benchmarks, CHANGELOG, announcement post.
