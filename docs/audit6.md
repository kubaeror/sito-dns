# Audit 6 — sito-dns 2.0 Readiness Audit

**Audited revision:** `acccdc4` (v1.9.3).
**Remediation target:** Phase 0 is the non-breaking **1.9.4** security patch;
Phase 1 and later ship in 2.0.0.
**Full plan:** [audit6-followup-plan.md](audit6-followup-plan.md).
**Verified prior claims:** [audit6-claim-matrix.md](audit6-claim-matrix.md).

This document is the concise audit record. The linked plan remains the source
of truth for finding details, work packages, and acceptance criteria.

## Executive verdict

**Production readiness: 4/10. Completeness: 7/10.**

sito-dns has a real resolver, a broad protocol surface, a serious test suite,
and many thoughtful controls. It is not production-ready at v1.9.3. The prior
audit's ~8/10 readiness claim is not supported by the current tree: a fresh ACME
install cannot obtain a certificate, DNSSEC denial validation has a
trust-boundary hole, HA cannot detect a dead master, and several documented
controls are incomplete or false.

“Completeness” is breadth, not correctness. The feature list is broad, but
parental/service data is tiny, safe search is narrow, ACME is broken, RouterOS
is niche and partially unsafe, and several settings exist only as raw TOML or
dead knobs.

After the Phase 0 safety gate, the realistic target is 6/10 readiness. After the
2.0 plan, the target is 8.5/10 for core features, with RouterOS explicitly
experimental and documentation matching code.

## Scorecard

Scale 1–10. Readiness is “can an operator run this safely today?” Completeness
is “how much of the stated feature is actually implemented?”

| Area / function | Readiness | Completeness | Main reason |
|---|---:|---:|---|
| **Overall** | **4.0** | **7.0** | Broad resolver, but P0 ACME/DNSSEC and P1 HA/auth/DoS gaps. |
| Core pipeline | 6.5 | 8 | Coherent runtime snapshot, filtering/cache/DNSSEC stages; torn apply and response shaping remain. |
| Config/validation/startup | 5.5 | 7 | Typed sections and validation exist; unknown keys, check-config parity, TLS/ACME restart gaps. |
| Hot reload | 5.0 | 7 | Listener rebind and component swaps exist; not atomic to queries, HA publish truth missing. |
| Filter engine | 5.0 | 6 | Structures and precedence are thoughtful; empty-list fail-open and untrusted-size/OOM. |
| Filter parser | 5.0 | 6 | ABP coverage is good; unbounded lines, raw-IDN loss, partial-token widening. |
| Subscriptions/downloader | 7.0 | 7 | SSRF, caps, 304 and atomic cache are real; empty bodies, URL-keyed cache, drop guard gaps. |
| Rewrites | 6.0 | 6 | Cycles, wildcard specificity, multi-answer; identity spoof, TXT chunking, local NODATA gaps. |
| Client identification/policy | 6.0 | 7 | Secret/IP/CIDR/MAC/RouterOS chain; rewrite-id spoof, stale MAC, silent bad IDs. |
| Parental/services | 3.0 | 2 | 40 adult + 40 gambling domains, 35 tiny service maps; not real protection without external lists. |
| Schedules | 6.0 | 6 | Timezone/fail-closed evaluation; instant-cron semantics and no IANA zones. |
| Safe search | 3.0 | 3 | Narrow exact domains, self-CNAME for DuckDuckGo, rewrites non-address qtypes. |
| Transport UDP/TCP | 6.5 | 7 | Reuseport, PKTINFO, framing, pipelining cap; EDNS shaping and slowloris/per-IP caps. |
| DoT | 6.0 | 7 | Handshake/idle/write timeouts, ALPN/SNI, padding; cert mismatch and per-IP exhaustion. |
| DoH | 4.0 | 6 | H1/H2, GET/POST, body cap; pre-body buffering, no global request cap, response size. |
| DoH3 | 5.0 | 6 | H3, field/body/window limits; no total request deadline, inconsistent host/method. |
| DoQ | 3.0 | 6 | RFC framing/ID; quinn default windows, 25k streams, late rate check. |
| TLS/ACME | 3.0 | 5 | TLS reload exists; ACME bootstrap never issues, ALPN selection and all-manager reload wrong. |
| Rate limiting | 5.0 | 6 | Shared limiter across protocols; full-address keying, arbitrary eviction, post-body checks. |
| Upstream transports | 7.0 | 8 | Plain/DoT/DoH/DoQ with validation and caps; bare DoH path, proxy, ALPN, EDNS fallback. |
| Failover/health/bootstrap | 5.0 | 6 | Strategies/deadlines; RD-less probes, stale bootstrap cache, SSRF not applied. |
| DNSSEC validation | 3.0 | 6 | Real chain/NSEC/NSEC3 code; delegation denial bypass and fail-open paths. |
| DNSSEC cache | 7.0 | 7 | Bounded, atomic, policy-aware; trusts local file, signed evidence outlives DS TTL. |
| Cache | 6.0 | 7 | Key includes DO/CD/ECS, TTL/negative/single-flight; invalidation broken, question/OPT shaping. |
| Auth/session | 6.0 | 8 | Persistence, epochs, revocation, Argon2, TOTP; re-enrollment/re-auth gaps, login input limits. |
| RBAC | 5.0 | 7 | Extractor hierarchy; REST/UI/docs drift and Admin-only self-service. |
| CSRF/web security | 7.0 | 8 | Origin/Referer + double-submit + `__Host-` cookies + CSP; WebSocket Origin, cache headers, login CSRF. |
| REST API | 6.0 | 7 | RFC 7807, most handlers; OpenAPI security drift, silent invalid input, status codes. |
| Config apply | 5.0 | 7 | Atomic writes/locks; unknown keys, restart-only lockouts, filter outage blocks unrelated writes. |
| Web UI | 5.0 | 6 | Askama escaping, CSRF forms; missing TOTP enrollment, stale hints, inert fields. |
| Updater | 5.0 | 7 | Checksum/signature caps, cosign pinning; systemd cannot apply, no rollback/lock, version truth. |
| HA master | 7.0 | 8 | Term/version/persist/auth; publish can fail silently, key loss invisible, fork ACK lost. |
| HA slave | 4.0 | 7 | Apply/watermark ordering; no master-loss timeout, watermark hides local drift. |
| HA mTLS/crypto | 6.0 | 7 | Ed25519/BLAKE3/pins/CA; existing CA, unpinned-without-CA, SAN/hostname, pin expiry. |
| HA failover/promotion | 3.0 | 6 | Manual promotion is conservative; stale Synced, hidden forks, global resync clear, state-loss reset. |
| Stats/querylog | 6.0 | 7 | Parameterized SQL, rollups, caps; permanent PII, polling amplification, long retention lock. |
| Metrics/observability | 7.0 | 8 | Auth-by-default, cardinality caps, snapshot deltas; histogram mutex, stale series, ignore_stats. |
| Tests | 7.0 | 6 | 1,045 tests, broad acceptance; missing security/privacy/migration/scale paths and fuzz. |
| Code quality | 5.0 | 6 | 28 files >1,000 lines, 114 functions >100 lines, 24 allows, dead APIs, unused deps. |
| Docker | 8.0 | 8 | Pinned bases, nonroot, read-only compose, multi-arch; mutable tags and admin exposure. |
| systemd/installer | 5.0 | 6 | Hardened unit, checksum/cosign; live upgrade/rollback broken, no E2E. |
| CI/CD | 7.0 | 7 | SHA-pinned actions, least privilege, release signing/SBOM; main skips tests, release not gated. |
| Release/supply chain | 7.0 | 7 | Checksums/signatures/SBOM/provenance; installer signature best-effort, no image scan/sign. |
| Docs/config truth | 4.0 | 6 | Many accurate docs, but ACME/TLS/metrics/HA/API/fuzz/benchmark claims are wrong. |
| Migration tooling | 5.0 | 5 | Fixture coverage; no-PyYAML fallback silently emits defaults, migration guide teaches wrong login. |

## P0 and P1 summary

P0 means deployment/security blocker; P1 means high severity. Detailed evidence
and the fix plan live in the [full plan](audit6-followup-plan.md). P1-19, P1-23,
and P1-24 are explicitly deferred to Phase 2 and recorded as residual risks in
the 1.9.4 release notes.

### P0 — release-blocking

| ID | Area | Finding |
|---|---|---|
| P0-1 | ACME/TLS | The ACME bootstrap certificate has a ~2,000-year validity and no bootstrap marker, so a fresh ACME-only install never orders or renews a certificate. |
| P0-2 | DNSSEC | NSEC/NSEC3 denial validation accepts ancestor-delegation records and does not check closest-encloser/NS-without-SOA semantics, allowing a signed parent's public delegation data to forge AD=1 NXDOMAIN/NODATA below a child zone. |

### P1 — high

| ID | Area | Finding |
|---|---|---|
| P1-1 | DNSSEC | Fail-open paths: junk RRSIG suppresses the unsigned probe, signed CNAME to unsigned target is classified without an authenticated DS denial, and strict mode can serve `Indeterminate`. |
| P1-2 | DNSSEC | Key/chain fetching has per-fetch limits but no overall wall-clock or global per-query work cap. |
| P1-3 | HA | The slave session loop has no master heartbeat/read deadline and can report `Synced` while serving stale shared config. |
| P1-4 | HA | Same-version ACK trusts the local watermark as proof the local config still matches the master bundle. |
| P1-5 | HA | A delayed same-version fork ACK is ignored after a newer publish, hiding divergence from the operator. |
| P1-6 | HA/API | `publish_bundle()` logs and drops publish failures and does not enforce the 1 MiB WebSocket limit before persisting. |
| P1-7 | Filter | Parser/compiler budgets are enforced after materialization; no line, token, or total parsed-byte caps. |
| P1-8 | Filter | Empty or zero-yield list responses are accepted as a successful empty snapshot; `fail_closed` does not trigger. |
| P1-9 | Filter/Rewrites/Clients/DoH | Malformed rules widen scope by dropping invalid tokens; rewrite `exception_clients` trusts an unauthenticated DoH path/SNI identity. |
| P1-10 | DoQ | Admission allows unauthenticated memory/task growth before rate limiting (default stream/connection windows). |
| P1-11 | DoH | The body is buffered before the rate check and there is no global request semaphore or lowered H2 stream cap. |
| P1-12 | ACME/TLS | Challenge selection can pick TLS-ALPN-01 with no TCP 443 listener; only the DoH manager reloads after issuance. |
| P1-13 | Cache/Transport | Forced-DO upstream OPT is not stripped and cache hits clone the stored question/flags, leaking OPT and wrong case/RD/DO/CD. |
| P1-14 | DoH/DoH3 | Response encoding has no 65,535-byte cap, violating DNS message framing and allowing unbounded bandwidth. |
| P1-15 | Auth/TOTP | TOTP setup/enable replaces the secret and backup codes with only an Admin session, allowing a stolen session to take over 2FA. |
| P1-16 | Auth/UI | The setup wizard is re-openable by any Admin and can reset the admin password without the current password or TOTP. |
| P1-17 | Installer | Live upgrade and rollback use `cp -f` over a running binary, so the documented upgrade fails with `ETXTBSY`. |
| P1-18 | Cache | Cache invalidation closures are never enabled; “invalidate domain” reports success while leaving entries cached. |
| P1-19 | Stats | Hourly rollups permanently retain client IPs, names, and full domains; retention/clear do not erase rollups. *(Deferred to Phase 2.)* |
| P1-20 | Auth | Login accepts unbounded username/password strings and uses the full username as a lockout key, enabling pre-auth DoS and lockout eviction. |
| P1-21 | CI/Release | Release validation does not require the tagged commit to be on `main`, tested, or security-checked; main pushes skip tests/clippy/fmt. |
| P1-22 | Installer/Docs | Signature verification defaults to off and silently downgrades to same-origin SHA-256 when assets are missing; docs claim signed verification. |
| P1-23 | Stats/API | Query-log pages run whole-table `COUNT(*)` every 3 seconds and dashboards run repeated aggregate scans, enabling authenticated self-DoS. *(Deferred to Phase 2.)* |
| P1-24 | Stats | Retention runs as one large immediate transaction with full scans, holds the write lock for minutes, and never runs at startup. *(Deferred to Phase 2.)* |
| P1-25 | Upstream | Bootstrap/health probes omit RD=1, bootstrap answers bypass the SSRF denylist, and re-resolution serves stale cache instead of forcing refresh. |
| P1-26 | Core/Config apply | The filter engine is swapped before the runtime snapshot, creating a filter-enable bypass window and inconsistent failure state. |
| P1-27 | Core/Config apply | The DNSSEC validator is swapped before the cache flush, so old-policy validation status can survive a policy change. |

## Baseline at audit time

Commands were run at `acccdc4` (v1.9.3) and match the plan's recorded baseline:

| Command | Result |
|---|---|
| `cargo fmt --all --check` | Pass |
| `cargo clippy --workspace --all-features --all-targets -- -D warnings` | Pass |
| `cargo test --workspace --all-features --locked` | 1,057 passed, 0 failed, 0 ignored across 40 test binaries |
| `cargo deny check` | advisories, bans, licenses, sources all ok (pre-existing `advisory-not-detected` warning for `RUSTSEC-2026-0374`) |

A green baseline is not evidence that the security properties above hold.

WP-0.1 verification on this branch after adding the regression-harness tests:
`cargo test --workspace --all-features --locked` → **1,065 passed, 0 failed,
0 ignored**; `cargo fmt --all --check`, `cargo clippy --workspace
--all-features --all-targets -- -D warnings`, and `cargo deny check` are green.
The weekly workflow now sets `SITO_PERF_TESTS=1` so the opt-in 50k insertion
timing gate actually runs on the dedicated weekly runner.

## Historical documents

`docs/audit.md`, `docs/audit2.md`, and `docs/audit5.md` now carry a historical
banner. They remain useful context but must not be cited as current evidence;
use the [claim matrix](audit6-claim-matrix.md) instead.
