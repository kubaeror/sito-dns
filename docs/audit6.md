> **Historical document — not evidence.** This document records the state at
> its original commit and is kept for context only. Historical audits and plans
> are leads; verify every claim against the current code and tests. Current
> references: [2.0 migration guide](2.0-migration.md),
> [config v2](config-v2.md), [2.0 public API diff](2.0-public-api-diff.md),
> [P0/P1 test evidence](audit6-test-matrix.md) and the
> [historical/current documentation index](history/README.md).

# Audit 6 — sito-dns 2.0 Readiness Audit

**Audited revision:** `acccdc4` (v1.9.3).
**Remediation target:** Phase 0 is the non-breaking **1.9.4** security patch;
Phase 1 and later ship in 2.0.0.
**Full plan:** [audit6-followup-plan.md](audit6-followup-plan.md).
**Verified prior claims:** [audit6-claim-matrix.md](audit6-claim-matrix.md).

> **Phase 0 status: complete in sito 1.9.4.** The safety gate fixed P0-1/P0-2 and
> P1-1 through P1-18 and P1-20 through P1-22 and P1-25 through P1-27, plus the
> directly exploitable transport/upstream/auth/installer items in the same work
> packages. P1-1's DNAME half remains open (the pinned hickory parser decodes
> DNAME as unsupported `RData::Unknown`; validation fails closed; see the
> residual-risk note). P1-19, P1-23, and P1-24 (stats
> privacy/polling/retention) are also closed in this branch; see the
> [1.9.4 release notes](release-notes-1.9.4.md#stats-privacy-retention-and-polling). P2/P3 documentation truth items
> are addressed in 1.9.4; RouterOS remains experimental and 2.0 still owns the
> structural refactor (config/validator/session/chain state machines). The
> verdict and scorecard below describe the audited v1.9.3 tree, not 1.9.4.

This document is the concise audit record. The linked plan remains the source
of truth for finding details, work packages, and acceptance criteria.

## Executive verdict at audit time (v1.9.3)

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

After the Phase 0 safety gate, the realistic target is 6/10 readiness (the
shipped 1.9.4 state). After the 2.0 plan, the target is 8.5/10 for core features,
with RouterOS explicitly experimental and documentation matching code.

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
and the fix plan live in the [full plan](audit6-followup-plan.md). The status
column records the 1.9.4 safety-gate outcome. P1-19, P1-23, and P1-24 are
closed by the deferred stats/privacy work; see the
[1.9.4 release notes](release-notes-1.9.4.md#stats-privacy-retention-and-polling).

### P0 — release-blocking

| ID | Area | Finding (v1.9.3) | Status in 1.9.4 |
|---|---|---|---|
| P0-1 | ACME/TLS | The ACME bootstrap certificate has a ~2,000-year validity and no bootstrap marker, so a fresh ACME-only install never orders or renews a certificate. | **Fixed.** 7-day marked bootstrap placeholder; bootstrap is not served unless `acme.allow_bootstrap_cert = true`; legacy year-4096 self-signed pairs are detected and renewed. |
| P0-2 | DNSSEC | NSEC/NSEC3 denial validation accepts ancestor-delegation records and does not check closest-encloser/NS-without-SOA semantics, allowing a signed parent's public delegation data to forge AD=1 NXDOMAIN/NODATA below a child zone. | **Fixed.** Parent-side delegation NSEC/NSEC3 records cannot prove denial below the cut; DS NODATA at the cut still works. |

### P1 — high

| ID | Area | Finding (v1.9.3) | Status in 1.9.4 |
|---|---|---|---|
| P1-1 | DNSSEC | Fail-open paths: junk RRSIG suppresses the unsigned probe, signed CNAME to unsigned target is classified without an authenticated DS denial, strict mode can serve `Indeterminate`, and DNAME/QTYPE=CNAME are misclassified. | **Fixed for CNAME/strict mode; DNAME remains open.** Per-RRset probing, authenticated DS-denial requirement, CNAME/QTYPE=CNAME fixes, and strict `Indeterminate` → SERVFAIL. DNAME is decoded by the pinned hickory-proto 0.26.3 as `RData::Unknown` and is not interpretable/validatable, so the validator fails closed in validate mode (Bogus/SERVFAIL, no AD) rather than following it; see the residual-risk note below. |
| P1-2 | DNSSEC | Key/chain fetching has per-fetch limits but no overall wall-clock or global per-query work cap. | **Fixed.** 5-second per-query validation/key-fetch deadline; timeout fails closed in validate mode. |
| P1-3 | HA | The slave session loop has no master heartbeat/read deadline and can report `Synced` while serving stale shared config. | **Fixed.** Any-frame liveness deadline of `3 × ping_interval_secs` clears `Synced` and fails readiness. |
| P1-4 | HA | Same-version ACK trusts the local watermark as proof the local config still matches the master bundle. | **Fixed.** Watermark stores a BLAKE3 digest of the applied document; local drift forces a full apply. |
| P1-5 | HA | A delayed same-version fork ACK is ignored after a newer publish, hiding divergence from the operator. | **Fixed.** Bounded publish-envelope history attributes late fork ACKs. |
| P1-6 | HA/API | `publish_bundle()` logs and drops publish failures and does not enforce the 1 MiB WebSocket limit before persisting. | **Fixed.** Fallible publish outcomes, readiness failure, bounded retry, and pre-persist size rejection. |
| P1-7 | Filter | Parser/compiler budgets are enforced after materialization; no line, token, or total parsed-byte caps. | **Fixed.** Line/pattern/total-byte/rule-count and AC/prefix budgets are enforced before allocation. |
| P1-8 | Filter | Empty or zero-yield list responses are accepted as a successful empty snapshot; `fail_closed` does not trigger. | **Fixed.** Empty/HTML/zero-yield responses are rejected unless `filtering.allow_empty_list = true`; previous rules stay active. |
| P1-9 | Filter/Rewrites/Clients/DoH | Malformed rules widen scope by dropping invalid tokens; rewrite `exception_clients` trusts an unauthenticated DoH path/SNI identity. | **Fixed.** Whole-rule rejection for bad modifier tokens and `id_authenticated` gating for rewrite exceptions. |
| P1-10 | DoQ | Admission allows unauthenticated memory/task growth before rate limiting (default stream/connection windows). | **Fixed.** 128 KiB/2 MiB windows, 16 bidi streams, global stream semaphore, pre-read rate check, per-IP cap. |
| P1-11 | DoH | The body is buffered before the rate check and there is no global request semaphore or lowered H2 stream cap. | **Fixed.** Pre-body admission, global request cap/503, 32 H2 streams, 10 s deadline, 300 s lifetime. |
| P1-12 | ACME/TLS | Challenge selection can pick TLS-ALPN-01 with no TCP 443 listener; only the DoH manager reloads after issuance. | **Fixed.** TLS-ALPN requires a bound 443 DoH listener; HTTP-01 fallback; all four TLS managers reload after issuance. |
| P1-13 | Cache/Transport | Forced-DO upstream OPT is not stripped and cache hits clone the stored question/flags, leaking OPT and wrong case/RD/DO/CD. | **Fixed.** One `sito_proto::ResponseShaper::shape` path rebuilds the client question/OPT/AD and strips upstream EDNS options on cache, stale, upstream, rewrite and synthesized answers. Cache keys include EDNS presence and are re-clamped after a policy reload. |
| P1-14 | DoH/DoH3 | Response encoding has no 65,535-byte cap, violating DNS message framing and allowing unbounded bandwidth. | **Fixed (defensive).** Explicit TC=1 truncation guard; the pinned hickory encoder already truncates at `u16::MAX`. |
| P1-15 | Auth/TOTP | TOTP setup/enable replaces the secret and backup codes with only an Admin session, allowing a stolen session to take over 2FA. | **Fixed.** Setup/enable/disable require a short-lived reauth ticket (`X-Reauth-Token`). |
| P1-16 | Auth/UI | The setup wizard is re-openable by any Admin and can reset the admin password without the current password or TOTP. | **Fixed.** Wizard is bootstrap-only and returns 403 after setup, including for Admins. |
| P1-17 | Installer | Live upgrade and rollback use `cp -f` over a running binary, so the documented upgrade fails with `ETXTBSY`. | **Fixed.** Stop → temp-file/fsync/rename install → start, with binary+config rollback. |
| P1-18 | Cache | Cache invalidation closures are never enabled; “invalidate domain” reports success while leaving entries cached. | **Fixed.** Moka invalidation closures enabled; errors flush instead of silently succeeding. |
| P1-19 | Stats | Hourly rollups permanently retain client IPs, names, and full domains; retention/clear do not erase rollups. | **Fixed.** Keyed BLAKE3 rollup client IDs, opt-in client names, rollup retention, clear/vacuum with `keep_aggregates` opt-in, `secure_delete`, and 0600 repair. |
| P1-20 | Auth | Login accepts unbounded username/password strings and uses the full username as a lockout key, enabling pre-auth DoS and lockout eviction. | **Fixed.** 64/1024-byte caps and BLAKE3 lockout keys; active lockouts are never evicted. |
| P1-21 | CI/Release | Release validation does not require the tagged commit to be on `main`, tested, or security-checked; main pushes skip tests/clippy/fmt. | **Fixed.** Branch/check release gate; CI and security run on `main` and `release/1.9.x` pushes. |
| P1-22 | Installer/Docs | Signature verification defaults to off and silently downgrades to same-origin SHA-256 when assets are missing; docs claim signed verification. | **Fixed.** Signatures/cosign are required by default; `SITO_REQUIRE_SIGNATURE=0` is the explicit opt-out. |
| P1-23 | Stats/API | Query-log pages run whole-table `COUNT(*)` every 3 seconds and dashboards run repeated aggregate scans, enabling authenticated self-DoS. | **Fixed.** Optional `include_total` for live refresh, 45 s dashboard cache with invalidation, and per-user stats rate limits. |
| P1-24 | Stats | Retention runs as one large immediate transaction with full scans, holds the write lock for minutes, and never runs at startup. | **Fixed.** Bounded hour chunks with separate commits, jittered startup catch-up, and retention metrics. |
| P1-25 | Upstream | Bootstrap/health probes omit RD=1, bootstrap answers bypass the SSRF denylist, and re-resolution serves stale cache instead of forcing refresh. | **Fixed.** RD=1, SSRF-filtered bootstrap (`upstream.allow_private_targets` opt-in), forced refresh, UDP junk tolerance, DoH/EDNS fixes. |
| P1-26 | Core/Config apply | The filter engine is swapped before the runtime snapshot, creating a filter-enable bypass window and inconsistent failure state. | **Fixed.** Runtime snapshot publishes before the filter swap; hook failures roll back. |
| P1-27 | Core/Config apply | The DNSSEC validator is swapped before the cache flush, so old-policy validation status can survive a policy change. | **Fixed.** The chain cache and the response cache both carry a monotonic DNSSEC policy generation; old-generation entries are unservable and in-flight inserts from the old policy are rejected. `Indeterminate` is no longer served from the response cache while validation is active. |

### Residual risk: DNAME

P1-1's CNAME and strict-`Indeterminate` paths are fixed in 1.9.4, but DNAME
remains open. The pinned `hickory-proto 0.26.3` has no `RData::DNAME` variant;
on the wire it decodes a DNAME record as `RData::Unknown { code: DNAME }`
(`record_data.rs`), so sito cannot inspect, validate, or follow it. The
transport does not reject the message. Instead the validator cannot interpret
the RRset and fails closed in `validate` mode (Bogus/SERVFAIL, `AD=0`); the
regression test `test_dname_unknown_rdata_fails_closed` asserts the wire decode
and that fail-closed outcome. Closing this requires a hickory upgrade or a
local DNAME RDATA implementation; it is tracked for the Phase 1/2 DNSSEC work
and is not claimed as fixed below.

## Baseline at audit time

Commands were run at `acccdc4` (v1.9.3) and match the plan's recorded baseline:

| Command | Result |
|---|---|
| `cargo fmt --all --check` | Pass |
| `cargo clippy --workspace --all-features --all-targets -- -D warnings` | Pass |
| `cargo test --workspace --all-features --locked` | 1,057 passed, 0 failed, 0 ignored across 40 test binaries |
| `cargo deny check` | advisories, bans, licenses, sources all ok (pre-existing `advisory-not-detected` warning for `RUSTSEC-2026-0374`) |

A green baseline is not evidence that the security properties above hold.

WP-0.1 verification on this branch after adding the regression-harness tests
and the shared `sito-test-support` port broker:
`cargo test --workspace --all-features --locked` → **1,068 passed, 0 failed,
0 ignored**; `cargo fmt --all --check`, `cargo clippy --workspace
--all-features --all-targets -- -D warnings`, and `cargo deny check` are green.
The weekly workflow now sets `SITO_PERF_TESTS=1` so the opt-in 50k insertion
timing gate actually runs on the dedicated weekly runner.

The final 1.9.4 safety-gate tree also passes the documentation checks:

| Command | Result |
|---|---|
| `python3 scripts/check_config_reference.py --github` | Pass (key presence, documented types, and extractable defaults) |
| `python3 scripts/check_markdown_links.py` | Pass (tracked internal Markdown files/anchors) |
| `cargo fmt --all --check` | Pass |

The Phase 0 work adds no config-schema version change, API contract break,
SQLite migration, or HA wire-protocol change. Three additive config keys were
introduced with safe defaults: `acme.allow_bootstrap_cert = false` (fail closed
on encrypted listeners until a trusted certificate exists),
`upstream.allow_private_targets = false` (hostname-configured upstreams may not
resolve to private targets), and `filtering.allow_empty_list = false` (reject
empty/zero-yield sources). Operators who intentionally relied on the old
behavior must opt in; this is called out in the release notes.

## Historical documents

`docs/audit.md`, `docs/audit2.md`, and `docs/audit5.md` now carry a historical
banner. They remain useful context but must not be cited as current evidence;
use the [claim matrix](audit6-claim-matrix.md) instead.
