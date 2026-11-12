> **Historical document — not evidence.** This document records the state at
> its original commit and is kept for context only. Historical audits and plans
> are leads; verify every claim against the current code and tests. Current
> references: [2.0 migration guide](2.0-migration.md),
> [config v2](config-v2.md), [2.0 public API diff](2.0-public-api-diff.md),
> [P0/P1 test evidence](audit6-test-matrix.md) and the
> [historical/current documentation index](history/README.md).

# sito-dns 2.0 Audit and Remediation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce a source-verified audit of sito-dns at v1.9.3 and a phased 2.0 remediation plan that closes every P0/P1 finding, removes the worst architecture debt before adding features, and leaves the core resolver production-grade on a home/LAN deployment.

**Architecture:** A safety gate closes release-blocking defects on the current tree, then the 2.0 work replaces the fragile parts with explicit state machines and shared interfaces: one config validator, one runtime generation, one DNSSEC chain/denial walker, one admission controller, one HA session model, and one filter status model. Breaking config/API/DB/HA changes are allowed and are migrated deliberately.

**Tech Stack:** Rust 2024, Tokio, Axum, Hickory DNS, Rustls/Quinn, SQLite/SQLx, Askama/HTMX, Cargo, Docker, systemd, GitHub Actions.

**Spec:** This document is both the audit record and the 2.0 design/remediation spec. It must travel with the plan.

---

## Global Constraints

- Release mapping: **Phase 0 = 1.9.4** (non-breaking security patch) and **Phase 1 onward = 2.0.0**. Breaking changes in config keys/defaults, REST/API contracts, SQLite schema, and the HA wire protocol are allowed only from Phase 1 onward; Phase 0 must remain a safe 1.9.x patch.
- Primary deployment: **home lab / trusted LAN**. Do not optimize for public-resolver traffic, but do not introduce vulnerabilities that a public deployment would expose.
- Core features that must be production-grade: DNS filtering/cache, encrypted DNS, DNSSEC validation, Web UI/REST API, HA replication, ACME, parental/service lists.
- RouterOS integration is **not core**. It must be moved behind an optional feature/crate or removed from the default 2.0 build. Native DNSCrypt remains an external integration, not a core transport.
- Default behavior is **fail closed**: SERVFAIL for unprovable DNSSEC in validate/strict modes, startup failure for configured-but-broken TLS/ACME, rejection of empty/zero-yield filter lists unless explicitly allowed, and no silent fallback to global upstreams for a broken per-client upstream.
- No new silently ignored knobs. A setting is wired, removed, or documented as reserved with a startup warning.
- Every P0/P1 fix ships with a regression test that fails before the fix. Tests must be committed with the fix, not after it.
- No `let _ =` on security, config-apply, persistence, or readiness paths. Exceptions require a comment explaining why the error is non-actionable.
- Baseline commands must stay green after every work package:
  `cargo fmt --all --check`, `cargo clippy --workspace --all-features --all-targets -- -D warnings`, `cargo test --workspace --all-features --locked`, `cargo deny check`.
- No direct pushes to `main`. **One PR per phase** (Phase 0, Phase 1, Phase 2, Phase 3); each PR contains one conventional commit per work package, with its tests and docs. Do not mix phases in one PR. Phase 0 targets `release/1.9.x` and ships as **1.9.4**; after 1.9.4, `release/1.9.x` is merged into `main` before Phase 1 starts. Phase 1-3 target `main` and ship in the 2.0 line.
- Historical audit documents are not evidence. They are leads. The claim matrix in Appendix C records what is true at current HEAD.

---

## Review Focus

These are the failure modes most likely to hurt a real operator, in order:

1. **A fresh ACME deployment never obtains a real certificate.** The bootstrap self-signed cert is valid until 4096 and is treated as current, so renewal never starts.
2. **A signed zone can be given a forged NXDOMAIN below a delegation.** Parent-side NSEC/NSEC3 records are accepted as denial proofs below a zone cut.
3. **A partitioned slave reports healthy while serving stale shared configuration.** There is no master-loss heartbeat deadline, and the watermark is treated as proof that the local config still matches.
4. **A hostile or broken filter source can empty the rule set or exhaust memory.** Empty 200 responses are accepted as successful, and parser/compiler budgets are enforced after materialization.
5. **A stolen admin session can re-enroll TOTP or reset the admin password through the re-openable wizard without re-authentication.**
6. **DoQ/DoH admission allows unauthenticated memory/task growth before rate limiting.** Body and stream buffers are read before the limiter and have no per-IP cap.
7. **The documented live installer upgrade fails with ETXTBSY.** The installer copies over a running binary and its rollback does the same.
8. **Cache invalidation and response shaping are wrong.** `invalidate_domain` is a no-op, and cached/upstream responses can carry the wrong question, flags, or EDNS OPT.

---

# Part I — Audit

## 1. Executive Verdict

**Production readiness: 4/10. Completeness: 7/10.**

The project has a real resolver, a broad protocol surface, a serious test suite, and many thoughtful controls. It is not production-ready at v1.9.3. The previous audit’s claim of ~8/10 is not supported by the current tree: the ACME path cannot issue a certificate from a fresh install, DNSSEC denial validation has a trust-boundary hole, HA cannot detect a dead master, and several documented controls are incomplete or false.

“Completeness” is breadth, not correctness. The feature list is broad, but parental/service data is tiny, safe search is narrow, ACME is broken, RouterOS is niche and partially unsafe, and several settings exist only as raw TOML or dead knobs.

After the safety gate, the realistic target is 6/10 readiness. After the 2.0 plan, the target is 8.5/10 for core features, with RouterOS explicitly experimental and docs matching code.

## 2. Method and Evidence

- Eight read-only subsystem audits: core/pipeline/server, filter/rewrites/clients, transport/cache, upstream/DNSSEC, API/UI/auth, HA, stats/tests/quality, ops/CI/docs.
- Source verification of every P0/P1 claim against HEAD `acccdc4` (v1.9.3).
- Existing builds: `cargo fmt --all --check` passes; `cargo check --workspace --all-features --all-targets` passes.
- Full `cargo test --workspace --all-features --locked` passes: **1,057 passed, 0 failed, 0 ignored** across 40 test binaries. This is a green baseline, not evidence that the security properties above hold.
- Prior audits and CHANGELOG were treated as leads. Appendix C records claims that are fixed, false, or outdated.
- Severity: P0 = deployment/security blocker; P1 = high; P2 = medium; P3 = low/cleanup.
- Verification markers in the findings catalog: **[V]** lead-verified in source or runtime; **[S]** subagent source-verified; **[R]** requires runtime confirmation before release.

## 3. Scorecard

Scale: 1–10. Readiness is “can an operator run this safely today?” Completeness is “how much of the stated feature is actually implemented?”

| Area / function | Readiness | Completeness | Main reason |
|---|---:|---:|---|
| **Overall** | **4.0** | **7.0** | Broad resolver, but P0 ACME/DNSSEC and P1 HA/auth/DoS gaps. |
| Core pipeline | 6.5 | 8 | Coherent runtime snapshot, filtering/cache/DNSSEC stages; torn apply and response shaping remain. |
| Config/validation/startup | 5.5 | 7 | Typed sections and validation exist; unknown keys, check-config parity, TLS/ACME restart gaps. |
| Hot reload | 5.0 | 7 | Listener rebind and component swaps exist; not atomic to queries, HA publish truth missing. |
| Filter engine | 5.0 | 6 | Structures and precedence are thoughtful; empty-list fail-openand untrusted-size/OOM. |
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

## 4. Findings Catalog

The catalog lists every material finding from the eight audits. Some P2/P3 items are grouped; the work packages in Part III name the exact fix.

### 4.1 P0 — release-blocking

| ID | Status | Location | Finding | Impact |
|---|---|---|---|---|
| **P0-1** | [V] | `crates/sito-transport/src/acme.rs:294-350`, `crates/sito-transport/src/tls.rs:128-136`, `crates/sito/src/server.rs:1438-1470`, rcgen 0.14.10 `certificate.rs:84-85` | ACME bootstrap certificate is self-signed with rcgen’s default `not_after = 4096-01-01`; no `pair.sha256` marker is written. `pair_metadata_matches()` treats a missing marker as a match, and `certificate_needs_renewal()` sees ~2,000 years of validity and returns false. | A fresh ACME-only install never orders a certificate. TLS-ALPN-01/HTTP-01 are never exercised; DoT/DoH/DoQ/DoH3 serve the self-signed cert indefinitely. |
| **P0-2** | [V] | `crates/sito-dnssec/src/nsec.rs:91-133`, `crates/sito-dnssec/src/nsec3.rs:122-205`, `crates/sito-dnssec/src/lib.rs:828-899` | NSEC/NSEC3 denial validation accepts records whose owner is anywhere inside the signer zone, including ancestor-delegation records. It does not reject NS-without-SOA delegation NSECs/NSEC3s or check the closest-encloser bitmap (RFC 6840 §4.1, RFC 5155 §8.3). | A signed parent’s public delegation records can be replayed to forge AD=1 NXDOMAIN/NODATA for names below a signed child delegation, poisoning negative caches. This is a DNSSEC validation bypass. |

### 4.2 P1 — high

| ID | Status | Location | Finding | Impact |
|---|---|---|---|---|
| **P1-1** | [V] | `crates/sito-dnssec/src/lib.rs:2420-2529, 3190-3221, 3380-3416`; `crates/sito/src/pipeline.rs:1030-1069` | DNSSEC fail-open paths: a junk RRSIG suppresses the unsigned probe; a signed CNAME to an unsigned target is classified `Insecure` without an authenticated DS denial; strict mode serves `Indeterminate` after a failed probe; DNAME and QTYPE=CNAME are misclassified. | An on-path attacker can sometimes prevent validation while the resolver returns unvalidated data instead of SERVFAIL. |
| **P1-2** | [V] | `crates/sito-dnssec/src/lib.rs:1000-1042, 1883-2036, 2404-2529` | DNSSEC key/chain fetching has count limits but no overall wall-clock deadline or global per-query work cap; each signer/fetch has its own timeout. | One client query can pin a worker for minutes and amplify upstream traffic; repeated failures have only a short probe backoff. |
| **P1-3** | [V] | `crates/sito-ha/src/slave/worker.rs:1022-1091`, `crates/sito-ha/src/slave/state.rs:295-302` | Slave session loop has no master heartbeat/read deadline. It waits on `ws_stream.next()` forever and reports `Synced` whenever the state was set. | A network partition or hung master leaves `/health` green and the slave serving stale shared config indefinitely. |
| **P1-4** | [V] | `crates/sito-ha/src/slave/worker.rs:1252-1316`, `worker.rs:1342-1361`; `crates/sito-api/src/state.rs:57-109` | Same-version ACK trusts the local watermark and treats “version/hash applied previously” as proof the local config still matches the master bundle; the file watcher can edit shared fields without updating the watermark. | A slave whose config was edited/reverted while stopped or while running serves a different configuration while reporting `Synced`. |
| **P1-5** | [V] | `crates/sito-ha/src/master/coordinator.rs:1258-1273` | A delayed same-version fork ACK is ignored if the master has published a newer bundle, because `active_push_matches()` only compares the single current push. | The slave latches the fork and refuses pushes, but the master reports `diverged: false`; the operator loses the diagnostic. |
| **P1-6** | [V] | `crates/sito-api/src/state.rs:167-225`; `crates/sito-ha/src/bundle.rs:295-319`; `crates/sito-ha/src/transport/mod.rs:18-28` | `publish_bundle()` uses `sanitize_config_for_bundle(...).unwrap_or_default()` and returns `()`; publish failures are logged but not propagated. Outbound bundles are not checked against the 1 MiB WebSocket limit. | A master can report success while slaves never receive the config; an oversized bundle is persisted and then rejected by every slave forever. |
| **P1-7** | [V] | `crates/sito-filter/src/engine.rs:1080-1140`; `crates/sito-filter/src/parser.rs:1000-1141`; `crates/sito-filter/src/structures/compiled.rs:378-386` | Parser/compiler budgets are enforced after every list is parsed and materialized. There is no line-length cap, substring/prefix length cap, or total parsed-byte budget. Aho-Corasick/prefix structures have no equivalent limits. | A hostile 64 MiB list with one huge line can allocate hundreds of MB and multi-GB automata, aborting the daemon despite `max_rules`/`max_list_bytes`. |
| **P1-8** | [V] | `crates/sito-filter/src/subscription.rs:590-627`; `crates/sito-filter/src/engine.rs:983-991, 1213-1267` | Empty/zero-yield “successful” list responses are accepted. `reload_with_config()` sets `apply_drop_guard=false`; `count == 0 && failed_lists.is_empty()` publishes an available empty snapshot. | A CDN error page, empty 200, or compromised list host can replace all rules with an empty snapshot; `fail_closed` does not trigger because the snapshot appears available. |
| **P1-9** | [V] | `crates/sito-filter/src/parser.rs:593-636`; `crates/sito-rewrites/src/table.rs:320-347`; `crates/sito-clients/src/registry.rs:214-224`; `crates/sito-transport/src/doh.rs:313-315` | `$dnstype`/`$denyallow` drop invalid tokens and keep the rest; rewrite `exception_clients` trusts an unauthenticated DoH-path/SNI `ctx.id` whenever `client_name` is set; DoH injects raw path IDs. | Malformed rules can be wider than intended; a client at a configured IP can spoof a rewrite exception with `/dns-query/<exception-name>`. |
| **P1-10** | [V] | `crates/sito-transport/src/doq.rs:82-89, 177-223` | DoQ sets only idle timeout and 100 bidi streams. Quinn defaults to 1.25 MiB per stream and `VarInt::MAX` per connection; rate limiting happens after the full body is read and a task is spawned per stream. | ~256 connections × 100 streams × 1.25 MiB can buffer tens of GiB; a single IP can create ~25k stream tasks before spending a token. |
| **P1-11** | [V] | `crates/sito-transport/src/doh.rs:221-245, 347-354, 437-476` | The DoH route extracts `body: Bytes` before the rate check; there is no global request semaphore or lowered HTTP/2 stream cap. | 256 connections × up to 200 H2 streams × 65,535 bytes can buffer ~3.3 GiB before a 429. |
| **P1-12** | [V] | `crates/sito-transport/src/acme.rs:443-462`; `crates/sito/src/server.rs:1485-1582` | Challenge selection chooses TLS-ALPN-01 whenever any acceptor exists, even when no listener serves TCP 443; there is no fallback to HTTP-01. Only the DoH TLS manager is reloaded after ACME issuance; DoT/DoQ/DoH3 keep static certs. | A DoT-only/custom-DoH-port deployment selects an impossible challenge and retries forever; DoT/DoQ/DoH3 serve stale certs, and a restart reverts DoH to static material. |
| **P1-13** | [V] | `crates/sito/src/pipeline.rs:82-101, 167-177, 1682-1691`; `crates/sito-cache/src/cache.rs:221-250`; `crates/sito-transport/src/udp.rs:199-203` | Forced DO upstream adds an OPT; `strip_dnssec_records` never removes OPT or restores the client’s question/flags. Cache hits clone the stored question and only replace the ID. | Non-EDNS clients can receive OPT (RFC 6891 violation); cached question case/RD/DO/CD can be wrong; upstream EDNS cookies/NSID can leak to other clients. |
| **P1-14** | [V] | `crates/sito-transport/src/doh.rs:320-332`; `crates/sito-transport/src/doh3.rs:502-516` | DoH/DoH3 response encoding has no 65,535-byte cap; only requests are capped. | Large answers violate `application/dns-message` framing and consume unbounded HTTP/QUIC bandwidth; no TC fallback. |
| **P1-15** | [V] | `crates/sito-api/src/handlers/auth_handlers.rs:265-313`; `crates/sito-api/src/auth/manager.rs:2320-2423` | TOTP setup/enable requires only an Admin session; it replaces an existing TOTP secret and backup codes without the current password or current TOTP code. Disable requires re-auth, enable does not. | A stolen Admin session can re-enroll attacker-controlled 2FA and lock the real admin out; with a known password, it becomes persistent takeover. |
| **P1-16** | [V] | `crates/sito-api/src/ui/handlers.rs:1731-1746, 2177-2345` | The wizard is re-openable by any Admin after setup; `/ui/wizard/complete` calls `update_user_password_tracked()` without the current password or TOTP. | A stolen Admin session can reset the admin password to a known value and re-apply config without re-auth. |
| **P1-17** | [V] | `contrib/install.sh:395, 584` | Installer replaces the binary with `cp -f` while the service may be running; rollback also uses `cp -f`. Linux returns `ETXTBSY`. | The documented one-line upgrade fails on a live install; failed-health rollback cannot restore the backup. |
| **P1-18** | [V] | `crates/sito-cache/src/cache.rs:24-29, 602-617` | `build_cache()` never calls `support_invalidation_closures()`. Moka requires it for `invalidate_entries_if()`; the code ignores the error with `let _ =`. Only `invalidate_domain(".")` works via flush. | API/UI “invalidate domain” reports success but leaves cached entries; non-root invalidation is a no-op. |
| **P1-19** | [V] | `crates/sito-stats/src/db.rs:30-38, 310-345, 605-608, 1232-1251` | `stats_hourly` permanently retains client IPs, client names, and full domains; retention deletes only `query_log`. Clearing query logs folds all rows into rollups and does not vacuum or securely erase. | “90-day retention” leaves identifiable browsing history forever and grows without bound; “clear log” does not erase on-disk history. |
| **P1-20** | [V] | `crates/sito-api/src/auth/manager.rs:2065-2110`; `crates/sito-api/src/auth/lockout.rs:18, 77-90` | Login accepts unbounded username/password strings; the full username becomes a lockout-map key. At 10k keys, eviction can remove an active lockout. | Pre-auth memory/CPU DoS and a way to evict a target’s lockout by spraying usernames. |
| **P1-21** | [V] | `.github/workflows/release.yml:3-6, 41-78, 135-143`; `.github/workflows/ci.yml:115, 130, 146` | Release validates only the version string; it does not require the tagged commit to be on `main`, tested, or security-checked. CI skips tests/clippy/fmt on pushes to `main`. | A broken/compromised tag can be signed and published; post-merge regressions are not caught. |
| **P1-22** | [V] | `contrib/install.sh:335-369`; `docs/security-audit.md:31`; `docs/installation.md:104` | Installer signature verification defaults to `SITO_REQUIRE_SIGNATURE=0`; if assets/cosign are missing it warns and continues with same-origin SHA-256. Docs say signed archives are verified. | A release-channel attacker who removes `.sig`/`.pem` downgrades verification to a checksum from the same channel. |
| **P1-23** | [V] | `crates/sito-stats/src/db.rs:532-536`; `crates/sito-api/src/ui/handlers.rs:336-399, 493-497`; `docs` dashboard polling | Query-log pages compute `COUNT(*)` over the whole filtered table every 3 seconds and discard `total_count`; dashboard polling runs ~9 aggregate scans every 5 seconds with no cache. | Authenticated users can saturate SQLite and starve the single query-log writer; this is a realistic self-DoS. |
| **P1-24** | [V] | `crates/sito/src/server.rs:1154-1284`; `crates/sito-stats/src/writer.rs:36-62` | Retention is one large `BEGIN IMMEDIATE` transaction with full scans; the writer has a 10s busy timeout and drops batches after three retries. Retention never runs at startup and consumes the first interval tick. | A first large sweep can hold the write lock for minutes, dropping query-log batches; frequent restarts mean retention never runs. |
| **P1-25** | [V] | `crates/sito-upstream/src/bootstrap.rs:134-141`; `crates/sito-upstream/src/manager.rs:985-986`; `docs/security-audit.md:3-9` | Bootstrap and health-probe queries do not set RD=1; bootstrap answers are accepted without the SSRF denylist; re-resolution serves unexpired cache and does not force-refresh on failure. | Hostname upstreams may fail to bootstrap, probes can falsely mark healthy servers down, and a compromised bootstrap can point plain upstreams at private/metadata targets. |
| **P1-26** | [V] | `crates/sito/src/pipeline.rs:1276-1312`; `crates/sito-api/src/config_apply.rs:455-499` | Filter engine is swapped before the runtime config snapshot. When enabling filtering, queries read the old `filtering.enabled=false` and skip the new rules until `runtime.replace()`; if a later hook fails, the filter snapshot is changed but the config is not. | A filter-enable window bypasses filtering; a failed apply leaves components inconsistent. |
| **P1-27** | [V] | `crates/sito-api/src/config_apply.rs:476-482`; `crates/sito/src/pipeline.rs:1103-1158, 1643-1698` | DNSSEC validator is swapped before the cache flush; in-flight queries/prefetch can insert old-policy validation status after the flush. Cache entries carry status but no DNSSEC policy generation. | A Secure decision under a removed anchor or a log-only Indeterminate can survive a policy change. |

### 4.3 P2 — medium

| ID | Area | Finding |
|---|---|---|
| **P2-1** | DNSSEC | NSEC3 wildcard NODATA returns `Secure` before checking whether the next-closer covering record is Opt-Out; RFC 5155 §9.2 requires AD=0. |
| **P2-2** | DNSSEC | Three separate chain walkers (`fetch_zone_chain`, `probe_delegation`, `keys_for_zone`) duplicate DS/DNSKEY logic and have divergent checks. |
| **P2-3** | DNSSEC | Persisted `chain_cache` Signed/Unsigned statuses have no integrity protection; local write access can inject false statuses. |
| **P2-4** | DNSSEC | Signed-zone evidence can outlive the DS/chain TTL; a zone that removes its DS can stay “signed” for days. |
| **P2-5** | DNSSEC | A truncated delegation walk marks the name Signed without authenticating remaining cuts. |
| **P2-6** | DNSSEC | `with_trust_anchors()` replaces anchors but does not populate `anchor_zones`; non-root anchor sets cannot cold-start. |
| **P2-7** | Upstream | A bare `https://host` DoH upstream posts to `/`, not `/dns-query`; the parsed default path is discarded. |
| **P2-8** | Upstream | DoH client leaves reqwest system proxy auto-detection enabled, bypassing `resolve_to_addrs` pinning. |
| **P2-9** | Upstream | Plain UDP reads one datagram; a mismatched ID/question aborts instead of continuing to the deadline. |
| **P2-10** | Upstream | FORMERR/BADVERS and EDNS failures are not retried; no EDNS fallback. |
| **P2-11** | Upstream | No ALPN verification for DoT/DoQ; DoQ does not reconnect on stream-open failure. |
| **P2-12** | Upstream | `timeout_ms`/`pool_size` have no upper bounds; target parsing is not validated in `UpstreamConfig::validate()`. |
| **P2-13** | Transport | ACME account credentials are written non-atomically; a corrupt `account.json` blocks renewal; configured directory is ignored when restoring. |
| **P2-14** | Transport | Certificate/key pair is never checked for matching public keys; ACME writes key then cert, so a watcher can install a mismatched pair. |
| **P2-15** | Transport | Accept loops tight-spin on `EMFILE`/`ENFILE`; no backoff. |
| **P2-16** | Transport | TCP/DoT/DoH have global-only connection caps and no max lifetime; slowloris can hold all slots. |
| **P2-17** | Transport | DoH3 has no total request deadline; timeout resets per chunk. |
| **P2-18** | Transport | Listeners/pipeline accept QR=1 messages and multi-question queries; a DoQ test legitimizes 300 questions. |
| **P2-19** | Transport | Rate limiter keys full IPv4/IPv6 addresses, not prefixes; eviction is arbitrary, not LRU. |
| **P2-20** | Transport | ACME HTTP-01 listener has no connection/rate/timeout limits and is advertised even if bind failed. |
| **P2-21** | Transport | DoQ/DoH3 acquire connection permits before handshake and detach connection tasks; shutdown cannot await them. |
| **P2-22** | Cache | TTL policy changes (`min_ttl`, `max_ttl`, negative, stale) do not re-clamp or flush existing entries. |
| **P2-23** | Cache | Public cache helpers (`get`, `get_stale`, `insert`) use name-only keys/AD-derived status and can cross-serve DO/CD/ECS or mark unvalidated data Secure. |
| **P2-24** | Filter | Group compile-budget failure publishes no group snapshot, dropping all group rules including non-regex/custom rules; a test asserts this fail-open. |
| **P2-25** | Filter | Group standard `$dnsrewrite` can override a global block; group `$important @@` cannot override a global `$important` block. |
| **P2-26** | Filter | Group snapshot rebuild can race with list reload and publish a snapshot compiled from stale list rules. |
| **P2-27** | Filter | Huge `refresh_hours` can panic on `Instant + Duration` overflow; config validation only rejects zero. |
| **P2-28** | Filter | `apply_content_forced` is never used by production refresh, so a legitimate >50% shrink is rejected forever. |
| **P2-29** | Filter | Disk cache identity is keyed only by list name, not URL; changing URL while keeping the name serves stale/foreign rules. |
| **P2-30** | Filter | RouterOS client uses env proxies, silently falls through when `token_env` is missing, and reads unbounded error bodies. |
| **P2-31** | Rewrites | Local `TXT` rewrites do not split into 255-byte character-strings; long TXT values fail encoding. |
| **P2-32** | Rewrites | Local rewrites are type-exact; an A-only local name leaks AAAA to upstream. |
| **P2-33** | Rewrites | Invalid rewrite `type`/`answer`, invalid client IDs, and unknown group references are silently accepted and inert. |
| **P2-34** | Clients | Positive MAC cache is 60s and not invalidated on ARP snapshot change; `normalize_mac` accepts junk containing 12 hex digits. |
| **P2-35** | Safe search | Safe search rewrites every qtype, not just A/AAAA; coverage is narrow and `safe.duckduckgo.com` CNAMEs to itself. |
| **P2-36** | Schedules | `0 9 * * *` matches one second per day, not the 09:00 hour; IANA timezones are unsupported. |
| **P2-37** | Parental/services | Built-in data is 40 adult + 40 gambling domains and 35 tiny service maps; manifest is stale; not real parental protection. |
| **P2-38** | API | Unknown TOML keys/sections are silently ignored; a typo can reset runtime sections to defaults and still return 200. |
| **P2-39** | API | Restart-only fields are accepted by `PUT /config`; changing `server.role` applies live, changing `data_dir` can brick startup; `dns.tls`/`web.acme_*` missing from matrix. |
| **P2-40** | API | Every settings write uses `FilterApply::Sync`; a blocklist outage rejects unrelated cache/DNSSEC/upstream changes. |
| **P2-41** | API | Filter-list rename/delete and group delete do not check references; clients can point at a missing group and silently lose policy. |
| **P2-42** | API | Invalid rewrite entries are persisted and returned 200 but skipped by `RewriteTable::new`. |
| **P2-43** | API | Filter refresh/update-all do not take `apply_lock`; a concurrent config apply can be overwritten in the filter engine. |
| **P2-44** | API | OpenAPI has no `securitySchemes`, 34/59 operations lack security, 3 real paths are missing, 6 tags are undeclared. |
| **P2-45** | API | `no-store`/`Vary: Cookie` omits authenticated filtering/upstream/rewrites/cache/status/metrics GETs. |
| **P2-46** | API | WebSocket querylog upgrade has no Origin check; `?token=` is accepted on any request with Upgrade headers. |
| **P2-47** | API | Updater advertises in-app apply on systemd where `ProtectSystem=strict` prevents replacing the binary; only Docker is detected/disabled. |
| **P2-48** | API | `version_comparison_unknown` is ignored; UI/CLI report “up to date” for non-semver versions. |
| **P2-49** | API | A present signature with no verifier is skipped when `required=false`, contradicting docs; missing `.pem` also skips. |
| **P2-50** | API | Updater has no lock/rollback; downloads into `/tmp` with default permissions; no old-binary backup. |
| **P2-51** | API | Filter subscription URLs are rendered in full to Viewer sessions; URLs may contain credentials/tokens. |
| **P2-52** | API | UI has no TOTP enrollment route; settings hints are stale; wizard checkboxes cannot disable already-true cache/filtering; upstream weight is collected and discarded. |
| **P2-53** | API | Backup tar writes config at 0644; `get_config`/backup silently return defaults on read/serialization failure; backup metadata version is not validated. |
| **P2-54** | API | Status-code drift: creates return 200, TOTP challenge 200 vs documented 202, `update_user` always reports `totp_enabled: false`, duplicate group 400 vs 409. |
| **P2-55** | Stats | `error_queries` counts NXDOMAIN as an upstream error. |
| **P2-56** | Stats | Upstream metrics attribute failover time to the winner, count only the final error, and keep stale health series after config removal. |
| **P2-57** | Stats | `ignore_stats` only suppresses query counters; cache misses, identified clients, upstream RTT/errors/health, stale/DNSSEC/DoH-bypass counters still include the client. |
| **P2-58** | Stats | IPv4-mapped IPv6 addresses are anonymized as IPv6 /56 and collapse to `::`, merging all IPv4 clients. |
| **P2-59** | Stats | Anonymization is forward-only; existing query-log rows and rollups are never masked; client names/domains remain. |
| **P2-60** | Stats | Every query clones the full `QueryLogEntry` for live-tail broadcast even with no subscribers. |
| **P2-61** | Stats | Retention collects top lists for every affected hour into memory before writing; a large first sweep can OOM. |
| **P2-62** | Metrics | Every query observation locks a per-verdict mutex; module docs claim no global exclusive lock. |
| **P2-63** | Metrics | `cache_size_bytes` is not updated on flush/invalidate; `dnssec_bogus` is unbounded; filter rule gauge drifts after scheduled refresh. |
| **P2-64** | Tests | No fuzz harness/CI, despite release notes and audit claims; `fuzz/Cargo.toml` is absent. |
| **P2-65** | Tests | Core query-log filters (`from`/`to`/`qtype`), migration upgrades, partial-hour pruning, clear→vacuum, concurrent retention, mapped IPv6, and 1M-row scale are untested. |
| **P2-66** | Tests | Several tests assert unsafe behavior: group snapshot vanishes on budget failure; Indeterminate served in strict mode; Insecure CNAME without DS denial; DoQ accepts 300-question query. |
| **P2-67** | Ops | Docker compose publishes plaintext admin UI on all interfaces; fresh bind mount `./config` is root-owned and the container cannot write setup config. |
| **P2-68** | Ops | HA compose RouterOS DHCP option hex is odd-length/invalid; LAN topology is hardcoded. |
| **P2-69** | Ops | No behavioral installer test; CI only shellchecks. |
| **P2-70** | Ops | No container vulnerability scan or cosign signature for the image; release image built with stub binaries and smoke-tested only with `--version`/`check-config`. |
| **P2-71** | Ops | Config reference/example drift: auto-migrations claim false, metrics “always exposed” false, per-list `refresh_hours` omitted, `[dns.tls]` omitted, stale 1.9.2 text and non-default example values. |
| **P2-72** | Ops | `docs/configuration-reference.md` says `tls.cert` protects the Web UI; admin UI is plain HTTP and never uses the DNS TLS cert. |
| **P2-73** | Ops | Policy matrix says schedules use UTC; default is host-local. |
| **P2-74** | Ops | Migration guide says `--no-setup` leaves `admin/adminadmin`; actual behavior generates a random password and rejects bootstrap login. |
| **P2-75** | Ops | HA/API/metrics curl examples omit authentication; `/metrics` defaults to authenticated. |
| **P2-76** | Ops | README presents v1.0 benchmark numbers as v1.9 and claims weekly CI “gates performance”; weekly bench has no threshold. |
| **P2-77** | Ops | Docs say TOTP backup codes are Argon2id; implementation uses BLAKE3. |
| **P2-78** | Ops | Release notes still tell users to run `fuzz/Cargo.toml`; harness was removed post-v1.9.3. |
| **P2-79** | Ops | Config-reference checker only checks key presence, not defaults/types/nested structs; CI green while docs are wrong. |
| **P2-80** | Ops | Quickstart pipes mutable `main` script to root and recommends mutable `latest` image tags. |
| **P2-81** | Ops | README says certificate pinning is mandatory; `allow_unpinned_tls`/`allow_insecure_ws` are explicit opt-outs. |
| **P2-82** | Ops | No `EnvironmentFile` in the systemd unit for HA `${SECRET:...}` values; hardening lacks `PrivateTmp`, `ProtectProc`, `RestrictNamespaces`, `RestrictSUIDSGID`, `LockPersonality`, `SystemCallArchitectures`, `UMask`. |
| **P2-83** | Ops | `sito update` rewrites the executable 0755 and loses file capabilities/xattrs. |
| **P2-84** | Cache/transport | Cache hits return stored question/RD; upstream OPT/EDNS options are replayed to unrelated clients. |
| **P2-85** | Core | `check-config` does not call the shared full validator; upstream target strings and `[integrations.lists]` semantics can pass preflight then fail startup. |
| **P2-86** | Core | `build_scoped_upstreams` silently omits a client scope on manager construction failure and falls back to global upstreams/shared cache; scoped settings are not validated. |
| **P2-87** | Core | `build_tls_acceptor` warns and returns `None` on cert/key failure; encrypted listeners silently disappear while startup continues. |
| **P2-88** | Core | `[dns.tls]` and `[web] acme_*` are missing from `restart_required_fields`; hot reload does not rebuild TLS/ACME. |
| **P2-89** | Core | Wizard deferred filter refresh failure leaves the engine with startup config; scheduler never retries the wizard’s lists; fail-closed SERVFAILs every query. |
| **P2-90** | Core | `--no-setup` prepares `users.toml` before acquiring the service lease; concurrent starts can rotate/print unusable passwords. |
| **P2-91** | Core | HA bundle is built from a second file read while the runtime uses the earlier parse; a config change during startup can publish a bundle the master is not running. |
| **P2-92** | Core | DoQ/DoH3 bind both wildcard families with `quinn::Endpoint::server`; IPv6 `IPV6_V6ONLY` default can make the second bind fail, and startup continues. |
| **P2-93** | Core | `Config::validate` does not check cross-section port conflicts, duplicate binds, empty `data_dir`, ACME domain validity, or rate-limit burst overflow. |
| **P2-94** | Core | `run_server_full` does not call `Config::validate` for programmatic configs; `rate_limit_per_ip * 2` can overflow. |
| **P2-95** | Core | Filter enabled with zero sources compiles an empty available snapshot and reports Ready; fail-closed does not trigger. |
| **P2-96** | Core | List warnings log full raw rules/lines; a huge list causes log flooding/disk DoS. |
| **P2-97** | Core | Runtime-list status keys are case-sensitive; `"Adult"` creates a duplicate and leaves `"adult"` marked bundled; `refresh_hours = 0` not validated. |
| **P2-98** | Core | Anti-bypass dataset has no manifest/checksum/version; `domain_count` ignores wildcard suffixes. |
| **P2-99** | Core | `MAC` positive cache 60s and stale after ARP snapshot change; malformed IDs become MAC identities. |
| **P2-100** | Core | `refresh_filtering`/UI update-all do not take `apply_lock`; concurrent apply can revert the live filter snapshot. |

### 4.4 P3 — low / cleanup

| ID | Area | Finding |
|---|---|---|
| P3-1 | Code | 28 Rust files >1,000 lines; largest: dnssec `lib.rs` 8,064, API auth manager 5,704, UI handlers 5,431, HA coordinator 3,450, HA worker 3,402, pipeline 3,255. |
| P3-2 | Code | 114 functions >100 lines; `DnsPipeline::handle` 669, `validate_response_inner` 585, `render_prometheus` 501, `run_server_full` 437, `start_doh3_listener` 395. |
| P3-3 | Code | Workspace production: 63 `unwrap`, 26 `expect`, 2 panic sites, 147 `let _ =`, 96 `.ok()`, 41 `unwrap_or_default`, 24 `#[allow]`. |
| P3-4 | Code | `sito-ha` has 20 `Mutex::lock().unwrap()` calls; poison would abort release. `pktinfo.rs` has 17 unsafe sites, blanket `clippy::all`/`pedantic` allow, no SAFETY comments. |
| P3-5 | Code | Dead/test-only APIs: `run_server`, `run_healthcheck` re-export, `Config::network_exposure_warnings`, `DnsPipeline::with_anti_bypass`, `extract_query_info`, `RewriteAction::SynthesizeAnswer`, `RuntimeLists::apply_content_forced`, `FilterStatus` external use, `MAX_REGEX_BATCHES`, `config_writer::save_config_atomic`, `Session::to_cookie_header`, `AuthManager::admin_count`. |
| P3-6 | Code | Duplicated logic: three DNSSEC chain walkers, TCP/DoT writer loops, DoH/DoH3 request parsing, DoQ/DoH3 cert polling, four TLS acceptor sets, three CIDR parsers, two suffix matchers, six `mock_context` helpers, 22 hardcoded `"1.2.1"` test fixtures. |
| P3-7 | Code | Unused dependencies: `sito-stats` declares `sito-core`; `sito-rewrites` declares `serde_json`/`thiserror`. `tokio full` used workspace-wide. `rust-version = "1.99.1"` is an exact pin, not a minimum. |
| P3-8 | Code | Hardcoded values: 20+ transport timeouts/caps, 16 DNSSEC policy constants, `0.0.0.0` ACME bind, `127.0.0.1:8080`/`:53` health probe, `admin@example.com`, `example.com`, `localhost.`, 3600000 repeated in SQL, `HOUR_MS` absent. |
| P3-9 | Code | `stats_watermark` is written but no production code reads it; `get_upstream_reports` duplicates snapshot/delta; `total_count` computed even when unused. |
| P3-10 | Code | `sito-rewrites` docs claim `/etc/hosts` parsing/synchronization and upstream exception lists; neither exists. `sito-transport` non-Unix fallbacks are unreachable due to `compile_error!`. |
| P3-11 | Tests | `test_retention_watermark_prevents_double_counting` would pass with a broken watermark; vacuum/WAL tests are filesystem/timing-sensitive; batching test never reaches threshold; 50k perf test uses `SITO_PERF_TESTS` while CI sets `SITO_BENCH_TESTS`. |
| P3-12 | Tests | `MockDnsServer` returns NXDOMAIN for known owner + unconfigured qtype; no TCP/EDNS/truncation/DNSSEC fidelity. 104 sleep sites remain. |
| P3-13 | Docs | `docs/audit.md` and `docs/audit2.md` lack historical banners; `docs/audit5.md` “docs truth pass” is incomplete. |
| P3-14 | Docs | `docs/dns-server-plan-detailed.md` advertises `DNSD__SECTION__KEY` env overrides that do not exist. |
| P3-15 | Docs | `docs/runbook-ha.md` says both sides support multiple pins (slave has one), resync returns 503 (returns 200), divergence clears on higher version (advisory stays), SAN only needed without pinning (CA+pinning always checks hostname). |
| P3-16 | Docs | `docs/installation.md` `sha256sum -c SHA256SUMS` fails unless all assets, including `sito.spdx.json`, are downloaded. |
| P3-17 | CI | `docs.yml` workflow_dispatch/merge_group diffs only `HEAD^..HEAD`; manual dispatch can skip checks. |
| P3-18 | CI | `cargo clippy` lacks `--locked`; security workflow only runs on dependency-path changes or weekly; no coverage tool/cargo-machete/udeps. |
| P3-19 | CI | `deny.toml` ignores `RUSTSEC-2026-0374` but cargo-deny reports `advisory-not-detected`; stale suppression. |
| P3-20 | Ops | Uninstall leaves cosign installed; installer proceeds without systemd; `setcap || true`; no uninstaller test. |
| P3-21 | Ops | `scripts/test-ha-ownership-root.sh` is root-gated and not in CI. |
| P3-22 | Ops | `fuzz/target` is 2.2 GB and root `target` 39 GB; `.opencode` 63 MB; `__pycache__` tracked/untracked artifacts. |
| P3-23 | Ops | Two systemd unit copies and two hook systems can drift. |
| P3-24 | Ops | `.dockerignore` may not exclude `fuzz/target`; add explicit exclusion. |
| P3-25 | Ops | HA compose hardcodes `192.168.1.10/11`, subnet, gateway, `eth0`; optional slave-2 commented. |
| P3-26 | Ops | Docker release image built with stub binaries; no real container start/healthcheck test. |

## 5. Prior-Audit and Documentation Truth Matrix

| Claim | Source | Verdict | Evidence |
|---|---|---|---|
| Overall readiness ~8/10 after audit 5 | `docs/audit5.md:108-123` | **False** | P0 ACME and P0 DNSSEC denial bypass, plus P1 HA/API/transport, remain. Current 4/10. |
| DNSSEC chain/denial fixed | Audit 3/4/5 | **Partial** | Chain walk exists, but ancestor-delegation denial and fail-open paths remain. |
| HA state/replication fixed | Audit 4/5 | **Partial** | Version/term/signature work is real; no master-loss timeout, watermark hides local drift, publish can fail silently. |
| Rate limiting shared per-IP | `docs/audit5.md:40` | **Partial** | Shared limiter exists; full-address keying, arbitrary eviction, post-body checks. |
| Cache flushes every filter reload | `docs/audit5.md:46-48` | **False as written** | Config/API paths flush; scheduled `reload_lists` does not. Filtering runs before cache, so limited bypass, but claim is overbroad. |
| `/metrics` unauthenticated | `docs/audit.md:64` | **False/outdated** | `metrics_auth` defaults true; handler authenticates Viewer. |
| TOTP backup codes Argon2id | `docs/security-audit.md:22-23` | **False** | BLAKE3 `b3:` digests with rationale; legacy Argon2 hashes refused. |
| Signed archives always verified by installer | `docs/security-audit.md:31` | **False** | `SITO_REQUIRE_SIGNATURE=0` default; missing assets fall back to SHA-256. |
| Fuzz harness exists/nightly fuzz works | `docs/audit5.md:41`, release notes | **False at HEAD** | `git ls-files fuzz` empty; nightly workflow absent; post-v1.9.3 CI removed it. |
| Config auto-migrations | `docs/configuration-reference.md:18` | **False** | `config_version != 1` is rejected; no migration. |
| `tls.cert` protects Web UI | `docs/configuration-reference.md:153` | **False** | Admin UI is plain axum HTTP; DNS TLS cert is separate. |
| Schedules use UTC | `docs/policy-matrix.md:52` | **False** | `clients.timezone` defaults `"local"`. |
| `--no-setup` leaves `admin/adminadmin` | `docs/migration-adguard.md:77` | **False** | Random password generated, printed once, loopback bind; `adminadmin` rejected. |
| Benchmarks are v1.9 | `README.md:24-26` | **False** | `docs/benchmarks.md` says numbers captured at v1.0.0. |
| Weekly CI gates performance | `docs/benchmarks.md:5-9` | **False** | `cargo bench` uploads estimates; no threshold/regression failure. |
| Docs/config truth pass complete | `docs/audit5.md:96-102` | **Incomplete** | ACME/TLS/metrics/HA/API/fuzz/benchmark drifts remain. |
| All GitHub Actions SHA-pinned | `docs/ci.md:275-300` | **True** | Verified all `uses:` full SHAs. |
| DoH body cap and redirect policy | `docs/audit5.md:52` | **True per request** | 65,535-byte cap, redirects disabled; pre-body buffering/global concurrency still missing. |
| Docker `/etc/sito` owned by nonroot | `docs/audit5.md:101` | **True** | Dockerfile chowns 65532. |
| Per-archive `.sha256` published | `docs/audit5.md:102` | **True** | Real v1.9.3 assets contain `.sha256`/`.sig`/`.pem`. |

## 6. Architecture Assessment

Strengths:
- Clear crate split and a real pipeline with cache, filter, rewrites, clients, DNSSEC, upstream, stats, HA.
- `RuntimeSnapshot` is a good idea; one query sees one config/clients/rewrites set.
- Filter engine has deterministic rule ordering, interning, suffix/prefix/AC/regex structures, and a drop guard.
- Transport implements all major DNS protocols, including DoH3/DoQ, with meaningful caps and timeouts.
- HA has signed/term-bound bundles, mTLS/pinning, and persisted state.
- API/auth has Argon2, TOTP, session epochs, CSRF, CSP, setup tokens, and restore caps.
- Tests are extensive (1,045 attributes, 0 ignored) and CI is SHA-pinned with release signing/SBOM.

Structural debt:
- Several files are de facto monoliths; security logic is harder to review than it should be.
- Config has two representations (typed and raw TOML) and multiple validators; `check-config`, startup, API, restore and HA do not use one path.
- DNSSEC has three chain walkers and two denial evaluators.
- Transport has four TLS acceptor managers built from the same cert, which causes stale-cert behavior.
- HA has duplicated state/watermark writers and secret stripping in three places.
- Filter status is not exposed outside the crate; degraded/dropped rules are invisible.
- UI handlers duplicate API logic and test fixtures.
- Error handling is inconsistent: many `let _ =`/`.ok()` on paths that affect security, persistence, or readiness.

## 7. Feature Policy for 2.0

| Feature | Decision | Reason |
|---|---|---|
| DNS filtering/cache | **Core, production-grade** | Primary purpose. |
| Encrypted DNS (DoT/DoH/DoQ/DoH3) | **Core, production-grade** | Selected by user; currently uneven. |
| DNSSEC | **Core, production-grade, fail-closed** | Selected; current denial/fail-open defects. |
| Web UI/REST API | **Core, production-grade** | Selected; auth/config/OpenAPI gaps. |
| HA | **Core, production-grade** | Selected; split-brain/watermark defects. |
| ACME | **Core, production-grade** | Selected; currently cannot issue. |
| Parental/service lists | **Core, production-grade** | Selected; must replace tiny bundled data or label experimental. |
| RouterOS | **Optional/experimental; remove from default build** | Not selected as core; unsafe proxy/token/error-body behavior and niche. |
| Native DNSCrypt | **Not core** | Already an external integration; keep `docs/dnscrypt.md` as a bridge guide. |
| Per-domain upstreams | **Core policy feature** | Part of client policy; must be validated and fail closed. |
| Updater/self-update | **Core ops feature** | Must work on shipped systemd/Docker or be disabled honestly. |
| OpenAPI/Swagger | **Core API contract** | Fix security schemes and route coverage. |
| Fuzzing/benchmarks | **Core quality gate** | Restore real fuzz targets and thresholded benches. |

## 7.1 Overengineering, Placeholders, Hardcoded Values, and Legacy Inventory

This is the explicit cleanup list for the refactor. Each item is either removed, wired, or documented as experimental.

**Overengineering / duplication to collapse**

| Item | Locations | Decision |
|---|---|---|
| Four TLS acceptor managers built from one cert | `crates/sito/src/server.rs:1485-1523` | Replace with one `TlsManagerSet`; WP-2.6. |
| Two config representations and multiple validators | `sito-core/src/config.rs`, `sito-api/src/config_validation.rs`, `sito/src/server.rs`, `sito/src/cli.rs` | One typed v2 config + one `validate_full`; WP-1.3. |
| Three DNSSEC chain walkers | `sito-dnssec/src/lib.rs:988-1045, 1883-2036, 2158-2320` | One `TrustChain` machine; WP-2.1. |
| Two denial evaluators with divergent rules | `nsec.rs`, `nsec3.rs`, `lib.rs:828-899` | One `DenialProof` engine; WP-2.1. |
| Duplicated TCP/DoT writer and DoH/DoH3 parser | `tcp.rs:145-188`, `dot.rs:183-225`, `doh.rs`, `doh3.rs` | Shared framing/request helpers; WP-2.6. |
| Three CIDR parsers and two suffix matchers | `filter/parser.rs`, `clients/registry.rs`, `rewrites/table.rs`, `parental.rs`, `services.rs` | Shared `IpNetwork`/`DomainSuffix`; WP-1.2. |
| Two atomic state writers and three secret-strip copies | `ha/coordinator.rs`, `ha/slave/state.rs`, `ha/bundle.rs`, `api/state.rs` | One `AtomicFile`/`SecretSanitizer`; WP-2.9. |
| Two hook systems | `.pre-commit-config.yaml`, `scripts/git-hooks` | Keep one; WP-1.9. |
| `stats_watermark` written but never read | `sito-stats/src/db.rs` | Delete or wire to retention; WP-2.12. |
| `RuntimeState` separate 225-LOC crate | `sito-runtime` | Keep if generation/apply grows; otherwise merge into `sito-core`; WP-1.4. |
| Six `mock_context` helpers / 22 `"1.2.1"` fixtures | `sito-api` test modules | Consolidate into `test_support`; WP-1.8. |
| `sito-test` 45 dependencies | `crates/sito-test/Cargo.toml` | Split harness/mocks; remove unused; WP-1.8. |

**Placeholders / dead / test-only APIs**

| Item | Location | Decision |
|---|---|---|
| `run_server`, `run_healthcheck` re-export | `sito/src/{server,lib,cli}.rs` | Remove or document test-only; WP-1.1. |
| `Config::network_exposure_warnings` | `sito-core/src/config.rs:224` | Wire to startup or delete; WP-1.1. |
| `DnsPipeline::with_anti_bypass` | `sito/src/pipeline.rs:679` | Test-only; delete; WP-1.1. |
| `extract_query_info` | `sito-proto/src/wire.rs:22` | Delete; WP-1.1. |
| `RewriteAction::SynthesizeAnswer` | `sito-core/src/verdict.rs:62` | Never constructed; delete; WP-1.1. |
| `RuntimeLists::apply_content_forced` | `sito-clients/src/runtime_lists.rs:239-242` | Wire force refresh or delete; WP-2.5. |
| `FilterStatus` external use | `sito-filter` | Expose via API/metrics; WP-2.3. |
| `MAX_REGEX_BATCHES` | `sito-filter/src/structures/compiled.rs` | Dead limit; delete or derive; WP-2.3. |
| `config_writer::save_config_atomic` | `sito-api/src/config_writer.rs` | No production caller; delete; WP-1.1. |
| `Session::to_cookie_header` | `sito-api/src/auth/session.rs:100-102` | Test-only; move behind cfg(test); WP-1.1. |
| `AuthManager::admin_count` | `sito-api/src/auth/manager.rs` | Test-only; delete; WP-1.1. |
| `verify_archive_checksum`/`extract_binary_from_archive` | `sito-api/src/updater.rs` | Test-only; move behind cfg(test); WP-1.1. |
| `HaError::Degraded` | `sito-ha/src/error.rs:34-35` | Never constructed; delete or use; WP-2.9. |
| `staging_config` unused fields | `sito-ha/src/slave/worker.rs:150-235` | Consume or delete; WP-2.9. |
| `fuzz/` empty harness | `fuzz/` | Restore or remove docs; WP-1.9. |
| `docs/dnscrypt.md` native future | docs | Keep as external bridge; mark not implemented. |

**Hardcoded strings / magic values to centralize**

- `UDP_RECV_BUFFER_SIZE=4096`, `RECV_ERROR_BACKOFF=10ms`, `MAX_PIPELINED_QUERIES=64`, TCP/DoT/DoH/DoH3/DoQ timeouts/caps (`sito-transport`).
- `MAX_WS_MESSAGE_SIZE=1 MiB`, `MAX_SLAVE_CONNECTIONS=64`, `MAX_PEER_VERSION_LEAD=1,000,000`, handshake 10s, queue 32, backoff 1–60s (`sito-ha`).
- `MAX_DNSKEYS=64`, `MAX_DS_RECORDS=64`, `MAX_RRSIGS=128`, `MAX_VERIFICATIONS=256`, key cache 4,096, signed zones 8,192, chain cuts 8, TTL 3,600, clock skew 300, RSA 2,048, NSEC3 iterations 150 (`sito-dnssec`).
- `MAX_REGEX_PATTERNS=10,000`, `MAX_REGEX_PATTERN_BYTES=4 MiB`, `MAX_REGEX_PATTERN_LEN=16 KiB`, `MAX_DFA_SIZE_BYTES=10 MB`, batch 128 (`sito-filter`).
- `DEFAULT_REWRITE_TTL=60`, `MAX_CNAME_DEPTH=8`, safe-search TTL 300, blocking TTL 10 (`sito-rewrites`/`pipeline`).
- `3600000` repeated in SQL; `HOUR_MS` absent (`sito-stats`).
- `127.0.0.1:8080`, `127.0.0.1:53`, `0.0.0.0:80`, `admin@example.com`, `example.com`, `localhost.`, `sito.pid`, `/var/lib/sito`, `/etc/sito/config.toml`.
- Test fixtures: `"1.2.1"` (22 occurrences), `supersecret-token-value`, `mikrotik_secret_token_12345`, `routeros-password`.

**Legacy / compatibility paths to remove in 2.0**

| Legacy path | Location | Decision |
|---|---|---|
| `?token=` query auth | `sito-api/src/auth/rbac.rs:131-152` | Remove; use cookie/Bearer. |
| Legacy `sito_session` cookie | `sito-api/src/auth/session.rs:184-197` | Remove after migration; only `__Host-`. |
| `[web] acme_*` aliases | `sito-core/src/config.rs:156-201` | Migrate to typed `[acme]`; remove after alpha. |
| `[dns.tls]` alias | `sito-core/src/config.rs:620-621` | Move to typed TLS; remove after alpha. |
| `config_version = 1` | `sito-core/src/config.rs:82-88` | Migrate to v2; reject v1 with tool. |
| `allow_unpinned_tls` without CA | `sito-ha/src/transport/mtls.rs:232-253` | Require CA or explicit `allow_no_verification`; remove ambiguous path. |
| Raw TOML `[web]`, `[auth]`, `[stats]`, `[ha]`, `[integrations]` | `sito-core/src/config.rs:145-201` | Type and validate; no warn-and-default. |
| Native DNSCrypt plan | `docs/dnscrypt.md` | Keep external bridge only. |
| RouterOS in default build | `sito-clients/src/routeros.rs` | Optional crate/feature only. |

## 7.2 Decision Register (Builder Calls)

A fresh reviewer flagged the following ambiguities. They are resolved here; implementation tasks must follow these decisions.

### D1 — Safety-gate exit criterion

Phase 0 must close **all P0** and **P1-1 through P1-18, P1-20 through P1-22, and P1-25 through P1-27**. P1-19, P1-23, and P1-24 are operational/privacy issues that can be deferred to Phase 2, but they must be listed as residual risks in the 1.9.4 release notes and the gate cannot be called “production-ready” for stats/querylog until they close. Phase 0 is **3–4 weeks**, not 2–3. **Phase 0 ships as 1.9.4**: a non-breaking security patch, not a production-readiness declaration.

### D2 — Phase 0 is a patch, not the 2.0 interface

Phase 0 fixes use the smallest local change on the current tree. Names such as `AdmissionController`, `TlsManagerSet`, `ClientIdentity`, `ValidationDecision`, and `PublishOutcome` in Phase 0 tasks are conceptual; only the minimal internal helper needed for the fix is introduced. The full interfaces land in Phase 1/2. No public API/config stability is promised for Phase 0 helpers.

### D3 — Branch and release model

- **Phase 0 is one PR to `release/1.9.x` and ships as 1.9.4.** “Non-breaking” means no config schema v2, no API v2, no SQLite schema break, and no HA protocol break. Security behavior changes (fail-closed DNSSEC/filtering, ACME bootstrap handling, required signatures) are patch-level and must be called out in the 1.9.4 release notes.
- After 1.9.4, merge `release/1.9.x` into `main` so Phase 1 starts from the safety fixes. `main` becomes **2.0.0-alpha.1** at that point.
- **Phase 1, Phase 2, and Phase 3 are one PR each**, targeting `main` in order, and all ship in the 2.0 line.
- The 2.0 release gate requires green CI/security on `main`; the 1.9.4 gate requires green CI/security on `release/1.9.x`. The release workflow must encode the branch-specific gate.

### D4 — Config v1→v2 migration

- `sito config migrate --from v1 --to v2 --backup` is the explicit tool. The installer and Docker entrypoint run it automatically only when `config_version = 1`; `--no-migrate` is available for controlled upgrades.
- Migration is **behavior-preserving**: every known v1 key/value is copied, even when the new 2.0 default differs. A report lists moved/removed/dead keys and suggests safe defaults.
- New installs use the 2.0 safe defaults. Existing installs keep old effective behavior unless they pass `--adopt-safe-defaults`.
- Unknown keys are an error by default. `--ignore-unknown-keys` drops them with a machine-readable report; it never silently preserves or silently drops them.
- A checked-in `config-v1-to-v2-map.toml` enumerates every serde field and is verified by a test. Missing map entries fail CI.
- The v2 schema is frozen at WP-1.3. Phase 2 additions must be optional fields with defaults or a v2.1 migration.
- Installer rollback restores both the binary and the config backup.

### D5 — Unknown-key and typo policy

Startup, check-config, API writes, restore, and HA apply all reject unknown keys/tables by default. The migration tool is the only path that accepts them, and only with an explicit flag. This prevents a typo like `[upsteam]` from silently reverting to defaults.

### D6 — SQLite migration and PII policy

- Startup checks the schema. A v1.9 database requires `sito db migrate` or `SITO_DB_AUTO_MIGRATE=1` (set by the Docker entrypoint); the migration always backs up `stats.db` first.
- Migrations are forward-only. Rollback means restoring the backup. 2.0 refuses to start on a newer unknown schema.
- Rollup client IPs become keyed BLAKE3 hashes using a per-install salt in `<data_dir>/stats-salt` (0600). Unkeyed IPv4 hashes are reversible and are not acceptable.
- Client names are optional (`stats.rollup_client_names = false` by default); domains are retained for `stats.rollup_retention_days` (default 365) and then deleted.
- “Clear query log” deletes `query_log` and `stats_hourly` by default. `--keep-aggregates` preserves rollups and is documented in the API/CLI.
- Existing rollups are hashed during migration. Existing raw query-log rows are not retroactively anonymized unless the operator runs `sito db anonymize --all`; docs state the forward-only behavior.
- `secure_delete=ON` and a vacuum/incremental-vacuum policy after large clears are part of WP-2.12.

### D7 — HA protocol v2 upgrade/downgrade

- Upgrade order: **master first**, then slaves. A v2 master rejects v1 slaves with `protocol_mismatch` and a readiness reason; a v2 slave rejects a v1 master the same way. The cluster is upgraded one node at a time with replication intentionally degraded during the window.
- Downgrade is **not supported in place**. Restore the pre-upgrade backup of `config.toml`, `ha_state.toml`, `ha_watermark.toml`, and certificates, then run 1.9.3.
- `ha_state.toml`/`ha_watermark.toml` carry `protocol_version = 2`; v1 files are refused with migration instructions rather than guessed at.
- Shared config fields on a slave are read-only. A local edit to a shared field marks the slave `Degraded` and requires a full resync; node-local fields remain editable.

### D8 — HA publish failure semantics

- A local config apply that passes validation and persists locally **does not roll back** if HA publish fails. The master keeps the new local config, sets HA readiness false, returns `ha_publish: { status: "failed", error, retry_at }` in the API (`retry_at` is present only when this failure started a new retry loop; it is omitted while an existing loop owns the backoff schedule), and retries with backoff.
- `NoSlaves` is ready by default (`ha.require_slaves = false`). One missing slave among several marks `Degraded`; `ha.require_all_slaves = true` makes it not-ready.
- An **oversized bundle** is an apply error and rolls back because the config cannot be replicated.
- `/health` is false when `ha.require_slaves`/`require_all_slaves` is violated or when the local node is a slave that lost its master.

### D9 — DNSSEC modes and Opt-Out

- Modes: `disabled`, `log_only`, `validate` (strict default). `permissive` is a legacy alias for `log_only`; `strict` is a legacy alias for `validate`.
- `Secure`: AD=1, serve.
- `Insecure`: AD=0, serve (authenticated unsigned/opt-out delegation).
- `Bogus`: SERVFAIL in `validate`; AD=0 answer in `log_only`; bypass in `disabled`. CD=1 bypasses SERVFAIL.
- `Indeterminate`: SERVFAIL in `validate`; AD=0 answer in `log_only`; never cached as servable in `validate`.
- NSEC3 Opt-Out is `Insecure(InsecureProof::Nsec3OptOut)`, not a fifth top-level decision. Opt-Out NXDOMAIN/wildcard NODATA is Insecure, never Secure/AD=1.
- Cache entries store the decision plus `DnssecPolicyEpoch`; a policy change invalidates them.

### D10 — Identity trust table

| Identity source | Authenticated? | May match `$client` / rewrite exception? |
|---|---|---|
| IP/CIDR configured by operator | Yes, network identity | Yes |
| MAC from ARP with `clients.trust_arp = true` | Yes, if enabled | Yes |
| MAC from RouterOS verified lease (optional feature) | Yes, only with TLS verification | Yes |
| TLS SNI | No (unless future mTLS client cert) | No |
| DoH path label | No | No |
| Secret-gated client identity | Yes | Yes |
| RouterOS hostname without verified lease | No | No |

IP/CIDR is the normal LAN identity. SNI/DoH path may be used for display/statistics but never to bypass policy.

### D11 — API v2 restart-only and v1 compatibility

- Restart-only changes return **409 Conflict** with `restart_required` and are **not persisted**. A `GET /api/v2/config/restart-required` preview lists fields. Operators edit the file and restart, or use the installer.
- Restart-only fields: `server.role`, `server.data_dir`, `server.instance_name`, `[dns.tls]`, `[acme]`, `web.enabled/bind/port`, and server identity/format.
- `/api/v2` is canonical. `/api/v1` remains as a compatibility facade for **one 2.0 alpha** and is removed at 2.1.0. `docs/api-v1-compat.md` lists every preserved path; OpenAPI marks them deprecated.
- WebSocket auth requires cookie/Bearer + Origin; `?token=` is removed.

### D12 — ACME first-boot matrix

| Deployment | First boot | Renewal failure | Expired |
|---|---|---|---|
| Static cert only | Serve static | Warn/not-ready at expiry | Not-ready |
| ACME-only, no cert | DNS listeners bind; encrypted listeners disabled unless `acme.allow_bootstrap_cert = true`; admin loopback; ACME challenge on 80/443 | Keep current cert until expiry; degraded at 30 days; not-ready at expiry | Not-ready; no self-signed fallback |
| ACME + static | Static serves until real cert; ACME order starts | Keep static/current; degraded | Not-ready |
| No 80 and no 443 challenge path | Readiness false `acme_challenge_unavailable`; setup can complete; encrypted listeners disabled | Same | Same |

`acme.allow_bootstrap_cert = false` by default. Bootstrap certs are never used for normal DoH/DoT unless explicitly opted in. Cert content reload is hot across all transports; cert path/domain changes are restart-only.

### D13 — Updater, systemd, and Docker admin binding

- In-app `sito update` apply is disabled on systemd when the executable directory is read-only/`ProtectSystem=strict`, and on Docker. `--check` still works. The UI shows “use the installer/package manager”; no privileged helper is added in 2.0.
- The installer is the supported upgrade path: stop, atomic replace, start, health check, rollback.
- Container listens on `0.0.0.0:8080` internally; compose publishes `127.0.0.1:8080:8080` on the host. The healthcheck uses the container loopback. Docs explain LAN exposure and SSH tunneling.

### D14 — Test evidence and manual gates

- Every P0/P1 has a named failing-first test in its WP. `docs/audit6-test-matrix.md` maps finding ID -> test name -> command -> evidence and is checked in release PRs.
- Network/hardware-dependent gates (ACME staging, real signed zone, 24h fuzz, benchmark baseline, HA lab, installer E2E) run as a release checklist with recorded logs, not as flaky PR CI jobs.
- `scripts/check-error-swallowing.sh` enforces a reviewed allowlist for `let _ =`/`.ok()`; every remaining site has a reason in `docs/audit6-best-effort.md`.

### D15 — Parental/service lists and RouterOS

- Parental/service lists are **core production-grade** in 2.0. Require a maintained external source with license, version, checksum, and update pipeline; bundled data remains a clearly labeled fallback. If no licensed source can be secured, the feature is descoped to experimental and the user must approve that change before 2.0.
- RouterOS moves to optional `sito-routeros`; if built, it must meet the same security bar (no env proxy, verified lease, capped error body, no silent token fallback).

---

# Part II — 2.0 Target Design

## 8. Design Principles

1. **One source of truth per concern.** One config validator, one runtime generation, one DNSSEC decision model, one filter status, one HA session state machine.
2. **Stage, then publish.** Compile/validate everything before swapping any live component. A failed apply leaves the old generation intact.
3. **Provenance is explicit.** Client identity records whether it came from IP, SNI, DoH path, secret, MAC, or RouterOS, and whether it is authenticated. Policy rules may only use authenticated identity for secret/client exceptions.
4. **Fail closed for security, fail visible for operations.** No silent fallback on DNSSEC, TLS/ACME, empty filter lists, per-client upstreams, or config validation.
5. **Bound every unauthenticated resource.** Connection, stream, request, body, task, queue, memory, compile, and fetch budgets are acquired before work, not after.
6. **No giant files.** Split by responsibility; pipeline stages and validators become named modules with tests.
7. **Docs and code ship together.** Every config/API/behavior change updates the reference, OpenAPI, migration guide, and release notes in the same PR.

## 9. Target Module/Crate Map

Keep the crate split, but clarify responsibilities and optional features:

- `sito-core`: config schema v2, domain types, verdicts, traits, SSRF, error types. No raw TOML in hot paths.
- `sito-proto`: wire encode/decode, response shaping, EDNS helpers.
- `sito-runtime`: `RuntimeSnapshot`, `RuntimeGeneration`, staged apply.
- `sito-filter`: streaming parser, compile budgets, engine, status, subscriptions.
- `sito-dnssec`: one chain walker, one denial evaluator, key cache, deadline/budget.
- `sito-transport`: listeners, admission controller, TLS/ACME manager set.
- `sito-upstream`: transports, bootstrap, health, deadlines.
- `sito-cache`: key, entry, TTL policy, invalidation, generation epoch.
- `sito-clients`: identity/policy/schedules/parental/services/safe search.
- `sito-rewrites`: local records and exception policy.
- `sito-stats`: querylog DB/writer/retention/metrics.
- `sito-ha`: protocol v2, master/slave state machines, crypto.
- `sito-api`: REST/UI/auth/updater/config apply.
- `sito`: binary, CLI, pipeline stages.
- `sito-test`: harness, mocks, acceptance tests.
- `sito-routeros` (optional): RouterOS integration behind a feature/crate; not in default build.
- `sito-integrations` (optional): external DNS bridges (DNSCrypt) if ever native; not core.

## 10. Core Interfaces (New or Reworked)

These signatures are the contract for implementation. Names may be adjusted only if all tasks are updated.

### 10.1 Runtime generation and apply

```rust
pub struct RuntimeGeneration(u64);

pub struct ApplyPlan {
    pub config: Config,
    pub clients: ClientsConfig,
    pub rewrites: RewritesConfig,
    pub filter: Option<FilterSnapshot>,
    pub dnssec_policy: DnssecPolicy,
    pub cache_policy: CacheConfig,
    pub transport_policy: TransportPolicy,
}

pub enum ApplyError {
    Validation(ConfigError),
    Filter(FilterError),
    Upstream(UpstreamError),
    Tls(TlsError),
    Ha(HaError),
    GenerationConflict { expected: RuntimeGeneration, actual: RuntimeGeneration },
}

impl RuntimeState {
    pub fn generation(&self) -> RuntimeGeneration;
    pub async fn apply(&self, plan: ApplyPlan) -> Result<RuntimeGeneration, ApplyError>;
}
```

Apply is all-or-nothing for local components: no component swap until every stage succeeds. Queries read one `Arc<RuntimeSnapshot>` containing `generation`, config, clients, rewrites, filter, DNSSEC policy and cache policy. HA publish failure is **not** an `ApplyError` after the local config is valid and persisted; it sets HA readiness false and retries (see D8). The only HA apply error is an oversized/invalid bundle that cannot be replicated.

### 10.2 Client identity

```rust
pub enum IdentitySource {
    Ip,
    Cidr,
    Mac,
    TlsSni,
    DohPath,
    Secret,
    RouterOs,
}

pub struct ClientIdentity {
    pub ip: IpAddr,
    pub source: IdentitySource,
    pub authenticated: bool,
    pub name: Option<String>,
    pub group: Option<String>,
    pub mac: Option<String>,
}

impl ClientIdentity {
    pub fn may_match_secret_rules(&self) -> bool;
    pub fn may_match_client_exception(&self) -> bool;
}
```

Filter `$client`, rewrite `exception_clients`, and any secret-gated policy use `may_match_*`, never the raw `ctx.id`.

### 10.3 DNSSEC

```rust
pub struct ValidationContext<'a> {
    pub response: &'a mut Message,
    pub qname: &'a Name,
    pub qtype: RecordType,
    pub deadline: Instant,
    pub budget: FetchBudget,
}

pub enum ValidationDecision {
    Secure,
    Insecure(InsecureProof),
    Bogus(BogusReason),
    Indeterminate(IndeterminateReason),
}

pub trait DnssecKeyFetcher {
    async fn query(&self, name: &Name, rtype: RecordType, deadline: Instant) -> Result<Message, UpstreamError>;
}

impl DnssecValidator {
    pub async fn validate(
        &self,
        ctx: ValidationContext<'_>,
        fetcher: &dyn DnssecKeyFetcher,
    ) -> ValidationDecision;
}
```

`Bogus` maps to SERVFAIL unless CD=1 or mode=log-only. `Indeterminate` is only servable in log-only mode; strict/validate returns SERVFAIL for a name that should be signed or whose signature evidence is incomplete. Denial evaluation takes the signer zone and rejects ancestor-delegation records.

### 10.4 Transport admission

```rust
pub struct AdmissionController;

pub struct ConnectionPermit(/* ... */);
pub struct RequestPermit(/* ... */);

impl AdmissionController {
    pub async fn acquire_connection(&self, ip: IpAddr) -> Result<ConnectionPermit, AdmissionError>;
    pub async fn acquire_request(&self, ip: IpAddr) -> Result<RequestPermit, AdmissionError>;
    pub fn rate_key(&self, ip: IpAddr) -> RateKey; // IPv4 /24, IPv6 /64
}
```

All listeners acquire a connection permit before handshake and a request permit before reading a body. QUIC configs set stream/connection receive windows and stream caps explicitly. A `TlsManagerSet` owns all four acceptor managers and reloads them together from one certificate source.

### 10.5 Filter engine

```rust
pub struct FilterStatus {
    pub state: FilterState,
    pub rules: usize,
    pub loaded_lists: usize,
    pub failed_lists: Vec<String>,
    pub dropped_patterns: usize,
    pub degraded: bool,
    pub last_error: Option<String>,
}

impl FilterEngine {
    pub async fn prepare(&self, config: &FilteringConfig) -> Result<FilterSnapshot, FilterError>;
    pub fn publish(&self, snapshot: FilterSnapshot) -> FilterStatus;
    pub fn status(&self) -> FilterStatus;
}
```

`prepare` streams each list through a parser with per-line, per-pattern, total-byte, rule-count, regex-count, DFA-byte and compile-time budgets. Empty/zero-yield lists are errors unless `allow_empty_list = true`. `publish` is generation-checked; a group compile failure degrades only that group and retains non-regex rules.

### 10.6 HA

```rust
pub struct HaPublisher;

pub enum PublishOutcome {
    Published { version: u64, term: u64 },
    NoSlaves,
    TooLarge { bytes: usize, limit: usize },
}

impl HaPublisher {
    pub async fn publish(&self, snapshot: &RuntimeSnapshot) -> Result<PublishOutcome, HaError>;
}

pub struct SlaveSession {
    pub last_frame: Instant,
    pub applied_version: u64,
    pub applied_term: u64,
    pub applied_config_digest: blake3::Hash,
}
```

The slave closes and marks `Degraded` after `3 × ping_interval_secs` without a frame/Pong. A restart must compare the persisted applied config digest; mismatch forces a full apply or `Degraded`. The master keeps a bounded history of published `(term, version, hash)` envelopes until ACKed and returns publish errors to the API/readiness.

### 10.7 Auth re-authentication

```rust
pub enum ReauthProof {
    Password { password: SecretString },
    PasswordAndTotp { password: SecretString, code: String },
}

impl AuthManager {
    pub async fn reauth(&self, username: &str, proof: ReauthProof) -> Result<(), AuthError>;
    pub async fn begin_totp_enrollment(&self, username: &str, proof: ReauthProof) -> Result<TotpSetupResponse, AuthError>;
}
```

Sensitive operations (TOTP setup/enable/disable, password change, wizard re-run, user role changes) require `reauth`.

### 10.8 Stats/querylog

```rust
pub struct StatsQuery {
    pub from: Option<i64>,
    pub to: Option<i64>,
    pub qtype: Option<RecordType>,
    pub include_total: bool,
    pub limit: u32,
}

impl StatsDb {
    pub async fn query_logs(&self, query: StatsQuery) -> Result<QueryLogPage, StatsError>;
    pub async fn run_retention_once(&self, now: i64, chunk_hours: u32) -> Result<RetentionReport, StatsError>;
}
```

UI/live refresh sets `include_total=false`; retention processes bounded hour chunks with separate commits; rollups anonymize/hash client IPs and have their own retention.

## 11. Migration Strategy

### 11.1 Config v2

- Add `config_version = 2`; freeze the schema at WP-1.3.
- Reject unknown keys/tables (`deny_unknown_fields` for typed sections; a raw-key walk for legacy sections).
- Move `[web] acme_*` and `[dns.tls]` into typed config; support them as deprecated aliases for one 2.0 alpha, then remove.
- Add `sito config migrate --from v1 --to v2 --backup` that reads v1, copies every known value behavior-preservingly, writes v2 with a 0600 backup, and emits a report. `--adopt-safe-defaults` opts into the new defaults.
- A checked-in `config-v1-to-v2-map.toml` enumerates every serde field; a test fails if the map and the schema diverge.
- Installer/Docker entrypoint run migration automatically only for `config_version = 1`; rollback restores both binary and config backup.
- Startup/API/restore/HA all use `Config::validate_full()`.
- New installs use safe defaults (loopback web bind, DNS ACL, fail-closed); upgrades keep old effective behavior unless `--adopt-safe-defaults`.

### 11.2 REST/API v2

- Add `/api/v2`; keep `/api/v1` as a compatibility facade for one 2.0 alpha. `docs/api-v1-compat.md` lists every preserved path; removal at 2.1.0.
- Return 201/202/409 correctly. Restart-only changes return **409 and are not persisted**; `GET /api/v2/config/restart-required` previews the fields.
- Add OpenAPI `securitySchemes` and per-operation security.
- Remove `?token=` WebSocket auth; require `Authorization`/cookie + Origin check.
- Add config schema endpoint and migration warnings.

### 11.3 SQLite

- Add migrations for `stats_hourly` retention/PII:
  - keyed BLAKE3 hash of `client_ip` using a per-install salt in `<data_dir>/stats-salt` (0600);
  - optional `rollup_client_names` (default false);
  - `rollup_retention_days` (default 365);
  - indexes for `from`/`to`/`qtype`;
  - `secure_delete`/incremental vacuum policy.
- Startup checks schema; v1.9 DB requires `sito db migrate` or `SITO_DB_AUTO_MIGRATE=1`; always back up `stats.db` first.
- Migrations are forward-only; rollback = restore backup; 2.0 refuses an unknown newer schema.
- “Clear query log” deletes `query_log` and `stats_hourly` by default; `--keep-aggregates` preserves rollups.
- Existing raw query-log rows are not retroactively anonymized unless `sito db anonymize --all`; document the forward-only behavior.
- Migration must be online-safe and tested from the v1.9 schema.

### 11.4 HA protocol v2

- Add `protocol_version = 2`; v1 peers rejected with `protocol_mismatch` and a readiness reason.
- Bind bundle `term`, `version`, `config_digest`, `signing_key_fingerprint` into the signed payload.
- Require local config digest match on restart.
- Add heartbeat/pong deadline and per-slave ACK history.
- Require CA or pin+CA semantics; no “unpinned without CA” unless an explicit `allow_no_verification` flag is set.
- Upgrade order: master first, then slaves; downgrade is not supported in place. Restore config/HA state/certs backups to return to 1.9.3.
- Shared config fields are read-only on slaves; local shared-field edits mark `Degraded` and require resync.
- Coordinated cluster upgrade documented in `docs/runbook-ha.md`.

## 12. Fail-Closed Policy

| Situation | Default | Opt-out |
|---|---|---|
| DNSSEC signed zone, missing/invalid proof | SERVFAIL (CD=1 bypasses) | `dns.dnssec.mode = "log_only"` |
| DNSSEC key fetch timeout | SERVFAIL after global deadline | log-only mode |
| Configured TLS/ACME listener cannot build acceptor | Startup error + not-ready | explicitly disable listener |
| ACME bootstrap cert | Treated as renewal-needed; real order attempted | none |
| Empty/zero-yield filter list | Keep previous snapshot; mark degraded | `filtering.allow_empty_list = true` |
| All filter sources fail at first boot | SERVFAIL if `fail_closed` | `fail_closed = false` with warning |
| Per-client upstream invalid | Config rejected | remove/fix upstream |
| HA publish fails | Local config remains; HA readiness not-ready; retry/alert (`NoSlaves` ready unless `require_slaves`) | none |
| HA slave loses master | Close, `Degraded`, readiness false | none |
| Web admin exposed on non-loopback HTTP | Startup warning; compose defaults loopback | explicit bind/public URL |
| Unknown TOML key | Startup/API error | `--ignore-unknown-keys` for migration only |

---

# Part III — Remediation Work Packages

Each work package is a reviewable commit-sized unit inside its phase PR. A phase PR contains one commit per WP (tests and docs included). Estimates are for one senior Rust engineer including tests/docs; no deadline is assumed. Phase 2 is intentionally one PR as requested; review it commit-by-commit and request an explicit exception before splitting it.

## Phase 0 — 1.9.4 Safety Gate (3–4 weeks, time-boxed)

The safety gate is the only work done before the 2.0 refactor. It closes all P0 and the directly exploitable/data-loss/credential/ops-blocking P1s so the refactor does not ship a known-vulnerable resolver. It must remain a **non-breaking 1.9.4 patch**: no config v2, API v2, SQLite schema break, or HA protocol break. P1-19/P1-23/P1-24 are the only P1s deferred to Phase 2; they are recorded as residual risks in the 1.9.4 release notes.

### WP-0.1 — Baseline, release freeze, and regression harness

**Addresses:** all P0/P1 confirmation; test gaps.
**Files:** `Cargo.toml`, `crates/sito-test/src/harness.rs`, `crates/sito-test/src/mock.rs`, `.github/workflows/ci.yml`.
**Interfaces:** `TestHarness::reserve_port()`, `TestHarness::wait_until()`, `MockDnsServer::with_nodata()`, `MockDnsServer::with_edns()`.
**Steps:**
- [ ] Run `cargo fmt --all --check`, `cargo clippy --workspace --all-features --all-targets -- -D warnings`, `cargo test --workspace --all-features --locked`, `cargo deny check`; record results in the PR.
- [ ] Add a `docs/audit6.md` copy of this audit and a `docs/audit6-followup-plan.md` pointer to this plan.
- [ ] Add `TestHarness::reserve_port()` (bind :0, return listener, hold until test) and replace probe-then-bind in transport/HA tests.
- [ ] Add `MockDnsServer` modes for NODATA vs NXDOMAIN, EDNS/DO, TCP, truncation, and malformed responses.
- [ ] Add `SITO_PERF_TESTS` to weekly CI or remove the 50k timing gate.
- [ ] Mark `docs/audit.md`, `docs/audit2.md`, `docs/audit5.md` as historical with a banner; add Appendix C as `docs/audit6-claim-matrix.md`.
- **Acceptance:** baseline commands green; flaky/sleep tests either fixed or explicitly marked; no P0/P1 fix starts without a failing test.
**Estimate:** S–M.

### WP-0.2 — ACME bootstrap, renewal, and all-transport reload

**Addresses:** P0-1, P1-12, P2-13, P2-14, P2-20, P2-21.
**Files:** `crates/sito-transport/src/acme.rs`, `tls.rs`, `crates/sito/src/server.rs`, `crates/sito-test/tests/m11_acme.rs` (new).
**Interfaces:** `AcmeServiceConfig { bootstrap_marker: bool, renew_before_days, directory_url }`, `TlsManagerSet::reload_all(cert, key)`, `AcmeServiceConfig::is_bootstrap_cert()`.
**Steps:**
- [ ] Write a failing test: fresh ACME storage with a generated bootstrap cert must return `needs_renewal == true`.
- [ ] Write a failing test: bootstrap cert validity is <= 7 days or marked `bootstrap`; real ACME cert is not.
- [ ] Write a failing test: TLS-ALPN-01 is selected only when a 443 listener is bound; otherwise HTTP-01 is selected.
- [ ] Write a failing test: after issuance, DoT/DoH/DoQ/DoH3 managers all see the new cert; a restart prefers the ACME cert over static files.
- [ ] Implement the marker/validity fix and challenge selection; make `build_tls_acceptor` failures fatal for configured listeners.
- [ ] Write account credentials atomically; on parse failure back up and re-register; compare configured directory.
- [ ] Verify cert/key public keys match before installing a reloaded pair.
- **Acceptance:** fresh ACME-only install obtains a cert against a mock CA; renewal works; all transports reload; no self-signed cert is served after issuance.
**Estimate:** M.

### WP-0.3 — DNSSEC denial and fail-closed emergency patch

**Addresses:** P0-2, P1-1, P1-2, P1-27, P2-1, P2-2, P2-5, P2-6.
**Files:** `crates/sito-dnssec/src/{lib,nsec,nsec3,chain_cache}.rs`, `crates/sito/src/pipeline.rs`, `crates/sito-test/tests/m11_dnssec_security.rs` (new).
**Interfaces:** `evaluate_nsec_denial(..., signer_zone, delegation_policy)`, `evaluate_nsec3_denial(..., signer_zone)`, `ValidationContext { deadline, budget }`, `ValidationDecision`.
**Steps:**
- [ ] Write a failing test: parent-side NSEC for `child.example` cannot prove NXDOMAIN for `x.child.example`.
- [ ] Write a failing test: parent-side NSEC3 for a delegation cannot be the closest encloser; Opt-Out wildcard NODATA returns `OptOut`, not `Secure`.
- [ ] Write a failing test: a junk RRSIG does not suppress the unsigned probe; signed CNAME to an unsigned target without DS denial returns `Bogus` in strict mode.
- [ ] Write a failing test: strict/validate mode returns SERVFAIL for post-fetch `Indeterminate` when the name is in a signed/unknown zone; CD=1 still returns data.
- [ ] Write a failing test: a query with 8 CNAME hops and blocked key fetches completes within the deadline and returns SERVFAIL, not a pinned worker.
- [ ] Write a failing test: a query in flight during a DNSSEC mode/anchor change cannot insert old-policy validation status after the cache flush.
- [ ] Implement delegation-aware denial filtering and restricted `Indeterminate`.
- [ ] Add one global fetch deadline/budget through `DnssecKeyFetcher` and the chain walk; add a negative cache with backoff.
- [ ] Add a DNSSEC policy epoch to cache inserts; reject entries from a previous epoch.
- **Acceptance:** hostile-chain suite passes; real signed zone validates; blocked key fetch cannot produce AD=1 or unvalidated answer in strict mode; no old-policy cache entry survives a change.
**Estimate:** L.

### WP-0.4 — HA liveness and applied-config integrity

**Addresses:** P1-3, P1-4, P1-5, P1-6, plus HA hardening H-06 (send timeout), H-07 (handshake slots), H-08 (signing-key identity), H-10 (resync clearing).
**Files:** `crates/sito-ha/src/slave/worker.rs`, `slave/state.rs`, `master/coordinator.rs`, `crates/sito-api/src/state.rs`, `crates/sito-test/tests/m11_ha_partition.rs` (new).
**Interfaces:** `SlaveSession.last_frame`, `PublishOutcome`, `applied_config_digest`, `active_push_history`.
**Steps:**
- [ ] Write a failing test: a fake master stops sending frames; the slave must transition to `Degraded`/not-ready after 3× ping interval.
- [ ] Write a failing test: restart with a locally modified shared config must not early-ACK `Synced`; it must apply or report `Degraded`.
- [ ] Write a failing test: a delayed same-version fork ACK after a newer publish is recorded as divergence.
- [ ] Write a failing test: sanitize/persist failure returns an error from `publish_bundle`; oversized bundle returns `TooLarge`.
- [ ] Implement heartbeat/read deadline, applied config digest, bounded envelope history, publish `Result`, and size checks.
- [ ] Add send timeouts and bounded queue bytes per slave.
- **Acceptance:** partition/fork/drift tests pass; `/health` goes false on master loss; operator sees divergence.
**Estimate:** M–L.

### WP-0.5 — Filter empty-list, budgets, and identity trust

**Addresses:** P1-7, P1-8, P1-9, P1-26, P2-24, P2-25, P2-26, P2-95, P2-96.
**Files:** `crates/sito-filter/src/{parser,engine,structures/compiled,subscription}.rs`, `crates/sito-rewrites/src/table.rs`, `crates/sito-clients/src/registry.rs`, `crates/sito-transport/src/{doh,doh3}.rs`, `crates/sito-api/src/config_apply.rs`, tests.
**Interfaces:** `FilterSnapshot::prepare_with_budget`, `FilterStatus`, `ClientIdentity.authenticated`.
**Steps:**
- [ ] Write a failing test: an empty 200 response or HTML error page is rejected and the previous snapshot is retained.
- [ ] Write a failing test: a 64 MiB line and a 10M-rule list abort at the configured byte/rule budget without OOM.
- [ ] Write a failing test: `filtering.enabled` with zero sources is `Failed`/fail-closed, not `Ready`.
- [ ] Write a failing test: enabling filtering during apply never exposes old config + new filter snapshot; a failed later hook leaves both old.
- [ ] Write a failing test: DoH path `/<exception>` cannot satisfy a rewrite exception for an IP-identified client.
- [ ] Implement per-line/pattern/byte/rule/DFA/compile budgets during parsing; reject empty/zero-yield lists.
- [ ] Reject partial invalid `$dnstype`/`$denyallow` tokens; add `authenticated` identity gate.
- [ ] Publish `FilterStatus` to API/metrics; log truncated rule excerpts only.
- **Acceptance:** hostile/empty-list tests pass; no group silently vanishes; status reflects degraded lists.
**Estimate:** M–L.

### WP-0.6 — Transport admission, DoQ/DoH, EDNS/response shaping

**Addresses:** P1-10, P1-11, P1-13, P1-14, P2-15..21, P2-84.
**Files:** `crates/sito-transport/src/{doq,doh,doh3,udp,tcp,dot,limiter}.rs`, `crates/sito-cache/src/cache.rs`, `crates/sito/src/pipeline.rs`.
**Interfaces:** `AdmissionController`, `ConnectionPermit`, `RequestPermit`, `RateKey`, `TlsManagerSet`.
**Steps:**
- [ ] Write failing tests: DoQ cannot allocate more than `stream_receive_window`/`receive_window`; a client cannot hold 100 streams before rate check.
- [ ] Write failing tests: DoH request body is not read before rate admission; global request cap returns 429/503.
- [ ] Write failing tests: non-EDNS client never receives OPT; cache hit copies current question/RD/CD; upstream cookies/NSID are stripped.
- [ ] Write failing tests: DoH/DoH3 responses >65,535 bytes are truncated with TC=1.
- [ ] Implement admission permits, QUIC windows/stream caps, per-prefix rate keys, total deadlines, response shaping.
- [ ] Set `stream_receive_window`/`receive_window` for DoQ; lower stream caps; acquire permits before handshake/body.
- **Acceptance:** DoS regression tests pass; cache/EDNS tests pass; no response exceeds protocol framing.
**Estimate:** L.

### WP-0.7 — Auth re-auth and wizard bootstrap-only

**Addresses:** P1-15, P1-16, P1-20, P2-52, P2-54.
**Files:** `crates/sito-api/src/handlers/auth_handlers.rs`, `auth/manager.rs`, `auth/lockout.rs`, `ui/handlers.rs`, templates, tests.
**Interfaces:** `ReauthProof`, `AuthManager::reauth`, `begin_totp_enrollment`.
**Steps:**
- [ ] Write failing tests: TOTP setup/enable without current password/TOTP returns 401; with re-auth succeeds; existing TOTP cannot be replaced without re-auth.
- [ ] Write failing tests: wizard completion outside bootstrap state returns 403; an Admin cannot reset a password without re-auth.
- [ ] Write failing tests: username/password length limits; lockout eviction does not remove active locked entries.
- [ ] Implement re-auth for sensitive operations; restrict wizard to `is_first_run() || setup_token_required()`; add login limits and digest lockout keys.
- [ ] Add TOTP enrollment to the Account page for all roles; require re-auth for disable.
- **Acceptance:** stolen-session tests fail before fix and pass after; self-service 2FA works for Viewer/Operator/Admin.
**Estimate:** M.

### WP-0.8 — Installer atomic upgrade, release gate, cache invalidation

**Addresses:** P1-17, P1-18, P1-21, P1-22, P2-69, P2-70.
**Files:** `contrib/install.sh`, `.github/workflows/{ci,release,security}.yml`, `crates/sito-cache/src/cache.rs`, tests.
**Interfaces:** `install_binary_atomic()`, `verify_release_gate()`.
**Steps:**
- [ ] Write a failing shell E2E: install, start service, re-run installer; upgrade must succeed (no ETXTBSY).
- [ ] Write a failing shell E2E: health-check failure restores the previous binary and config backup.
- [ ] Write a failing installer test: missing `.sig`/`.pem` or missing cosign fails when `SITO_REQUIRE_SIGNATURE=1`; default is required.
- [ ] Write a failing workflow test: a tag whose commit is not on the required release branch (`release/1.9.x` for 1.9.4, `main` for 2.0) or lacks green CI/security cannot reach publish.
- [ ] Write a failing test: `invalidate_domain("example.com")` removes `example.com` and `www.example.com`, not other names.
- [ ] Implement `systemctl stop`/atomic `install`/`rename` and rollback; preserve capabilities; restore config backup.
- [ ] Make signature verification required by default; fail if cosign/assets are missing unless explicitly overridden.
- [ ] Gate release on the required branch ancestry (`release/1.9.x` for 1.9.4) + green CI/security; add image scan/sign.
- [ ] Add `support_invalidation_closures()` and handle the error.
- **Acceptance:** live upgrade/rollback E2E passes; cache invalidation test passes; release refuses untested tags.
**Estimate:** M.

### WP-0.9 — Upstream bootstrap, SSRF, and EDNS emergency patch

**Addresses:** P1-25, P2-7, P2-9, P2-10.
**Files:** `crates/sito-upstream/src/{bootstrap,manager,plain,doh,key_fetch,health}.rs`, `crates/sito-core/src/ssrf.rs`, tests.
**Steps:**
- [ ] Write a failing test: bootstrap/probe queries set RD=1 and a mock resolver that rejects RD=0 is not marked down.
- [ ] Write a failing test: bootstrap A/AAAA answers to loopback/private/metadata IPs are rejected unless the operator explicitly allowlists the upstream target.
- [ ] Write a failing test: a mismatched UDP datagram is ignored until the deadline instead of failing the query.
- [ ] Write a failing test: a bare `https://host` DoH target uses `/dns-query`; a FORMERR response triggers one no-EDNS retry.
- [ ] Implement RD=1, SSRF filtering, forced bootstrap refresh, UDP receive loop, DoH path/proxy fix, and EDNS fallback.
- **Acceptance:** upstream security/wire tests pass; no private-target bootstrap redirect; bare DoH works.
**Estimate:** M.

### WP-0.10 — Docs truth banners and claims

**Addresses:** P2-71..P2-83, P3-13..P3-16.
**Files:** `README.md`, `docs/{security-audit,configuration-reference,installation,runbook-ha,policy-matrix,migration-adguard,benchmarks,release-notes-1.9.2,release-notes-1.9.3}.md`, `config.example.toml`.
**Steps:**
- [ ] Add historical banners to `audit.md`, `audit2.md`, `audit5.md`.
- [ ] Fix ACME/TLS/metrics/HA/API/fuzz/benchmark/Argon2 claims listed in §5.
- [ ] Fix `--no-setup`, schedule timezone, container admin bind, and authenticated curl examples.
- [ ] Mark `fuzz` commands as v1.9.3-only or remove them.
- [ ] Add a CI link checker and a config-reference default/type checker.
- **Acceptance:** `scripts/check_config_reference.py` passes with defaults/types; no documented command fails.
**Estimate:** S–M.

## Phase 1 — 2.0 Refactor Foundations (6–8 weeks)

### WP-1.1 — Freeze/cut non-core features and dead code

**Addresses:** P3-5, P3-6, P3-7, P3-10; RouterOS decision.
**Files:** workspace `Cargo.toml`, `crates/sito-clients/{lib,Cargo.toml}`, new `crates/sito-routeros` (optional), dead-code modules.
**Steps:**
- [ ] Move RouterOS code to `sito-routeros` behind `--features routeros`; default build excludes it; docs mark experimental.
- [ ] Remove `run_server`, dead re-exports, unused helpers, `MAX_REGEX_BATCHES`, test-only public APIs.
- [ ] Remove unused deps and tighten Tokio features per crate.
- [ ] Delete unreachable non-Unix fallbacks or gate them.
- **Acceptance:** default build has no RouterOS; `cargo machete`/`udeps` clean; public API diff documented.
**Estimate:** M.

### WP-1.2 — Normalized domain and client identity model

**Addresses:** P1-9, P2-31..P2-35, P2-97..P2-99, IDN gaps.
**Files:** `sito-core/src/{domain,client}.rs`, `sito-clients/src/{registry,mac,schedule}.rs`, `sito-filter/src/parser.rs`, `sito-rewrites/src/table.rs`.
**Interfaces:** `NormalizedDomain`, `ClientIdentity`, `IdentitySource`.
**Steps:**
- [ ] Write table-driven tests for IDN/punycode, trailing dots, uppercase, wildcard labels.
- [ ] Introduce `NormalizedDomain`; make filter/rewrite/client APIs accept it, not raw `&str`.
- [ ] Add provenance/authenticated flags; migrate `ClientContext`.
- [ ] Replace duplicated CIDR/suffix matchers with shared helpers.
- **Acceptance:** all matching uses normalized input; no raw `ctx.id` in policy.
**Estimate:** M–L.

### WP-1.3 — Config v2 schema and one validator

**Addresses:** P2-38, P2-39, P2-85..P2-88, P2-93, P2-94.
**Files:** `sito-core/src/config.rs`, `sito-api/src/{config_validation,config_apply,config_writer}.rs`, `sito/src/{cli,server}.rs`.
**Interfaces:** `Config::validate_full()`, `ConfigError`, `Config::migrate_v1_to_v2()`.
**Steps:**
- [ ] Write failing tests for unknown keys, duplicate binds, port conflicts, empty data_dir, bad upstream target, bad integrations list, invalid ACME domain.
- [ ] Add `config_version = 2` and a migration function; reject v1 in 2.0 with a clear `sito config migrate` message.
- [ ] Make startup, check-config, API, restore, HA all call `validate_full`.
- [ ] Add restart-only matrix from effective getters (`get_tls_config`, `get_acme_config`).
- **Acceptance:** one validator; parity tests across all entry points.
**Estimate:** L.

### WP-1.4 — Staged runtime generation and atomic apply

**Addresses:** P1-26, P1-27; torn reload.
**Files:** `sito-runtime/src/lib.rs`, `sito-api/src/config_apply.rs`, `sito/src/{pipeline,server}.rs`, filter/dnssec/cache.
**Interfaces:** `RuntimeGeneration`, `ApplyPlan`, `RuntimeState::apply`.
**Steps:**
- [ ] Write a failing test: enable filtering; a query during apply must see either old config+old filter or new config+new filter, never old config+new filter.
- [ ] Write a failing test: DNSSEC policy change plus in-flight query cannot insert old-policy status after the new generation.
- [ ] Implement staged apply: validate/compile all components, then one ArcSwap publish; on any failure, no component changes.
- [ ] Flush/re-key caches by generation/epoch, not by timing.
- **Acceptance:** generation race tests pass; HA/API/watcher use the same apply path.
**Estimate:** L.

### WP-1.5 — Split monoliths and define module boundaries

**Addresses:** P3-1, P3-2, P3-6.
**Files:** `sito-dnssec/src/lib.rs`, `sito-api/src/auth/manager.rs`, `sito-api/src/ui/handlers.rs`, `sito-ha/src/{master/coordinator,slave/worker}.rs`, `sito/src/pipeline.rs`, `sito-stats/src/metrics.rs`.
**Steps:**
- [ ] Extract DNSSEC: `anchor.rs`, `chain.rs`, `denial.rs`, `verify.rs`, `cache.rs`.
- [ ] Extract auth: `login.rs`, `totp.rs`, `sessions.rs`, `users.rs`, `tokens.rs`.
- [ ] Extract UI handlers by page; share DTO/validation with API.
- [ ] Extract HA session state machines from WebSocket I/O.
- [ ] Split pipeline into named stages with `PipelineContext`.
- [ ] Split `render_prometheus` by metric family.
- **Acceptance:** no production file >2,000 lines; no function >200 lines without a documented exception.
**Estimate:** L.

### WP-1.6 — Shared DNS response shaping and cache keys

**Addresses:** P1-13, P1-14, P2-22, P2-23, P2-84.
**Files:** `sito-proto/src/wire.rs`, `sito-cache/src/{key,entry,cache}.rs`, `sito/src/pipeline.rs`.
**Interfaces:** `ResponseShaper::shape(response, client_query, dnssec_mode)`, `CacheKey::for_query`, `CachePolicyEpoch`.
**Steps:**
- [ ] Write failing tests for question/RD/DO/CD/EDNS/OPT on cache hits and upstream responses.
- [ ] Implement `ResponseShaper` used on every path (cache, stale, upstream, rewrite, safe search).
- [ ] Add cache key fields for EDNS presence/options that matter; sanitize the rest.
- [ ] Add cache policy epoch and TTL re-clamp on reload.
- **Acceptance:** one shaper; no path bypasses it; tests cover DO=0/1, EDNS/non-EDNS, CD.
**Estimate:** M–L.

### WP-1.7 — Error/health/readiness policy

**Addresses:** P1-6, P2-87, P2-89, P2-90, P3-3, P3-4.
**Files:** `sito-core/src/error.rs`, `sito/src/server.rs`, `sito-api/src/state.rs`, all crates with `let _ =`.
**Steps:**
- [ ] Classify every `let _ =`/`.ok()`/`unwrap` on security/apply/persistence/readiness paths; replace with typed errors or documented best-effort.
- [ ] Add readiness reasons for TLS/ACME/HA/filter/stats; `/health` stays generic, `/status` detailed.
- [ ] Acquire the service lease before any bootstrap mutation.
- [ ] Add poison-recovery helpers for `Mutex::lock`.
- **Acceptance:** no silent failure on security/apply paths; `/health` false when core listeners or HA are broken.
**Estimate:** M.

### WP-1.8 — Test harness, mocks, and deterministic timing

**Addresses:** P3-11, P3-12; test fidelity.
**Files:** `sito-test/src/{harness,mock,client}.rs`, tests.
**Steps:**
- [ ] Add port broker, deterministic clock, and event-driven waits.
- [ ] Add mock TLS/ACME/HA/DNSSEC fixtures.
- [ ] Replace semantic sleeps where possible; mark the rest with a reason.
- [ ] Add property tests for domain normalization/ABP parser.
- **Acceptance:** test suite runs in parallel without port collisions; no flaky timing failures in 20 runs.
**Estimate:** M.

### WP-1.9 — Fuzz, benchmarks, and CI gates

**Addresses:** P1-21, P2-64..P2-66, P3-17..P3-19.
**Files:** `fuzz/`, `.github/workflows/{ci,weekly,security,release}.yml`, `benches/`.
**Steps:**
- [ ] Restore `cargo-fuzz` workspace with targets: `dns_wire`, `abp_parser`, `dnssec_response`, `ha_bundle`, `config_toml`.
- [ ] Add nightly fuzz job with corpus and timeout.
- [ ] Add criterion benches for pipeline, filter, cache, stats, metrics; store baseline and fail outside tolerance.
- [ ] Run tests/clippy/fmt/deny on `main` and PR; release requires green main ancestry.
- [ ] Add `cargo machete`/`udeps`, coverage, and Prometheus exposition parser check.
- **Acceptance:** fuzz 24h clean; bench gate fails on >10% regression; release refuses untested tags.
**Estimate:** M–L.

### WP-1.10 — Docs structure and migration guide

**Addresses:** P2-71..P2-83, P3-13..P3-16.
**Files:** `docs/`, `README.md`, `config.example.toml`, `scripts/check_config_reference.py`.
**Steps:**
- [ ] Create `docs/2.0-migration.md` for config/API/DB/HA.
- [ ] Add historical banners; move old audits to `docs/history/` or mark clearly.
- [ ] Rewrite current README/security/HA/config docs from code.
- [ ] Extend config-reference checker to nested structs/defaults/types.
- **Acceptance:** doc link/default/type checks green; every 2.0 breaking change has a migration step.
**Estimate:** M.

## Phase 2 — 2.0 Core Hardening and Feature Completion (10–14 weeks)

### WP-2.1 — DNSSEC chain state machine

**Addresses:** P0-2, P1-1, P1-2, P2-2..P2-6.
**Files:** `sito-dnssec/src/{anchor,chain,verify,denial,cache}.rs`, `sito-core/src/dnssec_fetch.rs`, tests.
**Interfaces:** §10.3.
**Steps:**
- [ ] Replace three chain walkers with one `TrustChain` state machine returning `Signed|Unsigned|Unknown|Bogus`.
- [ ] Implement RFC 6840 §4.1 delegation filtering and RFC 5155 §8.3 closest-encloser bitmap checks.
- [ ] Add DNAME and QTYPE=CNAME tests; strict-mode SERVFAIL on `Indeterminate`.
- [ ] Add one global deadline/fetch budget; negative cache with backoff.
- [ ] Add signed-zone evidence TTL capped by DS/chain TTL; integrity-protect persisted cache.
- **Acceptance:** hostile-chain suite + real signed zone pass; no AD=1 without proof; no worker pinning.
**Estimate:** L.

### WP-2.2 — DNSSEC negative cache and policy integration

**Addresses:** P1-1, P2-1, P2-4, P2-84.
**Files:** `sito-dnssec/src/chain_cache.rs`, `sito-cache/src/{entry,cache}.rs`, `sito/src/pipeline.rs`.
**Steps:**
- [ ] Add `DnssecPolicyEpoch` to cache entries; flush/reject on validator/anchor change.
- [ ] Cache `Bogus`/`Indeterminate` with explicit policy and short TTL; never serve stale Indeterminate.
- [ ] Add metrics for `Secure/Insecure/Bogus/Indeterminate`, key fetch budget, deadline failures.
- **Acceptance:** policy-change race test passes; stale cache never serves unvalidated data.
**Estimate:** M.

### WP-2.3 — Filter parser/compiler streaming and budgets

**Addresses:** P1-7, P1-8, P2-24..P2-29, P2-95, P2-96.
**Files:** `sito-filter/src/{parser,engine,structures/*,subscription,downloader}.rs`.
**Steps:**
- [ ] Stream list parsing; enforce per-line/pattern/byte/rule/regex/DFA/compile budgets.
- [ ] Reject empty/zero-yield lists unless allowed; apply drop guard to all remote reload paths.
- [ ] Store URL in cache metadata; invalidate on URL change.
- [ ] Expose status/degraded counts and per-list errors via API/metrics.
- [ ] Cap `refresh_hours` and use checked time arithmetic.
- **Acceptance:** hostile/empty/URL-change tests pass; status truthful; no OOM.
**Estimate:** L.

### WP-2.4 — Filter precedence, groups, and rewrites

**Addresses:** P1-9, P2-24..P2-26, P2-31..P2-33, P2-35.
**Files:** `sito-filter/src/engine.rs`, `sito-rewrites/src/table.rs`, `sito/src/pipeline.rs`.
**Steps:**
- [ ] Define global/group precedence table; test `$important @@`, `$dnsrewrite`, `$denyallow`, `$client`.
- [ ] Never drop a whole group on compile failure; publish non-regex subset + degraded status.
- [ ] Add authenticated identity gate for rewrite exceptions.
- [ ] Chunk TXT records; local owner NODATA for unconfigured qtypes; safe search only A/AAAA/HTTPS.
- **Acceptance:** precedence matrix tests pass; no group fail-open; rewrite exception spoof test passes.
**Estimate:** M–L.

### WP-2.5 — Client policy, schedules, parental/service lists

**Addresses:** P2-34..P2-37, P2-97..P2-99.
**Files:** `sito-clients/src/*`, `sito-filter/data/*`, docs.
**Steps:**
- [ ] Strict MAC parsing and ARP-snapshot invalidation.
- [ ] Add IANA timezone support or document fixed-offset only; validate cron window semantics.
- [ ] Replace tiny bundled parental/service data with a maintained manifest or mark experimental in UI/docs.
- [ ] Add force-refresh/status for runtime lists; validate category keys.
- [ ] Expand safe search coverage; remove self-CNAME.
- **Acceptance:** parental/service tests and data manifest checks pass; UI no longer overclaims.
**Estimate:** L.

### WP-2.6 — Transport admission and TLS hardening

**Addresses:** P1-10..P1-14, P2-15..P2-21.
**Files:** `sito-transport/src/{udp,tcp,dot,doh,doh3,doq,tls,acme,limiter,handler}.rs`, `sito/src/server.rs`.
**Steps:**
- [ ] Implement `AdmissionController` permits before handshake/body; per-prefix rate keys.
- [ ] Set QUIC windows/stream caps; total request/connection deadlines.
- [ ] Reject QR=1/multi-question; enforce 65,535-byte responses.
- [ ] Validate cert/key pair and ALPN; one `TlsManagerSet` reloads all protocols.
- [ ] Add accept-error backoff, slowloris caps, ACME HTTP-01 limits.
- **Acceptance:** DoS/slowloris/EDNS/TLS tests pass; no listener silently disappears.
**Estimate:** L.

### WP-2.7 — Upstream bootstrap, SSRF, and protocol correctness

**Addresses:** P1-25, P2-7..P2-12.
**Files:** `sito-upstream/src/{manager,bootstrap,plain,dot,doh,doq,health,key_fetch}.rs`, `sito-core/src/ssrf.rs`.
**Steps:**
- [ ] Set RD=1 on bootstrap/probes; force refresh on candidate failure; apply SSRF denylist with explicit private-upstream allowlist.
- [ ] Fix bare DoH `/dns-query`; disable system proxy; verify ALPN.
- [ ] Loop UDP receives until deadline; ignore mismatched datagrams.
- [ ] Add EDNS/FORMERR fallback; bound timeout/pool; validate targets in config.
- [ ] Per-attempt RTT/error metrics; remove stale health series.
- **Acceptance:** bootstrap/DoH/EDNS/failover tests pass; no private-target redirect.
**Estimate:** L.

### WP-2.8 — Cache and response shaping

**Addresses:** P1-13, P1-14, P1-18, P2-22, P2-23, P2-84.
**Files:** `sito-cache/src/*`, `sito-proto/src/wire.rs`, `sito/src/pipeline.rs`.
**Steps:**
- [ ] Enable moka invalidation closures; add non-root test.
- [ ] Rebuild question/flags/OPT per client; strip upstream EDNS options.
- [ ] Add policy epoch and TTL re-clamp; sanitize public helpers.
- [ ] Enforce response size on DoH/DoH3/TCP/DoT.
- **Acceptance:** cache invalidation/shaping/size tests pass.
**Estimate:** M.

### WP-2.9 — HA protocol v2 and failover

**Addresses:** P1-3..P1-6, plus HA hardening H-05..H-23 (bundle size, send timeout, handshake limits, signing-key identity, resync clearing, CA/key permissions, IPv6 URL, backoff, divergence cleanup, metrics).
**Files:** `sito-ha/src/*`, `sito-api/src/handlers/ha.rs`, `docs/runbook-ha.md`.
**Steps:**
- [ ] Add heartbeat/pong deadline, applied config digest, bounded publish history.
- [ ] `publish` returns `Result`; oversized bundle rejected before persist.
- [ ] Send timeouts, per-slave queue bytes, handshake rate limits.
- [ ] Per-slave resync ACK clears divergence; signing key fingerprint persisted.
- [ ] CA/pin/SAN policy and key permissions; IPv6 URL; clean-close backoff.
- [ ] Protocol v2; coordinated upgrade docs.
- **Acceptance:** partition/fork/drift/publish/oversize/IPv6 tests pass; health truthful.
**Estimate:** L.

### WP-2.10 — Auth, RBAC, and self-service 2FA

**Addresses:** P1-15, P1-16, P1-20, P2-52, P2-54.
**Files:** `sito-api/src/{auth/*,handlers/auth_handlers.rs,ui/*}`, templates.
**Steps:**
- [ ] Re-auth for TOTP enable/disable, password, wizard, role changes.
- [ ] Wizard bootstrap-only; self-service TOTP for all roles; UI enrollment.
- [ ] Login length/lockout digest keys; Argon2 semaphore.
- [ ] Status codes 201/202/409; `totp_enabled` truthful.
- **Acceptance:** stolen-session/reauth tests pass; all roles can enroll 2FA.
**Estimate:** M.

### WP-2.11 — API v2, OpenAPI, config apply, updater

**Addresses:** P2-38..P2-55, P2-44.
**Files:** `sito-api/src/{router,openapi,handlers/*,config_apply,updater}.rs`, `docs/openapi.json`.
**Steps:**
- [ ] Add OpenAPI security schemes/tags/path coverage; drift validator.
- [ ] Reject unknown config keys; restart-only changes return 409 with no persistence; invalid references/rewrites rejected.
- [ ] Deferred filter apply for unrelated settings; apply lock in refresh/update-all.
- [ ] Cache-Control private/no-store on authenticated GETs; WebSocket Origin.
- [ ] Updater: disable in-app apply on systemd/Docker, version truth, update lock, rollback, 0600 temp.
- **Acceptance:** API/OpenAPI/updater tests pass; no false success.
**Estimate:** L.

### WP-2.12 — Stats retention, PII, and polling

**Addresses:** P1-19, P1-23, P1-24, P2-55..P2-63.
**Files:** `sito-stats/src/{db,writer,metrics,anonymize,lib}.rs`, `sito-api/src/ui/handlers.rs`.
**Steps:**
- [ ] Write a failing test: after retention, `stats_hourly` contains no raw client IP/client name and old rollups are deleted per `rollup_retention_days`.
- [ ] Write a failing test: “clear query log” empties both `query_log` and `stats_hourly` by default; `--keep-aggregates` keeps rollups.
- [ ] Write a failing test: a 90-day retention sweep completes in bounded chunks without holding a write lock long enough to drop a concurrent insert.
- [ ] Write a failing test: live query-log refresh does not execute a `COUNT(*)`; dashboard polling is served from cache within 30s.
- [ ] Incremental retention with bounded chunks/commits, startup catch-up, metrics.
- [ ] Rollup PII policy: keyed hash IPs, optional client names/domains, rollup retention, clear/vacuum.
- [ ] `include_total=false` for live UI; cache dashboard aggregates; rate-limit stats.
- [ ] Fix error definition, failover attribution, ignore_stats, mapped IPv6.
- [ ] Remove per-verdict mutex or document/shard it.
- **Acceptance:** retention scale/PII/polling/metrics tests pass; no dropped batches on normal sweep.
**Estimate:** L.

### WP-2.13 — Ops, Docker, systemd, installer, release

**Addresses:** P1-17, P1-21, P2-67..P2-83, P3-20..P3-26.
**Files:** `contrib/install.sh`, `contrib/systemd/sito.service`, Dockerfiles/compose, workflows, docs.
**Steps:**
- [ ] Atomic install/rollback, stop/start service, preserve capabilities.
- [ ] Compose defaults loopback admin; named volume/init for config; valid DHCP hex.
- [ ] Systemd `EnvironmentFile`, hardening directives, `UMask`.
- [ ] Installer E2E, image scan/sign, release gate on tested main.
- [ ] Pin `latest`/digest; verify install commands.
- **Acceptance:** fresh install/upgrade/rollback/uninstall E2E passes; image scan clean; docs commands work.
**Estimate:** L.

### WP-2.14 — Documentation, migration, and final truth pass

**Addresses:** P2-71..P2-83, P3-13..P3-16.
**Files:** all docs, README, OpenAPI, config example.
**Steps:**
- [ ] Rewrite current docs from code; add 2.0 migration guide and breaking-change list.
- [ ] Add banners to historical audits; publish claim matrix.
- [ ] Update OpenAPI, config reference, HA runbook, security audit.
- [ ] Run link/config/default/type/route checks.
- **Acceptance:** no known false claim; all documented commands execute.
**Estimate:** M.

## Phase 3 — 2.0 Verification and Release (3–4 weeks)

### WP-3.1 — Full regression, fuzz, benchmark, Docker E2E

- [ ] `cargo fmt/clippy/test/deny` green.
- [ ] 24h fuzz clean for all targets.
- [ ] Benchmarks within baseline; no >10% regression.
- [ ] Docker image build/run/healthcheck/DNS query/upgrade E2E.
- [ ] Installer fresh/upgrade/rollback/uninstall E2E.
- **Acceptance:** release gate script passes from a clean checkout.

### WP-3.2 — 2.0 migration and compatibility tests

- [ ] `sito config migrate` v1→v2 round-trip; invalid/unknown key tests.
- [ ] SQLite migration from v1.9 schema; rollback/backup.
- [ ] HA v1→v2 coordinated upgrade; v1 slave rejected clearly.
- [ ] API v1 compatibility facade tests where promised.
- **Acceptance:** documented migration path works on a copy of a real 1.9.3 data dir.

### WP-3.3 — Security review and threat model

- [ ] Re-run the eight audit streams against the 2.0 branch.
- [ ] Verify `docs/audit6-test-matrix.md`: every P0/P1 has a failing-first test from its WP, not a late Phase 3 test.
- [ ] Review unsafe/FFI, secrets, file permissions, SSRF, auth, HA, DNSSEC.
- [ ] Update `SECURITY.md` and threat model.
- **Acceptance:** no open P0/P1; residual risks documented.

### WP-3.4 — Release candidate, rollback, and post-release monitoring

- [ ] Tag `2.0.0-rc.1`; publish signed artifacts/SBOM/image.
- [ ] Run `docs/release-verification.md` end to end.
- [ ] Publish rollback instructions and known issues.
- [ ] Monitor DNSSEC/ACME/HA/filter/error metrics after release.
- **Acceptance:** rc passes all gates; rollback tested; release notes truthful.

---

# Part IV — Execution Order and Dependencies

## 14. Ordering

1. **Phase 0** in the order listed (0.1 → 0.10), on `release/1.9.x`. Do not start the refactor before all P0s and P1-1..P1-18, P1-20..P1-22, P1-25..P1-27 are closed. Tag **1.9.4**, then merge `release/1.9.x` into `main`. P1-19/P1-23/P1-24 are the only deferred P1s and must be recorded in the 1.9.4 residual-risk list.
2. **Phase 1.1–1.4** first: feature freeze, identity, config, generation. These are dependencies for most Phase 2 work.
3. **Phase 1.5–1.10** can run in parallel by subsystem after 1.2–1.4.
4. **Phase 2** in dependency order:
   - DNSSEC (2.1, 2.2)
   - Filter (2.3, 2.4)
   - Transport/upstream/cache (2.6, 2.7, 2.8)
   - HA (2.9)
   - Auth/API (2.10, 2.11)
   - Stats/parental/ops/docs (2.5, 2.12, 2.13, 2.14)
5. **Phase 3** only after all Phase 2 acceptance tests pass.

## 15. Branching and Releases

- **One PR per phase.** Branches:
  - `fix/1.9.4-phase0-safety-gate` -> `release/1.9.x` (tag `v1.9.4`)
  - `refactor/2.0-phase1-foundations` -> `main`
  - `feat/2.0-phase2-core-hardening` -> `main`
  - `release/2.0-phase3-verification` -> `main`
- Inside each phase PR, one commit per WP (`WP-0.1 ...`, `WP-1.1 ...`, etc.). Do not mix phases.
- After the 1.9.4 tag, merge `release/1.9.x` into `main`; Phase 1 starts from that merge. Do not start Phase 1 from a main without the safety fixes.
- No merge without every WP’s regression test, docs update, and green baseline commands.
- Phase 2 is intentionally one PR as requested. Review commit-by-commit; if it becomes unmergeable, request an explicit exception before splitting it.
- Tag `1.9.4` after Phase 0. Tag `2.0.0-alpha.N` after Phase 1, `2.0.0-beta.N` after Phase 2, and `2.0.0-rc.N` after Phase 3.

## 16. Effort Estimate

Single senior Rust engineer, including tests/docs:

| Phase | Estimate |
|---|---|
| Phase 0 safety gate (1.9.4) | 3–4 weeks |
| Phase 1 refactor foundations (2.0) | 6–8 weeks |
| Phase 2 core hardening (2.0) | 10–14 weeks |
| Phase 3 verification/release (2.0) | 3–4 weeks |
| **Total** | **22–30 weeks** |

No deadline is assumed. Phase 0 is shippable as **1.9.4** (with P1-19/P1-23/P1-24 recorded as residual risks); Phase 1-3 build the 2.0 line. If time is constrained, ship 1.9.4 first and do not start 2.0 breaking work until it is tagged.

---

# Part V — Release Gates

## 1.9.4 gate (Phase 0)

1. All P0 and Phase 0 P1 findings are closed with regression tests; P1-19/P1-23/P1-24 are explicitly listed as residual risks.
2. `cargo fmt --all --check`, `cargo clippy --workspace --all-features --all-targets -- -D warnings`, `cargo test --workspace --all-features --locked`, `cargo deny check` pass on `release/1.9.x`.
3. ACME staging issues/renews/reloads all transports; DNSSEC hostile-chain/strict-mode tests pass; HA partition/drift tests pass; installer upgrade/rollback E2E passes.
4. No breaking config/API/DB/HA changes: `config_version` stays 1, `/api/v1` stays, SQLite schema stays compatible, HA protocol stays v1.
5. Current docs match 1.9.4 behavior; no false claims in README/security/HA/config/release notes.
6. The release workflow requires green CI/security on `release/1.9.x`.

## 2.0 gate (Phase 1–3)

1. All P0/P1 findings in §4 are closed with regression tests, including P1-19/P1-23/P1-24.
2. Baseline commands pass; fuzz targets run 24h clean; benchmarks pass the stored baseline.
3. ACME staging issues/renews/reloads all transports; DNSSEC hostile-chain and real signed-zone tests pass; HA partition/fork/drift/promotion tests pass; `/health` false on a dead master.
4. Installer fresh/upgrade/rollback/uninstall and Docker health/DNS tests pass.
5. Config v1→v2, SQLite migration, API v2, and HA protocol v2 migration/rollback tests pass on a copy of a real 1.9.4 data dir.
6. OpenAPI has security schemes and route coverage; docs commands execute; historical audits are marked.
7. Threat model/security review signed off.

---

# Part VI — Risk Register

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Refactor introduces regressions | High | High | Phase 0 regression tests, per-WP tests, snapshot/behavior tests, feature branches, no big-bang merge. |
| Safety gate delays 2.0 | Medium | Medium | Time-box 3–4 weeks; all P0 and the listed P1s; defer stats P1-19/P1-23/P1-24 to Phase 2 with residual-risk notes. |
| HA protocol v2 breaks clusters | High | High | Coordinated upgrade guide, v1 rejection message, test both mixed and upgraded clusters, rollback. |
| SQLite migration loses history | Low | High | Backup, transactional migration, dry-run on copy, rollback script. |
| Config v2 breaks existing deployments | High | High | `sito config migrate`, deprecation aliases for one alpha, clear errors, docs. |
| ACME changes cause cert outage | Medium | High | Staging test, keep static cert fallback, atomic pair, all-transport reload test. |
| DNSSEC stricter policy causes SERVFAIL | Medium | High | Log-only mode, test real signed zones, metrics, rollback to permissive documented. |
| Parental list sourcing/licensing | Medium | Medium | Prefer maintained public lists with license/checksum; otherwise mark experimental. |
| DoQ/DoH admission breaks legitimate clients | Medium | Medium | Configurable limits, load test, clear 429/REFUSED behavior. |
| Docs rewrite lags code | High | Medium | Docs update is part of each WP; CI checks links/config/OpenAPI. |

---

# Appendix A — Hot Spots (Files Over 1,000 Lines)

| File | Lines | Action |
|---|---:|---|
| `crates/sito-dnssec/src/lib.rs` | 8,064 | Split into anchor/chain/denial/verify/cache; WP-2.1. |
| `crates/sito-api/src/auth/manager.rs` | 5,704 | Split auth domains; WP-1.5/2.10. |
| `crates/sito-api/src/ui/handlers.rs` | 5,431 | Split by page; share DTOs; WP-1.5. |
| `crates/sito-ha/src/master/coordinator.rs` | 3,450 | Extract session state machine; WP-2.9. |
| `crates/sito-ha/src/slave/worker.rs` | 3,402 | Extract session/apply; WP-2.9. |
| `crates/sito/src/pipeline.rs` | 3,255 | Split stages; WP-1.5. |
| `crates/sito-stats/src/metrics.rs` | 1,845 | Split metric families; WP-1.5. |
| `crates/sito-stats/src/db.rs` | 1,404 | Split retention/query; WP-2.12. |
| `crates/sito-stats/src/lib.rs` | 1,394 | Move tests/fixtures; WP-1.8. |
| `crates/sito/src/server.rs` | ~2,300 | Extract init/reload/shutdown; WP-1.5. |
| `crates/sito/src/cli.rs` | ~2,100 | Extract update/restore/health; WP-1.5. |

# Appendix B — Code-Quality Metrics (Production, Approximate)

| Metric | Count |
|---|---:|
| Rust files | 162 |
| Total source lines | ~104,600 |
| Files >1,000 lines | 28 |
| Functions >100 lines | 114 |
| Functions >200 lines | 20 |
| Functions >500 lines | 3 |
| `unwrap` | 63 |
| `expect` | 26 |
| `panic!`/`unreachable!` | 2 |
| `let _ =` | 147 |
| `.ok()` | 96 |
| `unwrap_or_default` | 41 |
| `#[allow(...)]` | 24 |
| Test attributes | 1,045 |
| Ignored tests | 0 |
| Integration test files | 9 |
| Fuzz targets | 0 |
| Workspace crates | 15 |

# Appendix C — Prior Claim Matrix

See §5. This appendix is duplicated into `docs/audit6-claim-matrix.md` by WP-0.1 so the truth is discoverable outside the plan.

# Appendix D — Immediate First PR Checklist

- [x] `cargo test --workspace --all-features --locked` result recorded (1,057 passed, 0 failed).
- [ ] `docs/audit6.md` and `docs/audit6-claim-matrix.md` added.
- [ ] Historical banners on `docs/audit.md`, `docs/audit2.md`, `docs/audit5.md`.
- [ ] Failing tests for P0-1, P0-2, P1-3, P1-8, P1-15, P1-17 committed inside the single Phase 0 PR (one commit per WP).
- [ ] Release freeze note in `CHANGELOG.md` and README.
- [ ] `release/1.9.x` branch exists; Phase 0 PR targets it and tags `v1.9.4`.
- [ ] After 1.9.4, merge `release/1.9.x` into `main` before opening the Phase 1 PR.

# Appendix E — Finding-to-Work-Package Traceability

| Finding range | Work package(s) |
|---|---|
| P0-1 | WP-0.2, WP-2.6 |
| P0-2 | WP-0.3, WP-2.1 |
| P1-1..P1-2 | WP-0.3, WP-2.1, WP-2.2 |
| P1-3..P1-6 | WP-0.4, WP-2.9 |
| P1-7..P1-9 | WP-0.5, WP-2.3, WP-2.4 |
| P1-10..P1-14 | WP-0.6, WP-2.6, WP-2.8 |
| P1-15..P1-16 | WP-0.7, WP-2.10 |
| P1-17, P1-21, P1-22 | WP-0.8, WP-2.13 |
| P1-18 | WP-0.8, WP-2.8 |
| P1-19, P1-23, P1-24 | WP-2.12 (residual risk until then) |
| P1-20 | WP-0.7, WP-2.10 |
| P1-25 | WP-0.9, WP-2.7 |
| P1-26..P1-27 | WP-0.3, WP-0.5, WP-1.4, WP-2.2 |
| P2-1..P2-6 | WP-0.3, WP-2.1, WP-2.2 |
| P2-7..P2-12 | WP-0.9, WP-2.7 |
| P2-13..P2-21 | WP-0.2, WP-0.6, WP-2.6 |
| P2-22..P2-23 | WP-2.8 |
| P2-24..P2-29 | WP-0.5, WP-2.3, WP-2.4 |
| P2-30 | WP-1.1 (move RouterOS optional), WP-2.5 |
| P2-31..P2-37 | WP-2.4, WP-2.5 |
| P2-38..P2-55 | WP-1.3, WP-2.10, WP-2.11 |
| P2-56..P2-63 | WP-2.12 |
| P2-64..P2-66 | WP-0.1, WP-1.8, WP-1.9 |
| P2-67..P2-83 | WP-0.10, WP-2.13, WP-2.14 |
| P2-84..P2-100 | WP-1.3, WP-1.4, WP-2.3, WP-2.4, WP-2.6, WP-2.8 |
| P3-1..P3-10 | WP-1.1, WP-1.5, WP-1.6, WP-1.7 |
| P3-11..P3-12 | WP-0.1, WP-1.8 |
| P3-13..P3-16 | WP-0.10, WP-2.14 |
| P3-17..P3-19 | WP-1.9 |
| P3-20..P3-26 | WP-2.13 |
