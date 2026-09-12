# sito-dns v1.2.1 — Post-Remediation Audit & Fix Plan (Agent Handoff)

## Context

This is a full re-audit after PR #5 (P0-3…P3-24 remediation). Prior fixes are verified **real and correctly implemented** (server gate, updater hard-fail, systemd hardening, UDP per-query spawn, cache TTL clamp, bootstrap `.first()` guard, upstream manager persistence). However the audit found a cluster of **HA master-side security gaps**, one **wizard bug that leaves default credentials active**, and several correctness/data-quality bugs. Tera autoescaping covers template XSS; no TODO/FIXME debt exists; UI RBAC is consistent.

**Note:** plan mode blocked compilation; the fix agent MUST run `cargo clippy --workspace --all-features -- -D warnings` and `cargo test --workspace` first (step 0) to establish a green baseline before touching code.

***

## P1 — Security (fix first)

### P1-1: HA master replication is unauthenticated/unencrypted by default

* `crates/sito-ha/src/master/coordinator.rs:393-428` (`spawn_master_server`): when `[ha]` has no `cert`/`key`, the master serves **plaintext WebSocket on 0.0.0.0:8953** with no warning, no opt-in gate.

* `crates/sito-ha/src/transport/mtls.rs:88`: `PinnedClientCertVerifier` **accepts ANY client certificate when** **`pinned_slave_fingerprints`** **is empty**; `verify_tls12/13_signature` (lines 97-113) are unconditional `Ok(assertion())` no-ops.

* `crates/sito-ha/src/master/coordinator.rs:188-197`: slave token optional.

* `crates/sito-ha/src/config.rs:116-156`: `HaConfig::validate()` **only validates the slave role** and — critically — **is never called from production code** (only in tests, `sito-ha/src/lib.rs:171-192`). Slave-side hardening from the previous remediation is effectively dead in production.

**Fix (all required):**

1. Call `ha_config.validate(&config.server.role)` in `crates/sito/src/server.rs` right after building `ha_config` (\~line 150-155); fail startup on error.
2. Extend `validate()` with a `"master"` branch: when replication enabled (`replication_port > 0`), require **at least one** of `slave_token` or non-empty `pinned_slave_fingerprints`; reject `cert`/`key` missing unless `allow_insecure_ws = true` (explicit opt-in).
3. In `PinnedClientCertVerifier::verify_client_cert`, reject empty pin lists outright (`if self.pinned_fingerprints.is_empty() { return Err(...) }`) instead of accept-all.
4. Implement real signature verification in both verifiers (or delegate to `rustls::crypto::verify_tls12/13_signature` with the ring provider's algorithm set) — no-op signature checks defeat cert ownership verification.
5. `spawn_master_server`: log a loud `error!` and refuse to serve plaintext when TLS is unset and `allow_insecure_ws` is false.

### P1-2: Wizard can mark setup complete while default credentials remain active

* `crates/sito-api/src/ui/handlers.rs:1416-1419`:

```1416:1419:crates/sito-api/src/ui/handlers.rs
    let _ = ctx
        .auth_mgr
        .update_user_password(&form.admin_user, &form.admin_password);
    ctx.auth_mgr.mark_setup_complete();
```

`update_user_password` returns `Result` that is discarded; if `admin_user` doesn't match an existing user (free-text field), the password change silently fails and the wizard closes → **default admin credentials stay live with** **`first_run`** **cleared**.

**Fix:** propagate the error (400 + retry form). If the username doesn't exist, create the user as Admin (that's the wizard's purpose) or pre-fill/restrict to the bootstrapped username. Also propagate the discarded `save_config_atomic` error at line 1427.

### P1-3: `/metrics` unauthenticated by default

* `crates/sito-core/src/config.rs:249` defaults `metrics_auth: false`; `crates/sito-api/src/handlers/metrics.rs:25` allows anonymous access when false. Previous remediation made it *configurable*, but the changelog claims auth enforced.
  **Fix:** flip default to `true` (breaking change → bump minor, note in CHANGELOG), or enforce network restriction (bind check) when false. Update README + example config.

***

## P2 — Correctness / bugs

### P2-1: HA config changes are never pushed to slaves

`MasterCoordinator::update_bundle` is called **only once at startup** (`crates/sito/src/server.rs:195`). No API/UI handler calls it (verified by search) → slaves keep version 1 until master restart; `trigger_resync` re-pushes the stale bundle.
**Fix:** call `update_bundle` (bumping version = current + 1) on every mutating API/UI operation (filter rules, rewrites, clients, config save). Centralize in one `publish_bundle(&ctx)` helper.

### P2-2: NXDOMAIN negative caching is dead code

`crates/sito/src/pipeline.rs:456` and `:562` gate cache insert on `ResponseCode::NoError` only, while `sito-cache/cache.rs` and config implement full negative-TTL support.
**Fix:** extend the insert gate to cache negative responses per their SOA/NEGATIVE TTL (`cache.rs` already computes it). Add a test: NXDOMAIN cached, re-query hits cache with negative TTL.

### P2-3: Per-upstream stats are meaningless

`crates/sito/src/pipeline.rs:576` writes literal `"upstream"` as the upstream label; UI querylog "upstream" column and any per-upstream stats are useless. Additionally `sito_stats::anonymize_ip` is exported but **never called anywhere** (dead privacy feature).
**Fix:** thread the actual upstream ID/URL into `QueryLogEntry`; wire `anonymize_ip` behind a `privacy.anonymize_querylog` config toggle applied in the stats writer.

### P2-4: Filter engine — join error silently wipes all rules

`crates/sito-filter/src/engine.rs:386`: on `spawn_blocking` join error, falls back to an **empty default snapshot** and — because `reload_with_config` passes `apply_drop_guard=false` — stores it, unblocking all traffic.
**Fix:** treat join error as failure: return `Err(FilterError)` and keep the previous snapshot. Map-then-store only on success.

### P2-5: Slave stats reporting is a stub

`crates/sito-ha/src/slave/worker.rs:414-425`: `StatsReport` always sends `queries: 0, blocked: 0, upstreams: {}` while advertising the `stats-v1` capability.
**Fix:** collect from `MetricsRegistry`/`QueryLogWriter` counters within the window, or remove the capability until implemented.

### P2-6: Corrupt `users.toml` silently re-bootstraps default credentials

`crates/sito-api/src/auth/manager.rs` (`with_storage` load path): a parse failure falls back to bootstrap instead of failing loudly → admin lockout is "solved" by corruption, and default creds may come back.
**Fix:** on parse error, back up the corrupt file and require a CLI `--reset-admin` (or similar) instead of silently recreating defaults. At minimum `error!` + refuse to start.

### P2-7: `X-Forwarded-For` uses the first (leftmost) entry

`crates/sito-api/src/auth/client_ip.rs:43-57`: a trusted proxy that *appends* client IP is standard; taking the leftmost lets clients behind the proxy spoof their identity (client naming, per-client rules, lockout targeting).
**Fix:** when the peer is trusted, take the **last** entry in the list; keep leftmost only as documented fallback. Add a spoofing test.

### P2-8: UI handlers swap in-memory config even when persistence fails

Pattern (e.g., `ui/handlers.rs:1427-1428`, metrics/settings handlers): `save_config_atomic` result ignored, then `config.store()` proceeds → runtime/disk drift, silent loss on restart.
**Fix:** save first, only `store()` on success; surface HTTP 500 on persist failure.

***

## P3 — Performance / polish

1. **Double candidate collection per query** — `engine.rs` `evaluate()` → `evaluate_important()` collects allow/block candidates, then `evaluate_standard()` collects them again. Refactor `evaluate()` to collect once and pass candidates through (hot path).
2. **REST** **`PUT /upstream`** **requires manual restart** (`handlers/upstream.rs`) while UI edits hot-reload — inconsistent. Apply live via `UpstreamManager` reload.
3. **Per-query INFO log in pipeline** — one log line per DNS query is noisy at scale; make it `debug`/sampled, keep `info` for blocks.
4. **Docker**: `EXPOSE` only 53 — add 853 (DoT), 443 (DoH), 8080 (web) and document `cap_add` (compose already has it). No GHCR publish workflow exists — add one to `release.yml`.
5. **CI**: build job compiles `debug` profile only; add a `--release` smoke build for x86\_64.
6. UDP crate uses `std::os::fd` unconditionally (Unix-only) — add a `#[cfg(unix)]` guard with a clear compile error on other targets, or document Linux-only support in README.

***

## Prod-readiness verdict

**Conditional yes** for single-node home/LAN use after P1-1…P1-3 (HA unused = low risk, wizard = high risk, metrics = medium). **No for clustered/master deployments** until the HA block is fixed — default master config disseminates the full (sanitized) config to any connecting client. Infra (distroless, compose caps, cargo-deny advisories, fuzz job, release workflow) is in good shape.

## Suggested new features (post-fix backlog)

* **DoH/DoQ upstream support** (currently plain + TLS only) — biggest functional gap vs AdGuard.

* **DNSSEC validation** (trusted keys + hickory validation mode).

* **Live per-upstream latency dashboard** (depends on P2-3) + Grafana dashboard JSON export.

* **Querylog privacy toggle** (depends on P2-3 anonymize wiring) + retention pruning policy in UI.

* **Persistent API tokens** (PAT) for automation; sessions currently memory-only — optionally persist sessions so restarts don't log users out.

* **SIGHUP config hot-reload** + config change webhook/audit log.

* **2FA (TOTP) for the web UI** — `sito-totp`-style dependency, pairs with existing lockout/RBAC.

* **Prometheus** **`/metrics`** **hardening**: optional separate listener + basic auth when `metrics_auth=false`.

***

## Execution order & verification

| Step           | Targets                                                                                                 | Verification                                                                                                                                         |
| -------------- | ------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0              | —                                                                                                       | `cargo clippy --workspace --all-features -- -D warnings`; `cargo test --workspace` green baseline                                                    |
| 1 (P1-1)       | `sito-ha/config.rs`, `transport/mtls.rs`, `master/coordinator.rs`, `sito/src/server.rs`                 | New unit tests: empty pins rejected, master validate fails without token/pins, plaintext refused; existing `lib.rs` HA integration test still passes |
| 2 (P1-2)       | `sito-api/ui/handlers.rs`, `auth/manager.rs`                                                            | Wizard test: wrong username → 400, `first_run` stays true; nonexistent user → created as admin                                                       |
| 3 (P1-3)       | `sito-core/config.rs`, `handlers/metrics.rs`, README, example config                                    | Anonymous `/metrics` → 401 by default; authorized path still 200                                                                                     |
| 4 (P2-1)       | `sito/src/server.rs`, new `publish_bundle` helper, mutating handlers                                    | Integration test: config change bumps version & broadcast received by fake slave                                                                     |
| 5 (P2-2, P2-3) | `sito/pipeline.rs`, stats writer                                                                        | NXDOMAIN cache hit test; querylog shows real upstream ID                                                                                             |
| 6 (P2-4…P2-8)  | `sito-filter/engine.rs`, `sito-ha/slave/worker.rs`, `auth/manager.rs`, `auth/client_ip.rs`, UI handlers | Join-error keeps old snapshot; XFF last-entry spoof test; persist-failure → 500 without swap                                                         |
| 7 (P3)         | engine.rs, pipeline.rs, upstream.rs, Dockerfile, ci.yml                                                 | Bench or unit check for single-pass candidates; `docker build` smoke; clippy clean                                                                   |
| 8              | CHANGELOG + version bump                                                                                | `cargo test --workspace` full suite green                                                                                                            |

**DoD:** all steps verified; no new clippy warnings; HA integration tests cover auth-negatives; CHANGELOG updated; report maps each finding ID to fixed/deferred.
