# sito-dns — Full Audit #5 (independent, v1.6.0)

Scope: whole workspace (15 crates, ~64k LOC), `.github/`, Docker/systemd,
installer, converter, docs. Method: parallel source review plus hand
verification of every P0/P1 against the tree at `105a310` (`cargo tree`,
rustls/hickory upstream sources, live code paths). No builds were trusted as
evidence.

Severity legend: **P0** = deployment/security blocker, **P1** = high,
**P2** = medium, **P3** = low/cleanup.

Remediation was implemented in this branch (`fix/audit5-remediation`); each
finding marked *Fixed* has a regression test that fails without the fix
(except where noted). Deferred findings remain listed at the end.

---

## P0 — critical

| ID | Finding | Evidence | Status |
|---|---|---|---|
| P0-1 | `DotUpstream::new` used `ClientConfig::builder()`; the graph enables both rustls `ring` and `aws_lc_rs`, so construction panics ("could not determine CryptoProvider") and `panic = "abort"` kills the daemon for any `tls://` upstream — including `config.example.toml`. | `crates/sito-upstream/src/dot.rs:50`; `cargo tree -p sito` shows both providers; no `install_default` in tree | **Fixed** (`builder_with_provider(ring)` + test that constructs `DotUpstream::new`) |
| P0-2 | DNSSEC accepted RRSIGs from any chain-validated key for records of any owner: a signed attacker zone could authenticate `victim.com A` with `signer=attacker.example`, set AD=1, and poison the cache served to DO clients. | `crates/sito-dnssec/src/lib.rs:1374-1414,1471`; negative path already checked `trusted_signer_covers_qname` | **Fixed** (RFC 4035 §5.3.1 signer containment + hostile test) |
| P0-3 | The setup token was pruned after 24 h; `/ui/wizard/complete` is exempt from the middleware and only checks the token while one exists, so any network peer could set a new admin password on a server left in first-run. | `auth/manager.rs:1421-1427`, `router.rs:133-139`, `ui/handlers.rs:2057-2106` | **Fixed** (token lives until setup completes; one-time pending warning instead; clock-advance test) |

## P1 — high

| ID | Finding | Evidence | Status |
|---|---|---|---|
| P1-1 | CSRF percent-decoder sliced `&str` at `i+1..i+3`, panicking (abort in release) on `%` followed by a multi-byte character; reachable by any authenticated mutating request. | `sito-api/src/security.rs:227` | **Fixed** (byte-wise decoder + non-ASCII tests) |
| P1-2 | `$client=` matched `ctx.id` set from the client-controlled DoH path / DoT SNI, bypassing client-scoped allow/exclude rules. | `sito-filter/src/parser.rs:77`; `doh.rs:177` | **Fixed** (registry-resolved identity only; spoof tests) |
| P1-3 | A failed initial list load left an enabled engine with an empty snapshot that allowed everything; no fail-closed option existed. | `sito-filter/src/engine.rs:478,833` | **Fixed** (`filtering.fail_closed`, default true, SERVFAIL + `FilterUnavailable`) |
| P1-4 | Background prefetch inserted raw upstream responses into the cache, trusting attacker-supplied AD=1 for entries served to clients signalling AD interest (and marking them secure in logs). | `sito/src/pipeline.rs:584-611` vs validated path `:965+` | **Fixed** (prefetch validates; test fails without it) |
| P1-5 | HA `apply_config_push` wrote raw ArcSwaps while the pipeline reads `RuntimeState::snapshot`, so pushed config reached queries only if the file watcher happened to fire after a `Synced` ACK. | `sito-ha/src/slave/worker.rs:137-150`; `sito-runtime/src/lib.rs:65` | **Fixed** (handles carry `RuntimeState`, `replace`; e2e snapshot assertion) |
| P1-6 | The slave persisted the master's sanitized TOML verbatim, deleting `[ha]` and `instance_name`; after one push + restart, replication was silently lost. | `sito-ha/src/bundle.rs:68-75`, `worker.rs:154` | **Fixed** (local `[ha]`/identity/data_dir merged on persist + tests) |
| P1-7 | `POST /config/reload` returned success while applying only the config snapshot; `PUT /config` accepted configs the startup validation rejects (deep validation lived only in the binary). | `sito-api/src/handlers/config.rs:203-231,353-375`; `sito/src/server.rs:78-109` | **Fixed** (shared `sito-api::config_validation`; reload applies all hot components; truthful restart list) |
| P1-8 | `update_require_signature` defaulted to false and `sito update` silently dropped it if the config was unreadable; cosign identity was repo-wide. | `sito-core/src/config.rs:369`; `sito/src/cli.rs:548`; `updater.rs:336` | **Fixed** (default true, CLI fails closed, identity pinned to release workflow tags) |
| P1-9 | `verify_totp` did not hold `totp_verification_lock`, so concurrent requests could replay one TOTP step or spend one backup code twice. | `auth/manager.rs:1030-1116` | **Fixed** (lock spans read-verify-write; concurrency test fails without it) |
| P1-10 | Restore archive extraction had no per-entry or total decompression cap (gzip bomb). | `sito-api/src/handlers/config.rs:431-447` | **Fixed** (4 MiB config / 64 KiB metadata / 8 MiB total + bomb test) |
| P1-11 | Rate limiting was per listener and only at accept time for TCP/DoT/DoQ, so clients multiplied budgets across protocols and per connection. | `sito-transport/src/{tcp,dot,doq}.rs`; `sito/src/server.rs:1467+` | **Fixed** (one shared per-IP bucket, per-query on every transport, DoT connect semaphore) |
| P1-12 | Nightly fuzz could never run (install-action had no `tool:` input; `rust-toolchain.toml` overrode nightly), and `workflow_dispatch` releases could never publish (no `tag_name`, `draft: false`). | `.github/workflows/nightly-fuzz.yml:87`, `release.yml:142` | **Fixed** (`tool: cargo-fuzz`, `RUSTUP_TOOLCHAIN: nightly`, tag passed and verified, timeouts) |
| P1-13 | AdGuard converter emitted `blocking_mode = "custom_ip"` (invalid variant, IP dropped) and invalid TOML for regex rules (only quotes escaped). | `contrib/adguard_to_sito.py:75-83,173-174` | **Fixed** (`custom_ip:<ip>`, full TOML escaping, per-client mapping; acceptance test extended) |

## P2 — fixed in this branch

- **Cache**: out-of-bailiwick answer owners are rejected; CNAME targets are
  re-evaluated on cache hits; every filter reload path flushes the cache.
- **IDN**: query-side matching/routing/cache keys use punycode; per-domain
  config accepts raw IDN (`normalize_domain_or_idna`).
- **Subscriptions**: SSRF denylist unwraps NAT64/6to4/Teredo; disk-cache reads
  are size-capped.
- **Transport**: DoH body limit (65535) + axum body-limit layer; DoQ/DoH3
  stream step timeouts; DoH3 partial-body errors no longer decode partial
  messages; DoH3 GET length checked.
- **DNSSEC**: key fetcher sets DO; RRSIG failures are only fatal when the
  covered RRset is relevant to the question.
- **HA**: concurrent `update_bundle` cannot regress the version; client
  secrets and RouterOS credentials are stripped from bundles and restored
  locally.
- **API/auth**: deleting/overwriting a user revokes sessions; API tokens
  default to a 90-day TTL; group `description` persists; query-log rate-limiter
  state is bounded.
- **Metrics**: `sito_filter_rules` and `sito_filter_compile_seconds` are wired;
  label cardinality is capped at 4096 with `__other__`; upstream error labels
  use bounded kinds.
- **Runtime lists**: concurrent category updates are serialized (lost-update
  regression test).
- **Ops**: ACME bootstrap key written 0600 with errors logged; watcher
  initialization failures log the hot-reload impact at error level.

## Follow-ups completed after the first remediation pass

1. **NSEC wildcard denial proofs** (`nsec.rs`): NXDOMAIN now requires both an
   NSEC covering the qname and an NSEC covering the wildcard at the closest
   encloser (RFC 4035 §5.4); wildcard NODATA (NSEC at `*.<ancestor>` denying
   the type plus a cover of the exact name) is accepted instead of failing
   closed. NSEC records are grouped per signer so multi-record proofs are
   evaluated together. Tests cover the secure, missing-wildcard-denial and
   wildcard-NODATA cases, and the existing Bogus/Indeterminate cases.
2. **HA duplicate-instance cleanup race**: each connection carries a monotonic
   id in its `ActiveSlave`; cleanup, watchdog, ACK/stats/pong handling and
   resync only act while the session owns the entry. Unit test covers the
   unregister race.
3. **HA master accept loop**: TLS + WebSocket upgrades are bounded by a 10 s
   handshake timeout and connections by a 64-session semaphore; a stalled
   socket is closed (regression test).
4. **Wizard TLS acceptors**: the setup-complete path re-runs TLS/ACME
   initialization against the updated config before binding listeners; a unit
   test proves acceptors populate from a config that appeared after startup.
5. **RouterOS sync registry**: registry generations share the RouterOS lease
   store, so the running sync task keeps updating the live identification
   data across reloads (unit test).
6. **Listener rebind failure**: `restart()` no longer consumes the manager and
   always leaves a usable manager in the slot; the rebind test now covers a
   failed bind followed by a successful rebind to a third port.
7. **Docs/ops truth pass**: `security-audit.md` rewritten to the implemented
   controls, `SECURITY.md` version corrected, HA runbook dead links/false
   metrics/log paths fixed, benchmarks marked as a reference-hardware run with
   the phantom `target-cpu` and conflicting RSS numbers resolved,
   `first-time-setup.md` marked historical, README Compose example completed,
   and Docker images now create `/etc/sito` owned by the nonroot uid;
   per-archive `.sha256` files are published as documented.

**Accepted limitation (unchanged):** the deprecated `?token=` query parameter
is accepted only on the WebSocket upgrade when no `Authorization` header is
present, logs a warning, and is scheduled for removal in 2.0.

## Production-readiness snapshot (post follow-ups)

| Area | Before | After |
|---|---:|---:|
| DNSSEC | 3 | 8 |
| Upstream | 4 | 8 |
| Filter engine | 5 | 7.5 |
| API/UI/auth | 4.5 | 7 |
| HA | 4 | 7.5 |
| Transport | 5 | 7 |
| Binary/pipeline | 4 | 7.5 |
| Cache | 7 | 8 |
| Stats | 7 | 8 |
| CI/CD | 4 | 7 |
| Overall | 4.5 | ~8 |

Conclusions: the three P0s were release-blocking and are fixed with tests; the
entire P1 set (auth bypass, panic, fail-open, HA state, supply chain, CI) and
all deferred P2 follow-ups in the list above are closed. The only intentional
departure from strictness is the documented `?token=` WebSocket deprecation,
which fails closed for every other endpoint.
