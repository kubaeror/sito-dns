# sito-dns v1.4.0 — Full Audit #3 (post first-time-setup-wizard)

Scope: whole workspace (14 crates, ~39k LOC), `contrib/`, Docker, systemd, CI, release
pipeline, docs and example configuration. Findings were verified directly in source
(all `file:line` references point at commit `82c8672` + untracked docs at audit time).

Severity legend: **P0** = deployment/security blocker, **P1** = high, **P2** = medium,
**P3** = low / cleanup.

Remediation status for every finding is tracked in the table at the end of this document.
All fixes for this audit are implemented in the same PR as this document.

---

## P0 — Critical

### P0-1. Release tarball installer is broken
`contrib/install.sh:180-181` extracts the release archive and copies `${TMP_DIR}/sito`,
but the release workflow packs a top-level directory
(`release.yml:71,79` → `sito-v1.4.0-<target>/sito`). The copy fails and `set -e` aborts.
A fresh install from a published release can never succeed.
Also `release.yml:70` reads `VERSION="${GITHUB_REF_NAME:-...}"`, which ignores the
`tag_name` input on `workflow_dispatch` (GITHUB_REF_NAME is always set).

### P0-2. Installer verification bypass
`contrib/install.sh:118-120` installs `target/release/sito` from the working directory
(running as root) with no checksum and no signature verification. Line 121
(`elif [ -f "${TMP_DIR}/sito" ]`) is dead code because `TMP_DIR` is empty at that point.

### P0-3. TOTP second factor is brute-forceable
`crates/sito-api/src/auth/manager.rs:505-537`: `verify_totp` never checks the lockout
tracker or the IP rate limiter, does not invalidate the partial token after a wrong
code, and ignores the `record_failure` result. Anyone who knows the password gets
unlimited attempts against a 6-digit TOTP (and 32-bit backup codes).

### P0-4. Setup wizard completes with default credentials
`crates/sito-api/src/ui/handlers.rs:1837-1853`: an empty password on first run silently
maps to `"adminadmin"`, then `mark_setup_complete()` (`:1917`) locks in the default.
A deployment can go "live" with default admin credentials. Tests assert this fallback
(`ui/handlers.rs:2201`), i.e. it is intentional behaviour that must be removed.

### P0-5. Fail-open when `users.toml` disappears
`crates/sito-api/src/auth/manager.rs:230-236` re-creates `admin/adminadmin` if the
users file is missing, leaving `setup_complete=false`. `setup_pending` only depends on
`config.toml` existing (`crates/sito/src/main.rs:99`), and the wizard accepts
unauthenticated access while `is_first_run()` is true
(`ui/handlers.rs:1802`). Deleting/losing `users.toml` (or an HA mis-sync) turns the
wizard into an unauthenticated admin-password reset.

### P0-6. HA Docker deployment is inert; env overrides do not exist
`docker-compose.ha.yml:54-60,86-92` sets `DNSD__SERVER__ROLE`, `DNSD__HA__*` and
`docs/configuration-reference.md:5` advertises `DNSD__<SECTION>__<KEY>` overrides, but
the code reads only `DNSD_SECRET_*` (`sito-ha/src/bundle.rs:186`). Both containers boot
as default master/wizard. The env names (`CERT_PATH`, `KEY_PATH`, `CA_PATH`) do not even
match the real config fields (`cert`, `key`, `ca`).

### P0-7. Filter `$important` allowlist has no effect
`crates/sito/src/pipeline.rs:298-300` only reacts to `verdict.is_blocked()`, while
`evaluate_standard_candidates` skips `important` allow rules
(`sito-filter/src/engine.rs:203-205`). `@@||domain^$important` is therefore ignored and
a standard blocklist entry still wins. This is the documented override mechanism for
premium allowlists.

### P0-8. CNAME cycle in local rewrites crashes the process
`sito-rewrites/src/table.rs:155,188` recurse `lookup()` without a visited set or depth
limit. A configuration with `{a CNAME b, b CNAME a}` (or any loop) causes unbounded
recursion → stack overflow, and `panic = "abort"` kills the resolver.

---

## P1 — High

### P1-1. DoH3 request body is unbounded (memory DoS)
`sito-transport/src/doh3.rs:246-252` accumulates every `recv_data` chunk into a `Vec`
with no cap; a single HTTP/3 client can push until OOM. No axum `DefaultBodyLimit`
applies on this path.

### P1-2. DNSSEC validation cannot build a trust chain and is downgrade-prone
`sito-dnssec/src/lib.rs:442-449` accepts a key only if it *is* a configured anchor; there
is no DS/DNSKEY chain walking. Unsigned responses are classified `Insecure`
(`:353-359`), so stripping RRSIGs in Validate mode yields a non-SERVFAIL answer. Also
`mode = "permissive"` is accepted by `config.rs:627` but `DnssecMode::from` maps it to
`Validate` (`lib.rs:34-42`, strict instead of permissive). First failing RRSIG aborts
even if another valid signature exists (`:364-384`).

### P1-3. HA bundle replay/downgrade
`verify_and_unpack_push` checks monotonicity on the envelope
`HaMessage::ConfigPush.version` (`sito-ha/src/bundle.rs:259-287`), but the signature
covers only the payload and the slave stores `bundle.version`
(`slave/worker.rs:159`). An attacker (plaintext `ws://` is explicitly supported) can
replay an old signed payload with a bumped envelope version, rolling state backward.

### P1-4. Upstream IPv6 literals are unusable
`sito-upstream/src/manager.rs:99-105,121-127` splits on `:` — `tls://[2606:4700::1111]:853`
is parsed as host `[2606`; a bare `2001:db8::1` fails `SocketAddr` parsing and the
fallback resolves the hostname `2001`.

### P1-5. Upstream answers are never validated
`sito-upstream/src/plain.rs:100-110` and `dot.rs:161-168` return the decoded response
without checking the message ID or the question section against the outgoing query.

### P1-6. Slave read-only middleware does not cover the UI
`crates/sito-api/src/router.rs:211-214` applies `slave_read_only_middleware` only to
`api_v1`; `ui_router()` is merged at `:223` without it, so a slave's web UI can mutate
local config/state.

### P1-7. Plaintext DoH fallback
`crates/sito/src/server.rs:735-748` silently starts a plaintext HTTP DoH listener when
TLS is absent and `doh_port != 443`, without warning or opt-in.

### P1-8. TCP pipelining spawns unbounded tasks
`sito-transport/src/tcp.rs:176-184` spawns one task per query with no per-connection cap
(DoT has 1000). An attacker can pipeline queries on one connection without bound.

### P1-9. ACME TLS-ALPN challenge map is lost on reload
`sito-transport/src/tls.rs:438` / `acme.rs:394-397` rebuild the server config via
`load_server_config`, which creates a new empty challenge map (`tls.rs:276-283`), while
`register_challenge` writes to a different map (`tls.rs:346-348`). After the first cert
reload, ACME challenges fall through to the default cert and validation fails. ACME
account key/`key.pem` are also written with default permissions
(`acme.rs:174-180,379-386`).

### P1-10. Sessions/tokens survive credential changes and restarts
Sessions and API tokens are memory-only (`auth/manager.rs:90-100`), and
`update_user_password`/`disable_totp` never purge the user's sessions, so a stolen
session survives a password/2FA change.

### P1-11. No CSRF protection or security headers
The UI relies only on `SameSite=Strict` (`auth/session.rs:58`); no Origin/Referer check
or per-form CSRF token exists, and no CSP/X-Frame-Options/X-Content-Type-Options/HSTS
headers are set anywhere.

### P1-12. `users.toml`/config persistence details
`config_writer.rs:24-43` writes to a deterministic `.tmp` name and `File::create`
(default 0644) even though the config can contain `slave_token`. `GET /api/v1/config`
masks `key/password/secret/token` prefixes but not `slave_token`.

### P1-13. `/metrics` and stats surface partially stubbed
The querylog drop counter (`stats/metrics.rs:195-200`), cache-stale counter, upstream
RTT/errors/health, `dnssec_bogus` and `clients_identified` are never updated on
production paths, while `/metrics` advertises them with default values. The
`cache_size_bytes` gauge is only updated in some paths.

### P1-14. Hot reload is partial and torn
Components still capture startup config: `UpstreamManager` is never reloaded by the file
watcher (`server.rs:354-453`), `DnsCache` owns a frozen `CacheConfig`, the filter engine
keeps a frozen `FilteringConfig` (`engine.rs:336`) so the next scheduled refresh reverts
UI edits, and the rate limiter / DNSSEC / retention / listener settings require restart.
The watcher also silently does nothing when `config.toml` does not exist at startup
(`server.rs:371-379`). Three `ArcSwap`s are loaded independently per query, so a query
can observe mixed old/new state.

### P1-15. `check-config` cannot validate TOML-valued sections
`[web]`, `[auth]`, `[stats]`, `[ha]`, `[integrations]` are stored as `toml::Value`
(`sito-core/src/config.rs:30-43`); parse failures fall back to defaults with only a
`warn!`, silently dropping trusted proxies / metrics auth / retention policy.

### P1-16. Healthcheck false positives
`crates/sito/src/cli.rs:225-233` accepts any decodable DNS response (ignores ID and
rcode), so SERVFAIL/REFUSED still reports healthy. It also always probes `127.0.0.1`,
ignoring the configured `dns.bind`.

---

## P2 — Medium

- **P2-1 Filter engine fail-open:** a single unsupported regex drops the whole
  regex+wildcard class (`compiled.rs:204-209`); only one regex/wildcard candidate is
  collected per domain (`compiled.rs:84-91`).
- **P2-2 Downloader:** whole body is buffered before the size check
  (`subscription.rs:214-229`); `file://` bypasses the limit entirely.
- **P2-3 Cache:** key ignores DO/CD (`cache/key.rs:7-11`) so a DO client can be served a
  non-DNSSEC entry; fallback 300 s for negative answers without SOA; `*3600` overflow
  with absurd config (no validation caps).
- **P2-4 Cache config is frozen:** toggling cache `enabled` hot is a silent no-op; the
  pipeline checks live config while the cache checks its own copy.
- **P2-5 Parental/service lists are stubs:** `clients/parental.rs` ships 20/12 domain
  lists while the UI presents them as full category protection.
- **P2-6 Per-client knobs dead:** `EffectivePolicy.upstreams`,
  `use_global_upstreams`, `ignore_stats` are populated but never read.
- **P2-7 RouterOS disables TLS verification unconditionally**
  (`clients/routeros.rs:180-184`) with a default `https://192.168.1.1`.
- **P2-8 Schedule expansion semantics:** `0 0 * * *` expands to the whole 00:00–00:59
  hour; 7-field crons pass validation but get no window
  (`clients/schedule.rs:163,271-308`).
- **P2-9 Filters/per-domain allocations:** `format!(".{rule}")` in parental/services and
  parser `$denyallow`; hash-order-dependent rule precedence
  (`compiled.rs:144-169`).
- **P2-10 Dead knobs:** `filtering.lists[].refresh_hours`, `ha.ping_interval_secs`,
  `ha.ca`, `dns.doh_dedicated_hostname`, `acme.http_port`, updater/HA config fields,
  `PROTOCOL_VERSION`.
- **P2-11 Stats:** `top_domains`/`top_clients` always `[]`, `db_size_bytes` ignores
  `-wal`, retention window snapshotted at startup, backdated inserts can be deleted
  unaggregated.
- **P2-12 HA robustness:** master silently drops pushes on `try_send` failure
  (`coordinator.rs:110`), trusts slave-reported `have_version` (can suppress
  replication), no protocol role check, clean-disconnect reconnect spin, per-instance
  metric label never removed, `slave_token` compared with `!=`.
- **P2-13 Updater:** no signature verification despite the doc comment, no download
  size cap, `browser_download_url` not host-pinned; `apply_update` writes the binary
  while systemd `ProtectSystem=strict` (unit files) blocks it.
- **P2-14 Config/docs drift:** `[[clients.groups]]` documented as array but is a map;
  `[web].bind` array in docs vs `IpAddr` in code; `[stats]` keys that do not exist;
  DNSSEC modes documented as `off|process|log_fail` vs accepted
  `validate|strict|log_only|permissive|off`; SIGHUP claimed but only SIGTERM handled;
  `doh_dedicated_hostname` never read; example config enables `doq_port = 853` against
  the 1.3 port-conflict fix.
- **P2-15 Installer/ops:** `setcap || true`; no uninstaller; `.bak` never restored on
  failed health check; health check hardcodes port 8080; `curl | sudo bash` unpinned.
- **P2-16 Docker:** nonroot (uid 65532) cannot write the host bind mount
  `./config:/etc/sito`; healthcheck probes DNS port 53 which is closed during setup
  wizard mode → permanently unhealthy; 443/udp missing from compose; Dockerfile builds
  without `mimalloc`.
- **P2-17 Release:** no cosign signing exists despite installer + CHANGELOG claims;
  `latest` tag never pushed on tag builds (`enable={{is_default_branch}}`); image is
  `ghcr.io/<repo>` = `sito-dns` while README/docs pull `.../sito`; `id-token: write`
  unused.
- **P2-18 Fuzz workspace:** `fuzz/Cargo.toml` lacks `[workspace]` and root lacks
  `exclude = ["fuzz"]` → cargo workspace resolution error, nightly fuzz job broken.
- **P2-19 Dead code:** `IntoArcSwap` (tests only), unused public helpers across
  filter/cache/clients, duplicated blocked-response builders and anti-bypass blocks in
  `pipeline.rs`, 3× duplicated length-prefix loops in transport, `run_server_full` 645
  lines.
- **P2-20 Shutdown:** listener `JoinHandle`s are collected but never awaited; filter
  refresh task has no shutdown; cert watcher handle dropped.
- **P2-21 XFF fallback:** when the peer is not trusted the leftmost (attacker-supplied)
  XFF entry is still used (`auth/client_ip.rs:57-62`), and an absent peer address is
  treated as trusted (`:68-84`).
- **P2-22 UI/API mutation handlers that silently "succeed"** without applying changes
  (full-config PUT does not reload filter/upstream/clients/rewrites;
  `trigger_ha_resync` ignores send failure; several `let _ =` reloads).
- **P2-23 Corrupt-list handling in clients:** silent drops of invalid rewrite entries,
  anti-bypass JSON parse errors ignored, `services.rs` panics.

---

## P3 — Low / cleanup

- Querylog metric names/values drift (`cache_size_bytes`, retentions), magic numbers
  throughout (TTLs, buffers, intervals).
- `docs/audit.md`, `docs/audit2.md` were untracked; docs version drift (`README` says
  v1.3, security audit says v1.0.0).
- `config.example.toml` referenced nowhere and not shipped in the release archive.
- Grafana dashboard has no import instructions.
- `adguard_to_sito.py` emits config with invalid types/unsupported keys and silently
  degrades to defaults without PyYAML.
- Duplicate git-hook systems (`.pre-commit-config.yaml` vs `scripts/git-hooks`).
- `setcap` capability is lost after a self-update replaces the binary.

---

## Prod-readiness scorecard (audit time)

| Area | Prod-ready | Completion |
|---|---|---|
| Overall architecture | 7/10 | 85% |
| Security (auth/API) | 4/10 | 70% |
| Core pipeline | 6/10 | 80% |
| Filter engine | 6/10 | 80% |
| Cache | 7.5/10 | 85% |
| Rewrites | 5/10 | 70% |
| Clients | 5.5/10 | 65% |
| Transport | 5/10 | 75% |
| Upstreams | 4/10 | 50% |
| DNSSEC | 3/10 | 40% |
| API/UI | 6/10 | 85% |
| HA | 5/10 | 70% |
| Stats | 7/10 | 80% |
| Tests | 5/10 | 70% |
| Build/release | 4/10 | 60% |
| Docker/systemd/ops | 5/10 | 60% |
| Docs | 3/10 | 55% |
| **Overall** | **5/10** | **~75%** |

---

## Remediation status (this PR)

| ID | Finding | Status |
|---|---|---|
| P0-1 | Installer tarball path / dispatch tag | Fixed |
| P0-2 | Installer verification bypass | Fixed |
| P0-3 | TOTP brute force | Fixed |
| P0-4 | Wizard default password | Fixed |
| P0-5 | users.toml fail-open | Fixed |
| P0-6 | HA compose env overrides | Fixed (documented as unsupported; compose uses config files) |
| P0-7 | `$important` allowlist | Fixed |
| P0-8 | CNAME cycle crash | Fixed |
| P1-1 | DoH3 body cap | Fixed |
| P1-2 | DNSSEC chain/permissive/multi-RRSIG | Partially fixed (mode mapping, multi-RRSIG, downgrade guard); full DS/DNSKEY chain walking documented as deferred |
| P1-3 | HA bundle replay | Fixed |
| P1-4 | IPv6 upstream literals | Fixed |
| P1-5 | Upstream response validation | Fixed |
| P1-6 | UI slave read-only | Fixed |
| P1-7 | Plaintext DoH fallback | Fixed (warn + explicit opt-in required) |
| P1-8 | TCP pipelining cap | Fixed |
| P1-9 | ACME reload + key permissions | Fixed |
| P1-10 | Session invalidation | Fixed |
| P1-11 | CSRF + security headers | Fixed (same-origin check + headers middleware) |
| P1-12 | Config writer perms/masking | Fixed |
| P1-13 | Metrics stubs | Fixed (wired) |
| P1-14 | Hot reload gaps | Fixed (upstream reload, filter config snapshot, cache config); restart-only settings documented |
| P1-15 | check-config TOML sections | Fixed (hard error on parse failure) |
| P1-16 | Healthcheck | Fixed (ID/rcode check, bind-aware, web fallback) |
| P2-1…P2-23 | Medium items | Fixed where safe; deferred items listed in the PR description |
| P3 | Cleanup | Partially addressed (docs drift, example config, fuzz workspace) |

### Explicitly deferred to follow-up work

> Implementation plan for all deferred items: **[docs/audit3-followup-plan.md](audit3-followup-plan.md)**
> (work packages, dependencies, estimates, acceptance criteria, PR sequencing).
>
> Follow-up progress: **WP-10 (updater artifact signature verification) — done**
> (`server.update_require_signature`, cosign verification of `.sig`/`.pem`,
> `SITO_REQUIRE_SIGNATURE=1` installer support);
> **WP-3 (persistent sessions/tokens) — done** (`auth.session_persist`,
> `sessions.toml`/`tokens.toml` 0600, `auth.token_default_ttl_days`,
> `sito reset-sessions`); **WP-9 (HA leftovers) — done** (`Hello` role +
> protocol version, `stats-v1` capability check, heartbeat watchdog,
> `ca` chain validation, mandatory slave `master_pubkey`);
> **WP-4 (per-list refresh) — done** (nearest-due scheduler, partial list
> reload keeping other lists' rules); **WP-5 (per-client upstreams) — done**
> (scoped `UpstreamManager` per client upstream list, cache bypass, and
> `ignore_stats` suppressing Prometheus counters); **WP-2 (DoH upstream) —
> done** (RFC 8484 DoH and RFC 9250 DoQ, response validation, size caps); **WP-8 (ACME HTTP-01 + DoH hostname) — done**
> (dedicated port-80 challenge listener, `doh_dedicated_hostname` enforced
> with 421 on DoH/DoH3); **WP-14 (OpenAPI drift check) — partial** (CI gate
> added; config-reference generation pending); **WP-12 — partial**
> (`--uninstall`, `SITO_VERSION` pin, armv7 image; SHA-pinned Actions
> pending); **WP-13 (test quality) — partial** (perf budgets behind
> `SITO_BENCH_TESTS`, ephemeral HA ports, real mid-push chaos test,
> monotonic/broadcast/pubkey tests; remaining items tracked in the plan);
> **WP-11 (architecture cleanup) — partial** (certificate watcher lifetime bug
> fix, shutdown joins, dead-code removal, allocation-free suffix matching,
> deterministic pattern order; pipeline helper extraction pending);
> **WP-12 — partial** (SHA-pinned GitHub Actions in addition to the earlier
> installer/armv7 work; `deny.toml` tightening pending);
> **WP-14 — partial** (bidirectional config-reference drift validator in CI,
> which fixed several undocumented settings; table generation pending);
> **WP-1 — partial** (in-response DS/DNSKEY chain walk: KSK→ZSK and signed DS
> delegation, validated-only key cache, additional-section RRSIGs; async
> fetcher and NSEC/NSEC3 proofs pending);
> **WP-7 — partial** (versioned bundled-list manifest with source, license and
> BLAKE3 integrity checks exposed by the registries; curated expansion and
> runtime refresh pending);
> **WP-12 — complete** (installer uninstall/pinning, SHA-pinned Actions, armv7
> image, SBOM, tightened `deny.toml`, shellcheck `warning`, Docker ownership
> and release-verification/reproducibility docs);
> **WP-11 — partial** (`IntoArcSwap` removed in favour of explicit `ArcSwap`,
> shuffled-order precedence test; `handle` helper extraction pending);
> **WP-6 — partial** (hot cache resize with carry-over, retention read per
> cycle; atomic `RuntimeSnapshot` and listener/rate/log reload pending).

- **Full DNSSEC DS/DNSKEY chain walking.** Validation verifies RRSIGs against
  configured trust anchors and forces the DO bit upstream; serving unvalidated
  cache data to DNSSEC-aware clients is blocked. Chain-of-trust validation
  beyond the direct anchor remains future work (P1-2).
- Native DoH/DoQ upstream transports landed in follow-up WP-2; remaining
  unsupported schemes are rejected with a clear error instead of being
  misparsed (P1-4).
- **Persistent sessions/API tokens.** Sessions and tokens remain memory-only;
  this PR adds revocation on password/TOTP changes (P1-10).
- **Per-list `refresh_hours` scheduling** remains deprecated; the global
  `filtering.refresh_interval_hours` is used (P2-10).
- **Per-client upstream overrides / `ignore_stats` / `use_global_upstreams`**
  are still not wired into the pipeline (P2-6).
- **Restart-only settings:** cache `size_mb`, listener ports/binds, rate
  limits, `stats.retention_days` and log settings still require a restart;
  cache enable/prefetch/stale and filter/upstream settings now hot-reload
  (P1-14).
- **Parental/service category lists** remain the small bundled sets shipped in
  the binary (P2-5).
- **`doh_dedicated_hostname`** and `acme.http_port` are documented as
  reserved/ignored (`acme.http_port` is fixed at the internal HTTP-01 mount)
  (P2-10).
