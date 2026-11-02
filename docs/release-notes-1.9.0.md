# sito 1.9.0 — release notes

Target release: **1.9.0** on 2026-11-02. The tag and publication are handled
separately; this page summarizes the user-visible behavior and migration notes
accumulated on the `feat/deferred-1.9.0` branch. The exhaustive, per-commit
history remains in [`CHANGELOG.md`](../CHANGELOG.md).

Operators upgrading from 1.8.0 should read the **Migration checklist** before
restarting production nodes.

## Security

- **DNSSEC cold-start signature stripping is fail-closed.** A response without
  RRSIGs is now probed from the configured trust anchor even when the zone was
  never seen signed in this process. An authenticated DS makes the response
  `Bogus`/SERVFAIL with AD cleared; an authenticated DS denial keeps a genuinely
  unsigned delegation `Insecure`. If the probe cannot complete (offline or
  unprovable) and there is no prior evidence, the result is `Indeterminate`
  with AD=0 and the original NOERROR/NXDOMAIN rcode is preserved; no
  unauthenticated evidence is persisted.
- **Authenticated delegation status is persisted** in
  `<data_dir>/dnssec-chain-cache.toml` (mode 0600, bounded to 8192 entries,
  entries expire). The file is advisory: a missing or corrupt cache starts
  empty and never prevents startup. It is not part of HA config bundles or
  configuration backups. Cached statuses survive restarts and hot reloads, so a
  restart does not reopen a stripping downgrade window.
- **CNAME chains are covered.** Every distinct name in the CNAME chain is
  checked for known signed evidence, and each name that needs a network probe is
  probed within a per-response budget of 8 distinct names. If the budget is
  exhausted, the response fails closed as `Bogus` rather than falling through to
  `Insecure`/`Indeterminate`.
- **Authenticated NSEC3 covering proofs.** A covering NSEC3 NXDOMAIN proof is
  accepted as proof that a cut is in-zone only when its RRSIG validates with a
  key trusted for the parent zone. A forged/unsigned proof cannot mark a zone
  signed or persist `Signed`.
- **TOTP secrets are encrypted at rest.** `users.toml` stores each TOTP secret
  as `enc:v1:<base64>` sealed with AES-256-GCM, a fresh 12-byte nonce, and the
  username as additional authenticated data. The key lives in
  `<data_dir>/totp.key` (0600, created automatically on first start). Legacy
  plaintext secrets are encrypted once on startup with a single atomic rewrite.
  A missing key, a key that does not decrypt an existing secret, or a failed
  decryption refuses startup instead of silently disabling 2FA.
  **Back up `totp.key` together with `users.toml`.**
- **Recovery copies are sanitized.** `users.toml.reset.*.bak` copies are written
  as sanitized TOML with legacy plaintext TOTP secrets sealed. An unparseable
  `users.toml` no longer gets a verbatim backup copy; the original file remains
  on disk until `sito reset-admin` replaces it, so protect or remove it as part
  of recovery because it may still contain plaintext TOTP secrets. `TotpConfig`
  and the one-time setup response redact secrets in `Debug` output.

## Behavior changes

### Filtering

- **`$dnsrewrite` is record-type aware.** `A`, `AAAA`, `PTR` and `TXT` rules
  answer only a question of the same type; `CNAME` rules answer any type. If
  matching rewrite rules have no value for the query type, the answer is
  `NOERROR` with zero records (NODATA) and is not sent upstream. Non-`NOERROR`
  rewrite rcodes still take precedence over record synthesis. Unsupported
  record types (for example `NS` or `MX`) are rejected at load time with a
  warning.
- **Bare and explicit-NOERROR cancellation differ.** A bare
  `@@...$dnsrewrite` cancellation still cancels every rewrite for the owner,
  while `@@...$dnsrewrite=NOERROR` now cancels only an identical NODATA rewrite,
  so valued rewrites survive it. The canonical string for a bare rule is now
  `$dnsrewrite` instead of `$dnsrewrite=NOERROR;;`; review `$badfilter` entries
  that targeted the old shared form.
- **Corrupt embedded rule data no longer panics.** Parental, service, and
  anti-bypass manifests that fail to load now refuse startup with a clear error
  instead of panicking; the server does not run with a partially loaded
  registry.

### Filtering configuration

- **`filtering.max_list_bytes`** (integer, default `67108864`, must be > 0)
  bounds each downloaded subscription list and its disk-cache read, enforced
  before the body is buffered. Lowering the cap invalidates larger cached
  lists. A live reload keeps the previous snapshot and records the list in
  `failed_lists`; after a restart with no snapshot, `fail_closed = true` plus no
  network answers SERVFAIL until a fetch under the new cap succeeds.
- **`filtering.regex_compile_budget_ms`** (integer, unset by default, must be
  > 0) is an optional wall-clock budget for compiling regex/wildcard rules.
  When a reload exceeds it, compilation aborts, the previous snapshot is
  retained, and the failure is reported through `last_error` and
  `last_compile_ms`. Unset disables the budget.

### High availability

- **A slave ACKs only after the pushed configuration is applied and
  persisted.** The slave applies every hot-appliable component (runtime
  pipeline, filtering, upstreams, DNSSEC, clients, rewrites), persists the
  exact document atomically, and waits for the DNS listener readiness gate
  before acknowledging a pushed bundle. Restart-only sections (`auth`, `web`,
  `tls`, `acme`, `integrations` and node role/identity changes) are persisted
  but are **not** live until the slave restarts; the slave logs the exact
  `restart_required` fields instead of claiming them as applied. A failure
  leaves the version watermark unchanged, marks the node `Degraded`, and sends
  `applied: false`; the last known good runtime configuration is retained.
  Node-local settings (`[ha]`, instance name, `data_dir`, MikroTik credentials,
  client secrets) are preserved on apply.
- **New HA metrics:** `sito_ha_diverged{instance}` (1 while a connected slave
  acknowledged a version above the master's; returns to 0 after recovery and
  the series is removed on disconnect) and
  `sito_ha_startup_noop_total{role,reason}` for startup paths that leave
  replication inactive (`replication_disabled`, `missing_master_url`,
  `tls_init_failed`, `bind_failed`). The HA status API schema is unchanged.

### Upstreams

- **Per-upstream failure attribution.** `sito_upstream_errors_total` no longer
  records every failure under the aggregate `upstream="all"` label; it uses the
  configured upstream server that failed. A failure immediately sets that
  server's `sito_upstream_health` gauge to `0`, and a later success resets it to
  `1`. The health gauge previously exposed as the synthetic
  `upstream="default"` series is now keyed by the configured server; `default`
  remains only as the empty-map fallback and disappears once per-server health
  is recorded. Failures that cannot be attributed to one server use the
  constant `upstream="unattributed"` label and do not write a health gauge. The
  separate 3-strike active health state machine is unchanged.
- **Idle pooled DoT sockets are health-pinged.** Sockets idle for at least 5 s
  receive a root `NS` probe (2 s cap) during the periodic upstream maintenance
  sweep. Dead sockets are dropped without failing user queries; live sockets
  return to the pool and are reused.

### Statistics and API

- **`X-Total-Count` on bounded aggregate responses.** `GET
  /api/v1/stats/clients` and `GET /api/v1/stats/upstreams` return the number of
  distinct matching rows before the 1000-row response limit in the
  `X-Total-Count` response header. The existing `?window=` validation is
  unchanged.
- **`stats_hourly.top_upstreams` rollup column.** Migration
  `20260922000000_hourly_rollup_tops.sql` lets retained hourly rollups answer
  per-upstream statistics for windows older than the detailed query-log
  retention. Existing rows default to an empty list; see the migration note
  below.
- **New `GET /api/v1/clients/unidentified` endpoint (Operator).** Returns
  unidentified client discoveries newest-first, bounded by `?limit` (default
  100, maximum 1024). Discoveries expire after 24 hours and are pruned on read.
  The response also reports `max_entries` and `retention_hours`. This is an
  API-only view; there is no UI table. Discovery data is preserved across
  config reloads and HA applies.

### Updater

- **Release downloads are streamed and capped.** The updater now streams the
  archive to a temporary file with a running byte cap (256 MiB for archives,
  1 MiB for `.sig`/`.pem` assets), rejects an over-cap declared
  `Content-Length` before creating the destination, and aborts a chunked
  response as soon as the running total exceeds the cap. Signature and checksum
  verification still happen in the same order (signature first), the archive is
  never buffered whole in memory, and temporary files/directories are removed
  on every failure path, including a failed atomic binary replacement.

### Authentication internals

- **Auth persistence runs off the async runtime.** User, session, and token
  writes use blocking worker threads, and user/token/session mutations are
  async without holding a mutex guard across an await. Token revocation is
  immediate in memory and on all request paths; the on-disk token snapshot may
  lag by up to 60 s until the pruner persists it.

## Toolchain and dependencies

- **Rust 1.99.1** is the pinned toolchain and MSRV (`rust-toolchain.toml`,
  `Cargo.toml`). The pin is a fixed version, not the `stable` channel.
- **utoipa 6.0.0**, **utoipa-swagger-ui 10.0.2**, and **zip 9.2.1** (which
  clears the zip advisories) are in use. `docs/openapi.json` was regenerated;
  it adds the unidentified-clients endpoint and its schemas and the documented
  `X-Total-Count` response headers, plus order-only moves in two optional
  `oneOf` branches. The served document remains OpenAPI 3.1.0.
- The lockfile also raises compatible floors for tokio 1.54, hickory-proto
  0.26.3, hyper 1.12, rust-embed 8.13, and croner 4.0.2.
- **`tower-http 0.7` is not applied.** The repository resolves
  `tower-http 0.6.11`, pulled only transitively by `reqwest 0.13.5`, which
  requires `^0.6.8`. There is no direct `tower_http` use in the workspace, and a
  version requirement cannot be changed with `[patch.crates-io]`. Revisit when
  reqwest or axum ships a compatible requirement; a future bump should be a
  dedicated PR because 0.7 changes compression and redirect behavior.

## Migration checklist

1. **Back up `users.toml` and `totp.key` together.** After the first 1.9.0
   start, TOTP secrets are encrypted; restoring only one of the two files is a
   lockout. Keep the key out of logs and backups that are shared more widely
   than the user store.
2. **Remove or securely store pre-1.9.0 raw user backups.** Upgrade does not
   rewrite existing `users.toml.reset.*.bak` / `users.toml.corrupt.*.bak` files
   from earlier releases; they may contain plaintext TOTP secrets. Delete them
   or move them to the same protected storage as `totp.key`.
3. **Review `$badfilter` rules that target bare `$dnsrewrite`.** Bare rules now
   canonicalize as `$dnsrewrite`, distinct from `$dnsrewrite=NOERROR`.
4. **Update dashboards and alerts.** `sito_upstream_errors_total` no longer
   emits `upstream="all"`, and `sito_upstream_health` no longer stays on the
   synthetic `upstream="default"` series once per-server health is recorded.
   Switch both panels and alerts to the per-server `upstream` label and account
   for `upstream="unattributed"` on the error counter.
5. **Expect a one-time first start after lowering `filtering.max_list_bytes`.**
   Larger cached lists are invalidated and re-downloaded. With
   `fail_closed = true` and no network, DNS answers SERVFAIL until a fetch
   succeeds. A live reload keeps the previous snapshot.
6. **Expect no historical backfill for `stats_hourly.top_upstreams`.** Hours
   already rolled up and removed from `query_log` remain empty for per-upstream
   statistics. Hours still present in `query_log` are populated by the next
   retention sweep, and new rollups are populated normally. No manual data
   migration is required.
7. **Keep the DNSSEC chain cache local to the node.** Do not copy
   `dnssec-chain-cache.toml` between nodes; it contains only authenticated
   local observations and is rebuilt automatically.

## Known behavior limits

- A response whose CNAME chain needs more than 8 distinct network probes fails
  closed as `Bogus`.
- Delegation walks are bounded to the 8 shallowest cuts. A deeper name beyond
  that budget is `Bogus` for the current query; the unauthenticated status is
  not persisted, so a restart re-probes.
- An NSEC3 opt-out NXDOMAIN proof remains `Insecure` by RFC 5155 design: an
  opt-out span can legitimately hide an unsigned delegation.
- The DNSSEC algorithm/digest policy is unchanged from 1.8.0; see
  [`CHANGELOG.md`](../CHANGELOG.md) for the existing RFC 8624/6840 behavior.

## Validation

The release gates are the repository's standard commands, not a fixed test
count:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features --locked
python3 scripts/check_config_reference.py --github
SITO_UPDATE_OPENAPI=1 cargo test -p sito-api --all-features test_export_openapi_json
git diff --exit-code docs/openapi.json
cargo deny check
```

The full suite passes on this branch, including the docs-adjacent
configuration-reference and OpenAPI checks.
