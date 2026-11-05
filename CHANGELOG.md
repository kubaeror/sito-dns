# Changelog

All notable changes to the **sito** project are documented in this file.
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) and follows [Conventional Commits](https://www.conventionalcommits.org/).

---

## [Unreleased]

### Added
- **`sito ha gen-certs --uid/--gid`**: the generator can transfer the generated
  certificates and private keys to the unprivileged HA runtime user. Container
  deployments run as uid/gid `65532` and systemd runs as `sito`; keys generated
  by root were previously unreadable by the runtime, so the mTLS replication
  listener failed to start while DNS health stayed green. Both flags are
  required together, the chown is applied after every file is written, and a
  failed transfer is reported instead of being silently skipped.

### Fixed
- **Web UI update form sends the CSRF token**: the system page's
  "Download & Install" button called native `form.submit()`, bypassing htmx
  and omitting the session-bound CSRF value, so the middleware rejected the
  POST. The form now includes the hidden `csrf_token` used by the other UI
  forms and lets htmx perform the request.
- **Self-update prerequisites are installed and checked up front**: a fresh
  systemd install could not use the documented `sito update` path because
  `server.update_require_signature` defaults to `true` while `install.sh` only
  checked for cosign instead of installing it. The installer now installs a
  checksum-verified cosign binary (`v2.6.5` by default, architecture-matched,
  `SITO_INSTALL_COSIGN=0` to opt out) to `/usr/local/bin`, and `sito update`
  refuses before downloading when signatures are required but cosign is
  unavailable, naming the verifier, the install path and the configuration key.
- **`sito update` finds the system configuration**: without `--config`, the CLI
  prefers an existing `/etc/sito/config.toml` and otherwise uses
  `./config.toml`. The documented
  `sudo systemctl stop sito && sudo sito update` path therefore works from
  `/root` instead of failing to read `./config.toml`. If neither file exists,
  updates refuse with an actionable error naming `--config`; the signature
  policy is never silently skipped.
- **HA failures are visible in status and healthchecks**: a master whose
  replication listener failed to initialize mTLS or bind, and a slave whose
  handshake never completed or that has not reached `synced`, now report
  `ready: false` with a `readiness_reason` in `GET /api/v1/ha/status`. The
  public `/health` endpoint exposes only a generic ready flag (detailed
  reasons stay in the authenticated status endpoint and logs), and
  `sito healthcheck` fails when `[ha]` makes replication part of the role, so
  a successful DNS probe can no longer mask a broken HA node. A master with
  `replication_port = 0` remains ready and explains that replication is
  intentionally disabled.
- **HA compares effective `[auth]` policy, not raw TOML**: an `[auth]` table
  that spells out the default values (as `config.example.toml` does) is now
  equivalent to omitting the section, and inert legacy keys stripped during
  bundle sanitization no longer look like a restart-only change. Previously
  the documented master example plus the minimal slave template produced
  `restart_required: auth` on every push and left the slave permanently
  `Degraded`. A genuine policy change such as `session_ttl_hours` is still
  rejected until a coordinated restart.
- **HA restart-only changes are rejected, not ACKed as applied**: a push that
  changes a restart-only field which is not node-local (for example
  `server.log_format` or `[auth]`) now fails before anything is applied or
  persisted. The slave keeps its previous live configuration and file, enters
  `Degraded`, and ACKs `applied: false` with a `restart_required` reason naming
  the fields. Previously it persisted the change, reported `applied: true`, and
  silently kept the old live behavior until the next restart.
- **HA pushes preserve node-local listeners and certificates**: a slave's
  persisted configuration now keeps its own `dns.bind`, `[dns.tls]`/`[tls]`
  paths, `[acme]`, `web.bind`/`web.port` and the complete
  `[integrations.mikrotik]` section instead of inheriting the master's. A
  master bound to one address can no longer make a slave fail to bind (or use
  certificate paths that do not exist on that node), and the runbook's IPv6-vs-
  IPv4 bind difference between master and slave is safe on the first push.
- **HA master restarts reconcile `config.toml`**: a master that restarts with a
  persisted `ha_state.toml` now compares the sanitized current configuration
  with the stored bundle (semantically) and republishes at `N + 1` when they
  differ. Previously it resumed the old bundle and never pushed the edited
  configuration, leaving every slave on stale settings indefinitely. An
  unchanged configuration still resumes the existing sequence without churn.
- **HA peer version bounds (security)**: an authenticated replica can no longer
  freeze publishing by reporting `u64::MAX` (or any implausibly high
  `have_version`/ACK version). The master rejects Hello values more than
  1,000,000 above its own sequence without seeding or registering, ignores
  implausible ACK versions without rebasing, rejects publishing or restoring a
  sequence at `u64::MAX`, and uses `checked_add` for every sequence increment.
- **HA applied-version watermark is durable**: slaves now persist
  `{version, payload_hash, timestamp}` to `data_dir/ha_watermark.toml`
  (atomic, mode `0600`) after applying and persisting a pushed bundle and
  before acknowledging it. On startup the watermark is restored, so a restart
  can no longer replay an older signed bundle or accept the same version with
  different content. A corrupt watermark fails startup instead of silently
  resetting to version 0.
- **HA term/epoch stops stale-master overwrites (security)**: bundles and the
  master/slave state now carry a cluster term. A slave rejects a push from an
  older term even when its version counter is higher; within a term the version
  must advance and a same-version push must match the applied payload hash. A
  master that sees a replica ahead in the same term or in a newer term marks
  itself `diverged` and no longer seeds its counter or republishes its stale
  active bundle. Recovery is an explicit promotion that raises `term` and
  `version` in `ha_state.toml`; a higher term does not bypass version
  continuity, so the promoted version must also exceed the cluster high-water
  mark. Existing state files without a term load as term 0 and old signed
  bundles remain verifiable. Upgrade slaves before promoting a master (see
  `docs/runbook-ha.md`).
- **Same-term HA forks are latched**: when a slave receives the same version
  and term with a different signed payload hash, it persists a fork marker in
  `ha_watermark.toml`, degrades immediately, and rejects every further push in
  that term until an explicit higher-term promotion (with a higher version)
  arrives. If the durable write fails, the in-memory latch is kept and the ACK
  reports the failure instead of proceeding unlatched. The ACK carries a
  structured `same_version_fork` reason; the master records divergence and
  stops reporting the slave as synced instead of letting the next version
  silently win the fork.
- **HA divergence is sticky**: divergence records now retain their kind
  (same-term version gap, newer term, or same-version fork) and are no longer
  cleared by an unrelated slave applying the current version. A same-version
  fork marks that slave unsynced and keeps it visible, but does **not** stop
  publishing to healthy replicas; it clears when the slave accepts the current
  bundle after promotion/reconciliation or disconnects. A resync clears only
  advisory ahead/newer-term records, never a real fork. The slave list reports
  a latched divergence even when its version counter would otherwise look in
  sync.
- **DNSSEC verification amplification (security)**: a crafted authoritative
  response can no longer force unbounded cryptographic work. Each response now
  has a hard budget of 256 RRSIG verification attempts (shared across the
  pre-fetch and strict passes), candidate keys per RRSIG are capped at 8, and
  trusted/validated keys are tried before unvalidated response keys. The
  bounded work covers the DS/DNSKEY trust walk and the DS-status probes as
  well.
- **NSEC3 iteration cap bypass (security)**: `matches()`/`covers()` now reject
  records whose iteration count exceeds 150 (RFC 9276) before hashing a name.
  The DS-status exact-match/opt-out paths therefore no longer hash a name
  65535 times or accept an over-cap denial.
- **Secure answers no longer outlive their signature**: `dns.cache.min_ttl` is
  a floor for unvalidated data only. Raising a `Secure` entry above its
  authenticated TTL could serve AD=1 data after the RRSIG original TTL or
  validity expired; validated records now keep the smaller TTL. Secure
  NXDOMAIN/NODATA lifespans are additionally capped by the NSEC/NSEC3 denial
  records and their RRSIGs, so a long-lived SOA can no longer extend a
  validated negative answer past its proof.
- **Stale cache entries follow the validation policy**: the RFC 8767 stale
  fallback now refuses both `Unchecked` and `Indeterminate` entries while local
  validation is active (an `Indeterminate` entry may be an inconclusive answer
  or, in log-only mode, a Bogus result). Only authenticated `Secure`/`Insecure`
  decisions are served from the stale window, always with AD=0. Stale
  sanitization removes every DNSSEC RR type (RRSIG, DNSKEY, DS, NSEC/NSEC3),
  not just RRSIGs.
- **DNSSEC policy changes flush cached answers**: changing `dns.dnssec.mode`,
  `validate`, `trust_anchors`, `nta` or `ntp` invalidates the response cache,
  so a decision made under the old policy (Secure after an anchor removal, or
  Unchecked after validation was enabled) cannot be served afterwards.
- **Credential revocation races (security)**: sessions and API tokens now store
  the account's persisted `credential_epoch` and are revalidated against
  `users.toml` on every request: the account must still exist, the role must
  still match, and the epoch must be current. Password changes, role changes,
  TOTP enable/disable, account deletion/recreation and `reset-admin` advance
  the epoch; a login that raced a credential mutation is refused instead of
  inserting a session with the old role or for a deleted account. Persisted
  sessions and API tokens written before this release have no epoch and are
  rejected once after upgrade: users must sign in again and API tokens must be
  re-issued. User-credential writes (create, password, role, TOTP
  enable/disable, delete and `reset-admin`) now fail closed: a failed
  `users.toml` write returns an error and rolls the in-memory change back
  instead of reporting success. Interrupted revocations are also revalidated on
  restart, so a crash between the users write and the session/token write
  cannot resurrect a revoked credential.
- **Reset commands no longer claim live revocation**: the server now holds an
  exclusive lease on `<data_dir>/sito.pid`. `sito reset-sessions` and
  `sito reset-admin` refuse to run while that lease is held, because the running
  process keeps users, sessions, API tokens and the auth generation in memory.
  The documented recovery sequence is `systemctl stop sito` → reset →
  `systemctl start sito`. `--force` performs the on-disk reset anyway and prints
  a warning that existing sessions/tokens remain valid and a new admin password
  is not accepted until the service is restarted. A stale `sito.pid` from a
  crash does not block resets; only the live lock does.
- **First-boot login gating (P0)**: with `config.toml` present but
  `users.toml` still holding the bootstrap `admin/adminadmin`, the setup token
  was active while `setup_pending` was false. The default password could log in
  remotely and the rest of the API stayed reachable. The middleware now gates on
  the setup token and an active bootstrap admin as well: `/api/v1/auth/*`
  returns 403, other `/api/v1/*` routes return 503, and only `/wizard`,
  `/ui/wizard/*`, static assets, `/health`, `/status` and the
  setup-token-protected paths remain reachable. An authenticated Admin may
  always open the wizard.
- **`reset-admin` no longer installs `adminadmin` or deletes accounts**: when
  `--password` is omitted the command generates a 192-bit random password and
  prints it exactly once. Supplied passwords must meet the API/wizard policy
  (at least 8 characters, no whitespace/control characters, not `adminadmin`).
  Non-admin accounts are preserved by default; use `--reset-all` /
  `--reset-users` for an explicit full account-store replacement. Recovery from
  a corrupt `users.toml` requires that explicit full reset.
- **Setup wizard persists credentials before configuration**: the administrator
  password is written and verified before `config.toml` is persisted. A later
  configuration failure rolls the password back and leaves setup pending, a
  non-Admin target account is rejected with 400, and the bootstrap `admin`
  account is removed before setup is marked complete. A failed user-store write
  is reported as an error instead of a successful setup redirect.
- **DNSSEC false SERVFAIL after the first signed zone (P0)**: with
  `dns.dnssec.validate = true` and `mode = "validate"`, resolving one signed
  domain and then a different signed domain (for example `cloudflare.com`
  followed by `example.com`) returned SERVFAIL with EDE
  `Missing RRSIG for zone previously proven signed`. DNSKEY/DS RRSIGs fetched
  during the chain walk were appended to the response and treated as evidence
  that the root/TLD had signed the query, and a response that carried a
  relevant RRSIG but no key yet was rejected before the key chain could be
  fetched. Chain-helper RRSIGs are now separated from the original response,
  the root is never used as descendant signed-zone evidence, a relevant RRSIG
  without key material returns `Indeterminate` so the chain fetch can run, and
  a legacy chain-cache format drops unsafe root/TLD `Signed` entries on load.
  Genuinely stripped responses under a proven-signed zone and genuinely bogus
  zones still fail closed with SERVFAIL in `validate` mode.

## [1.9.1] - 2026-11-04

Patch release fixing residual correctness, concurrency, and UI issues found
after 1.9.0. See the [1.9.1 release notes](docs/release-notes-1.9.1.md) for the
user-visible summary and upgrade notes; this changelog remains the exhaustive
record.

### Fixed
- **DNSSEC chain-cache policy invalidation is targeted**: a configuration
  reload now clears only cached `Unsigned` evidence at or above newly added
  trust anchors instead of discarding the whole cache. Adding an unrelated
  anchor no longer forces re-probes of unaffected zones. Anchor removal,
  non-additive policy changes, and NTA changes still clear the cache; a legacy
  cache file without anchor/NTA metadata is cleared on its first policy change.
- **Chain-cache flush writes are serialized**: cache flushes use a dedicated
  flush lock and do not hold the policy state lock across disk I/O, so reloads
  cannot block behind a flush. The dirty flag is restored on serialization or
  write failure, and the parent directory is fsynced after the atomic rename.
  Malformed individual cache entries are skipped with a path-only warning.
- **All configuration writers are serialized through the apply pipeline**:
  admin writes from the REST API and web UI (filter lists/rules, clients,
  groups, rewrites, upstreams, settings, and the setup wizard) acquire the
  shared apply lock before reading the running configuration and use the
  locked apply/persist/rollback path. Concurrent writes can no longer overwrite
  each other, and a persistence failure rolls back live state. Filter list,
  rule, and settings writes apply synchronously; clients, rewrites, upstreams,
  and the setup wizard defer blocklist work.
- **HA conflict restore runs off the async worker**: when an async bundle
  publish detects that another publisher advanced the version, the active
  bundle is restored through the blocking writer under the persistence lock
  instead of synchronous filesystem I/O on the async worker. Published versions
  cannot regress, and a failed restore leaves the conflict error intact.
- **Auth store persistence is retry-safe**: token/session removals and token
  `last_used` updates advance per-store revision counters. A concurrent save
  clears the dirty flag only when no mutation landed after its snapshot, so the
  pruner rewrites a stale snapshot instead of losing the mutation. Expired
  session removals now mark the session store dirty, and a serialization or
  write failure no longer drops the pending retry.
- **Enabling TOTP revokes owned API tokens**: enabling TOTP now revokes every
  API token owned by that account, matching the existing disable lifecycle.
  Automations using an owned token must create a new one after 2FA is enabled.
  Legacy ownerless tokens are unaffected. The synchronous users writer is now
  private and constructor-only (`save_users_initial`); runtime user writes use
  the serialized async path.
- **Discovered-clients pagination (D-09)**: the read-only discovered-clients
  table on the Clients page is paginated at 100 rows per page with clamped page
  numbers and Previous/Next controls. The total remains the full registry count,
  the Operator gate still runs server-side before slicing, and Viewers never
  load or render discovery data. The 1024-entry registry cap is unchanged.

### Known issues
- **`tower-http 0.7` remains blocked (D-20)**: the repository still resolves
  `tower-http 0.6.11`, pulled transitively by `reqwest 0.13.5`, which requires
  `tower-http ^0.6.8`. There is no direct `tower_http` use in the workspace and
  the requirement cannot be widened with `[patch.crates-io]`. Revisit when
  reqwest or axum widen the range.

## [1.9.0] - 2026-11-02

Security, filtering, high-availability, observability, updater and dependency
release. See the [1.9.0 release notes](docs/release-notes-1.9.0.md) for the
user-visible summary and migration checklist; this changelog remains the
exhaustive record.

### Added
- **Configurable filter-list size cap**: `filtering.max_list_bytes` (default
  `67108864`, 64 MiB) bounds each downloaded subscription list and its
  disk-cache read, enforced before the body is buffered. The value must be
  greater than 0. Lowering the cap invalidates larger cached lists. After a
  restart (or when no previous snapshot exists), an invalidated larger cache
  with `fail_closed = true` and no network answers SERVFAIL until a fetch under
  the new cap succeeds; a live reload keeps the previous snapshot and records
  the list in `failed_lists`.
- **Regex compile budget**: `filtering.regex_compile_budget_ms` is an optional
  wall-clock budget for compiling regex/wildcard rules (unset by default, must
  be greater than 0). When a reload exceeds it, compilation aborts, the
  previous snapshot is retained, and the failure is reported through
  `last_error` and `last_compile_ms`. Unset disables the budget.
- **`X-Total-Count` on bounded aggregate responses**: `GET
  /api/v1/stats/clients` and `GET /api/v1/stats/upstreams` return the number of
  distinct matching rows before the 1000-row response limit in the
  `X-Total-Count` response header.
- **`GET /api/v1/clients/unidentified` (Operator)**: returns unidentified
  client discoveries newest-first, bounded by `?limit` (default 100, maximum
  1024). Discoveries expire after 24 hours and are pruned on read; the response
  also reports `max_entries` and `retention_hours`. Operators also see the same
  bounded data in the read-only “Discovered but unidentified” table on the
  Clients page; Viewers do not. The store is preserved across config reloads
  and HA applies.
- **Web UI user management**: Admins get a `/users` page to list/create/delete
  accounts and change roles (same last-admin guard as the REST API). Every
  signed-in user gets an `/account` page for profile/TOTP status, their own
  password change, their own API tokens (create/list/revoke, plaintext shown
  once), and TOTP disable after re-authentication. Forms are CSRF- and
  RBAC-protected; unauthorized pages return `403` and anonymous requests
  redirect to `/login`.
- **API-token ownership and lifecycle**: tokens record their creating account.
  `/account` lists only the caller's tokens (Admins also see legacy ownerless
  tokens and an Owner column). Deleting an account, changing its password,
  disabling its TOTP, changing its role (promotion or demotion), or
  overwriting/recreating it revokes every token it owns; the revocation is
  persisted to `tokens.toml`. Legacy ownerless tokens are never matched and
  remain Admin-managed.
- **Per-owner API-token quota**: a single owner may hold at most 16 tokens
  (`MAX_API_TOKENS_PER_OWNER`); creating a 17th evicts that owner's oldest token
  and never another owner's. The separate global cap remains 256
  (`MAX_API_TOKENS`); when it is reached and the requesting owner has no token
  to evict, creation returns `400`.
- **Atomic last-admin protection**: last-admin checks for role changes and
  account deletion now run under the same users lock as the mutation. Two
  concurrent demotions/deletions cannot both pass and leave the deployment
  without an Admin; the loser receives `400` and unknown accounts still receive
  `404` on both the REST API and web UI.
- **New HA metrics**: `sito_ha_diverged{instance}` (1 while a connected slave
  acknowledged a version above the master's; returns to 0 after recovery and
  the series is removed on disconnect) and
  `sito_ha_startup_noop_total{role,reason}` for startup paths that leave
  replication inactive (`replication_disabled`, `missing_master_url`,
  `tls_init_failed`, `bind_failed`).

### Changed
- **`$dnsrewrite` record-type matching**: rewrite records are now filtered by
  the query type. `A`, `AAAA`, `PTR` and `TXT` rules answer only a question of
  the same type, while `CNAME` answers any type. When matching rules contribute
  no value for the question type, the answer is `NOERROR` with zero records
  (NODATA) instead of falling back to an upstream lookup. Non-`NOERROR` rcodes
  still take precedence over record synthesis. Unsupported record types (for
  example `NS` or `MX`) are rejected at load time with a warning.
- **Bare `$dnsrewrite` vs explicit `$dnsrewrite=NOERROR`**: only the bare
  `@@...$dnsrewrite` exception cancels every rewrite for the owner. An explicit
  `@@...$dnsrewrite=NOERROR` now cancels only an identical NODATA rewrite, so
  valued rewrites survive it. Canonical strings for bare rules changed from
  `$dnsrewrite=NOERROR;;` to `$dnsrewrite`; existing `$badfilter` entries that
  targeted a bare rewrite must be reviewed.
- **Per-upstream metric attribution**: `sito_upstream_errors_total` and
  `sito_upstream_health` now label a failed query with the configured server
  that failed instead of the former aggregate `upstream="all"`, and a failure
  immediately sets that server's health gauge to `0` (a later success resets it
  to `1`). The health gauge previously exposed as the synthetic
  `upstream="default"` series is now keyed by the configured server; `default`
  remains only as the empty-map fallback and disappears once per-server health
  is recorded. Failures that cannot be attributed to one server (for example, no
  candidates available) use the constant `upstream="unattributed"` label and do
  not write a health gauge. The separate 3-strike active health state machine is
  unchanged. *Dashboard/alert migration:* update panels and alert rules that
  filter, group, or alert on `upstream="all"` (or the synthetic
  `upstream="default"` health series); the aggregate error series is no longer
  emitted.
- **Config watcher skips identical documents**: a file that parses to the
  running configuration (an HA self-write, a duplicate event, or an identical
  external save) is ignored instead of triggering a full re-apply. Use
  `POST /api/v1/config/reload` for an explicit reload. A differing file —
  including an external revert — is still applied; a rejected file leaves the
  last good runtime configuration active.
- **HA apply and ACK**: a slave now applies every hot-appliable component
  (runtime pipeline, filtering, upstreams, DNSSEC, clients, rewrites), persists
  the exact document atomically, and waits for the DNS listener readiness gate
  before acknowledging a pushed bundle. Restart-only sections (`auth`, `web`,
  `tls`, `acme`, `integrations`, role/identity changes) are persisted but only
  take effect after a slave restart; the exact fields are logged instead of
  being reported as live. A failure leaves the version watermark unchanged,
  marks the node `Degraded`, and sends `applied: false` while retaining the last
  known good runtime configuration. Node-local settings (`[ha]`, instance name,
  `data_dir`, MikroTik credentials, client secrets) are preserved on apply.
- **Updater streaming**: release downloads are streamed to a temporary file
  with a running byte cap (256 MiB for archives, 1 MiB for `.sig`/`.pem`
  assets). An over-cap declared `Content-Length` is rejected before the
  destination is created, and a chunked response is aborted as soon as the
  running total exceeds the cap. Signature and checksum verification still run
  in the same order (signature first), the archive is never buffered whole in
  memory, and temporary files/directories are removed on every failure path.
- **Idle pooled DoT sockets are health-pinged**: sockets idle for at least 5 s
  receive a root `NS` probe (2 s cap) during the periodic upstream maintenance
  sweep. Dead sockets are dropped without failing user queries; live sockets
  return to the pool and are reused.
- **Auth persistence runs off the async runtime**: user, session, and token
  writes use blocking worker threads, and user/token/session mutations are
  async without holding a mutex guard across an await. Token revocation is
  immediate in memory and on all request paths; the on-disk token snapshot may
  lag by up to 60 s until the pruner persists it.
- **Corrupt embedded rule data no longer panics**: parental, service, and
  anti-bypass manifests that fail to load now refuse startup with a clear error
  instead of panicking. The failure is reported by `load_bundled_registries`;
  operators should reinstall the packaged data rather than run with a partially
  loaded registry.

### Security
- **TOTP secrets encrypted at rest**: `users.toml` now stores each TOTP secret
  as `enc:v1:<base64>` (AES-256-GCM, random 12-byte nonce, username bound as
  additional authenticated data) using `<data_dir>/totp.key` (0600, created
  automatically on first start). Legacy plaintext secrets are encrypted once on
  startup with a single atomic rewrite. **Back up `totp.key` together with `users.toml`**:
  restoring both is equivalent to the old plaintext file, while restoring only
  one is a lockout. A missing or wrong key, or a failed decryption, refuses
  startup instead of silently disabling 2FA. An HA slave keeps its own
  `totp.key`; `users.toml` is never replicated. Recovery copies
  (`users.toml.reset.*.bak`) are sanitized before being retained, and an
  unparseable `users.toml` is no longer copied raw. `TotpConfig` and the
  one-time setup response now redact secrets in `Debug` output.
- **DNSSEC cold-start signature stripping**: a response without RRSIGs is now
  probed from the configured trust anchor even when the zone was never seen
  signed in this process. An authenticated DS turns the response into
  Bogus/SERVFAIL regardless of process uptime, while an authenticated DS denial
  remains Insecure. Authenticated signed/unsigned delegation statuses are
  persisted in `<data_dir>/dnssec-chain-cache.toml` (0600, bounded, expiring,
  never part of HA bundles or backups). Every distinct name in a CNAME chain is
  checked, and a chain that needs more than 8 distinct probes fails closed as
  Bogus. A never-proven zone that cannot be probed while offline is reported as
  Indeterminate with AD=0 instead of being treated as signed or unsigned; a
  failed probe for any CNAME hop fails closed even when the original qname is
  legitimately unsigned. NSEC3 covering proofs are only accepted from an RRset
  signed by a validated parent key, so a forged covering proof cannot mark a
  cut signed or persist a `Signed` cache entry. Cached delegation statuses are
  scoped to the trust-anchor/NTA policy that produced them, so adding an anchor
  cannot be overridden by an older cached `Unsigned` delegation.

### Migration
- **Stats rollup schema**: migration `20260922000000_hourly_rollup_tops.sql`
  adds `stats_hourly.top_upstreams` so retained hourly rollups can answer
  per-upstream statistics for windows older than the detailed query-log
  retention instead of silently under-reporting. Existing rows default to an
  empty list. Historical per-upstream data is **not backfilled**: hours that
  were already fully rolled up and removed from `query_log` keep `[]` and stay
  empty for per-upstream statistics. Hours still present in `query_log` are
  populated by the next retention sweep, and new rollups are populated
  normally; no manual data migration is required.
- **Back up `users.toml` and `totp.key` together** and remove or securely store
  pre-1.9.0 raw user backups (`users.toml.reset.*.bak`,
  `users.toml.corrupt.*.bak`), which may still contain plaintext TOTP secrets.
- **Review `$badfilter` rules that target bare `$dnsrewrite`** and dashboards or
  alerts that use `upstream="all"` or the synthetic `upstream="default"` health
  series.
- **Keep `dnssec-chain-cache.toml` local to the node**: it contains only
  authenticated local observations and is rebuilt automatically.

### Toolchain and dependencies
- **Rust 1.99.1** is the pinned toolchain and MSRV (`rust-toolchain.toml`,
  `Cargo.toml`). The pin is a fixed version, not the `stable` channel.
- **utoipa 6.0.0**, **utoipa-swagger-ui 10.0.2**, and **zip 9.2.1** are in use;
  the zip advisories are cleared. `docs/openapi.json` was regenerated and
  remains OpenAPI 3.1.0.
- Compatible lockfile floors were raised for tokio 1.54, hickory-proto 0.26.3,
  hyper 1.12, rust-embed 8.13, and croner 4.0.2.
- **`tower-http 0.7` is not applied.** `tower-http 0.6.11` is pulled only
  transitively by `reqwest 0.13.5`, which requires `^0.6.8`; there is no direct
  `tower_http` use in the workspace, and a version requirement cannot be changed
  with `[patch.crates-io]`. Revisit when reqwest or axum ships a compatible
  requirement; 0.7 changes compression and redirect behavior and should be a
  dedicated PR.

---

## [1.8.0] - 2026-11-01

Independent audit 6 remediation. This release fixes every P0 and P1 finding
from the v1.7.0 audit: DNSSEC validation bypass/SERVFAIL regressions, the
default dual-stack startup failure, TLS advisories, transport hardening,
per-group filtering, the config apply/validation pipeline, API/UI secret and
session handling, HA replication state/version continuity, cache/DNSSEC
response correctness, stats cardinality and retention, CI/ops and docs truth.

Migration notes:
- Filter list caches written by <= 1.7.0 lack integrity metadata and are
  re-downloaded once; with `fail_closed = true` and no network the first boot
  answers SERVFAIL until a fetch succeeds.
- `upstream.timeout_ms` is now the overall per-query retry budget (shared by
  failover/load-balance attempts), not a per-attempt timeout.
- Behavior changes: DNSSEC Insecure/Bogus policy, HA persist-before-ACK,
  per-group rules now active, `clients.timezone` (default `local`),
  `upstream.ecs` (default `off`), `rewrites.auto_ptr` (default `false`),
  `$dnsrewrite` PTR/TXT/aggregation/cancellation.

### Critical (P0)
- **DNSSEC validation bypass via key-tag collision**: trust was keyed on the
  16-bit key tag, so an anchored key paired with a same-tag forgery could
  authenticate forged answers (AD=1) and poison the validated-key cache. Trust
  is now bound to the full DNSKEY public-key bytes, validated cache entries are
  never overwritten by a same-tag key, and every candidate key for an RRSIG is
  tried instead of the first tag match.
- **DNSSEC global SERVFAIL after the first chain fetch**: linking the fetched
  root DNSKEY to the trust anchor marked the root as a "signed zone", turning
  every later unsigned response into a stripped-signature Bogus/SERVFAIL in the
  default `validate` mode. Only signatures that validated over response data
  now record zone evidence.
- **Default `dns.bind = ["0.0.0.0", "::"]` failed to start**: the TCP `::`
  socket was dual-stack, so binding it after `0.0.0.0` returned EADDRINUSE and
  aborted startup. TCP/DoT/DoH listeners now set `IPV6_V6ONLY` and
  `SO_REUSEADDR` explicitly.
- **RUSTSEC-2026-0285**: `rustls` 0.23.43 accepted TLS 1.3 handshake messages
  across encryption level boundaries; upgraded to 0.23.45 (CI `cargo deny`
  now passes).

### High (P1)
- **Listener tasks busy-spun at 100% CPU** after a partial startup or failed
  listener rebind because a closed shutdown channel was treated as "no change"
  in every listener/pruner/watcher loop; a dropped sender now stops the task.

### DNSSEC correctness (Phase 1)
- **Chain-fetch budget**: a flat budget of 6 fetches could not reach the root
  from signers with three or more labels; the budget now scales with the label
  count (`2*labels+1`).
- **Stripped signature vs unsigned delegation**: a response without RRSIGs
  under a previously validated zone was always a downgrade. The validator now
  probes the DS records of the candidate delegation cuts with the zone's
  validated key; an authenticated DS denial (NSEC/NSEC3 including opt-out)
  proves an unsigned delegation and resolves as Insecure, while an
  authenticated DS, an in-zone DS NODATA or an unprovable delegation stays
  fail-closed Bogus.
- **NSEC DS NODATA at a delegation** is accepted (RFC 6840 §4.1/§4.4).
- **NSEC3 NODATA** requires the CNAME bit to be clear (RFC 6840 §4.3) and the
  wildcard NODATA proof now covers the next closer name (RFC 5155 §8.7).
- **Authenticated TTLs**: validated RRsets and RRSIGs are capped by the
  signature validity (RFC 4035 §5.3.3), so cache entries cannot outlive their
  signatures.
- **AD semantics**: AD is only set when every Answer/Authority RRset is
  authentic (RFC 4035 §3.2.3); unsupported DS digests/algorithms treat the
  delegation as unsigned (RFC 6840 §5.2) instead of SERVFAIL.
- **Trust anchors**: malformed `dns.dnssec.trust_anchors` entries now fail
  configuration validation instead of silently defaulting algorithms.

### Transport (Phase 2)
- **DoH**: dedicated-hostname matching uses the URI authority (HTTP/2/3
  `:authority`) and normalizes ports, IPv6 literals and FQDNs; connections get
  a header-read timeout and a 30 s read-idle timeout.
- **DoH3**: field-section limit (16 KiB) and bounded QUIC receive windows
  (128 KiB/stream, 2 MiB/connection) stop whole-HEADERS buffering from being
  used for memory exhaustion.
- **DoQ**: RFC 9250 wire Message ID 0 is enforced (and responses use ID 0);
  oversized responses fall back to TC=1.
- **Framing**: TCP/DoT/DoQ responses above 65535 bytes are answered with TC=1
  (question preserved) instead of being dropped; DoT padding only applies to
  EDNS clients and never exceeds the framing limit; a default `DotConfig`
  enforces its per-query rate limit.
- **ACME**: rotation writes key and cert atomically and records a cert/key
  fingerprint so a partially completed rotation forces renewal instead of
  serving a mismatched pair.
- **Upstream**: plain UDP/TCP randomize the on-the-wire Message ID (RFC 5452)
  and restore the caller's ID; the bootstrap resolver only accepts answers for
  the queried owner.
- **Listeners**: SO_REUSEPORT failures surface as the real error, the sendmsg
  source-address fallback is logged, DoT without TLS and DoQ/DoH3 bind failures
  log at error level, and Alt-Svc advertises h3 only when a DoH3 listener is
  possible.

### Filtering (Phase 3, partial)
- A failed reload with zero loadable sources now keeps the engine explicitly
  unavailable, so `fail_closed` answers SERVFAIL after a disabled → enabled
  transition instead of silently allowing traffic.

### Filtering (Phase 3)
- **Per-group `lists`/`custom_rules` are implemented**: the engine compiles one
  extra snapshot per group from the referenced loaded lists plus the group's
  custom rules; the pipeline evaluates group `$important` after global ones and
  combines standard verdicts so a group allow can unblock and a group block
  applies to members.
- **Bounded regex compilation**: patterns compile in 128-pattern batches with
  bisection on failure and a hard batch budget, so one pathological subset can
  no longer stall compilation or silently disable the regex/wildcard class;
  dropped patterns are counted and logged.
- **`filtering.max_rules`** (default 2,000,000) caps the parsed rule set; an
  over-limit reload retains the previous snapshot or stays fail-closed.
- A failed reload with zero loadable sources keeps the engine unavailable, so
  `fail_closed` survives a disabled → enabled transition.
- **AdGuard semantics**: bare domains block the exact host only, URL/path rules
  are inert at DNS level, and `$denyallow` is honoured on exception rules.
- **Rewrites**: IDN config entries and lookups are normalized to ASCII/
  punycode, so punycode entries (the form the wire and lists use) match.

### HA (Phase 5)
- **Bundle secrets**: the structured `clients` value is sanitized like
  `config_toml`, so master client shared secrets are no longer replicated;
  legacy `[auth]` secret keys are stripped instead of becoming unresolvable
  `${SECRET:...}` placeholders.
- **`[tls] key` is no longer masked** (it is a path, not secret material) —
  this previously made every slave reject pushes for standard TLS configs. The
  placeholder secret store is documented as environment-only.
- **Version continuity**: a promoted slave or a lost `ha_state.toml` seeds the
  master sequence from the highest slave-reported version before publishing;
  a slave-ahead ACK is logged at error level and surfaced as
  `diverged`/`diverged_reason` in `/ha/status` (with `master_pubkey` exposed
  for slave configuration).
- **Slave state machine**: an already-current reconnect marks `Synced` without
  clearing `Degraded`; a failed persist is an apply failure (no
  `applied:true` ACK); TLS/WS handshakes are bounded by a 10 s timeout;
  WebSocket messages are capped at 1 MiB on both ends; absent `clients`/
  `rewrites` mean authoritative removal in runtime, snapshot and disk; the
  bundle list metadata is consumed by the slave.
- **Hygiene**: signing/cert keys are created 0600 and an existing 0644 file is
  repaired; `/ha/resync` reports an honest 503/429 instead of always
  `resync_triggered`; the runbook documents the real status JSON, promotion
  steps and `ha_state.toml`.

### Upstream (Phase 6.1)
- **Failover retries on SERVFAIL/REFUSED/NOTIMP** (previously a well-formed
  SERVFAIL was treated as success, so the default failover strategy gave up
  while healthy upstreams remained).
- Retries share one overall `timeout_ms` budget (each sequential attempt gets
  an equal share of the remainder); failures are attributed to the failing
  server via `UpstreamQueryError`, health is recorded for every failed
  candidate, and the active health probe uses a separate (≥5 s) timeout so a
  slow-but-healthy handshake is not marked down.

### Stats (Phase 7)
- **qtype metric cardinality is bounded** (known types + `__other__`) instead
  of up to 65 536 permanent series per protocol/verdict.
- Retention rollups now populate `top_domains`/`top_clients`/`top_upstreams`
  and are merged into global/client/upstream stats, so windows longer than the
  detailed retention no longer silently under-report; `VACUUM` runs after
  large retention sweeps; "clear query log" folds rows into the rollups first;
  pagination exposes a real total count.
- Per-client/per-upstream queries are `LIMIT`-bounded with deterministic
  labels and expose `X-Total-Count`.

### Filtering robustness (Phase 3, continued)
- **List cache integrity**: cache writes are atomic (temp + fsync + rename),
  metadata records content length and line count, and a truncated/mismatched
  or metadata-less cache is re-fetched instead of trusted. *Migration note:* a
  cache written by ≤ 1.7.0 lacks the new integrity fields and will be
  re-downloaded once; with `fail_closed = true` and no network, that first boot
  answers SERVFAIL until a fetch succeeds.
- Duplicate filter-list names are rejected by config validation.
- `reload_with_config` is transactional: a rejected configuration is no longer
  retained for later scheduled refreshes.
- Prefix rules are indexed in a trie (no linear scan) and the regex matcher
  reuses a scratch `PatternSet`.
- Removed dead `FilterSnapshot.exact`/`legacy_exact` and `parse_hosts`.

### CI / ops / docs (Phases 8 and 10)
- CI: `clippy --all-targets --all-features`, pre-merge fuzz compilation with a
  refreshed `fuzz/Cargo.lock`, corpus caching, pinned tool versions, `--locked`
  cross builds; releases publish on tag pushes only (so cosign identity
  `refs/tags/*` is verifiable by the installer/updater).
- Docker: builder cross-compiles from `$BUILDPLATFORM` (no QEMU on fat-LTO),
  `mimalloc` on every arch, `ha/`/key material excluded from the build context,
  compose hardening (`no-new-privileges`, read-only rootfs, tmpfs,
  `start_period`).
- Installer: the web health probe respects `web.enabled`/`web.bind` (no more
  rollback of a working upgrade), capabilities are re-applied after a
  rollback, and uninstall cleans up the user/group.
- AdGuard converter: correct AdGuard keys (`statistics.interval` as duration,
  `tls.port_https`, `filtering.blocked_response_ttl`,
  `dns.anonymize_client_ip`), IP-only bootstrap with warnings, DoH/DoQ schemes
  preserved, plus a fixture self-test wired into CI.
- Docs truth pass: config-reference modes/defaults corrected and a hot-reload
  matrix added, compatibility matrix re-verified against the engine, SECURITY
  versions, install/migration samples, README wizard claims.

### Clients (Phase 3.7)
- Schedules evaluate in a configurable timezone (`clients.timezone`, default
  `"local"`; `"UTC"` and fixed offsets accepted) instead of always UTC.
- MAC resolution no longer reads `/proc/net/arp` on the query hot path
  (background snapshot + bounded positive/negative caches; ARP is skipped
  entirely when no client uses MAC identity).
- RouterOS only trusts `status = "bound"` leases; a failed client build no
  longer downgrades settings or panics; a missing `password_env` errors
  instead of sending an empty password.
- `unidentified_clients` is bounded (1024 entries, 24 h retention);
  runtime-list drop guards count parsed entries instead of raw lines.

### API / UI / auth (Phase 4)
- The admin scheme is no longer derived from the DNS TLS certificate config:
  `web.public_url`/`web.tls_terminated_by_proxy` or a trusted proxy's
  `X-Forwarded-Proto` decide `Secure` cookies, HSTS and CSRF origins.
- Secret handling: path-aware TOML masking (valid round-trip, includes
  `client_id_secrets`), client secrets returned as markers with an Admin-only
  audited reveal, no token hashes or session ids in API bodies, UI client
  deletion removes the shared secret, backup/restore files are 0600.
- `reset-admin`/`reset-sessions` rotate the auth generation and delete
  persisted sessions/tokens; user management and change-password endpoints;
  the missing-config/existing-users deadlock is resolved; CSRF double-submit
  enforcement; TOTP backup codes use fast digests; the UI probe requires
  Operator.
- One apply/validate pipeline is shared by the watcher, API, UI and wizard
  (deep upstream validation, persist-after-apply with rollback, truthful
  `restart_required`); the wizard fetches blocklists asynchronously.
- `--no-setup` without a config generates a random admin password and binds
  the UI to loopback (existing `users.toml` credentials are kept untouched).

### Configuration (Phase 6.5)
- `rewrites.auto_ptr` now has a single default (`false`) for both serde and
  `Default`.
- Stricter validation: `rate_limit_per_ip` upper bound, `retention_days >= 1`,
  `web.port >= 1`, `session_ttl_hours >= 1`, `refresh_hours >= 1`, valid
  `probe_domain`, non-empty per-domain rules, and same-transport DNS port
  collisions are rejected.

### Transport (Phase 2 tail)
- ACME HTTP-01 binds both wildcard families; the certificate watcher watches
  the configured files (not the whole directory), survives atomic renames and
  logs watch errors; DoH3 GET matches DoH decoding; DoQ resets timed-out and
  truncated streams with RFC 9250 error codes; rate-limiter bursts saturate.

### Follow-up hardening (wave 4)
- **DNSSEC**: DS/DNSKEY trust-link signatures outside their validity window are
  Bogus with the correct EDE; a validated CNAME chain crossing into an unsigned
  zone is Insecure (not SERVFAIL); NSEC closest-encloser and NSEC3 DS-NODATA /
  wildcard / opt-out / next-closer proofs were corrected; bogus-reason metric
  cardinality is bounded.
- **Filtering/rewrites**: `||wildcard` patterns anchor at domain/subdomain
  boundaries, `|exact^` is exact, path rules are inert, and rewrite CNAMEs are
  synthesized for every query type.
- **Pipeline**: CNAME uncloaking now re-checks `$important`, parental, service
  and combined global+group rules on the target; filtering requires both the
  global switch and the client policy; prefetch no longer propagates CD=1 into
  the shared cache; block metrics carry rule/list labels.
- **HA statistics**: slaves report real window deltas (queries, blocked,
  upstream RTT/errors) instead of lifetime totals labelled as a 30 s window;
  query-log anonymization is applied once at ingest.
- **Cleanup**: removed the write-only `EffectivePolicy.ids`; startup uses the
  fallible bundled-list loaders (no panic on corrupt embedded data); the
  OpenAPI export writes only with `SITO_UPDATE_OPENAPI=1` and otherwise
  verifies the committed spec; RouterOS disables redirects; schedule window
  parsing handles wildcard minutes.

### Cache and response shaping (Phase 6.2–6.4)
- Negative cache TTLs are clamped by the SOA MINIMUM and the remaining CNAME
  chain TTLs, decremented on serve, and the SOA owner is bailiwick-checked.
- Cache entries carry a validation status (`Secure`/`Insecure`/`Indeterminate`/
  `Unchecked`); unsigned answers are now served from cache to DNSSEC-aware
  clients with AD=0 instead of being bypassed (which amplified upstream traffic
  and key fetches), while `Unchecked` entries are never served when validation
  is enabled.
- The cache key includes the opcode and handles the root name; `invalidate "."`
  flushes everything.
- Non-Query opcodes answer NOTIMP and EDNS versions above 0 answer BADVERS.
- RRSIG/NSEC/NSEC3/DNSKEY and DO-dependent EDNS options are stripped for
  clients that did not set DO; DO=1 responses are cached only under the DO=1
  key.
- New `upstream.ecs = "off" | "forward"` policy (default `off`): strip client
  ECS or forward it clamped to /24 (IPv4) and /56 (IPv6); cache keys follow the
  same policy.
- Synthesized block/rewrite/error responses preserve the client's CD and DO
  bits, and prefetch never caches AD=1 without local validation.

### Filtering semantics completion (WP-3.5)
- `$dnsrewrite` now synthesizes PTR and TXT (with 255-byte TXT chunking) in
  addition to A/AAAA/CNAME, aggregates every matching rewrite for an owner,
  and honours AdGuard cancellation: `@@...$dnsrewrite` cancels all matching
  rewrites and `@@...$dnsrewrite=value` cancels only that value (an
  `$important` cancellation also cancels standard rewrites). Unsupported
  record types are rejected at parse time with a warning instead of silently
  answering NODATA.
- `$client` supports quoted names and `\,`/`\|` escapes (spaces, commas,
  pipes), while negation and CIDR matching are unchanged.

### Dependencies
- Security updates: `rustls` 0.23.46, `ctutils` 0.4.7, `rustls-webpki`
  0.103.16, `webpki-roots` 1.0.11, `tokio` 1.54.1 (RUSTSEC-2026-0285/0346/0347/
  0348/0349/0381/0382/0385/0386).
- Patch updates: `hickory-proto` 0.26.3, `clap` 4.6.7, `reqwest` 0.13.5,
  `quinn` 0.11.12, `quinn-proto` 0.11.19, `rand` 0.10.3, `toml` 1.1.8.
- Accepted, documented in `deny.toml`: `zip` 3.x is a build dependency of
  `utoipa-swagger-ui` 9 used only to unpack the crate's bundled Swagger UI
  assets (never user archives at runtime). The fixes require `zip` 9 via
  `utoipa-swagger-ui` 10 / `utoipa` 6, a breaking major upgrade scheduled
  separately (RUSTSEC-2026-0367/0368/0369).

---

## [1.7.0] - 2026-09-13

### Audit 5 remediation (independent full audit)

Full findings, evidence and status: `docs/audit5.md`. No breaking configuration
or API changes. Wave 0 (P0), Wave 1 (P1) and the highest-value Wave 2 (P2)
items are fixed with regression tests; deferred items are listed in the audit.

#### Critical (P0)
- **DoT upstream startup crash**: `DotUpstream::new` used the ambiguous
  rustls `ClientConfig::builder()` while the dependency graph enables both
  `ring` and `aws_lc_rs`, aborting the process (`panic = "abort"`) for any
  `tls://` upstream, including the shipped example config. It now selects the
  ring provider explicitly.
- **DNSSEC cross-zone signature forgery**: a signature from any chain-validated
  key was accepted for records owned by any other name, granting AD=1 and
  poisoning the cache. RFC 4035 §5.3.1 signer-containment is now enforced for
  every trusted signature.
- **Unauthenticated wizard takeover**: the first-boot setup token expired after
  24 h, after which `/ui/wizard/complete` accepted unauthenticated requests
  and let any network peer set a new admin password. The token now survives
  until setup completes.

#### Security (P1)
- **Authenticated process abort**: CSRF form percent-decoding sliced a `str`
  at a non-char boundary for non-ASCII input; decoding is now byte-based.
- **Filter identity spoofing**: `$client=` matched the client-controlled DoH
  path / DoT SNI claim; only registry-resolved identity now matches.
- **Filtering fail-open**: a failed initial list load left an enabled engine
  allowing all traffic; `filtering.fail_closed` (default true) answers
  SERVFAIL until a snapshot loads.
- **DNSSEC prefetch bypass**: background cache refresh inserted unvalidated
  upstream responses (including attacker AD=1); prefetch now validates.
- **Updater**: signature policy defaults to required and `sito update` fails
  closed when the config cannot be read; cosign identity is pinned to the
  release workflow on tag refs (installer included).
- **TOTP replay**: `verify_totp` now serializes read-verify-write, preventing
  code replay and double-spent backup codes under concurrency.
- **Restore decompression**: config backups are capped per entry and in total.
- **Rate limiting**: one shared per-client budget across all transports, and
  per-query limits on TCP/DoT/DoQ instead of accept-time only; DoT upstream
  connections are capped.
- **SSRF**: subscription targets now unwrap NAT64/6to4/Teredo IPv4 embeddings.
- **Secret handling**: HA bundles strip `client_id_secrets` and RouterOS
  credentials (restored from node-local config); ACME bootstrap key is 0600.

#### High (P1, continued)
- **HA apply**: pushed bundles are published through `RuntimeState` instead of
  raw ArcSwaps, so the pipeline observes them; slave-local `[ha]` section,
  instance name and data dir are preserved when persisting pushes.
- **API config integrity**: `PUT /config` and `POST /config/reload` run deep
  section validation; reload applies filter/upstream/cache/clients/rewrites
  and reports restart-only settings truthfully.
- **CI**: nightly fuzz installs cargo-fuzz and pins the nightly toolchain;
  `workflow_dispatch` releases pass `tag_name` and verify tag == version; all
  jobs have timeouts.
- **AdGuard converter**: emits `custom_ip:<ip>`, escapes TOML strings
  correctly, maps per-client upstreams/log toggles and filtering groups.

#### Correctness and hygiene (P2)
- Cache rejects out-of-bailiwick answer owners, re-checks CNAME targets on
  cache hits, and is flushed whenever filter rules change.
- IDN queries are consistently handled as punycode (parental/service matching,
  per-domain routing, cache keys); config accepts raw IDN.
- DoH bodies are capped at 65535 bytes; DoQ/DoH3 streams have timeouts; DoH3
  no longer decodes a partial body after a receive error.
- DNSSEC key fetches set the DO bit; irrelevant expired RRSIGs no longer turn
  processable answers Bogus.
- API tokens default to a 90-day TTL; deleting a user revokes their sessions;
  group descriptions persist; query-log rate-limiter state is bounded.
- Filter rule count/compile metrics are reported; metric label cardinality is
  capped; upstream error labels use bounded kinds.
- Concurrent runtime-list updates are serialized; config-watcher failures log
  the hot-reload impact at error level.

#### Follow-ups (previously deferred, now fixed)
- **DNSSEC**: NSEC NXDOMAIN proofs now require a wildcard denial at the
  closest encloser (RFC 4035 §5.4) and wildcard NODATA proofs are accepted;
  records are grouped per signer so multi-record proofs validate together.
- **HA**: reconnecting slave sessions carry a connection id so superseded
  connections cannot evict or mutate live entries; the master listener bounds
  handshakes at 10 s and concurrent sessions at 64.
- **Setup/ops**: wizard-completed setup rebuilds TLS/ACME acceptors before
  binding listeners; Docker images ship a writable `/etc/sito` owned by the
  nonroot uid; client-registry generations share the RouterOS lease store so
  sync survives hot reloads; a failed listener rebind leaves a retryable
  manager instead of orphaning the server; release assets include the
  documented per-archive `.sha256` files.
- **Docs**: security review rewritten to the implemented controls,
  `SECURITY.md` version corrected, HA runbook/benchmarks/first-time-setup
  claims reconciled with the tree.

---

## [1.6.0] - 2026-09-13

### Audit 4 remediation (DNSSEC, HA, security, correctness, ops)

Full findings, work packages and status: `docs/audit4-followup-plan.md`.
No breaking configuration or API changes; DNSSEC remains enabled by default.

#### Critical
- **DNSSEC trust chain**: DS delegation now requires a strict parent/child
  hierarchy with a signer-bound RRSIG; signatures are bound to the RRset they
  cover (empty coverage fails); the root DNSKEY is fetched and linked to the
  root anchors; stripped RRSIGs under a zone previously proven signed are
  `Bogus`; NSEC and NSEC3 denial proofs are validated with an iteration cap;
  the key cache only stores verified keys, never downgrades validated entries
  and is bounded; RFC 8624 algorithm/digest policy; +/-300 s clock skew;
  CD=1 skips validation and AD is only returned to clients that requested it.
- **HA replication state**: the master publishes v1 at startup and persists
  the active version/bundle (`ha_state.toml`, 0600) so restarts continue the
  monotonic sequence; stale slave ACKs trigger a one-shot catch-up push;
  fallback deliveries are coalesced; secret substitution fails closed; the
  slave persists pushed configs 0600 atomically; `scan_for_secrets` is wired
  into publish; TLS masters with empty pins now require a client CA (which is
  honoured by the verifier).

#### Security
- **First boot**: one-time setup token (CSPRNG, printed to the console) gates
  the wizard and the upstream tester; probe targets are pinned and deny
  loopback/private/metadata ranges with bounded concurrency.
- **Web**: session-bound CSRF tokens, strict Origin/Referer (null rejected),
  `__Host-` cookies when TLS, tightened CSP, `no-store` on auth/config, HSTS
  only on genuine TLS; unauthenticated `/health` reports setup state.
- **Auth**: Argon2 moved off the async mutex (`spawn_blocking`); timing-safe
  unknown-user path; TOTP replay protection; 128-bit Argon2-hashed backup
  codes accepted by the UI; re-auth required to disable TOTP; `?token=` only
  on the WebSocket upgrade without `Authorization` (deprecated); ordered
  session eviction, token cap, poisoned-lock recovery.
- **Filtering/subscriptions**: `file://` is allowlisted to the data directory
  and regular files; HTTP fetches block private/metadata targets, disable
  redirects, and never use environment proxies (which would bypass the
  resolved-address SSRF guard); streamed size caps; cache filenames hashed;
  runtime parental and service catalogues get drop guards; IDN/punycode rules
  now match (fail-open normalization removed); overlapping Aho-Corasick
  matches are collected; parser precedence is deterministic and unknown
  modifiers no longer widen a rule to all clients; DFA compile is bounded.
- **Transport**: UDP responses truncated to `min(client, server)` EDNS size;
  TLS handshake/write timeouts; DoT pipeline cap; >64 KB framing rejected
  instead of wrapping; rate-limiter buckets bounded; ACME challenge cleanup
  and SNI preservation on reload; DoQ accepts up to 65535-byte queries.
- **Upstreams**: DoH GET fallback fixed; redirects disabled; DNS content type
  required; streamed body cap; real DoQ wire-ID check; multi-IP failover with
  re-resolution; bootstrap asks A and AAAA with single-flight.
- **API**: stable IDs for lists/rewrites, partial client/group updates that
  preserve fields, `doh_path` classification fix, stats window clamps, strict
  updater semver and per-entry decompression caps, masked restore preview,
  surfaced reload errors, metrics token auth, pagination caps.

#### Correctness / performance / ops
- **Cache**: DO/CD/ECS in the key, stale serves lose AD/RRSIG, negative
  answers require SOA, only cacheable rcodes stored, per-key single-flight.
- **Rewrites**: CNAME cycles suppressed, deterministic wildcard specificity,
  multiple answers, configurable `ttl`, CGNAT/link-local auto-PTR.
- **Clients**: DoH path / DoT SNI identity requires a shared secret
  (`client_id_secrets`, now written and validated by the clients API);
  RouterOS lease names are opt-in; longest-prefix match; schedules fail
  closed; rewrite exceptions only match an authenticated resolved client
  (a raw `/dns-query/<name>` path can no longer bypass them).
- **Stats**: retention is transactional with backdated-row safety, failed
  flushes are retried and counted, hot-path metrics are allocation-free,
  label escaping covers all families, new `(client_ip, ts)` index.
- **Hot reload**: watcher path canonicalization (relative `config.toml` now
  works), typed-section validation before apply, DNSSEC validator and
  per-client upstream scopes reload, filter errors surfaced.
- **Ops**: `ha gen-certs` accepts repeatable `--san HOST_OR_IP` for LAN
  certificates; installer resolves the latest release tag (no stale 1.4.0),
  healthcheck requires NOERROR and only fails over to the web UI with
  `--setup-fallback` during setup, digest-pinned images with a writable data
  volume and SBOM/provenance attestations, least-privilege CI permissions,
  `deny.toml` source policy tightened, install/HA runbooks corrected.
- **Config**: invalid `[clients]`/`[rewrites]`/`[web]`/`[auth]`/`[stats]`/
  `[ha]`/`[integrations]` sections now fail startup and `check-config`
  instead of silently falling back to defaults.

---

## [1.5.0] - 2026-09-12

### Audit 3 Remediation (security, correctness, ops)

Full findings and remediation mapping: `docs/audit3.md`.

#### Security (P0/P1)
- **Installer fixes**: release archives are now extracted with `--strip-components=1` (fresh installs from GitHub releases previously failed with a missing-binary error); the unverified local-binary path is now gated behind `SITO_INSTALL_LOCAL_BINARY=1`; health check derives the web port from config and restores the previous binary on failure.
- **TOTP hardening**: `verify_totp` now enforces the IP rate limit and account lockout, caps wrong codes per partial token (`MAX_TOTP_ATTEMPTS = 5`), consumes the token when locked, and invalidates sessions on password/TOTP changes.
- **Setup wizard**: completing setup with an empty or default `adminadmin` password is rejected; the wizard requires a real administrator password on first run.
- **Auth fail-closed**: if `config.toml` exists but `users.toml` is missing, the server now refuses to start instead of silently re-bootstrapping default credentials (`sito reset-admin` recovers).
- **HA**: signed-bundle envelope version is now bound to the signed payload version (replay/downgrade rejected); pushes are no longer dropped on a full queue; non-monotonic `update_bundle` is rejected; plaintext master replication requires a token; per-slave metric labels are removed on disconnect and escaped in `/metrics`.
- **Upstreams**: responses are validated against the sent query (ID + question); IPv6 literal upstreams work (`[::1]:853`, bare IPv6); unsupported schemes are rejected with a clear error.
- **Transport**: DoH3 request bodies are capped at 65535 bytes; TCP pipelining is bounded per connection; ACME certificate reloads keep TLS-ALPN challenge keys, and ACME account/key files are written 0600; plaintext DoH is limited to unprivileged loopback ports unless `dns.allow_plaintext_doh = true`.
- **DNSSEC**: `permissive`/`log_fail` now map to log-only (previously silently strict); all RRSIGs are evaluated instead of failing on the first bad signature; upstream queries force the DO bit and DNSSEC-aware clients are never served non-validated cache entries.
- **API/UI**: CSRF same-origin checks and baseline security headers (CSP, X-Frame-Options, nosniff, Referrer-Policy, HSTS when HTTPS); slave read-only middleware now also covers the web UI; `X-Forwarded-For` is ignored without a trusted peer; sessions are purged on credential changes; config writes are 0600 with unique temp names; `slave_token` is masked in `GET /api/v1/config`; TOTP endpoints use the authenticated username instead of a hardcoded `admin`.
- **Filtering**: `$important` allowlists now override standard blocks; `$dnsrewrite` rules are honored; a single invalid regex no longer disables all regex/wildcard rules; overlapping regex matches are all collected; subscription downloads are streamed with a hard size cap (including `file://`).
- **Rewrites**: CNAME loops are depth-limited and can no longer crash the resolver with unbounded recursion; wildcards no longer match the bare suffix.
- **Hot reload**: config watcher watches the parent directory (works when config.toml is created later) and now reloads upstreams, cache settings, filter configuration and anonymization; scheduled filter refresh keeps hot-reloaded list settings.
- **Ops/release**: HA compose env-var overrides removed (configuration comes from `config.toml` only); container health check passes during setup-wizard mode; `443/udp` exposed; cosign keyless signing added to the release workflow; `latest` container tag published on tag builds; fuzz workspace fixed.
- **Docs/config**: configuration reference corrected (web bind type, clients group map, stats/privacy split, DNSSEC modes, ACME `domains`), README/GHCR image names, Swagger path, AdGuard migration script now emits valid config and maps DoH/DoQ upstreams to `tls://`.

#### Follow-ups (deferred work plan)
- **Updater signature verification (WP-10)**: `apply_update`/`sito update` now verify cosign keyless signatures (`<archive>.sig` + `<archive>.pem`) when present; a present signature must always verify. New `server.update_require_signature` (default `false`) makes signatures mandatory and aborts when assets or the `cosign` binary are missing. Installer honors `SITO_REQUIRE_SIGNATURE=1`. Full plan: `docs/audit3-followup-plan.md`.
- **Persistent sessions and API tokens (WP-3)**: sessions (`sessions.toml`) and API tokens (`tokens.toml`, hashes only) are persisted 0600 in `data_dir` when `auth.session_persist = true` (default). Sessions/tokens survive restarts until their TTL, are revoked on credential changes, and corrupt stores are backed up and start empty. New `auth.token_default_ttl_days` (`0` = never) and `sito reset-sessions` CLI.
- **HA hardening (WP-9)**: `Hello` now carries the node role and HA protocol version (non-slave roles and version mismatches rejected); stat reports require the advertised `stats-v1` capability; the master sends heartbeats at `ha.ping_interval_secs` and drops slaves silent for 3× that interval; `ca` now performs additional chain validation on top of BLAKE3 pinning; slaves must configure `master_pubkey`.
- **Per-list blocklist refresh (WP-4)**: the filter scheduler now honors each list's `refresh_hours` (nearest-due wake-ups) and refreshes only due lists while keeping other lists' parsed rules cached; lists without `refresh_hours` keep using `filtering.refresh_interval_hours`.
- **Per-client upstreams and stats policy (WP-5)**: client entries with `use_global_upstreams = false` and `upstreams = [...]` now resolve through a dedicated `UpstreamManager`; cache is bypassed for these clients to avoid cross-scope answer leakage, and `ignore_stats = true` suppresses Prometheus query counters/durations (query log opt-out remains `ignore_query_log`). Scopes are built at startup; changing a client's upstream list requires a restart.
- **Native DoH/DoQ upstreams (WP-2)**: `https://host[:port]/dns-query` (RFC 8484 POST with GET fallback) and `quic://host[:port]` (RFC 9250, dedicated bi stream per query, ID 0 on the wire, connection reuse) upstreams are now supported, with response ID/question validation and size caps. The UI upstream tester can probe both schemes.
- **Live reload (WP-6 complete)**: DNS listeners now rebind in-process — `DnsListenerManager` owns one generation of listener tasks behind a dedicated shutdown channel, the config watcher detects changes to bind addresses, ports, dedicated hostname, EDNS size, connection cap or DoT padding, stops the old listeners, binds a new generation and falls back to the previous bindings if the new ones fail. An end-to-end test changes `dns.port` in the watched config file and asserts queries succeed on the new port without a restart. `dns.*` settings are no longer reported as restart-only.
- **Live reload (WP-6 partial)**: `dns.rate_limit_per_ip` now hot-reloads — the token-bucket limiter keeps its per-IP state in atomics (`set_rate`) and the server shares one limiter per listener with the config watcher, so changing the value takes effect immediately without dropping buckets. The config watcher still reports all other restart-only fields through the API response.
- **Live reload (WP-6 complete)**: DNS listeners now rebind in-process — `DnsListenerManager` owns one generation of listener tasks behind a dedicated shutdown channel, the config watcher detects changes to bind addresses, ports, dedicated hostname, EDNS size, connection cap or DoT padding, stops the old listeners, binds a new generation and falls back to the previous bindings if the new ones fail. An end-to-end test changes `dns.port` in the watched config file and asserts queries succeed on the new port without a restart. `dns.*` settings are no longer reported as restart-only.
- **Live reload (WP-6 partial)**: `server.log_level` now hot-reloads through a `tracing-subscriber` reload layer (new `sito::logging` module; `log_format` remains restart-only), and configuration writes through the API now answer with `ConfigUpdateResponse.restart_required` naming every changed restart-only setting (`server.role/instance_name/data_dir/log_format`, `dns.bind`/ports/hostname/rate limit, `web`, `tls`, `acme`, `ha`) instead of silently pretending they were applied.
- **Live reload (WP-6 complete)**: DNS listeners now rebind in-process — `DnsListenerManager` owns one generation of listener tasks behind a dedicated shutdown channel, the config watcher detects changes to bind addresses, ports, dedicated hostname, EDNS size, connection cap or DoT padding, stops the old listeners, binds a new generation and falls back to the previous bindings if the new ones fail. An end-to-end test changes `dns.port` in the watched config file and asserts queries succeed on the new port without a restart. `dns.*` settings are no longer reported as restart-only.
- **Live reload (WP-6 partial)**: `dns.rate_limit_per_ip` now hot-reloads — the token-bucket limiter keeps its per-IP state in atomics (`set_rate`) and the server shares one limiter per listener with the config watcher, so changing the value takes effect immediately without dropping buckets. The config watcher still reports all other restart-only fields through the API response.
- **Live reload (WP-6 complete)**: DNS listeners now rebind in-process — `DnsListenerManager` owns one generation of listener tasks behind a dedicated shutdown channel, the config watcher detects changes to bind addresses, ports, dedicated hostname, EDNS size, connection cap or DoT padding, stops the old listeners, binds a new generation and falls back to the previous bindings if the new ones fail. An end-to-end test changes `dns.port` in the watched config file and asserts queries succeed on the new port without a restart. `dns.*` settings are no longer reported as restart-only.
- **Live reload (WP-6 partial)**: queries now observe config, clients and rewrites as one immutable `RuntimeSnapshot` (new `sito-runtime` crate) loaded once per query, so a hot reload can no longer be observed halfway; writers publish through `RuntimeState` (serialized by a write lock) and the config watcher swaps all three components in a single publish. API handlers call `ServerContext::set_config/set_clients/set_rewrites`. Concurrent-writer test proves no component is lost.
- **Live reload (WP-6 complete)**: DNS listeners now rebind in-process — `DnsListenerManager` owns one generation of listener tasks behind a dedicated shutdown channel, the config watcher detects changes to bind addresses, ports, dedicated hostname, EDNS size, connection cap or DoT padding, stops the old listeners, binds a new generation and falls back to the previous bindings if the new ones fail. An end-to-end test changes `dns.port` in the watched config file and asserts queries succeed on the new port without a restart. `dns.*` settings are no longer reported as restart-only.
- **Live reload (WP-6 partial)**: `dns.rate_limit_per_ip` now hot-reloads — the token-bucket limiter keeps its per-IP state in atomics (`set_rate`) and the server shares one limiter per listener with the config watcher, so changing the value takes effect immediately without dropping buckets. The config watcher still reports all other restart-only fields through the API response.
- **Live reload (WP-6 complete)**: DNS listeners now rebind in-process — `DnsListenerManager` owns one generation of listener tasks behind a dedicated shutdown channel, the config watcher detects changes to bind addresses, ports, dedicated hostname, EDNS size, connection cap or DoT padding, stops the old listeners, binds a new generation and falls back to the previous bindings if the new ones fail. An end-to-end test changes `dns.port` in the watched config file and asserts queries succeed on the new port without a restart. `dns.*` settings are no longer reported as restart-only.
- **Live reload (WP-6 partial)**: `server.log_level` now hot-reloads through a `tracing-subscriber` reload layer (new `sito::logging` module; `log_format` remains restart-only), and configuration writes through the API now answer with `ConfigUpdateResponse.restart_required` naming every changed restart-only setting (`server.role/instance_name/data_dir/log_format`, `dns.bind`/ports/hostname/rate limit, `web`, `tls`, `acme`, `ha`) instead of silently pretending they were applied.
- **Live reload (WP-6 complete)**: DNS listeners now rebind in-process — `DnsListenerManager` owns one generation of listener tasks behind a dedicated shutdown channel, the config watcher detects changes to bind addresses, ports, dedicated hostname, EDNS size, connection cap or DoT padding, stops the old listeners, binds a new generation and falls back to the previous bindings if the new ones fail. An end-to-end test changes `dns.port` in the watched config file and asserts queries succeed on the new port without a restart. `dns.*` settings are no longer reported as restart-only.
- **Live reload (WP-6 partial)**: `dns.rate_limit_per_ip` now hot-reloads — the token-bucket limiter keeps its per-IP state in atomics (`set_rate`) and the server shares one limiter per listener with the config watcher, so changing the value takes effect immediately without dropping buckets. The config watcher still reports all other restart-only fields through the API response.
- **Live reload (WP-6 complete)**: DNS listeners now rebind in-process — `DnsListenerManager` owns one generation of listener tasks behind a dedicated shutdown channel, the config watcher detects changes to bind addresses, ports, dedicated hostname, EDNS size, connection cap or DoT padding, stops the old listeners, binds a new generation and falls back to the previous bindings if the new ones fail. An end-to-end test changes `dns.port` in the watched config file and asserts queries succeed on the new port without a restart. `dns.*` settings are no longer reported as restart-only.
- **Live reload (WP-6 partial)**: `dns.cache.size_mb` is now hot-reloadable — `DnsCache::resize` rebuilds the moka cache behind an `ArcSwap` and carries over live entries best-effort (documented brief peak-memory window of old + new size); `update_config` triggers it automatically when the size changes. The stats retention task now reads `stats.retention_days` on every cycle so retention changes apply without restart.
- **Pipeline cleanup (WP-11 partial)**: extracted the query pipeline's blocked-response builder (`blocked_outcome`), both Anti-DoH bypass checks (domain and resolved-IP, with the cache/upstream origin logged) and the entire parental/service/standard filter stage (ADR-0007 stage 3) into private, individually documented helpers; `handle` is now ~90 lines shorter and the removed dead `QueryOutcome::anti_doh_blocked` builder is gone. Existing pipeline tests (blocking, `$important` allow, CNAME uncloaking, rewrites) cover the extracted units.
- **Pipeline cleanup (WP-11 partial)**: removed the test-only `IntoArcSwap` trait — `DnsPipeline::new` now takes `Arc<ArcSwap<T>>` explicitly and all callers (including the M7 harness) use `ArcSwap` directly; added a deterministic-precedence test that inserts identical rules in shuffled orders and asserts identical candidate ordering, with the lowest rule id first.
- **Supply chain hardening (WP-12)**: `deny.toml` now rejects new duplicate crate versions (15 known transitive duplicates explicitly skipped) and unused license allowances; shellcheck runs at `warning` severity; installation guide documents container UID/GID `65532` ownership for bind-mounted config, cosign keyless verification, SBOM contents and the reproducibility guarantees (`--locked`, pinned toolchain, release profile).
- **Curated data and status (WP-7)**: expanded the built-in fallback lists (adult 20→40, gambling 12→40, services 23→35 including a new `ads` tracker category and LinkedIn/Zoom/Minecraft/Viber/Line/Tumblr/Imgur/SoundCloud/Crunchyroll/HBO/Prime Video), manifest bumped to 2026.09.2 with fresh checksums. `RuntimeLists` now tracks per-category refresh status (source URL, timestamp, entry count, bundled vs runtime) and the Filtering page shows it with a "Last refresh" column.
- **Curated list refresh (WP-7)**: new `[integrations.lists]` configuration points parental/service categories at maintained sources; a background task downloads them through the shared subscription downloader (ETag/disk cache/size caps) on per-category schedules and hot-swaps the runtime registries via `RuntimeLists` (domain lists replace the bundled category, `services` expects JSON). Invalid content is rejected without disturbing the previous registry. Tests cover replacement semantics, invalid JSON, config validation and a `file://` refresh through the real task.
- **Bundled list provenance (WP-7 partial)**: the Filtering page now renders a "Built-in Curated Lists" table (list id, version, entry count, license, source link) marked `built-in (minimal)`, so users can see the provenance and coverage limits of the fallback data instead of assuming it is a full blocklist.
- **Curated data and status (WP-7)**: expanded the built-in fallback lists (adult 20→40, gambling 12→40, services 23→35 including a new `ads` tracker category and LinkedIn/Zoom/Minecraft/Viber/Line/Tumblr/Imgur/SoundCloud/Crunchyroll/HBO/Prime Video), manifest bumped to 2026.09.2 with fresh checksums. `RuntimeLists` now tracks per-category refresh status (source URL, timestamp, entry count, bundled vs runtime) and the Filtering page shows it with a "Last refresh" column.
- **Curated list refresh (WP-7)**: new `[integrations.lists]` configuration points parental/service categories at maintained sources; a background task downloads them through the shared subscription downloader (ETag/disk cache/size caps) on per-category schedules and hot-swaps the runtime registries via `RuntimeLists` (domain lists replace the bundled category, `services` expects JSON). Invalid content is rejected without disturbing the previous registry. Tests cover replacement semantics, invalid JSON, config validation and a `file://` refresh through the real task.
- **Bundled list provenance (WP-7 partial)**: the parental (adult, gambling) and service lists now ship with `bundled/manifest.json` describing version, source, license and a BLAKE3 checksum per list. Registries verify integrity at load and expose the metadata via `ParentalRegistry::lists()` / `ServiceRegistry::lists()`; corrupted or silently edited data files fail loudly. The curated data remains the minimal built-in fallback (runtime refresh and UI display of metadata are still pending).
- **NSEC3 opt-out (WP-1)**: RFC 5155 denial enumeration now walks the closest encloser and next-closer coverage; NXDOMAIN responses proven only by an opt-out NSEC3 (which may hide an unsigned delegation) are downgraded from Secure/AD to Insecure, and exact/wildcard NODATA proofs are recognised. Only NSEC3 records covered by a validated RRSIG are considered, so unsigned forgeries cannot force the downgrade.
- **NSEC negative responses (WP-1)**: signed NSEC denial records for NXDOMAIN and NODATA are validated through the chain-validated RRSIG path; tests assert NXDOMAIN and NODATA become Secure with AD=1 when the covering zone is anchored, and stay Indeterminate (AD=0) when it is not.
- **DNSSEC telemetry and fuzzing (WP-1)**: validated-key cache hits/misses are counted and exported as `sito_dnssec_key_cache_hits_total`/`_misses_total`, and a new `fuzz_dnssec_response` target feeds arbitrary wire data into the verification path (added to the nightly fuzz matrix).
- **DNSSEC chain validation (WP-1 partial)**: when the in-response chain is incomplete (signatures verify but no anchor link), the validator now resolves the missing DNSKEY/DS records through a new `DnssecKeyFetcher` trait — production implementation `UpstreamKeyFetcher` uses the same upstream manager as queries; the walk is bounded (6 lookups, depth 12, visited-zone set) and fetched records are appended only for the validation pass. Tests cover KSK→ZSK over a fetch, DS delegation over a fetch, and the unsigned-delegation budget.
- **NSEC3 opt-out (WP-1)**: RFC 5155 denial enumeration now walks the closest encloser and next-closer coverage; NXDOMAIN responses proven only by an opt-out NSEC3 (which may hide an unsigned delegation) are downgraded from Secure/AD to Insecure, and exact/wildcard NODATA proofs are recognised. Only NSEC3 records covered by a validated RRSIG are considered, so unsigned forgeries cannot force the downgrade.
- **NSEC negative responses (WP-1)**: signed NSEC denial records for NXDOMAIN and NODATA are validated through the chain-validated RRSIG path; tests assert NXDOMAIN and NODATA become Secure with AD=1 when the covering zone is anchored, and stay Indeterminate (AD=0) when it is not.
- **DNSSEC telemetry and fuzzing (WP-1)**: validated-key cache hits/misses are counted and exported as `sito_dnssec_key_cache_hits_total`/`_misses_total`, and a new `fuzz_dnssec_response` target feeds arbitrary wire data into the verification path (added to the nightly fuzz matrix).
- **DNSSEC chain validation (WP-1 partial)**: the validator now extends trust from configured anchors through DS records and DNSKEY RRsets present in the response — a DNSKEY RRset self-signed by an anchored KSK validates the zone's ZSKs, and a DS RRset signed by a validated parent key vouches for the matching child DNSKEY. `KeyCache` entries now carry a `validated` flag (only chain-linked keys can mark a response `Secure`) and expire at the minimum of record TTL and matching signature expiration. RRSIGs in the additional section (where upstreams place signed DNSKEY RRsets) are now evaluated.
- **Example config parity**: `config.example.toml` now includes `doh3_port`, `dot_padding`, dedicated-hostname, DNSSEC `mode`/`nta`/`trust_anchors`, `[auth]`/`[stats]` settings, plus commented `[ha]` and `[integrations.mikrotik]` blocks; M9 parses and validates it on every run.
- **Docs automation (WP-14)**: `--write` now uses the Rust doc comments as generated descriptions for new config fields (falling back to a TODO only when a field has no doc comment).
- **Docs automation (WP-14)**: the config-reference validator gained `--write`, which appends placeholder rows (correct type, TODO description) for newly added struct fields while preserving all existing prose, so adding a setting no longer requires hand-editing tables before CI can pass.
- **Example config parity**: `config.example.toml` now includes `doh3_port`, `dot_padding`, dedicated-hostname, DNSSEC `mode`/`nta`/`trust_anchors`, `[auth]`/`[stats]` settings, plus commented `[ha]` and `[integrations.mikrotik]` blocks; M9 parses and validates it on every run.
- **Docs automation (WP-14)**: `--write` now uses the Rust doc comments as generated descriptions for new config fields (falling back to a TODO only when a field has no doc comment).
- **Docs automation (WP-14)**: CI now validates `docs/configuration-reference.md` against the Rust config structs in both directions via `scripts/check_config_reference.py`, which already surfaced and fixed undocumented settings (`dns.allow_plaintext_doh`, `dns.dnssec.nta`/`trust_anchors`, `acme.cache_dir`/`http_port`, HA `listen_addr`/`pinned_slave_fingerprints`/`allow_*`/`stats_interval_secs`, MikroTik basic-auth and `allow_invalid_certs`).
- **Supply chain (WP-12 partial)**: all GitHub Actions are now pinned to immutable commit SHAs (with the original tag in a trailing comment), including the separately-resolved `nightly` toolchain branch for fuzzing.
- **Architecture cleanup (WP-11 partial)**: fixed a real bug where all four `CertWatcher` handles were dropped immediately, silently disabling certificate hot-reload; the filter refresh task now observes shutdown and listener tasks are joined after the drain; removed dead code (`HaStubResponse`, `ProblemDetails::not_implemented`, `CacheEntry.is_negative`, `DnsCache::entry_count`, `ServiceRegistry::available_services`, `reload_with_options`, `get_unidentified_clients`, `load_from_file`); replaced per-query `format!(".{suffix}")` allocations with a shared allocation-free `matches_domain_suffix`/`matches_strict_subdomain` helper; compiled prefix/AC/regex patterns are sorted by rule id so precedence no longer depends on hash iteration order.
- **HA reconnect test (WP-13)**: added an end-to-end test where the slave worker starts before the master exists, backs off through failed connection attempts, then reconnects and syncs once the master listener appears — covering the reconnect/backoff path deterministically.
- **Behavioral release checks (WP-13)**: M9 now parses and validates `config.example.toml` through the real config parser and runs `systemd-analyze verify` on a rendered unit (skipped when systemd tooling is unavailable), replacing grep-only assurances with executable checks.
- **HA tests (WP-13)**: added behavioral coverage for explicit plaintext `ws://` replication with token auth, missing/invalid `master_pubkey` (push never applied, static validation rejects), duplicate-instance re-registration, and a nightly `--release` test job running the full suite with strict perf budgets.
- **Test-suite quality (WP-13)**: wall-clock budgets (failover, shutdown, WebSocket latency, regex DFA) now use generous CI deadlines with the strict DoD budgets gated behind `SITO_BENCH_TESTS`; HA replication tests reserve ephemeral ports instead of hardcoded ones; the m8 chaos test now really publishes a bundle before killing the master; promotion rejects non-monotonic versions; anti-DoH trusted-client behavior is asserted via the query log; new HA tests cover non-monotonic `update_bundle`, full-queue broadcast fallback, and mandatory slave `master_pubkey`.
- **Ops follow-ups (WP-12/WP-14 partial)**: installer `--uninstall` mode and documented `SITO_VERSION` pin; armv7 container image; CI now fails when the committed `docs/openapi.json` drifts from the generated spec. SHA-pinning GitHub Actions and generating the configuration reference remain.
- **ACME HTTP-01 and DoH hostname (WP-8)**: ACME HTTP-01 challenges are served by a dedicated plaintext listener on `acme.http_port` (default 80) instead of the DoH listener; `/.well-known/acme-challenge/*` is no longer exposed on DoH. `dns.doh_dedicated_hostname` is now enforced: DoH and DoH3 requests with a mismatching Host/authority return 421.

#### Deferred (tracked in `docs/audit3-followup-plan.md`)
- Full DNSSEC DS/DNSKEY chain walking (validation currently verifies against configured trust anchors only).
- Native DoH/DoQ upstream transports.
- Persistent sessions/API tokens across restarts (tokens remain memory-only, but are revoked on credential change).
- Per-list `refresh_hours` scheduling (deprecated; global interval used).
- Per-client upstream overrides are still not wired into the pipeline.

### Breaking changes
- Plaintext DoH on non-loopback or privileged ports now requires `dns.allow_plaintext_doh = true`.
- RouterOS integration no longer disables TLS verification by default; set `allow_invalid_certs = true` for self-signed router certificates.
- Invalid `[web]`/`[auth]`/`[stats]` TOML sections now fail validation instead of silently falling back to defaults.

---

## [1.4.0] - 2026-09-06

### First-Time Setup Wizard & Installer Hardening

#### First-Time Setup & Bootstrap Mode
- **Web-Based First-Time Setup Wizard**: When `config.toml` is missing at startup, the server boots into an in-memory bootstrap `setup_pending` mode, serving only the web panel on port 8080 and delaying DNS listener port bindings until setup is finished.
- **Route Gating Middleware**: While in `setup_pending` mode, all UI requests redirect (HTTP 302) to `/wizard`, API v1 endpoints return HTTP 503 `Setup not completed`, while `/wizard`, static assets, and upstream testing are permitted.
- **Expanded 6-Section Setup Wizard**: Implemented a comprehensive single-page wizard with pre-filled defaults covering:
  1. Administrator Account (username, password, confirm password)
  2. DNS Listeners & Protocols (IPv4/IPv6 bindings, UDP/TCP 53, DoT 853, DoH 443, DoQ disabled by default)
  3. Upstream Resolvers (presets for Cloudflare, Quad9, Google, resolution strategies, bootstrap IPs, and live HTMX latency testing)
  4. Cache & DNSSEC (local cache toggle, cache size, DNSSEC modes and validation)
  5. Filtering & Protection (blocking modes, CNAME cloaking defense, and one-click presets for OISD Big, OISD Small, StevenBlack, and HaGeZi Pro)
  6. Web Panel & Statistics (binding address, port, and query log retention days)
- **Headless Mode (`--no-setup`)**: Added `--no-setup` CLI flag to bypass wizard gating and immediately initialize all services with default configuration for automated or headless deployments.
- **In-Process DNS Listener Startup**: DNS listener pipelines are spawned in-process upon wizard completion without requiring a daemon restart.

#### Installer Hardening & Supply Chain Security
- **Config Generation Removed**: `contrib/install.sh` no longer writes a static `config.toml` or prints default credentials, directing operators to complete setup via the web wizard.
- **Download Retries & Backoff**: Added retry logic (up to 3 attempts with exponential backoff) and removed error swallowing.
- **Cosign Verification**: Added optional Cosign keyless signature verification for release archives with fallback to SHA-256 checksum validation.
- **Upgrade Detection & Backup**: Automatically detects existing installations and backs up the existing binary to `/usr/local/bin/sito.bak`.
- **Post-Install Health Check**: Added automated post-install health checks verifying `systemctl is-active` and HTTP server response, printing journal diagnostics on failure.
- **Firewall Guidance**: Added UFW and firewalld rule instructions to the installation summary.
- **CI ShellCheck Job**: Integrated automated shellcheck validation in both `.github/workflows/ci.yml` and `.github/workflows/release.yml`.
- **Port Conflict Fix**: Disabled DoQ by default (`doq_port = 0`) to eliminate default port collision with DoT on port 853.

---

## [1.3.0] - 2026-09-06

### Security, Performance & Operational Audit Remediation (Audit 2)
Comprehensive remediation of all findings identified in `/docs/audit2.md`:

#### Phase 1: Critical Security (P1)
- **HA Master Replication Hardening (P1-1)**: Enforced strict TLS certificate pinning (`expected_slave_pins`), rejected plaintext WebSocket replication by default, and required non-empty authentication tokens (`auth_token`) on the replication listener, preventing unauthorized configuration extraction and eavesdropping.
- **Setup Wizard Credential Validation (P1-2)**: Validated existing admin credentials if an admin user already exists, auto-created the admin account if missing, and surfaced configuration persistence errors to prevent runtime/disk drift.
- **Default Metrics Authentication (P1-3 - Breaking Change)**: Changed `metrics_auth` default from `false` to `true`, requiring authentication for `/metrics` by default.

#### Phase 2: Resilience & Integrity (P2)
- **Immediate HA Replication on Mutations (P2-1)**: Wired automatic bundle publishing to connected slave nodes immediately upon mutating API and UI configuration changes.
- **Negative Caching for NXDOMAIN Responses (P2-2)**: Enabled caching of NXDOMAIN responses using the minimum TTL from the SOA record and RFC 2308 compliance.
- **Upstream ID & Query Log Anonymization (P2-3)**: Propagated real upstream names into SQLite query log entries and wired querylog IP anonymization per configuration.
- **Filter Reload Join Error Handling (P2-4)**: Gracefully handled Tokio join errors during filter engine reloads without clearing or wiping existing filter rules.
- **HA Slave Telemetry (P2-5)**: Transmitted real query counts, block rates, and upstream performance in slave heartbeat reports to the HA master coordinator.
- **User Account File Corruption Protection (P2-6)**: Created automatic timestamped backups (`users.toml.corrupt.<ts>`) on unparseable user files and aborted startup rather than silently overwriting credentials with defaults.
- **Trusted Reverse Proxy Client IP Protection (P2-7)**: Used rightmost client IP from `X-Forwarded-For` when behind trusted reverse proxies to eliminate header spoofing.
- **Atomic UI Configuration Persistence (P2-8)**: Enforced atomic file persistence (`save_config_atomic`) before updating in-memory state across all UI handlers, returning HTTP 500 on disk failures.

#### Phase 3: Performance, Infrastructure & Polish (P3)
- **Single-Pass Filter Candidate Collection (P3-1)**: Refactored `evaluate()` in `sito-filter` to collect rule candidates once and pass them through `evaluate_important` and `evaluate_standard`, eliminating double traversal on the hot path.
- **Live Upstream Hot-Reloading (P3-2)**: Dynamically reloaded `UpstreamManager` servers, strategies, and per-domain rules on `PUT /api/v1/upstream` and UI upstream edits without requiring daemon restart.
- **Reduced Pipeline Log Level (P3-3)**: Lowered routine cache hits, safe search rewrites, and stale cache serves to `debug` level, keeping `info` exclusively for block verdicts.
- **Docker Port Exposures & Documentation (P3-4)**: Added DoT (853), DoH (443), and Web (8080) ports to Dockerfile and compose, documented `NET_BIND_SERVICE` capability requirements, and added workflow dispatch tags to container image metadata.
- **CI Release Smoke Build (P3-5)**: Added an x86_64 `--release` smoke build step to the continuous integration workflow.
- **Unix Compile Guard & Platform Support (P3-6)**: Added `#[cfg(not(unix))]` compile error guard to `sito-transport` and documented Unix/Linux platform requirements in documentation.

---

## [1.2.1] - 2026-09-06

### Security & Robustness Audit Remediation
Comprehensive remediation of all 24 security, stability, architecture, and correctness findings identified in `/docs/audit.md`:

#### Phase 1: Critical Security (P0)
- **Setup Wizard Gating**: Restricted `/ui/wizard` and `/ui/wizard/complete` endpoints so they can only be executed during initial first-run (when no users are registered) or by an authenticated admin session, returning HTTP 403 Forbidden once initialized.
- **User Account Persistence & Configuration Wiring**: Wired `auth.user` and `auth.role` configuration options, persisted user accounts to `<data_dir>/users.toml`, and restored them automatically on daemon startup.
- **Updater Integrity & Enforcement**: Enforced strict SHA256 checksum verification from `SHA256SUMS` during self-updates, protected the update check endpoint with authentication, and pinned GitHub update queries to `kubaeror/sito-dns`.
- **Installer Configuration Hardening**: Fixed missing default tables in installer config generation and added warnings when configuration sections fail to parse.
- **Hot-Reload Dynamic Pipeline**: Wired `ArcSwap` handles into the DNS processing pipeline to enable zero-downtime, restart-free updates of configuration, local rewrites, and client definitions.

#### Phase 2: High Priority Robustness (P1)
- **Defensive Cache TTL Clamping**: Defensively clamped TTL bounds and validated that `negative_ttl_max >= min_ttl` at configuration validation time.
- **UDP Concurrency & Head-of-Line Blocking**: Resolved UDP head-of-line blocking by spawning concurrent Tokio worker tasks per received query bounded by a high-capacity semaphore.
- **High-Availability Security**: Mandated TLS certificate pinning for HA replication, rejected plain WebSockets by default unless explicitly allowed, and required pre-shared token authentication for replica nodes.
- **Session Cookie Security**: Conditionally set the `Secure` flag on session cookies based on TLS status and issued clear warnings when serving over plain HTTP on non-loopback network interfaces.
- **Bounded State & Proactive Pruners**: Bounded lockout, session, and TOTP authentication maps with LRU eviction and spawned a dedicated background pruner task to purge expired entries every 5 minutes.
- **Comprehensive RBAC Enforcement**: Enforced role-based access control across all mutating UI routes and the `/metrics` endpoint; exposed OpenAPI docs endpoint in documentation.

#### Phase 3: Correctness & Configuration (P2)
- **Hourly Statistics Watermark**: Implemented a persistent high-water mark for stats rollups to prevent double-counting queries in `stats_hourly`.
- **Parameterized Query Logs**: Refactored query log filtering to use `sqlx::QueryBuilder` with strict parameterized `push_bind` expressions.
- **Installer Checksum Verification**: Hardened `contrib/install.sh` to require valid SHA-256 checksums from `SHA256SUMS` and fail loudly on mismatches.
- **Dead Configuration Pruning**: Removed deprecated `refresh_hours` settings from UI forms and sample configurations.
- **DNSSEC Validation Logging**: Added configuration validation for DNSSEC modes (`off`, `process`, `log_fail`) and recorded validation outcomes in query logs.
- **Query Log Graceful Shutdown**: Ensured the query log writer channel is flushed and awaited during graceful daemon shutdown.
- **Filter Rule Drop Guard**: Restricted rule-count drop protection to scheduled background refreshes to avoid blocking intentional user rule deletions.
- **Upstream Bootstrap Safety**: Guarded upstream bootstrap resolution against empty address lists using `.first()`.
- **Protocol Documentation Alignment**: Corrected upstream protocol labels and examples to `tls://` and UDP, reflecting implemented upstream protocols.

#### Phase 4: Low Priority & Code Polish (P3)
- **Pipeline QueryOutcome Refactoring**: Introduced private `QueryOutcome` struct, unified anti-bypass checks and blocked-response builders, bounded cache prefetching tasks with a semaphore, updated cache size metrics gauge, consolidated HTML escapers, and routed missing client/rewrite endpoints.
- **Atomic Config Persistence Documentation**: Clarified that atomic config saves preserve modeled fields and omit unknown top-level keys.
- **Systemd Unit Hardening**: Added `MemoryDenyWriteExecute`, `ProtectKernelTunables`, `ProtectKernelModules`, `ProtectControlGroups`, and `SystemCallFilter=@system-service` directives to systemd service units, and added default password change alerts.
- **Axum Explicit JSON Feature**: Explicitly declared `"json"` feature on `axum` workspace dependency.

---

## [1.2.0] - 2026-09-05

### Added
- **In-App Self-Updater**:
  - Direct software updates from web console and CLI (`sito update`).
  - Automatic query of GitHub Releases API, parsing semantic versions and release notes.
  - SHA256 checksum verification against published `SHA256SUMS`.
  - Docker/OCI container detection with non-destructive container upgrade guidance.
  - Safe, atomic self-replacement of the running executable on Linux (x86_64, aarch64, armv7).
  - Admin REST API endpoints: `GET /api/v1/system/update/check` and `POST /api/v1/system/update/apply`.
  - OpenAPI 3.0 specification updated in `docs/openapi.json`.
- **Advanced Upstream Strategies & Caching**:
  - `Parallel` upstream racing: concurrent query dispatch to all healthy upstreams; fastest valid answer wins.
  - `LoadBalance` round-robin: distributed query forwarding across upstream resolvers.
  - `[[upstream.per_domain]]`: domain-based routing for split-horizon or internal DNS zones.
  - RFC 8767 `serve_stale`: stale cache entry fallback during upstream network outages.

### Fixed
- **RouterOS Auth Fallback**: Automatically fall back to native RouterOS API (port 8728) if REST login fails.
- **SafeSearch Normalization**: Fixed domain matching bypasses with consistent trailing-dot FQDN normalization.
- **HA Redaction Loop**: Guarded against recursive cycle traversal in High Availability secret sanitization.
- **Auth IP Resolution**: Secured peer IP extraction against reverse proxy spoofing when proxies are untrusted.
- **Web Port Configuration**: Fixed web server listener to respect `config.web.port` (default `8080`).
- **Telemetry Retention Cleanup**: Added 24-hour background task to prune old query logs and keep SQLite storage bounded.
- **Test Harness Reliability**: Eliminated ephemeral port probe races in parallel acceptance test execution with automated retry.

### Changed
- **Workspace Version**: Bumped workspace package and all internal crates to `1.2.0`.
- **Configuration Persistence**: Persisting configuration changes via the Web UI or REST API round-trips modeled fields; unmodeled or unknown keys and custom comments are not preserved on save.

---

## [1.1.1] - 2026-09-05

### Maintenance & Rust 1.98.1 Toolchain Modernization
- **Rust Toolchain Bump**: Bumped toolchain and MSRV to `1.98.1` (`rust-toolchain.toml` and `Cargo.toml`). Adopted Rust 2024 let-chain idioms across codebase.
- **Transitive Dependency Refresh**: Updated 31 SemVer-compatible crates via `cargo update` previously blocked by older MSRV.
- **Major Dependency Upgrades**:
  - `totp-rs`: Upgraded from `5.6` to `6.0` (migrated to `TOTP::builder()` API, `try_from_base32`, and URL generation).
  - `sqlx`: Upgraded from `0.8` to `0.9` (adopted `sqlx::AssertSqlSafe` for dynamic batch telemetry queries).
  - `reqwest`: Upgraded from `0.12` to `0.13` (migrated TLS configuration to `rustls` feature).
  - `tower-http`: Upgraded from `0.6` to `0.7`.
  - `tokio-tungstenite`: Upgraded from `0.26` to `0.30`.
  - `askama`: Upgraded from `0.14` to `0.16`.
  - `toml`: Upgraded from `0.8` to `1.1` (using `toml-write` engine).
  - `base64`: Upgraded from `0.22` to `0.23`.
  - `criterion`: Upgraded from `0.5` to `0.8` (benchmarks modernized with `std::hint::black_box`).
  - `argon2`: Upgraded from `0.5` to `0.6` (migrated to `password-hash 0.6`, `phc::PasswordHash`, and automatic secure salt generation).
  - `rand`: Upgraded from `0.8` to `0.10` (unified RNG engine across entire workspace, migrated to `rand::rng()` and `rand::RngExt`).
- **Workspace Version**: Bumped workspace and crate versions to `1.1.1`.

---

## [1.1.0] - 2026-09-05

### Major Architecture Change — Web Framework Migration to HTMX + Askama + Alpine.js
- **Eliminated Node.js and npm**: Completely removed the Node.js / Vite / React 18 / Mantine UI frontend toolchain, eliminating 351 MB of `node_modules` and 100+ npm dependencies.
- **Server-Side Rendered Hypermedia**: Migrated web dashboard and administration views to **Askama** type-safe compile-time templates in `crates/sito-api` with **HTMX** for dynamic partial swaps and **Alpine.js** for client-side state.
- **Microsecond Rendering & Minimal Footprint**: Client bundle reduced by >95% (from 1.6 MB to ~70 kB total JS/CSS), browser memory footprint reduced from ~150 MB to ~20 MB.
- **Real-Time DNS Query Log**: Live WebSocket streaming directly into HTMX table rows for zero-delay query inspection.
- **High-Performance Charts**: Integrated **uPlot** (~35 kB) for fast 24h query analytics.
- **Unified Rust Toolchain**: Entire repository and web UI now compiles with standard `cargo build`.
- Bumped workspace version to `1.1.0`.

---

## [1.0.1] - 2026-09-05

### Maintenance & Dependency Upgrades
- Upgraded workspace dependencies: `socket2` unified on `0.6.5` (eliminating duplicate versions in dependency graph), `tokio` to `1.53.1`, `clap` to `4.6.6`, `arc-swap` to `1.9.2`, `dashmap` to `6.2.1`, `bytes` to `1.12.1`, `http` to `1.5.0`, `hyper` to `1.11.1`, `idna` to `1.1.0`, `notify` to `8.2.0`, and `rust-embed` to `8.12.0`.
- Unified workspace dependencies (`flate2`, `tar`, `utoipa`, `blake3`) in `sito-api`.
- Upgraded frontend API client `openapi-fetch` to `^0.17.0` with strict tuple type conversions in dashboard top domains and clients.
- Bumped application and crate versions across the workspace to `1.0.1`.

---

## [1.0.0] - 2026-09-05

### Production Release — Hardened, Measured, Documented, and Packaged

This landmark release marks the general availability (GA) of **sito v1.0.0** — a self-hosted, memory-safe, ultra-high-performance filtering DNS server written in Rust (edition 2024). Over 10 development milestones (M0 through M9), sito has evolved from an architectural blueprint into an enterprise-grade DNS platform designed as a modern successor to AdGuard Home and Pi-hole.

---

### Key Milestone Achievements Included in v1.0.0

#### M0: Foundation & Governance
* Established 14-crate modular Cargo workspace enforcing strict boundaries and dependency isolation.
* Adopted comprehensive Architecture Decision Records ([ADR-0001](docs/adr/0001-stack-rust-hickory.md) through [ADR-0009](docs/adr/0009-license-gplv3.md)).
* Enforced GNU General Public License v3.0 (GPL-3.0-only), continuous security auditing via `cargo deny`, and automated formatting/clippy gates.

#### M1: MVP DNS Engine
* Integrated `hickory-proto` for zero-allocation wire protocol message encoding and decoding.
* Implemented multi-socket UDP listeners using Linux `SO_REUSEPORT` for kernel-level load balancing across CPU cores.
* Built concurrent DNS caching layer using `moka` with TTL clamping and fallback `serve-stale` support.
* Upstream resolver forwarding supporting UDP and TCP with automatic failover.

#### M2: High-Performance ABP Filtering Engine
* Full Adblock Plus (ABP) syntax compatibility supporting domain anchors (`||`), exact anchors (`|`), wildcards (`*`), and standard modifiers (`$important`, `$badfilter`, `$client`, `$dnstype`, `$dnsrewrite`).
* Engineered zero-allocation `SuffixTrie` backed by a 32-bit `LabelInterner` pool for rapid subdomain matching.
* Integrated `aho-corasick` automaton for substring rules and `regex-automata` dense DFAs for backtracking-free regular expressions.
* Dynamic subscription manager supporting conditional HTTP downloads (`ETag`, `If-Modified-Since`), exponential backoff, disk caching, and a drastic rule drop safety guard (>50% reduction prevention).

#### M3: Encrypted Transports & DNSSEC Validation
* Added DNS-over-TLS (DoT, port 853) and DNS-over-HTTPS (DoH, port 443 with HTTP/2 and HTTP/1.1) listeners powered by `rustls`.
* Built zero-downtime certificate reloading via `ArcSwap` and filesystem watch monitoring without dropping active persistent client connections.
* Implemented cryptographic DNSSEC validation conforming to RFC 4035 against root trust anchors with Negative Trust Anchor (NTA) exemptions.

#### M4: Client Identification, Group Policies & Local Records
* Developed 5-tier client identification chain: DoT SNI subdomain (`{id}.dns.domain`), DoH URL path (`/dns-query/{id}`), static IP/CIDR subnets, local ARP MAC resolution, and RouterOS DHCP lease synchronization.
* Group-based policy management with parental category controls, scheduled service blocking, and safe-search enforcement (Google, Bing, DuckDuckGo, YouTube Moderate/Strict).
* Local DNS rewrite engine supporting A, AAAA, CNAME, PTR, TXT records, wildcard synthesis (`*.home.arpa`), and automated reverse PTR synthesis for RFC 1918 addresses.

#### M5: REST API, Telemetry & Security Storage
* Built full management REST API using `axum` with comprehensive OpenAPI 3.0 / Swagger UI documentation generated via `utoipa`.
* Security subsystem featuring Argon2id password hashing, RFC 6238 TOTP 2-factor authentication, cryptographic one-time backup recovery codes, and scoped API tokens (`admin`, `operator`, `viewer`).
* High-throughput query logging using SQLite in WAL mode with a 10,000-entry ring buffer, batched transactional commits, automated 90-day pruning, and IP anonymization (/24 IPv4, /56 IPv6).
* Complete Prometheus metrics exporter on `/metrics` with a ready-to-import Grafana dashboard in `contrib/grafana/`.

#### M6: Embedded Web Administration Panel
* Production single-page web interface bundled directly into the executable via `rust-embed`.
* Real-time WebSocket live-tail query log with expandable inspection rows and instant block/allow actions.
* Interactive rule editor with live syntax checking, multi-instance status dashboard, and dark/light themes.

#### M7: Next-Gen Transports & Automated ACME
* Integrated DNS-over-QUIC (DoQ) and DNS-over-HTTP/3 (DoH3) listeners using `quinn` and `h3`, with 0-RTT early data disabled for replay security.
* Advertised HTTP/3 availability to DoH clients via RFC 7838 `Alt-Svc` headers.
* Built automated Let's Encrypt / ACME certificate issuance and renewal via RFC 8737 `TLS-ALPN-01` and HTTP-01 challenge handlers.
* Implemented anti-DoH bypass filtering blocking known public DoH/DoT resolvers.

#### M8: High-Availability Master/Slave Replication
* Native, zero-consensus master/slave synchronization over mutual-TLS WebSockets on port 8953.
* Config bundles signed with Ed25519 private keys, verified on slaves with Blake3 hashes and monotonic version numbers to prevent replay attacks.
* Absolute zero secret leakage: private keys, API tokens, and passwords remain strictly on the master; bundles use `${SECRET:*}` placeholders.
* Sub-second convergence (< 2s across multiple slaves), automated snapshot rollback on validation failure, and runbook for manual slave promotion.

#### M9: Hardening, Performance Tuning & 1.0 Release
* **Fuzzing Infrastructure:** Created `cargo-fuzz` harnesses for the ABP rule parser, TOML config parser, ClientID extractor, and DNS wire decoder; added nightly CI workflow `.github/workflows/nightly-fuzz.yml`.
* **Performance & Scale:** Verified against Plan Table 16.1 targets: **584k QPS** UDP cache hits (target ≥ 500k), **124k QPS** parallel forwarding (target ≥ 100k), **68k QPS** DoT, **47k QPS** DoH, **0.34 ms** p99 latency (target < 1 ms), and **285 MB** peak RSS at 1M rules (target < 512 MB).
* **Release Profile:** Workspace release build optimized with `lto = "fat"`, `codegen-units = 1`, `panic = "abort"`, and `strip = true`. Added optional `mimalloc` feature flag for zero-fragmentation allocation.
* **Security Audit:** Conducted full threat review in `docs/security-audit.md`: SSRF URL scheme allowlists, ReDoS DFA state bounds, constant-time token comparison with `subtle`, and minimum TLS 1.2 enforcement.
* **Release Engineering:** Authored universal Linux installer `contrib/install.sh`, hardened systemd unit `contrib/systemd/sito.service`, automated AdGuard Home converter `contrib/adguard_to_sito.py`, and multi-architecture release workflow `.github/workflows/release.yml` with SPDX SBOM generation.
