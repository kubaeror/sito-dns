# sito 1.9.4 — release notes

Target release: **1.9.4** on 2026-11-10. This is the Phase 0 **safety-gate**
patch: it closes the release-blocking P0 and directly exploitable P1 findings
recorded in [audit6.md](audit6.md) while remaining a non-breaking 1.9.x patch.
There is **no configuration v2, REST/API v2, SQLite schema break, or HA
wire-protocol break**. A few additive configuration keys default to the safe
behavior described below.

The complete commit-level record is in [CHANGELOG.md](../CHANGELOG.md); this
document is the operator-facing summary and upgrade guide.

## Release-blocking security fixes

### ACME and TLS

- **A fresh ACME-only install can obtain a certificate.** The bootstrap
  certificate is now a short-lived (7-day), explicitly marked placeholder
  instead of a year-4096 self-signed certificate. A legacy 1.9.3 bootstrap pair
  is detected (self-signed issuer) and replaced by a real certificate.
- **Bootstrap serving is fail closed by default.** Set
  `acme.allow_bootstrap_cert = true` only if you accept the self-signed
  placeholder on DoT/DoH/DoQ/DoH3 until the first certificate is issued. With
  the default `false`, encrypted listeners stay disabled until a trusted
  certificate exists; the ACME manager still obtains the certificate through
  HTTP-01. A usable stored ACME certificate takes precedence over static
  `[tls]` files on restart; a bootstrap/expired placeholder never displaces a
  real static pair.
- **Correct challenge selection.** TLS-ALPN-01 is selected only when a DoH
  listener is actually bound on TCP 443. Otherwise HTTP-01 is used, and only
  after its listener binds successfully.
- **All encrypted transports reload after issuance.** DoT, DoH, DoQ, and DoH3
  now reload the issued certificate; previously only DoH did.
- **Invalid TLS material fails startup.** Unreadable, expired, malformed, or
  certificate/key-mismatched configured TLS material aborts startup instead of
  logging a warning and silently leaving encrypted listeners absent.
- ACME account credentials are written atomically with mode `0600`. Corrupt
  credentials or credentials registered against a different directory are
  backed up and re-registered instead of blocking renewal.

### DNSSEC

- **Delegation denial is checked.** Parent-side NSEC/NSEC3 records (NS without
  SOA) can no longer authenticate NXDOMAIN/NODATA below a delegation. DS
  NODATA at the cut still validates.
- **Junk signatures cannot suppress probing.** The unsigned-delegation probe is
  driven by relevant RRsets, not the presence of any RRSIG; forged covering
  signatures without a validated key still reach the bounded probe/fail-closed
  decision.
- **Signed CNAME into an unsigned target requires an authenticated DS denial.**
  Without one, strict/validate mode returns SERVFAIL rather than AD=0.
- **Strict mode fails closed on `Indeterminate`.** `log_only` keeps AD=0.
- NSEC3 opt-out next-closer wildcard NODATA is `Insecure`/AD=0, QTYPE=CNAME
  positive answers are not treated as negative, multi-label wildcard expansions
  validate, and chain-cache inserts from an old policy generation are rejected.
- **Bounded work:** validation and key/chain fetching share a 5-second
  per-query deadline. A timed-out validated query returns SERVFAIL; log-only
  returns AD=0.

### HA

- **Master-loss detection.** A slave that receives no frame (push, ping/pong,
  stats, close) within `3 × ping_interval_secs` (default 45 s) leaves `Synced`,
  records a `readiness_reason`, and fails `/health` while DNS keeps serving the
  last applied configuration.
- **Local drift detection.** `ha_watermark.toml` stores a BLAKE3 digest of the
  exact applied `config.toml`. A local edit/revert marks the node `Degraded` and
  forces a full apply before it can report `Synced`. A 1.9.3 watermark without a
  digest performs one full apply after upgrade.
- **Publish failures are visible.** `publish_bundle()` returns a fallible
  outcome; failed publishes make HA readiness false, expose an additive
  `ha_publish` object on config writes, and retry with a bounded backoff. The
  local config is not rolled back merely because replication failed.
- **Oversized bundles are rejected before persistence.** A signed WebSocket
  envelope over the 1 MiB limit returns an apply error and rolls back the live
  config instead of poisoning every slave forever.
- **Per-slave divergence.** `POST /api/v1/ha/resync` re-pushes the current
  bundle; it does not clear another slave's divergence. Each slave's record
  clears only when that slave ACKs the current term/version.
- **Signing-key identity.** `ha_state.toml` records the master signing key;
  replacing/losing `ha_signing.key` fails startup with an actionable mismatch
  error instead of silently re-signing persisted state.
- **Resource hardening:** 10 s WebSocket writes, 4 MiB per-slave queue budget,
  and 64-global/8-per-source-IP HA session admission. A NAT with more than eight
  simultaneous HA peers per source address needs separate addresses.
- The slave keeps a single `master_fingerprint`; the master keeps a list of
  `pinned_slave_fingerprints`. When `ca` is configured, hostname/SAN validation
  is always performed even with pinning; `allow_unpinned_tls` remains an
  explicit insecure opt-out.

### Authentication and API

- **TOTP operations require re-authentication.** Setup, enable/replace, and
  disable require a 5-minute ticket from `POST /api/v1/auth/reauth` in
  `X-Reauth-Token`. The ticket is bound to the account, session, and credential
  epoch. A stolen Admin session can no longer take over 2FA.
- **The wizard is bootstrap-only.** After setup, `/wizard` and
  `/ui/wizard/complete` return `403` even for an Admin session. Use the
  authenticated account flow for password changes.
- **Self-service 2FA for every role.** Viewer, Operator, and Admin can enroll,
  replace, and disable TOTP from `/account`; API bearer tokens are rejected for
  TOTP and reauth.
- **Login input bounds and lockout hardening.** Usernames over 64 bytes and
  passwords over 1024 bytes are rejected before lockout bookkeeping or Argon2.
  Lockout keys are BLAKE3 digests and active lockouts cannot be evicted by
  username spraying.
- **Status corrections:** auth creates return `201`, the TOTP challenge returns
  `202`, `update_user` reports the real `totp_enabled`, and duplicate client
  groups return `409 Conflict`.
- The legacy `?token=` query parameter remains accepted **only** on a WebSocket
  upgrade without an `Authorization` header, logs a warning, and is scheduled
  for removal in 2.0. Use `Authorization: Bearer` or a session cookie.

### Filtering

- **Empty/HTML/zero-yield lists are rejected by default.** The previous rules
  stay active and the list is marked failed/degraded. Set
  `filtering.allow_empty_list = true` only for a source that legitimately
  returns an empty list.
- **Zero-source filtering fails closed.** `filtering.enabled = true` with no
  enabled lists and no custom rules is unavailable on a cold start (SERVFAIL
  with the default `fail_closed = true`). Configure a source or set
  `filtering.enabled = false`. Removing the last source from a live
  configuration is rejected and keeps the previous snapshot.
- **Budgets are enforced before allocation:** per-line (8 KiB), per-pattern
  (16 KiB), total input bytes, total rules, regex, Aho-Corasick, and prefix
  limits. Oversized sets keep the previous snapshot instead of partially
  dropping a class.
- A malformed `$dnstype`/`$denyallow` token rejects the whole rule; it no longer
  widens by keeping the valid subset.
- Rewrite exceptions no longer trust DoH-path/SNI ids unless the client
  registry authenticated them (`/dns-query/<name>` cannot spoof a client).
- Group compile-budget failures publish the non-regex subset and report the
  group degraded instead of dropping it; stale group rebuilds are discarded.
- `GET /api/v1/filtering/status` and new Prometheus gauges expose
  loaded/failed/degraded lists, degraded groups, dropped regex patterns,
  unavailability, and compile time.

### Transport and response shaping

- **DoQ admission:** 128 KiB per-stream / 2 MiB per-connection flow-control
  windows, 16 concurrent bidi streams, a global stream semaphore, per-IP
  connection cap, pre-read rate check, 10 s handshake timeout, and tracked
  shutdown.
- **DoH/DoH3 admission:** DNS bodies are read only after rate/global admission;
  a global in-flight request cap returns 503, HTTP/2 streams are capped at 32,
  and requests/connections have absolute deadlines/lifetimes.
- **One response-shaping path:** cache hits, upstream, stale, and synthesized
  answers carry the current client question/RD/CD/ID, rebuild OPT from the
  client's EDNS, never replay upstream EDNS options (COOKIE/NSID/ECS/padding/
  unknown), never send OPT to non-EDNS clients, and only include DNSSEC records
  when the client asked for them.
- QR=1 messages are dropped; zero/multi-question queries get FORMERR before any
  policy/cache/upstream work.
- Rate limits are keyed per IPv4 `/24` and IPv6 `/64` (IPv4-mapped IPv6 peers
  use the IPv4 bucket) with approximate-LRU eviction. Per-source connection
  caps apply to TCP/DoT/DoH/DoQ/DoH3; TCP and DoH have explicit maximum
  connection lifetimes, while DoT/DoQ/DoH3 rely on idle, handshake and request
  deadlines rather than a separate maximum lifetime. Accept loops back off on
  resource-exhaustion errors.
- ACME HTTP-01 has connection/per-IP/rate/header/lifetime limits.
- DoQ/DoH3 connection and request tasks are tracked and drained on shutdown.

### Upstream

- **Bootstrap and health probes set RD=1.** Recursive resolvers that refuse
  RD=0 no longer make bootstrap or probes falsely mark a working upstream down.
- **Bootstrap answers are SSRF-filtered by default.** A hostname-configured
  upstream may not resolve to loopback, private, link-local, CGNAT, multicast,
  reserved, metadata, or NAT64/6to4/Teredo-embedded private addresses. IP
  literals remain an explicit operator choice. Opt in with
  `upstream.allow_private_targets = true`.
- **Forced refresh picks up rotated addresses** within the existing query
  timeout; plain UDP ignores malformed/mismatched junk until the deadline.
- A bare `https://host` DoH target uses `/dns-query`; upstream DoH ignores
  ambient proxy environment variables so address pinning cannot be bypassed.
- FORMERR/BADVERS triggers one no-EDNS retry per candidate; wedged DoQ
  connections are dropped so the next query reconnects.
- Per-client scoped upstream managers rebuild when bootstrap, timeout, strategy,
  pool size, or `allow_private_targets` changes.

### Installer, release, and cache

- **Live upgrade/rollback works.** The installer stops the service, installs via
  temp file + fsync + rename, re-applies `cap_net_bind_service`, and starts the
  service; a failed health check restores both the previous binary and
  `/etc/sito/config.toml.bak`.
- **Signatures are required by default.** Missing cosign, `.sig`, or `.pem`
  fails closed. `SITO_REQUIRE_SIGNATURE=0` is the explicit SHA-256-only opt-out.
  Cosign itself is installed checksum-verified unless
  `SITO_INSTALL_COSIGN=0`.
- Releases are gated on the required branch and green `ci-gate`/`cargo-deny`
  checks; container images are Trivy-scanned for fixed HIGH/CRITICAL
  vulnerabilities (`--ignore-unfixed` suppresses unfixed findings entirely,
  rather than merely not failing the gate) and cosign-signed with
  provenance/SBOM attestations.
- `invalidate_domain` works: cache invalidation closures are enabled, and a
  runtime error flushes the cache rather than reporting success while leaving
  stale entries.
- The bundled SQLite dependency is pinned to a patched `libsqlite3-sys`
  (`0.39.1`, SQLite ≥ 3.54.1); the stale advisory suppression is removed.

## Configuration additions

These keys are additive, optional, and default to the safer behavior:

| Key | Default | Effect |
|---|---|---|
| `acme.allow_bootstrap_cert` | `false` | Serve the short-lived self-signed ACME placeholder on encrypted listeners before the first trusted certificate. |
| `upstream.allow_private_targets` | `false` | Allow hostname-configured upstreams to resolve to private/reserved addresses. IP literals are unaffected. |
| `filtering.allow_empty_list` | `false` | Accept an empty list body or a source that parses to zero rules instead of retaining the previous snapshot and marking the list failed. |

No other configuration key, default, API shape, database schema, or HA protocol
field changed. Several response/status fields are additive (`ha_publish`,
filter status); existing clients ignore unknown fields.

## Upgrade actions

1. **Review ACME deployments.** If you relied on the self-signed bootstrap
   certificate for DoT/DoH/DoQ/DoH3 before the first issuance, set
   `acme.allow_bootstrap_cert = true`. Otherwise encrypted listeners remain
   disabled until the ACME certificate is obtained. After the first certificate
   with the default `false`, restart once to start listeners that never existed.
2. **Review hostname upstreams that intentionally use private addresses.** Set
   `upstream.allow_private_targets = true`; otherwise bootstrap resolution fails
   closed with an error naming the key.
3. **Review filtering with no sources.** If `filtering.enabled = true` and you
   have neither lists nor custom rules, add a source or disable filtering;
   otherwise a cold start fails closed (SERVFAIL by default).
4. **Update TOTP automation.** Scripts that call TOTP setup/enable/disable must
   first call `POST /api/v1/auth/reauth` and send `X-Reauth-Token`. Existing
   request/response bodies are otherwise unchanged.
5. **Expect one full HA apply after upgrade.** A 1.9.3 watermark has no config
   digest; the slave performs one full apply and then resumes early ACKs.
6. **HA certificate rotation:** the master may pin old and new slave
   fingerprints, but each slave has one `master_fingerprint`. With `ca`
   configured, include the LAN IP/hostname in the SAN.
7. **No data migration is required.** Existing configs, SQLite databases,
   sessions/tokens, and HA state files load; additive fields default safely.
8. **Pin releases.** Use `SITO_VERSION=1.9.4`/tag-pinned installer scripts and
   the `1.9.4` image tag instead of mutable `main`/`latest` in production.

## Stats privacy, retention, and polling

P1-19, P1-23, and P1-24 are closed in this branch:

- **P1-19 — query-log/rollup privacy.** `stats_hourly` now stores client IPs as
  keyed BLAKE3 hashes using `<data_dir>/stats-salt` (0600); client names are
  omitted unless `stats.rollup_client_names = true`. Rollups expire after
  `stats.rollup_retention_days` (default 365). “Clear query log” deletes both
  `query_log` and `stats_hourly` by default (`?keep_aggregates=true` preserves
  rollups), large clears are vacuumed, SQLite runs with `secure_delete=ON`, and
  `stats.db`/WAL/SHM permissions are repaired to 0600 on startup. Switching
  `rollup_client_names` off scrubs names from existing rollups on the next
  startup. Existing raw rollups are hashed once on startup; raw `query_log`
  rows are not retroactively anonymized.
- **P1-23 — query-log/dashboard polling cost.** Query-log pages accept
  `include_total` (default `true`; the live 3 s UI refresh sends `false`), and
  dashboard aggregates are cached for 45 s with invalidation on clear/retention.
  Stats endpoints are rate-limited per authenticated user.
- **P1-24 — retention lock duration.** Retention processes bounded hour chunks
  in separate short transactions, runs a bounded jittered catch-up on every
  startup (within 5 minutes even when the last success is recent), and exposes
  success/failure, duration, deleted-row and rollup-cleanup metrics.

Additional deferred/unchanged items:

- **DNAME (P1-1 residual).** The pinned `hickory-proto 0.26.3` has no DNAME
  RDATA type; a wire DNAME record decodes as `RData::Unknown { code: DNAME }`.
  The validator cannot interpret/follow it and fails closed in `validate` mode
  (Bogus/SERVFAIL, `AD=0`) without rejecting the whole message. This is not an
  `AD=1` bypass, but signed DNAME answers do not resolve until a hickory
  upgrade or local RDATA support lands in Phase 1/2.
- **RouterOS** remains an experimental, niche integration with the 1.9.x
  behavior; moving it behind an optional feature is a 2.0 item.
- **Fuzzing** is not part of the 1.9.4 build or CI. The old `fuzz/Cargo.toml`
  commands in the 1.9.2/1.9.3 release notes are marked historical; the harness
  existed through the v1.9.3 tag and was removed by the post-tag CI rework. See
  [docs/ci.md](ci.md#scheduled-fuzzing-was-intentionally-removed).
- **Benchmarks** remain a v1.0.0 reference-hardware record. The weekly job runs
  `cargo bench` and uploads estimates but has no threshold or regression gate.
- **Structural 2.0 work** (one validator, one runtime generation, one DNSSEC
  chain/denial walker, one HA session model, one filter status model) is not in
  this patch.

## Documentation and CI

- `docs/audit6.md` now records the Phase 0 outcome; the claim matrix has
  1.9.4 status and uses section references instead of stale line numbers.
- Current docs were corrected for ACME/TLS precedence, `/metrics`
  authentication, HA resync/pinning/SAN behavior, TOTP/reauth and
  wizard-bootstrap behavior, installer signature defaults, `--no-setup`,
  schedule timezone, container host vs in-container binds, benchmark provenance,
  and config defaults/types.
- `scripts/check_config_reference.py` now validates documented types and
  extractable defaults in addition to key presence.
- New `scripts/check_markdown_links.py` validates internal links and heading
  anchors across tracked Markdown; it is wired into the Docs CI lane.

## Validation

The safety-gate changes carry regression tests that fail without the fix. The
release baseline remains:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-features --all-targets -- -D warnings
cargo test --workspace --all-features --locked
cargo deny check
python3 scripts/check_config_reference.py --github
python3 scripts/check_markdown_links.py
```

The mock ACME CA used by the acceptance tests proves renewal scheduling,
challenge selection, persistence, and transport reload; it does not perform
real ACME challenge validation. The image scan/sign steps require GitHub OIDC
and GHCR and are covered by the static release-workflow policy test.

## Known issues

- A first ACME issuance with `allow_bootstrap_cert = false` requires one restart
  before encrypted listeners start (they are not hot-created after the first
  certificate).
- ACME readiness is visible in `/health` (`acme.ready` and the stable reason
  `acme_challenge_unavailable`) and in the authenticated `/api/v1/status`
  response. When neither port 80 nor a TCP 443 TLS-ALPN listener is available,
  issuance retries on the normal backoff while an existing certificate keeps
  serving; it does not abort startup.
- DoH returns HTTP 504 on its total request deadline while DoH3 aborts the
  stream; the parity difference is documented in the transport tests.
- TCP/DoH 300 s maximum-lifetime paths are covered structurally but not by a
  five-minute end-to-end test.
- `MAX_HANDSHAKES_PER_IP = 8` counts whole HA sessions; large shared-NAT
  clusters need more source addresses.
