# Security Review and Threat Model (2.0.0 final)

**Reviewed tree:** `39ba6da71f1068dd7da2ebf339909328bff2df26` (`39ba6da`, 2026-11-27)
**Workspace version:** `2.0.0`; the `v2.0.0` tag and publication are the
release-manager steps (H10), not a code change. This page describes the
frozen 2.0.0 release tree.
**Reviewer:** security reviewer (H4), read-only review of the implementation,
tests and release configuration.

This document summarizes the **implemented** security controls and known
limitations of the 2.0.0 tree. The detailed stream review, unsafe/FFI
inventory, suppression review and accepted-residual register are in the
[2.0.0 security review](phase3-security-review.md). Point-in-time audits with
file/line evidence and remediation status live in the
[historical documentation index](history/README.md); they are leads, not
current evidence.

**Verdict:** no open P0. The only open P1 is the DNAME availability/compatibility
residual (R-1), accepted for 2.0.0 because `validate`/`strict` fails closed
(SERVFAIL, AD=0, uninterpretable answer removed) and covered by
`test_dname_unknown_rdata_fails_closed`. It is owned by the DNSSEC maintainer,
accepted on 2026-11-27 and must be re-reviewed by **2027-01-31** or on any
`hickory-proto` upgrade, whichever comes first. Every other residual is an
accepted availability, exposure, operations, release-evidence or supply-chain
item with an owner or review date in the
[residual register](phase3-security-review.md#13-residual-risk-register).

Current contracts:

* [`docs/2.0-migration.md`](2.0-migration.md) — breaking changes, config and
  database migration, and the upgrade/rollback path.
* [`docs/2.0-claim-matrix.md`](2.0-claim-matrix.md) — delivered/deferred claims
  mapped to code, tests and documentation.
* [`docs/config-v2.md`](config-v2.md) — config v2 validation, unknown-key policy
  and restart-only matrix.
* [`docs/runbook-ha.md`](runbook-ha.md) — HA replication, readiness, manual and
  automatic promotion, fencing and key rotation.
* [`docs/audit6-test-matrix.md`](audit6-test-matrix.md) — named regression tests
  for the P0/P1 safety findings, mechanically checked by
  `scripts/check_test_matrix.py` (821 tokens at this review).
* [`docs/phase3-security-review.md`](phase3-security-review.md) — the 2.0.0
  stream review, unsafe/FFI inventory, suppression review and residual
  register.

Everything below is verifiable in the source at the reviewed SHA; the
referenced modules are the implementation of record.

---

## 1. Control summary

| Domain | Control | Implementation |
|---|---|---|
| **API surface** | `/api/v2` is the only mounted administrative API. `/api/v1` returns `404` after setup with no alias, redirect or facade; every OpenAPI path is under `/api/v2`. `GET\|PUT /api/v2/upstream/config` is an authenticated 308 alias to `/api/v2/upstream`. | `sito-api::router`, `openapi` |
| **API auth/RBAC** | Every non-login handler requires a `Viewer`, `Operator` or `Admin` extractor before doing work; tokens and sessions are validated first. Account-wide API rate limits (`429` + `Retry-After`) charge once per request. | `sito-api::auth::rbac`, `auth::rate_limit` |
| **Sensitive re-auth** | TOTP setup/enable/replace/disable, role changes, Admin user creation, Admin-scoped token creation and cross-account password resets require a short-lived, session-bound, single-use `X-Reauth-Token`; self-service password changes require the current password and TOTP when enrolled. API-token callers are exempt from the ticket as documented. | `sito-api::auth::manager`, `handlers::auth_handlers` |
| **CSRF / browser** | Same-origin `Origin`/`Referer` checks (missing origin fails closed for cookie sessions, `Origin: null` always rejected), session-bound double-submit CSRF tokens, `__Host-` cookies on TLS, `HttpOnly`, `SameSite=Strict`, `Cache-Control: no-store` and `Vary: Cookie` on authenticated `/api/v2/`, `/ui/` and `/metrics` responses, CSP/HSTS/X-Frame-Options/nosniff. | `sito-api::security`, `auth::session` |
| **Query log** | Newest-first keyset pages (`items`/`next_cursor`), default 50/max 500, no `COUNT(*)`; the opaque cursor embeds the row `(ts,id)` and a filter hash, so replaying it with different filters is `400`. The WebSocket live tail accepts only a Bearer header or session cookie, requires a same-origin `Origin` for session clients and never accepts `?token=`. | `sito-stats::db::cursor`, `sito-api::handlers::querylog` |
| **DNS client ACL** | ADR-0011 source-address admission runs before identity, wire parsing and every expensive stage. Deny is authoritative, then explicit allow, then opt-in client-entry allow, then the typed default policy. The ACL reads only the observed peer address: DoH path, SNI, headers, MAC/ARP, RouterOS leases, secrets and groups never admit a source. The compatibility default is `allow`; the **fresh-install wizard presents `deny` checked by default**, and keeping that default writes `deny` plus an explicit allow set (unchecking it is an explicit operator choice to keep `allow`). The ACL is shared HA configuration, compiled once per registry snapshot, hot-swapped atomically, and gated until a fresh slave has applied its first watermarked bundle. | `sito-clients::acl`, `sito::pipeline`, `sito-runtime`, `sito-ha` |
| **Client identity** | Identity comes only from the registry with provenance: configured IP/CIDR, a configured shared secret, a configured MAC entry, or a verified RouterOS HTTPS lease. Wire DoH path/SNI labels are display-only unless they match a configured secret. `clients.trust_arp` defaults to **false**; when enabled it grants only a trusted `IdentitySource::Mac` for an ARP-resolved MAC, never a name/group or another ARP attribute. ARP snapshots refresh in the background (2 s) and a new snapshot invalidates both positive and negative MAC caches through an epoch. | `sito-clients::registry`, `mac`, `sito-core::client` |
| **Outbound EDNS** | Client-only EDNS options `COOKIE`, `NSID`, `PADDING`, `DAU`, `DHU` and `N3U` are always removed from upstream queries. ECS follows `upstream.ecs` (`off` strips and deduplicates cache keys; `forward` clamps IPv4 to `/24`/IPv6 to `/56`, clears scope and zeroes host bits). The DO bit, configured payload behaviour and DNSSEC records are preserved. Response shaping rebuilds OPT from the client query, keeps only EDE across a cache/upstream boundary, and strips DNSSEC records/DO-only options for DO=0 clients. | `sito::pipeline`, `sito-proto::ResponseShaper` |
| **DNSSEC** | Fail-closed validation with trust-anchor chains, DS/DNSKEY walking, NSEC/NSEC3 denial proofs (including wildcard denial and delegation-boundary checks), algorithm/digest policy, key-cache bounds, a shared 5-second per-query validation deadline, CD/DO semantics and AD only for validated answers. DNAME cannot be interpreted by the pinned parser and fails closed in `validate`/`strict` mode (R-1). | `sito-dnssec` |
| **Filtering** | User regex and ABP wildcards compile to dense DFAs with hard budgets (≤ 10k patterns, ≤ 4 MiB pattern bytes, ≤ 16 KiB per pattern, ≤ 10 MiB per DFA and ≤ 60 MiB total) and a bounded per-pattern fallback. Linear-time matching, no backtracking. A budget-truncated rule set exposes dropped-class counters. Empty/zero-yield list responses are rejected unless explicitly allowed; a failed reload keeps the previous snapshot. | `sito-filter`, `sito-rewrites` |
| **SSRF / upstreams** | Subscription schemes are limited to `http`, `https` and `file`. HTTP fetches disable redirects and proxies, resolve and pin the target address, and deny loopback, RFC 1918/ULA, link-local/metadata (including CGNAT, reserved, documentation, and IPv4 embeddings via IPv4-mapped, NAT64, 6to4 and Teredo). Bootstrap answers apply the same denylist and denied-only answers are not cached; `upstream.allow_private_targets` is the only hostname opt-in. Production DoH disables redirects and ambient proxies; `with_client` is documented caller responsibility. | `sito-upstream`, `sito-filter::subscription` |
| **Auth timing** | Argon2id ($m=64$ MiB, $t=3$, $p=4$); constant-time comparisons for API tokens, session cookies, setup tokens and TOTP codes. Login/re-auth/change-password inputs are length-capped before hashing. Concurrent hash/verify work is bounded to **4** operations (`ARGON2_MAX_CONCURRENCY`, ≈256 MiB under a login burst); unknown users still perform a dummy verification. Password changes are self-service for Viewer/Operator/Admin and share the login lockout. | `sito-api::auth` |
| **2FA / lockout** | TOTP with replay cache, BLAKE3 (`b3:`) backup-code digests, lockout and IP throttling; verification is serialized so codes/backup codes are single-use under concurrency. The lockout map is bounded at 10,000 entries and active lockouts are never evicted. | `sito-api::auth::manager`, `auth::totp` |
| **First boot** | One-time setup token (CSPRNG, console-printed, per-IP rate-limited) gates the wizard until setup completes; the token is not pruned while first-run is pending. The wizard is bootstrap-only and returns `403` after setup even for an Admin. A configured-but-unfinished first boot keeps DNS gated across restarts. | `sito-api::auth::manager`, `sito-api::router` |
| **DoS / flooding** | One shared token bucket across UDP/TCP/DoT/DoH/DoQ/DoH3, keyed by IPv4 `/24` and IPv6 `/64` and checked before reading request bodies on DoH/DoQ; per-source connection caps, handshake/request deadlines, maximum connection lifetimes, bounded QUIC windows/streams, and approximate-LRU rate-limit eviction. | `sito-transport`, `crates/sito/src/server.rs` |
| **HA security** | mTLS with BLAKE3 certificate pinning or CA-chain validation (CA-only validates hostname/SAN; a configured pin or CA is always enforced; explicit insecure WS is a documented isolated-network opt-out), constant-time shared-token check, Ed25519-signed bundles with monotonic term/version, config-digest and signing-key-fingerprint binding, master-loss heartbeat deadline (`3 × ping_interval_secs`), applied-config digest drift detection, per-slave publish outcomes that make `/health` false on failure, 64-global/8-per-IP session admission, and a bounded signing-key identity check on state restore. Plaintext replication requires `allow_insecure_ws = true` **and** a non-empty `slave_token` on both ends; `wss://` never falls back to plaintext; plaintext combined with pins/CA is rejected. | `sito-ha`, `sito-ha-types` |
| **HA promotion / rotation** | Automatic promotion is opt-in (`ha.promotion.enabled = false` by default) and uses an external witness lease with monotonic term/revision and a published `(version, hash)` baseline. Acquisition, renewal, quiesce, reconcile, first publish, self-fence and durable fence are implemented; the node is read-only until it holds the lease and publishes. A durable `ha_fence.json`/`ha_fence.pending` blocks every restart until an explicit operator clear-fence. Promotion-enabled startup validates the persisted signing key against rotated state and refuses an old key with `promotion_interrupted`. Corrupt/v1/foreign `ha_state.toml` is left byte-for-byte in place and every start fails closed with no sequence reset. `sito ha rotate-signing-key --confirm` performs an offline backup + new `0600` key + re-seal at a strictly higher term/version, and prints the witness term floor without contacting or publishing. | `sito-ha::promotion`, `rotation`, `sito/src/cli.rs` |
| **Secrets** | HA bundles strip TLS/web keys, auth hashes/tokens, RouterOS credentials and per-client shared secrets (`${SECRET:*}` placeholders where applicable; node-local values are restored on the slave). Config/users/tokens/sessions, TOTP key, HA signing/CA/server/slave keys, `ha_state.toml`, `ha_watermark.toml`, stats database and salt, and updater assets are `0600` (wider modes repaired); updater signature scratch and witness state dir are `0700`; the witness token file must be `0600`. Headers, cookies, private keys and tokens are never logged. | `sito-ha::bundle`, `crypto`, `witness`, `sito-api::config_writer`, `auth::secret_store`, `sito-transport::acme` |
| **Updater** | Allowed repository/host policy, HTTPS only, capped streaming downloads, signature policy (cosign required by default; a present pair is always verified; an incomplete/unverifiable pair fails closed), cross-process update lock (`0600`, `O_NOFOLLOW`), staged-binary verification, backup/restore, temp assets `0600` in a `0700` directory, and preservation of mode/xattrs including `security.capability`. Every redirect hop is revalidated against the HTTPS/host allowlist, loops and hop limits; there is no cross-host or HTTPS-downgrade redirect. In-app apply is disabled on Docker and detected systemd services. | `sito-api::updater`, `contrib/install.sh` |
| **TLS/ACME readiness** | rustls-only, TLS 1.2/1.3, AEAD cipher suites, RPK/SNI certificate support, atomic certificate reload, native ACME (TLS-ALPN-01 with a bound TCP 443 listener, otherwise HTTP-01). Bootstrap certificates are 7-day self-signed placeholders and are not served unless `acme.allow_bootstrap_cert = true`; invalid/expired/mismatched configured TLS material is a startup error. Readiness distinguishes renewal failure, expiry within 30 days, and expired/unparseable material; there is no self-signed fallback for an expired ACME certificate. | `sito-transport::tls`, `::acme`, `sito-api::readiness` |
| **API/config integrity** | Config writes run the same deep typed-section validation as startup, unknown keys/tables are rejected, restart-only writes return `409` and persist nothing, restore archives are decompression-capped, `/metrics` requires Viewer-or-higher by default, tokens expire by default (90 days), deleting a user revokes sessions, and `/health` is generic. | `sito-api::config_validation`, `config_apply`, `handlers::config`, `auth::manager`, `handlers::metrics` |
| **DB/PII** | Stats schema v2 is explicit; startup refuses an older database unless `SITO_DB_AUTO_MIGRATE=1/true`, in which case it takes the shared migration lock, writes a `0600` backup, migrates, verifies, and only then serves. `sito db migrate` supports dry-run, `0600` backups, forward-only upgrade and refuses newer/corrupt schemas and a live service. Rollups use keyed BLAKE3 identifiers and names are opt-in; `sito db anonymize --all` rewrites detailed rows in bounded chunks (IPv4 `/24`, IPv6 `/56`, name cleared) with crash-resume and `VACUUM`. `keep_aggregates` clears are hour/row-bounded and resumable. `stats_watermark` is diagnostic only and is never read to skip rows. | `sito-stats`, `sito/src/db_startup.rs`, `db_anonymize.rs`, `db_migrate_cli` |
| **Unsafe/FFI** | Production `unsafe` is confined to UDP socket setup (`sito-transport::udp`), Unix packet-info syscalls (`sito-transport::pktinfo`), updater xattr/lock/chown syscalls (`sito-api::updater`), wizard interface discovery via `getifaddrs` (`sito-api::ui::handlers::wizard_acl`) and the promotion `CLOCK_BOOTTIME` read (`sito-ha::promotion::clock`). The allocation counter and timing helpers are test-only. Safety arguments are in the [review §5](phase3-security-review.md#5-production-unsafe-and-ffi-review). | as listed |
| **Supply chain** | `cargo deny` (advisories/bans/licenses/sources) in CI, SHA-pinned GitHub Actions, digest-pinned container bases, cosign-signed release archives, SPDX SBOM, BuildKit provenance and image SBOM attestations, per-architecture Trivy scans, and a release-bound catalog SHA-256. The installer requires signatures by default (`SITO_REQUIRE_SIGNATURE=1`, explicit `=0` opt-out); the self-updater uses `server.update_require_signature = true` by default. | `deny.toml`, `.github/workflows`, `contrib/install.sh`, `crates/sito-clients/src/catalog.rs` |

---

## 2. Threat notes

* **Malicious upstream / on-path attacker:** DNSSEC validation is
  non-bypassable in `validate`/`strict` modes, prefetch re-validates before
  caching, and cross-zone signatures are rejected. A chain that cannot be
  proven fails closed. Outbound client-only EDNS options cannot be relayed to
  the upstream or replayed from a cache entry.
* **Malicious subscription lists:** list parsing is fail-closed for regex
  budgets; hostile prefix/ACL load is bounded by the per-list byte cap and the
  parse pipeline never panics.
* **Spoofed DNS source:** admission is the observed peer address, not a DoH
  path, SNI, header, MAC, RouterOS lease, secret or group. A denied query
  writes no query-log row, does no discovery and does not run expensive stages.
  A DoH/DoH3 `X-Forwarded-For` header is never promoted to the client IP.
* **Compromised client identity claims:** DoH path segments and DoT/DoQ SNI
  only identify a client when they match a configured shared secret; filter
  `$client=` and rewrite exceptions use only registry-resolved, authenticated
  provenance. MAC identity requires a configured MAC entry or the explicit
  `trust_arp` opt-in and is only as trustworthy as the local L2/ARP segment.
* **Malicious HA peer:** mTLS pin/CA validation, signed bundles bound to the
  config digest and signing-key fingerprint, term/version continuity and
  secret stripping bound a compromised replica. A replica cannot publish; a
  promoted candidate must first acquire the witness lease, quiesce, reconcile
  and durably publish. A durable fence blocks a restart from re-acquiring.
* **Compromised witness:** the witness is a **trusted safety authority**. It
  holds no bundle-signing key and cannot forge configuration, but it decides
  which node may become writable. Its bearer token is `0600`, its TLS is
  CA/pin verified and there is no plaintext fallback; compromise of the
  witness host can defeat the single-writer guarantee. Run it on a separate,
  hardened host/VM and back up `lease.json`.
* **Stolen admin session:** bounded by re-authentication tickets, CSRF/Origin
  checks, session epochs and `no-store` responses. Admin API tokens are
  intentionally exempt from the interactive ticket; treat them as
  high-value credentials.
* **First-boot exposure:** during setup no DNS listener is bound and the
  wizard is token-gated. The 1.9.5 line binds the setup panel on
  `0.0.0.0:8080`; the 2.0 config-v2 safe default is `web.bind =
  "127.0.0.1"`. The shipped Compose file publishes the admin port only on
  loopback either way. Operators exposing the setup endpoint beyond a trusted
  network should treat the printed token as the only credential until setup
  completes.
* **Container isolation:** images run as nonroot (uid/gid 65532) with
  `NET_BIND_SERVICE` required for ports < 1024. Compose adds
  `no-new-privileges`, a read-only root filesystem and a small `/tmp` tmpfs;
  `/etc/sito` is the named `sito-config` volume and `/var/lib/sito` the named
  data volume, both initialised with uid/gid 65532. HA bind mounts still need
  `chown 65532:65532` on config and certificate directories, with keys `0600`.
  Docker's `ports` mapping controls host exposure; publish the admin port only
  on loopback (`127.0.0.1:8080:8080`).

---

## 3. Verification

The frozen full gate on `39ba6da` is green: fmt, clippy all-features/all-targets
`-D warnings`, `cargo test --workspace --all-features --locked` (65 suites,
**2,469 passed / 0 failed / 5 ignored**), `cargo test --workspace --locked`
(**2,229 passed / 0 failed / 5 ignored**), `cargo deny check`, catalog check,
and the docs/config/migration/test-matrix/fuzz/bench checks. This review did not
rerun the full workspace suite; it reran the focused checks below on the same
SHA.

```bash
cargo deny check
cargo test -p sito-api --all-features --lib test_api_surface_uses_only_v2_and_removes_v1
cargo test -p sito-api --all-features --lib test_querylog_stream_rejects_query_token
cargo test -p sito-clients --all-features --lib acl
cargo test -p sito-clients --all-features --lib trust_arp
cargo test -p sito-ha --all-features --lib corrupt_v1_and_foreign_state_fail_closed
cargo test -p sito-ha --all-features --lib promotion_master_refuses_old_key_with_rotated_state_before_acquisition
cargo test -p sito-ha --all-features --lib self_fence_persists_and_a_restart_refuses_to_acquire
cargo test -p sito --all-features --lib test_upstream_query_strips_client_only_edns_options
cargo test -p sito --all-features --test db_migrate_cli
cargo test -p sito --all-features --test db_anonymize_cli
python3 scripts/check_markdown_links.py
python3 scripts/check_test_matrix.py
python3 scripts/check_migration_guide.py
git diff --check
```

Results are recorded in the [review §12](phase3-security-review.md#12-verification-evidence).
`cargo deny check` reports `advisories ok, bans ok, licenses ok, sources ok`,
with the expected `advisory-not-detected` warning for the two reviewed
suppressions. The H1 24-hour fuzz campaign is green at `39ba6da` (run
45922217501, 25/25 fuzz jobs, zero crash artifacts); the H2 7-day live soak is
release-checklist evidence still in progress and is not claimed by this review.

---

## 4. Known accepted limitations

* **P1-1 DNAME residual (R-1, open P1, accepted for 2.0.0):**
  `hickory-proto 0.26.3` decodes DNAME as `RData::Unknown { code: DNAME }`. In
  `validate`/`strict` mode the validator returns `Bogus`, turns the response
  into SERVFAIL, clears AD, removes the uninterpretable answer and records the
  failure. A legitimate DNAME alias therefore fails closed
  (availability/compatibility limitation, not an authentication bypass);
  `log_only` returns it without AD by design. The regression test is
  `test_dname_unknown_rdata_fails_closed`. Owner: DNSSEC maintainer. Re-review
  on a `hickory-proto` upgrade or by **2027-01-31**.
* Query-string credentials are not accepted. The querylog WebSocket upgrade
  requires an `Authorization: Bearer` header or the `__Host-` session cookie
  (BC-8); `?token=` is ignored and an unauthenticated upgrade is rejected.
* Rate-limiting budgets are enforced per network prefix (IPv4 `/24`, IPv6
  `/64`), not per authenticated account. Authenticated API requests also have
  the account-wide ceiling.
* The account lockout map is bounded at 10,000 entries. If every entry is an
  active lockout, a new key is not tracked and relies on the per-IP login rate
  limit when `auth.login_rate_limit > 0` (setting it to `0` disables that
  fallback too). An active lockout is never evicted to make room.
* `auth.token_default_ttl_days = 0` disables token expiry for operators who
  explicitly opt out; the default is 90 days.
* DNSSEC wildcard denial requires complete NSEC/NSEC3 proofs; responses whose
  proofs are incomplete are treated as `Bogus` (fail closed) rather than
  downgraded to `Insecure`.
* The DNS client ACL's typed default is `default_policy = "allow"` so upgrades,
  headless installs and hand-written configs keep their 1.9.x behaviour. Only
  a fresh install completed through the wizard writes `deny`. `dns.bind =
  "0.0.0.0"`/`"::"` plus a host firewall remains defense in depth. A
  promotion-enabled HA cluster reports `acl_capability_missing` while a
  connected peer does not advertise `client_acl`; the cluster must upgrade
  peers before enabling deny. The slave DNS gate is tested through the startup
  seam, not a full socket-level listener integration test.
* `clients.trust_arp` is off by default. When enabled, MAC identity is only as
  trustworthy as the local L2/ARP environment; an on-link attacker can spoof
  it. It never grants a name, group or non-MAC identity.
* Automatic HA promotion is opt-in and default-off. The witness is a single
  point of **availability**: an outage fences the current master after the
  lease TTL and blocks promotion until it returns (DNS reads continue). The
  witness is also a trusted **safety** authority: its compromise can break the
  single-writer guarantee. `allow_unpinned_tls` and `allow_insecure_ws` are
  explicit insecure opt-outs; a configured pin or CA is still enforced and
  plaintext requires a shared token on both ends. Direct edits of shared
  `config.toml` fields are not rejected at edit time; drift is detected after
  the write and requires a full apply (role/logging/legacy auth keys are
  excluded from the projection).
* Config and `users.toml` atomic writers still create their temporary sibling
  with the process umask and narrow it to `0600` before content is written. A
  local user who opens the empty inode during that short window can retain a
  read descriptor; content is never written while wider than `0600`. This
  local-only race is accepted for 2.0.0; recommended hardening is
  `OpenOptionsExt::mode(0o600)` at create (R-14).
* Live query-log anonymization is forward-only. Enabling
  `privacy.anonymize_querylog` masks new rows; existing detailed rows are
  rewritten only by the explicit offline `sito db anonymize --all` command.
  The 1M-row/90-day capacity tests are `#[ignore]`/gated evidence, not default
  CI. Retention/rollups use bounded chunks, `keep_aggregates` is resumable and
  serialized with retention, and `stats_watermark` is diagnostic only.
* The updater follows only HTTPS redirects to an allowlisted GitHub host set
  and revalidates every hop. A compromise of an allowlisted download host is
  still mitigated by the mandatory (by default) cosign signature; an operator
  who sets `server.update_require_signature = false` accepts checksum-only
  integrity.
* The release image scan ignores **unfixed** HIGH/CRITICAL findings by design
  and fails only on fixed findings. Scanner/database and runner identity are
  supply-chain dependencies.
* The updater's `WitnessCert` type derives `Debug` while containing
  `key_pem`; no current production path prints it, but a future caller that
  logs the whole struct would expose a private key. Prefer a redacted `Debug`
  in a hardening pass.
* Self-update under systemd requires running `sito update` as root with the
  service stopped (the unit keeps `ProtectSystem=strict`). The updater writes a
  temporary executable next to the target, copies the existing mode and xattrs
  (including `security.capability`), then renames; a missing attribute or
  failed rename aborts and removes the temp file. The installer backs up the
  config only after stopping the service and restores it with temp-file +
  rename.
* RouterOS integration is experimental/niche and is not part of the core
  security posture. It lives in the optional `sito-routeros` crate and is
  absent from the default build. If enabled, only a verified `https://` lease
  grants identity; plaintext or insecure-TLS leases are unverified, ignored by
  identity matching, and not exposed by the 2.0 admin UI/API.
* Pull requests compile the Criterion benches but do not run a performance
  threshold. The nightly `bench.yml` comparison is **active**: it runs on
  GitHub-hosted `ubuntu-24.04`, compares against the committed
  `benches/baseline.json` and fails above the tolerance (default 10%). The
  checker fails closed on an environment mismatch.
* The H1 24-hour fuzz campaign (five targets × five shards × 17,280 s) is green
  at `39ba6da` (run 45922217501, 25/25 fuzz jobs, zero crash artifacts). The H2
  7-day live soak started `2026-11-27T10:38+01:00` and is in progress; it is
  release-checklist evidence with an owner, and this review does not claim a
  completed soak before the accepted window is recorded.
