# sito 2.0.0

**Target release:** `2.0.0` (release date pending; the `v2.0.0` tag has not
been created).

**Status: final release-notes text for the frozen 2.0.0 tree; the `v2.0.0` tag
is not created and no 2.0.0 stable artifact is published by this document.**
The code is frozen at `39ba6da`; the workspace version is `2.0.0`. The tagged
release workflow and `latest` move are the H10 step. The published stable line
remains **1.9.5** until that tag is published.

- **Source:** `v2.0.0` (tag pending; workspace reports `2.0.0`)
- **Config schema:** v2 only (`config_version = 2`); a v1 file must be migrated
- **Database:** statistics schema v2; explicit/opt-in `sito db migrate`
- **HA:** protocol v2; a coordinated cluster upgrade is required
- **API:** `/api/v2` only; `/api/v1` returns 404
- **Platform:** Linux is the supported production/test platform; macOS is
  development-only and not CI-covered; Windows is unsupported

## Highlights

- DNSSEC chain/delegation/NSEC3 validation with a shared per-query deadline and
  a fail-closed strict mode.
- Budgeted filter parsing/compilation, validated rewrites, group snapshots that
  never silently disappear, and a documented precedence matrix.
- Strict client MAC identity, ARP-aware cache invalidation, schedules, safe
  search and curated-list status/refresh operations.
- Pre-body transport admission, TLS manager-set reloads, QUIC connection
  lifetimes and visible encrypted-listener bind failures.
- Upstream bootstrap/probe SSRF checks, DoH path/proxy/ALPN correctness and
  per-attempt RTT/error metrics with stale-series pruning; optional weighted
  `load_balance` selection (global and per-domain config weights).
- Client-neutral response shaping, cache status/AD sanitization, TTL
  re-clamping and per-transport oversize truncation.
- HA protocol v2 with signed config digest/signing-key fingerprint, explicit v1
  rejection, truthful publish outcomes and bounded queues/history.
- Opt-in HA automatic promotion (ADR-0010, default `false`): witness lease,
  pre-publish quiesce, hello-only reconciliation, durable self-fencing,
  `promotion` status, bounded-label metrics/audit events and the local
  `confirm-promotion`/`clear-fence` CLI. Offline Ed25519 signing-key rotation
  and term-only witness recovery are documented in the HA runbook.
- Self-service password/2FA for every role; session-bound re-authentication for
  sensitive Admin mutations; bounded Argon2 work; account-wide authenticated
  API rate limits.
- OpenAPI security/tag/path coverage, fail-closed config apply, `no-store` API
  responses, WebSocket Origin checks, Viewer URL redaction and a hardened
  updater (systemd/Docker refusal, locking, rollback, signature policy).
- Bounded stats retention, keyed rollup PII hashing, live-tail clone gating and
  a cached dashboard aggregate; explicit schema/PII migration with a `0600`
  backup and fail-closed startup.
- ADR-0011 default-deny DNS client ACL for fresh wizard installs, with
  compatibility `allow` for upgrades/headless installs, hot reload and HA
  provisioning/capability gates.
- Embedded, release-bound HostlistsRegistry catalog with a pinned SHA-256;
  catalog metadata is never fetched at runtime.
- Loopback-admin Compose, hardened systemd unit, atomic installer rollback and
  capability-preserving updates.

## Breaking changes

Read the full [migration guide](2.0-migration.md) and its
[breaking-change index](2.0-migration.md#3-breaking-change-index). The final
index is BC-1 through BC-12:

| ID | Change |
|---|---|
| BC-1 | Config v2 is required; unknown keys/tables are rejected and v1 must be migrated |
| BC-2 | Safer new-install defaults; migrated v1 files stay behavior-preserving unless `--adopt-safe-defaults` is passed |
| BC-3 | Admin writes to restart-only fields return `409` and persist nothing |
| BC-4 | `/health` is a generic 200/503 probe; details move to authenticated status endpoints |
| BC-5 | RouterOS is an optional crate; unverified leases never grant client identity |
| BC-6 | Internal workspace Rust APIs changed (source-breaking; see the public API diff) |
| BC-7 | HA protocol v2 is incompatible with v1 peers/state; coordinated cluster upgrade required |
| BC-8 | The WebSocket `?token=` credential is removed; use the session cookie or Bearer |
| BC-9 | Updater/validation strictness: no in-app update under systemd/Docker, signature policy, stricter MAC/rewrite/upstream/filter bounds |
| BC-10 | Client-visible `/api/v2` REST contract: v1 gone, cursor query-log pages, `/upstream/config` 308 alias, new auth/error statuses |
| BC-11 | Statistics schema v2 with explicit/opt-in forward-only migration; startup fails closed on an unmigrated database |
| BC-12 | Fresh wizard installs start with a default-deny client ACL; upgrades/headless installs keep `allow` |

## Upgrade

1. Back up the whole data directory and `config.toml` (including `users.toml`,
   `totp.key`, `stats.db`, `stats-salt`, ACME material and HA state/watermark).
2. Stop the service.
3. Migrate the config and review the report:

   ```bash
   sudo sito config migrate --from v1 --to v2 --backup --config /etc/sito/config.toml
   sudo sito check-config --config /etc/sito/config.toml
   ```

4. Migrate the statistics database, or opt in to startup migration:

   ```bash
   sudo sito db migrate --config /etc/sito/config.toml --dry-run
   sudo sito db migrate --config /etc/sito/config.toml
   # or: SITO_DB_AUTO_MIGRATE=1
   ```

   Startup fails closed by default when `stats.db` is still schema 1. Installer
   and container upgrades run the explicit `sito db migrate` step before the
   new server starts; they do not rewrite `config.toml`.
5. Start 2.0 and verify DNS, `/health`, and authenticated `/api/v2/status`.
6. HA only: follow the coordinated v1→v2 procedure in
   [`docs/runbook-ha.md`](runbook-ha.md#7-ha-protocol-v2-upgrade-and-downgrade).
   Move the v1 `ha_state.toml`/`ha_watermark.toml` aside after backing them up;
   v1 state is refused by design.

### Installer and containers

The installer resolves the latest **stable** release by default. The published
stable tag and Compose pin stay on `1.9.5` until the final `v2.0.0` tag moves
them; this document does not move `latest` or publish a 2.0 image. Once
`v2.0.0` is published, install it with its explicit version/tag (and pin the
digest for production):

```bash
SITO_VERSION=2.0.0 bash contrib/install.sh
SITO_IMAGE=ghcr.io/kubaeror/sito-dns:2.0.0 docker compose up -d
```

The shipped `docker-compose.yml` remains pinned to `1.9.5` until the release
manager's final-tag step.

## Rollback

- Keep the previous binary/container tag and the pre-upgrade data/config backup.
- A 2.0 config is not readable by 1.9.x; restore `config.toml.v1.bak`.
- Statistics schema v2 is additive and a 1.9.5 binary can still open a migrated
  data directory, but the migration itself is forward-only: for the exact
  pre-migration state, restore the `stats.db.v<found>.bak` snapshot before
  starting the old binary. Anonymization has no inverse; keep a
  pre-anonymization copy.
- HA v2 is not rollback-safe in place: restore the pre-upgrade
  `ha_state.toml`/`ha_watermark.toml` and certificates before starting a v1
  binary.

See [migration §10](2.0-migration.md#10-rollback-and-known-issues) for the full
rollback procedure.

## Verification and release evidence

The frozen-tree hand-off is recorded in
[`docs/release-verification.md`](release-verification.md) and the
[claim matrix](2.0-claim-matrix.md).

| Evidence | Status |
|---|---|
| Frozen workspace gate at `39ba6da` | **GREEN** — all-features 65 suites, **2,469 passed / 0 failed / 5 ignored**; default **2,229 / 0 / 5**; no-HA `sito-api` **371 passed**; fmt, clippy `-D warnings`, `cargo deny`, docs/config/migration/test-matrix/catalog checks clean |
| H1 24-hour fuzz at `39ba6da` | **GREEN** — [run 45922217501](https://github.com/kubaeror/sito-dns/actions/runs/45922217501), 25/25 fuzz jobs success, each shard `Done ... in 17281 second(s)`, zero crash artifacts; per-target corpus in [release verification](release-verification.md#recorded-h1-result-2026-11-27) |
| H2 7-day live soak | **IN PROGRESS — not passed** — started `2026-11-27T10:38+01:00` on `sito-soak:39ba6da`; minimum 3 days, target 7 days (~`2026-12-04T09:38Z`); evidence `/home/ubuntu/sito-soak/evidence/soak.csv` |
| H10 tagged release workflow | **PENDING — not run** — no `v2.0.0` tag, no stable 2.0 image/release, `latest` still 1.9.5 |
| Thresholded benchmark gate | **PENDING — not recorded** — one green `bench.yml` comparison against `benches/baseline.json` on GitHub-hosted `ubuntu-24.04` is still required before the final tag |
| E4 per-architecture image scan | Implemented and policy-tested; the real scan runs in the tagged `docker-build-push` job (H10) |
| E5 root-gated HA ownership lane | Implemented and policy-tested; a real GitHub-hosted run is required on the final commit (H10) |
| OpenAPI snapshot | Committed `docs/openapi.json` reports `info.version = 2.0.0` and matches the router; `SITO_UPDATE_OPENAPI=1 cargo test -p sito-api --features ha test_export_openapi_json` produced the version update and a normal rerun produced no diff |
| Docs truth checks | Internal link check, config reference (188 keys), 12 BC IDs, 821 test-matrix names and the catalog check pass |

A crash or timeout in H2, a red H10 release workflow, a missing E4/E5 run, a
red or missing thresholded benchmark comparison, or any stale claim above is a
release blocker. Do not move `latest` or publish 2.0.0 before those rows pass.

## Known issues and accepted residuals

- **DNAME (P1-1)** remains a documented DNSSEC residual; `validate`/`strict`
  fails closed with SERVFAIL/AD=0. Accepted for 2.0.0 with owner DNSSEC
  maintainer and re-review by 2027-01-31 or a hickory upgrade.
- **Installer/container `config.toml` auto-migration** is deferred; the CLI
  `sito config migrate` is the supported path. Database migration *is*
  delivered and runs explicitly (BC-11).
- **Maintained external parental/service data** is deferred. The bundled
  `adult`/`gambling` and service lists are minimal fallbacks; use
  `[integrations.lists]` for broader coverage.
- **Per-domain upstream weights** are config-file-only; the 2.0 UI/API edits
  global weights only. Per-client scoped upstream lists remain unweighted.
- **`stats_watermark` is diagnostic (B7).** Retention writes it for progress
  diagnostics/v1.9 compatibility, but no production path reads it to skip rows.
  Backdated rows re-aggregate on the next sweep.
- **A TTL-only live cache apply is cold by design (B8).** The runtime advances
  the cache-policy epoch instead of re-clamping warm entries; direct
  `DnsCache` users keep the warm `update_config` path. The impact is a
  transient hit-rate drop, not a correctness issue.
- **Query-log anonymization is forward-only** for the live writer; existing
  detailed rows are rewritten only by the explicit offline
  `sito db anonymize --all`.
- **1M-row/90-day capacity tests** are gated release evidence, not default CI.
- **macOS `pktinfo`/`getifaddrs` paths** are compile-gated but not CI-covered;
  Linux is the tested production platform.
- **Image scanning** fails only on fixed HIGH/CRITICAL findings; unfixed
  findings are reported but non-blocking. The scan itself is per-architecture.
- **In-app and CLI updates share one lock.** The updater serializes applies
  with an in-process mutex and a cross-process `flock` on a `0600`/`O_NOFOLLOW`
  lock file in the data directory (`UpdateLock::acquire`), and both the API and
  CLI `apply_update` acquire it before network work. A concurrent apply gets
  `UpdateInProgress`/`409`; the CLI is serialized against a running server.
- **The H2 soak is still running.** This note does not claim a clean soak, the
  `v2.0.0` tag, the published image, or the tagged release workflow.

## Monitoring

After publishing, follow the 24–72 hour
[post-release monitoring](release-verification.md#post-release-monitoring-first-2472-hours)
checklist: DNS availability, DNSSEC bogus rate, ACME renewal, HA
`protocol_mismatch`/divergence/queue state, filter zero-yield/reload status,
error/429/503 rates and query-log drops. Keep the rollback backup ready.
