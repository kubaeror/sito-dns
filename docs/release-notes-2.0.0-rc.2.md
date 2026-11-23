# sito 2.0.0-rc.2

**Release candidate (prerelease).** This is the second 2.0 release candidate
after the Phase 2 core-hardening work packages. It supersedes the unpublished
rc.1 pipeline attempt (`rc.1` was never published; its staged draft was deleted
after the release workflow's new image smoke used a malformed test query). It is
not a stable/latest release: the published stable line remains **1.9.5**, and the `latest` Docker
tag must not move. Use an explicit version/tag for evaluation.

- **Source:** `v2.0.0-rc.2`
- **Config schema:** v2 only (`config_version = 2`); a v1 file must be migrated
- **Database:** the 1.9.x SQLite schema remains readable/usable; there is no new
  schema migration command in this release
- **HA:** protocol v2; a coordinated cluster upgrade is required
- **API:** `/api/v1` remains canonical; `/api/v2` and a compatibility facade are
  not part of this release

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
  per-attempt RTT/error metrics with stale-series pruning.
- Client-neutral response shaping, cache status/AD sanitization, TTL
  re-clamping and per-transport oversize truncation.
- HA protocol v2 with signed config digest/signing-key fingerprint, explicit v1
  rejection, truthful publish outcomes and bounded queues/history.
- Opt-in HA automatic promotion (ADR-0010, default `false`): witness lease,
  pre-publish quiesce, hello-only reconciliation, durable self-fencing,
  `promotion` status, bounded-label metrics/audit events and the local
  `confirm-promotion`/`clear-fence` CLI.
- Self-service password/2FA for every role; session-bound re-authentication for
  sensitive Admin mutations; bounded Argon2 work.
- OpenAPI security/tag/path coverage, fail-closed config apply, `no-store` API
  responses, WebSocket Origin checks, Viewer URL redaction and a hardened
  updater (systemd/Docker refusal, locking, rollback, signature policy).
- Bounded stats retention, keyed rollup PII hashing, live-tail clone gating and
  a cached dashboard aggregate.
- Loopback-admin Compose, hardened systemd unit, atomic installer rollback and
  capability-preserving updates.

## Breaking changes

Read the full [migration guide](2.0-migration.md) and the
[breaking-change index](2.0-migration.md#3-breaking-change-index). The BC IDs
are BC-1 through BC-9: config v2, safer new-install defaults, restart-only 409s,
generic `/health`, internal Rust API changes, the 2.0 HA v2 upgrade, the legacy
WebSocket `?token=` removal, and the updater/validation tightening.

## Upgrade

1. Back up the whole data directory and `config.toml` (including `users.toml`,
   `totp.key`, `stats.db`, `stats-salt`, ACME material and HA state/watermark).
2. Stop the service.
3. Migrate the config and review the report:

   ```bash
   sudo sito config migrate --from v1 --to v2 --backup --config /etc/sito/config.toml
   sudo sito check-config --config /etc/sito/config.toml
   ```

4. Start 2.0 and verify DNS, `/health`, and authenticated `/api/v1/status`.
5. HA only: follow the coordinated v1→v2 procedure in
   [`docs/runbook-ha.md`](runbook-ha.md#7-ha-protocol-v2-upgrade-and-downgrade).
   Move the v1 `ha_state.toml`/`ha_watermark.toml` aside after backing them up;
   v1 state is refused by design.

### Installer and containers

The installer resolves the latest **stable** release by default, so a
prerelease must be requested explicitly:

```bash
SITO_VERSION=2.0.0-rc.2 bash contrib/install.sh
```

The shipped Compose default stays pinned to stable `1.9.5`. For the RC, override
the image explicitly (and pin the digest when you have it):

```bash
SITO_IMAGE=ghcr.io/kubaeror/sito-dns:2.0.0-rc.2 docker compose up -d
```

The prerelease image is published as `2.0.0-rc.2` only; it does not move
`latest` or the `2.0` moving tag.

## Rollback

- Keep the previous binary/container tag and the pre-upgrade data/config backup.
- A 2.0 config is not readable by 1.9.x; restore `config.toml.v1.bak`.
- The SQLite schema is additive, so a 1.9.5 data directory can be reused after a
  binary/config rollback.
- HA v2 is not rollback-safe in place: restore the pre-upgrade
  `ha_state.toml`/`ha_watermark.toml` and certificates before starting a v1
  binary.

See [migration §10](2.0-migration.md#10-rollback-and-known-issues) for the full
rollback procedure.

## Verification

See [`docs/release-verification.md`](release-verification.md) and the
[Phase 3 security review](phase3-security-review.md).

- Workspace all-features **1,821 passed / 0 failed / 1 ignored** and default
  **1,713 passed / 0 failed / 1 ignored** on the rc.2 candidate.
- fmt, clippy `-D warnings`, `cargo deny`, machete, pinned-nightly udeps and
  the size/docs/OpenAPI/release-workflow checks pass.
- Fuzz workflow fixed (the previous matrix was invalid and every scheduled run
  failed before fuzzing). A five-target 60 s GitHub Actions smoke passed on the
  final `main` commit: <https://github.com/kubaeror/sito-dns/actions/runs/44961095631>.
  **The 24-hour campaign is explicitly deferred by the operator and is not
  claimed as completed for this RC.**
- Thresholded benchmark comparison on GitHub-hosted `ubuntu-24.04` for the
  final `main` commit: success after a rerun,
  <https://github.com/kubaeror/sito-dns/actions/runs/44961097837>. A preceding
  run on the same commit reported four microbenchmark regressions (including
  the known noisy per-label metrics histograms); the rerun passed the same
  10% gate. No rebaseline was performed.
- Installer fresh/upgrade/rollback/uninstall E2E; real Docker
  **1.9.5 → config v1→v2 → 2.0 rc.2 → healthcheck/DNS → rollback** E2E; real
  1.9.5 data-dir migration E2E; exact 1.9.3 schema fixture; HA v1 rejection.
- The release workflow now starts the attested image and requires a local
  rewrite plus Docker `healthy`; tag-time image scan/signature/provenance/SBOM
  verification remains mandatory before publication.

## Known issues and residuals

- **24-hour fuzz campaign deferred.** A short five-target smoke is recorded; the
  full 24-hour checklist is not a blocker for this RC by operator decision.
- **DNAME (P1-1)** remains a documented DNSSEC residual; the validator fails
  closed. See the security review for the risk acceptance.
- **SQLite schema/PII migration and API v2** are deferred; `/api/v1` is
  canonical and the 1.9.x schema is compatibility-only.
- **Weighted upstream balancing**, edit-time read-only HA enforcement and
  per-client upstream metric pruning are deferred.
- **Query-log anonymization** is forward-only; historical rows are not rewritten.
- **`stats_watermark` is diagnostic (B7, accepted residual).** Retention writes
  it for progress diagnostics and v1.9 schema compatibility but never reads it
  to skip rows; aggregate and delete share one transaction per chunk, and
  backdated rows re-aggregate. The `--keep-aggregates` clear has one documented
  deleted-rollup exception: if an hour's rollup exists when the clear reaches
  that hour but rollup retention deletes it mid-run, the clear still clears the
  detailed rows without resurrecting that rollup (a row already absent when the
  clear reaches its hour is recreated normally). See
  [migration §10.1](2.0-migration.md#101-backendstats-residual-b7).
- **A TTL-only live cache apply is cold by design (B8, accepted residual).** The
  runtime apply advances the cache-policy epoch instead of re-clamping warm
  entries, so old-generation entries are unservable and the cache refills; new
  inserts use the new TTL policy. `DnsCache::update_config` keeps the warm
  re-clamp for direct cache users. Expect a transient hit-rate drop only; there
  is no correctness issue, and preserving warm entries is a future
  optimization. See [migration §10.2](2.0-migration.md#102-cache-ttl-residual-b8)
  and the [cache configuration reference](configuration-reference.md#4-dnscache--caching-layer).
- **Release-image vulnerability scanning** covers linux/amd64 only; arm64/armv7
  are executed by artifact E2E. Root-gated HA ownership checks are manual.
- **In-app update locking** is process-wide; a cross-process file lock is
  deferred.
- **Installer/Compose auto-migration** is not implemented; `sito config migrate`
  is the supported path.

## Monitoring

After publishing, follow the 24–72 hour
[post-release monitoring](release-verification.md#post-release-monitoring-first-2472-hours)
checklist: DNS availability, DNSSEC bogus rate, ACME renewal, HA
`protocol_mismatch`/divergence/queue state, filter zero-yield/reload status,
error/429/503 rates and query-log drops. Keep the rollback backup ready.
