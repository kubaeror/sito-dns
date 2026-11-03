# sito 1.9.1 — release notes

Target release: **1.9.1** on 2026-11-04. This is a patch release for residual
correctness, concurrency, and UI issues found after 1.9.0. The tag and
publication are handled separately; this page summarizes the user-visible
behavior and upgrade notes. The exhaustive, per-commit history remains in
[`CHANGELOG.md`](../CHANGELOG.md).

Operators upgrading from 1.9.0 do not need any configuration changes. If you
are upgrading directly from 1.8.x, read the
[1.9.0 release notes](release-notes-1.9.0.md) first; its security, filtering,
HA, and migration notes still apply.

## Security and correctness

### DNSSEC chain cache

- **Policy changes invalidate only what they must.** A configuration reload
  that adds a trust anchor now clears cached `Unsigned` evidence only at or
  above that anchor, preserving unrelated zones. Previously any policy change
  discarded the whole cache, forcing unnecessary re-probes.
- **Non-additive policy changes still clear the cache.** Removing an anchor,
  changing the anchor set without a genuine addition (for example a same-zone
  key change), or changing the NTA list clears the cache. `Signed` evidence is
  never preserved against a removed anchor, so the change remains fail-closed.
- **Legacy cache files migrate safely.** A cache written before 1.9.1 has no
  anchor/NTA metadata, so its entries are cleared on the first policy change.
  The cache is advisory and is rebuilt automatically; no manual action is
  required.
- **Flushes no longer block policy changes.** Cache flushes serialize disk
  writes under a dedicated flush lock without holding the policy state lock
  across I/O. A failed serialization or write restores the dirty flag and
  leaves the existing file intact; the parent directory is fsynced after the
  atomic rename. Malformed individual entries are skipped with a path-only
  warning instead of aborting the load.

### Configuration writes

- **Every admin write goes through one serialized apply pipeline.** Filter
  lists and custom rules, clients, groups, rewrites, upstreams, settings, and
  the setup wizard now acquire the shared apply lock before reading the running
  configuration, then apply, persist, and publish through the same locked path.
  Two concurrent admin writes can no longer overwrite each other.
- **Persistence failures roll back live state.** If the candidate document
  cannot be written, the previous filter snapshot, client registry, rewrites,
  upstream manager, and runtime configuration remain active.
- **Apply cost depends on the section.** Filter list, rule, and settings writes
  use a synchronous filter apply; clients, rewrites, upstreams, and the setup
  wizard defer blocklist work while still performing the normal apply.

### High availability

- **Conflict restoration uses the async blocking pool.** When an async bundle
  publish detects that another publisher advanced the version, the active
  bundle is restored through the blocking writer while the persistence lock is
  held. No synchronous filesystem I/O remains on the async worker for this
  path, published versions cannot regress, and a failed restore logs the error
  without replacing the conflict response.
- The synchronous `update_bundle` entry point remains startup/test-only in
  production; production replication continues to use the async publisher.

### Authentication persistence and 2FA

- **Token and session persistence is retry-safe.** Removals and token
  `last_used` updates performed by the synchronous validators advance per-store
  revision counters. A concurrent save clears the dirty flag only if no
  mutation landed after its snapshot, so the next pruner pass rewrites the
  store instead of leaving a stale snapshot on disk. Expired session removals
  now mark the session store dirty, and a failed write never drops the retry.
- **Enabling TOTP now revokes owned API tokens.** This matches the existing
  disable lifecycle: changing the account's second factor is treated as a
  credential change. Every token owned by the account is revoked in memory and
  persisted to `tokens.toml`; other accounts' tokens are unaffected, and legacy
  ownerless tokens remain Admin-managed. Automations that use an owned token
  must create a new token after TOTP is enabled.
- This revocation applies to TOTP enable/disable operations performed on
  1.9.1 and later. Upgrading does not retroactively revoke tokens for accounts
  that already had TOTP enabled before the upgrade.

### Web UI

- **Discovered-clients pagination (D-09).** The read-only “Discovered but
  unidentified” table on the Clients page now shows 100 rows per page with
  Previous/Next controls and clamps out-of-range page numbers. The displayed
  total remains the full registry count, and the 1024-entry hard cap is
  unchanged. The Operator check runs server-side before slicing; Viewers never
  query, load, or render discovery data, including when a `discovered_page`
  query parameter is supplied.

## API and schema

- No REST endpoints, request/response schemas, configuration keys, or
  dependencies were added or changed. `docs/openapi.json` differs from 1.9.0
  only in `info.version` (`1.9.1`).
- The served document remains OpenAPI 3.1.0.

## Upgrade notes

1. **Reissue API tokens after enabling TOTP.** Enabling 2FA now revokes tokens
   owned by that account, just as disabling it already did. Store the new token
   before relying on it in automation.
2. **Expect a one-time DNSSEC re-probe after changing policy.** Legacy chain
   caches are cleared on the first policy change; unaffected zones are
   preserved for new-format caches. The cache is local to each node and is not
   part of HA bundles or configuration backups.
3. **No data migration is required.** Configuration and database formats are
   unchanged from 1.9.0.
4. **No action is needed for HA.** The conflict-restore change is internal and
   preserves the existing version ordering and error behavior.

## Known issues

- **D-20 (`tower-http 0.7`) remains blocked upstream.** The repository resolves
  `tower-http 0.6.11`, pulled only transitively by `reqwest 0.13.5`, which
  requires `tower-http ^0.6.8`. There is no direct `tower_http` use in the
  workspace, and a version requirement cannot be widened with
  `[patch.crates-io]`. Revisit when reqwest or axum widen the range.
- The DNSSEC documented policy limits from 1.9.0 are unchanged: NSEC3 opt-out
  proofs remain `Insecure`, CNAME chains needing more than 16 hops or more than
  8 network probes fail closed, delegation walks are bounded to 8 cuts, offline
  cold starts without evidence are `Indeterminate`, and `Signed` TTLs follow
  RRSIG expiry.
- Legacy ownerless API tokens remain Admin-managed, and the per-owner token
  quota remains 16.

## Validation

The release gates are the repository's standard commands:

```bash
cargo fmt --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked --no-fail-fast
cargo deny check
python3 scripts/check_config_reference.py --github
SITO_UPDATE_OPENAPI=1 cargo test -p sito-api test_export_openapi_json
git diff --exit-code docs/openapi.json
cargo check --manifest-path fuzz/Cargo.toml --locked
```
