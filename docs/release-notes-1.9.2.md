# sito 1.9.2 — release notes

Target release: **1.9.2** on 2026-11-05. This is a security and correctness
patch release for the 1.9 line. The tag and publication are handled separately;
this page summarizes user-visible behavior and upgrade actions. The exhaustive,
per-commit history remains in [`CHANGELOG.md`](../CHANGELOG.md).

Operators upgrading from 1.9.1 should still read the upgrade notes below:
legacy sessions and API tokens are invalidated once, and HA promotion has a
strict term/version procedure. If you are upgrading from 1.8.x, read the
[1.9.0 release notes](release-notes-1.9.0.md) first; its migration and policy
notes still apply.

## Security

### DNSSEC

- **False SERVFAIL after the first signed zone is fixed.** With
  `dns.dnssec.validate = true` and `mode = "validate"`, resolving one signed
  domain and then a different signed domain could return SERVFAIL with EDE
  `Missing RRSIG for zone previously proven signed`. RRSIGs fetched for the
  DNSKEY/DS chain walk were appended to the response and treated as evidence
  that the root/TLD had signed the query, and a response with a relevant RRSIG
  but no key was rejected before the chain could be fetched. Chain-helper
  RRSIGs are now kept separate from the original response, the root is never
  used as descendant signed-zone evidence, and a relevant RRSIG without key
  material returns `Indeterminate` so the chain fetch can run. Genuinely
  stripped responses and genuinely bogus zones still fail closed.
- **A legacy chain cache cannot preserve unsafe evidence.** Chain-cache files
  written before 1.9.2 drop root/TLD `Signed` entries on load. The cache is
  advisory and is rebuilt automatically; no manual action is required.
- **Verification work is bounded.** Each response now has a hard budget of 256
  RRSIG verification attempts shared across the pre-fetch and strict passes,
  no more than 8 candidate keys are tried per RRSIG, and trusted/validated keys
  are tried before unvalidated response keys. The bound also covers the
  DS/DNSKEY trust walk and DS-status probes.
- **NSEC3 iteration abuse is rejected.** `matches()`/`covers()` reject records
  whose iteration count exceeds 150 (RFC 9276) before hashing a name, so a
  crafted denial cannot force 65,535 hash iterations or be accepted over the
  cap.
- **Secure answers cannot outlive their proof.** `dns.cache.min_ttl` is now a
  floor for unvalidated data only. Validated records keep the smaller of the
  cache TTL and their authenticated TTL, and secure NXDOMAIN/NODATA lifespans
  are additionally capped by the NSEC/NSEC3 denial and its RRSIG, so a long SOA
  cannot extend a validated negative answer past its proof.
- **Stale cache entries follow the validation policy.** The RFC 8767 stale
  fallback refuses `Unchecked` and `Indeterminate` entries while local
  validation is active and serves only authenticated `Secure`/`Insecure`
  decisions, always with AD=0. Stale sanitization removes every DNSSEC RR type.
- **DNSSEC policy changes flush cached answers.** Changing
  `dns.dnssec.mode`, `validate`, `trust_anchors`, `nta`, or `ntp` invalidates
  the response cache, so a decision made under the old policy cannot be served.

### Credential revocation

- **Sessions and API tokens are revalidated on every request.** Each credential
  stores the account's persisted `credential_epoch`; the account must still
  exist, the role must still match, and the epoch must be current. Password and
  role changes, TOTP enable/disable, account deletion/recreation, and
  `reset-admin` advance the epoch. A login that races a credential mutation is
  refused instead of creating a session with the old role or for a deleted
  account. User-credential writes now fail closed and roll back the in-memory
  change when `users.toml` cannot be written; interrupted revocations are
  revalidated on restart.
- **`reset-sessions` and `reset-admin` no longer claim live revocation.** The
  server holds an exclusive lease on `<data_dir>/sito.pid`; both commands
  refuse to run while it is held. The documented recovery path is
  `systemctl stop sito` → reset → `systemctl start sito`. `--force` performs the
  on-disk reset anyway and warns that live sessions/tokens remain valid and a
  new admin password is not accepted until the service restarts. A stale PID
  file from a crash does not block resets.

### First-boot and setup

- **Bootstrap credentials can no longer be used remotely.** With `config.toml`
  present but `users.toml` still holding `admin/adminadmin`, the setup token was
  active while `setup_pending` was false. The middleware now gates on the setup
  token **and** an active bootstrap admin: `/api/v1/auth/*` returns 403, other
  `/api/v1/*` routes return 503, and only `/wizard`, `/ui/wizard/*`, static
  assets, `/health`, `/status`, and setup-token-protected paths remain
  reachable. An authenticated Admin may always open the wizard.
- **The setup wizard persists credentials before configuration.** The
  administrator password is written and verified before `config.toml`; a later
  configuration failure rolls the password back and leaves setup pending. A
  non-Admin target account is rejected with 400, the bootstrap `admin` account
  is removed before setup completes, and a failed user-store write is reported
  instead of redirecting as success.
- **`reset-admin` no longer installs `adminadmin` or deletes accounts.** Without
  `--password` it generates a 192-bit random password and prints it once.
  Supplied passwords must meet the API/wizard policy (at least 8 characters, no
  whitespace/control characters, not `adminadmin`). Non-admin accounts are
  preserved unless `--reset-all`/`--reset-users` explicitly replaces the store.

## High availability

- **Failures are visible in status and healthchecks.** A master whose
  replication listener could not initialize mTLS or bind, and a slave whose
  handshake never completed or that has not reached `synced`, now report
  `ready: false` and a `readiness_reason` in `GET /api/v1/ha/status`. `/health`
  exposes only a generic ready flag, and `sito healthcheck` fails when `[ha]`
  makes replication part of the role, so a successful DNS probe cannot mask a
  broken HA node. A master with `replication_port = 0` stays ready and explains
  that replication is intentionally disabled.
- **Old masters cannot resurrect stale bundles.** Bundles and state now carry a
  cluster term. A slave rejects a push from an older term even when its version
  is higher; within a term the version must advance and a same-version push must
  match the applied payload hash. A master that sees a replica ahead in the same
  term or in a newer term marks itself `diverged` and no longer seeds or
  republishes its stale bundle. Same-version forks are latched by the slave in
  `ha_watermark.toml` and rejected until an explicit higher-term, higher-version
  promotion. Divergence records are sticky and a real fork is not cleared by an
  unrelated resync.
- **Peer version values are bounded.** The master rejects implausible
  `have_version`/ACK values (more than 1,000,000 above its own sequence), ignores
  implausible ACKs without rebasing, rejects sequence values of `u64::MAX`, and
  uses checked arithmetic for increments.
- **Applied versions survive restarts.** Slaves persist
  `{version, payload_hash, timestamp}` to `data_dir/ha_watermark.toml` (atomic,
  mode `0600`) before acknowledging, and restore it on startup. A corrupt
  watermark fails startup instead of silently resetting to version 0.
- **Master restarts reconcile `config.toml`.** A restarted master compares the
  sanitized current configuration with its stored bundle and republishes at
  `N + 1` when they differ, so an edited configuration no longer leaves slaves
  on stale settings. An unchanged configuration resumes the sequence without
  churn.
- **A restart-only change is rejected, not acknowledged.** A push that changes
  a non-node-local restart-only field (for example `server.log_format` or
  `[auth]`) fails before anything is applied or persisted. The slave keeps its
  previous live configuration and file, enters `Degraded`, and ACKs
  `applied: false` with a `restart_required` reason naming the fields.
- **Effective `[auth]` policy is compared.** An `[auth]` table that spells out
  default values is equivalent to omitting the section, so the documented master
  example plus the minimal slave template no longer produces
  `restart_required: auth` on every push. A genuine change such as
  `session_ttl_hours` is still rejected until a coordinated restart.
- **Node-local listeners and certificates are preserved.** A slave keeps its own
  `dns.bind`, `[dns.tls]`/`[tls]` paths, `[acme]`, `web.bind`/`web.port`, and
  the complete `[integrations.mikrotik]` section instead of inheriting the
  master's, so a master bound to another address cannot make a slave fail to
  bind or use certificate paths that do not exist on that node.

## Updates and installation

- **The installer installs cosign by default.** A fresh systemd install could
  not use `sito update` because `server.update_require_signature` defaults to
  `true` while `install.sh` only checked for cosign. The installer now installs
  a checksum-verified `cosign` (`v2.6.5` by default, architecture-matched) to
  `/usr/local/bin`; set `SITO_INSTALL_COSIGN=0` to opt out and
  `COSIGN_VERSION` to pin another release. `sito update` refuses before
  downloading when signatures are required but cosign is unavailable, naming
  the verifier, the install path, and the configuration key.
- **`sito update` finds the system configuration.** Without `--config`, the CLI
  prefers an existing `/etc/sito/config.toml` and otherwise uses
  `./config.toml`, so the documented
  `sudo systemctl stop sito && sudo sito update` path works from `/root`. If
  neither file exists, the update refuses with an actionable error naming
  `--config`; the signature policy is never silently skipped.
- **The installer and docs recommend LAN-only exposure.** `install.sh` now
  allows SSH before enabling UFW's default-deny policy and prints LAN-scoped DNS
  rules, an SSH tunnel for the admin UI, a temporary LAN-scoped 8080 rule for
  first-time setup, and reverse-proxy guidance. The shipped compose mappings are
  unchanged.
- **Startup warns about exposed listeners.** The admin UI still defaults to
  `0.0.0.0:8080` over plain HTTP and DNS to `0.0.0.0`/`::` without a client
  allow-list, so startup logs an actionable warning for each exposed listener.
  A declared `https://` `web.public_url` (or
  `web.tls_terminated_by_proxy = true`) marks a deliberate TLS reverse-proxy
  deployment; loopback binds and `web.enabled = false` do not warn. The DNS
  warning is emitted only when DNS listeners actually start. Warnings contain
  only bind addresses and ports, never credentials or tokens.
- **`sito ha gen-certs --uid/--gid`** can transfer generated certificates and
  private keys to the unprivileged HA runtime user (`65532` in containers,
  `sito` under systemd). Both flags are required together, the chown is applied
  after every file is written, and a failed transfer is reported.
- **Container image publication is gated on the verified release.** The
  `docker-build-push` job waits for the tag/version check, binary builds, signed
  release/SBOM publication, and artifact E2E verification. Prerelease tags
  publish only their full version tag, never `latest`, the moving
  `<major>.<minor>` tag, or a stable GitHub release. The push is verified for
  digest consistency, `linux/amd64`/`linux/arm64`/`linux/arm/v7`, and SLSA
  provenance plus SPDX SBOM attestations.

## Web UI

- **The update form sends the CSRF token.** The system page's
  "Download & Install" button called native `form.submit()`, bypassing htmx and
  omitting the session-bound CSRF value, so the middleware rejected the POST.
  The form now includes the hidden `csrf_token` used by the other UI forms and
  lets htmx perform the request.

## API and schema

- `GET /api/v1/ha/status` now includes `ready` (boolean) and
  `readiness_reason` (string or null) on the node status object, so a broken
  replication role is visible to authenticated callers. `/health` remains a
  generic ready flag without the detailed reason.
- No REST endpoints, request parameters, configuration keys, or dependencies
  were added or changed. `docs/openapi.json` differs from 1.9.1 only in these
  HA status fields and `info.version` (`1.9.2`).
- The served document remains OpenAPI 3.1.0.

## Upgrade notes

1. **Expect one forced re-login and re-issue API tokens.** Persisted sessions
   and API tokens written before 1.9.2 have no `credential_epoch` and are
   rejected once after upgrade. Sign in again; automation that uses an API token
   must create a new token.
2. **The DNSSEC chain cache migrates automatically.** Legacy root/TLD `Signed`
   entries are dropped on load. The cache is advisory and local to each node; it
   is not part of HA bundles or configuration backups. No manual action is
   required, though the first queries after upgrade may re-probe previously
   cached zones.
3. **Upgrade every HA slave before promoting a master.** Existing state files
   without a `term` load as term 0 and old signed bundles remain verifiable. An
   explicit promotion must raise **both** `term` and `version` in
   `ha_state.toml`; a higher term alone does not bypass version continuity. See
   the [HA runbook](runbook-ha.md), including the same-version fork procedure.
4. **Check cosign after installing.** A systemd install performed by the 1.9.2
   installer already includes cosign. If you manage the binary manually, install
   cosign before running `sito update`, or deliberately set
   `server.update_require_signature = false` when you accept SHA-256-only
   integrity.
5. **Stop the service before reset commands.** `reset-sessions` and
   `reset-admin` refuse to modify a running instance because the process keeps
   credentials in memory. `--force` only prepares on-disk state and warns that a
   restart is required.
6. **First-boot setup is stricter.** Only the wizard, static assets,
   `/health`, `/status`, and setup-token-protected paths are reachable while the
   bootstrap admin is active. Complete setup through `/wizard` or use the
   documented `reset-admin` recovery after stopping the service.
7. **No configuration or data migration is otherwise required.** The 1.9.x
   configuration format and the documented defaults are unchanged; exposure
   warnings do not alter the running configuration.

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
shellcheck -S warning contrib/install.sh
python3 contrib/tests/test_adguard_to_sito.py
docker compose -f docker-compose.yml config
docker compose -f docker-compose.ha.yml config
```

For a local release binary:

```bash
cargo build --release --locked -p sito --features "embed-ui,mimalloc"
./target/release/sito --version
./target/release/sito check-config --config config.example.toml
```

## Known issues and deferred work

- **The default network exposure remains until 1.10.0.** The admin UI still
  binds `0.0.0.0:8080` over plain HTTP and DNS has no client allow-list. 1.9.2
  adds startup warnings and LAN-only firewall/reverse-proxy guidance; changing
  the default bind and adding a DNS client ACL are planned for 1.10.0.
- **Deferred to 1.10.0:** the TLS/ACME setup-wizard work (encrypted listeners
  configured with certificates), a full backup/restore UX including
  `users.toml`, `totp.key`, sessions/tokens, and HA state, and the remaining
  documentation truth pass.
- **D-20 (`tower-http 0.7`) remains blocked upstream.** The repository resolves
  `tower-http 0.6.11`, pulled only transitively by `reqwest 0.13.5`, which
  requires `tower-http ^0.6.8`. There is no direct `tower_http` use in the
  workspace, and a version requirement cannot be widened with
  `[patch.crates-io]`. Revisit when reqwest or axum widen the range.
- The DNSSEC documented policy limits from 1.9.0 are unchanged: NSEC3 opt-out
  proofs remain `Insecure`, CNAME chains needing more than 16 hops or more than
  8 network probes fail closed, delegation walks are bounded to 8 cuts, offline
  cold starts without evidence are `Indeterminate`, and `Secure` TTLs follow
  RRSIG expiry.
- Legacy ownerless API tokens remain Admin-managed, and the per-owner token
  quota remains 16.
- The published-image end-to-end check runs in the tag-triggered Release
  workflow; it cannot be completed before the tag is pushed.
