# High Availability (HA) Operational Runbook

This runbook provides step-by-step operational procedures for managing, maintaining, troubleshooting, and recovering the **sito DNS High Availability (HA)** cluster.

---

## 1. Overview and Architecture

`sito` implements an active-passive master/slave replication architecture governed by [ADR-0002](adr/0002-ha-master-slave-push.md):
- **Master Node**: Accepts administrative REST API mutations and Web UI configurations, generates monotonic configuration bundles, signs them using an Ed25519 private key (`data_dir/ha_signing.key`, permissions `0600`), and pushes updates to connected slaves in real-time over WebSocket with mutual TLS (mTLS) on port `8953`. The active bundle and its version are persisted to `data_dir/ha_state.toml` (mode `0600`) on every publish. On startup the master compares the sanitized current `config.toml` with the persisted bundle and republishes at `N + 1` when the configuration changed, so a restart can never leave slaves on stale settings.
- **Slave Nodes**: Connect to the master over WebSocket + mTLS, verify the master's Ed25519 signature and certificate fingerprint, enforce the cluster epoch (a bundle from an older term is rejected even when its version is higher) and strict monotonic version ordering within a term, and apply configuration snapshots atomically. The last applied term, version, signed payload hash, digest of the **shared projection** of the applied `config.toml`, signing-key fingerprint and timestamp are persisted to `data_dir/ha_watermark.toml` (atomic, mode `0600`) before the push is acknowledged, so a restart cannot replay an older bundle, accept same-version content with a different hash, or early-ACK a locally edited shared configuration. Protocol v2 refuses a v1 watermark; back it up and move it aside before the first v2 start (see §7). A slave that receives no frame for `3 × ping_interval_secs` leaves `Synced` and reports not-ready. A corrupt or v1 watermark fails startup; delete it only after backup to force a full resync.
- **Admission limits**: the replication listener accepts at most 64 concurrent slave sessions and at most 8 concurrent sessions per source IP; a 10 s timeout bounds TLS/WebSocket handshakes and one WebSocket write. A NAT deployment with more than eight simultaneous HA peers from one address must be split across source addresses.
- **Continuous Resolution**: Slaves serve DNS queries continuously without downtime. If an invalid or unparsable configuration bundle is received, the slave performs an automatic rollback to its last known good snapshot and enters a `Degraded` state.
- **Read-Only Enforcement**: Slave REST API endpoints reject mutating operations (`POST`, `PUT`, `DELETE`, `PATCH`) with HTTP `409 Conflict` and return the `X-Dnsd-Master: <master_url>` header to redirect operators to the authoritative master. The full-config apply endpoint `PUT /api/v2/config` is the exception: it reaches the handler so node-local edits can be applied, and the apply pipeline rejects any shared-field change with `409` and `type = "urn:sito:ha:shared_config_read_only"` (see §7.5).
- **Statistics Aggregation**: Slaves report traffic and upstream metrics to the master every 30 seconds via `stats_report`. The master stores the latest report per slave and exposes it through `GET /api/v2/ha/slaves`; replica counters are **not** merged into the master's own Prometheus registry. Scrape each replica's `/metrics` endpoint separately (labels such as `sito_ha_config_version{instance="..."}` identify the node).

### Witness server for automatic promotion

Opt-in automatic promotion (`[ha.promotion]`, ADR-0010) additionally needs the
built-in witness lease server on a **third host**:

```bash
sito ha lease-server \
  --listen 0.0.0.0:8954 \
  --cluster-id home-dns \
  --cert /etc/sito/lease/witness.crt \
  --key /etc/sito/lease/witness.key \
  --token-file /etc/sito/lease/witness.token \
  --state-dir /var/lib/sito-lease
```

Provisioning, TLS/token/state permissions, backup/restore, rotation and the
offline `sito ha lease-admin set` recovery tool are documented in the
[Witness lease server runbook](runbook-witness.md). Running the witness on an
HA node is supported only for lab/test and is **not** HA: it shares that node's
failure domain.

### DNS client ACL across HA (ADR-0011)

`clients.default_policy` and every `[clients.acl]` key are shared
configuration: the sanitizer keeps them in the bundle and the
shared-projection digest, and only `clients.client_id_secrets` is stripped.
There is no `[ha]` ACL key, no per-node ACL override and no node-local allow
file. For the same observed source address and applied bundle, every ACL-aware
node makes the same decision; nodes can legitimately differ when a client
reaches them through different NAT/proxy paths.

**All-site address plan.** The policy is one shared list. Before enabling deny,
add every site's client CIDRs to `[clients.acl] allow` (or opt in to the static
entry ids). A list that only contains site A is a deliberate denial of site B
on every node, not a local default. Agree the plan with the operator of every
site, then publish it from the master.

**Fresh/headless/rebuild slave.** A slave with no applied
`ha_watermark.toml`/bundle starts its admin/HA client, reports
`acl_unprovisioned`, and **does not bind DNS listeners**. It serves only after
the first valid bundle is applied, persisted and the watermark write succeeds;
a rejected bundle or a failed watermark write keeps DNS unbound. A restart with
a watermark serves the persisted applied configuration immediately. If the
master is unreachable, a first-boot slave cannot serve DNS: restore the master
(or use the documented recovery procedure) instead of expecting a temporary
allow. Setup completion does not bypass this rule: a setup-pending slave starts
its replication worker after the wizard completes and still waits for the first
watermarked bundle before binding DNS.

**Invalid bundle.** An invalid ACL (bad enum/CIDR, duplicate canonical prefix,
allow/deny exact conflict, over-cap list, malformed clients table) rejects the
whole bundle atomically. The slave keeps its previous runtime generation and
ACL, reports `Degraded`, and does not ACK `applied: true`.

**Mixed versions.** An ACL-aware slave advertises `client_acl` in its `Hello`.
While the published configuration has `default_policy = "deny"`, a connected
slave without the capability makes master readiness report
`acl_capability_missing` and logs a warning (at Hello and when an allow→deny
publish transition is made). Upgrade every DNS-serving node before enabling
deny; a mixed-version cluster must stay on `default_policy = "allow"`. Legacy v2
peers that cannot report `have_bundle_hash` also cannot participate in promotion
candidate reconciliation: reconciliation aborts with `candidate_hash_unknown`
rather than overwrite a possible fork. While promotion is enabled, such a peer
also makes master readiness report `promotion_peer_capability_missing` and
`/api/v2/ha/slaves` shows `bundle_hash_known: false`. Upgrade every peer before
enabling promotion.

**Promotion.** Automatic promotion is governed by ADR-0010. A node that has
already applied the bundle keeps that shared ACL if a promotion flow runs. An
unprovisioned, degraded, diverged or fork-latched slave is ineligible and the
engine refuses with `candidate_diverged`; it does not invent a policy for an
unprovisioned node. A promoted node writes the shared configuration it received,
so verify the all-site allow plan before promotion.

**Discovery.** Denied queries are absent from the detailed query log and the
`unidentified_clients` list by design. Use
`sito_dns_acl_decisions_total{action,reason,family}`,
`sito_dns_acl_matched_prefix_total`, `sito_dns_acl_dropped_total` and the
rate-limited ACL log lines on each node. ACL metrics are per node and are not
merged into the master's Prometheus registry.

### Build prerequisites and the optional HA module

HA is an optional Cargo feature, not a runtime toggle:

- **Official artifacts** (release archives and container image) are built with
  `embed-ui,ha,mimalloc`, so HA is available. The installer installs those
  release archives by default; set `SITO_INSTALL_LOCAL_BINARY=1` to install a
  locally built `target/release/sito` instead.
- **Source builds** must add `ha`:
  `cargo build --release --locked --features "embed-ui,ha,mimalloc"`.
  A plain `cargo build -p sito` is a no-HA binary.
- `sito-ha-types` is always compiled and owns the portable `[ha]` config,
  status and protocol types. `sito-ha` is the implementation behind the feature
  and re-exports the historical `sito_ha::*` paths.
- `sito ha gen-certs` exists **only** in an HA build. A no-HA binary reports an
  unknown `ha` subcommand; verify with `sito ha gen-certs --help` before
  provisioning certificates.

A no-HA binary still runs as a **master**, but it is fail-closed:

| Surface | No-HA behavior |
|---|---|
| Startup, `sito check-config`, API config writes, restore | Rejects `[ha]` and `server.role = "slave"` with an error naming the missing feature. |
| `GET /api/v2/ha/status`, `GET /api/v2/ha/slaves`, `POST /api/v2/ha/resync` | Return **501** with `ha_not_supported`; normal admin authentication still applies. |
| `/health`, `/api/v2/status` | HA is not part of the node's role and never gates readiness. |
| `[ha]` in `config.toml` | Not usable. Rebuild with `ha` or remove the section. |

This only affects source builds that omit the feature. A cluster running the
official binaries is unaffected.

### Certificate ownership and the runtime user

`sito ha gen-certs` writes private keys mode `0600`. The HA listener runs
unprivileged, so ownership matters as much as the mode:

- **systemd** runs as `User=sito` (see `contrib/systemd/sito.service`).
- **Docker/Compose** runs as uid/gid `65532` (distroless `nonroot`).

Generate as root with an explicit ownership transfer, or chown the copied
files before starting the service:

```bash
# systemd host
sudo sito ha gen-certs --dir /etc/sito/certs --master --slave \
  --uid "$(id -u sito)" --gid "$(id -g sito)"

# Docker Compose bind mount
sudo chown -R 65532:65532 ha/master/certs ha/slave/certs
sudo chmod 0600 ha/master/certs/*.key ha/slave/certs/*.key
```

`--uid` and `--gid` must be supplied together. The chown happens after every
file is written and a failed transfer aborts generation, so a root-owned key
cannot be mistaken for a working HA setup. Certificates (`*.crt`) may be
world-readable; the private keys (`*.key`) must stay `0600`.

The shipped `docker-compose.ha.yml` keeps those bind mounts explicit and
parameterizes the LAN topology instead of hardcoding it. Set these in the shell
or a `.env` file next to the compose file:

| Variable | Default |
|---|---|
| `SITO_HA_PARENT` | `eth0` |
| `SITO_HA_SUBNET` | `192.168.1.0/24` |
| `SITO_HA_GATEWAY` | `192.168.1.1` |
| `SITO_HA_MASTER_IP` | `192.168.1.10` |
| `SITO_HA_SLAVE_IP` | `192.168.1.11` |
| `SITO_HA_SLAVE2_IP` | `192.168.1.12` |

The RouterOS DHCP Option 6 example is `0xc0a8010ac0a8010b` for
`192.168.1.10,192.168.1.11`; regenerate the even-length hex value if you change
either DNS IP.

A key that the runtime cannot read fails closed: the master listener logs
`Failed to initialize mTLS for master HA replication server: ... Permission
denied`, `GET /api/v2/ha/status` reports `ready: false` with a
`readiness_reason`, and the `healthcheck` subcommand fails even though DNS
still answers. The same visibility applies to a failed listener bind, a slave
that cannot complete the handshake, and a slave that has not reached `Synced`.
Readiness is read from the admin web listener, so keep `[web] enabled = true`
(the default) on HA nodes; the healthcheck fails closed when HA is configured
but the web listener cannot report readiness. This readiness policy is
independent of replication: HA preserves each node's node-local `[web]`
identity, so a slave that disables the listener can still converge to `Synced`
while the healthcheck reports not ready. The unauthenticated `/health` endpoint
exposes only the generic ready flag; read `readiness_reason` on the
authenticated `/api/v2/ha/status` endpoint (or the logs) for the detailed
cause.

Master readiness can additionally require replication health with
`ha.require_slaves` (at least one connected slave synced to the current
configuration version) or `ha.require_all_slaves` (every connected slave synced;
zero connected slaves also fails). Both default to `false`, so an upgrade keeps
the previous behavior: a master with a healthy listener and last publish stays
ready even with no slaves. "Synced" means the slave acknowledged the master's
current published version and has no latched divergence; a slave ahead, behind,
or forked does not count. When the policy is unmet, `/api/v2/ha/status` reports
`ready: false` and a reason such as
`HA requires at least one synced slave (0/2 connected)` or
`HA requires all slaves synced (1/2 synced)`. These fields only gate the master
role; slave readiness is unaffected. See the
[configuration reference §13](configuration-reference.md#13-ha--high-availability-masterslave-replication).

### Health and status endpoint semantics (WP-1.7)

`/health` is the generic, unauthenticated probe:

| Condition | Response |
|---|---|
| Every blocking component is ready | `200 {"status":"ok"}` |
| Listeners, configured TLS, ACME, HA or the filter engine is not ready | `503 {"status":"unavailable"}` |

It deliberately exposes no component names, reason codes, filesystem paths,
certificate text or configuration values. The container healthcheck and
`GET /health` consumers must rely on the status code.

`GET /api/v2/status` (Viewer or higher) is the detailed admin view. It keeps
`version`, `uptime_seconds`, `role`, `listeners` and `acme`, and adds:

- `ready` — the same aggregate verdict `/health` uses.
- `reasons[]` — every blocking and advisory reason with `component`, `code`,
  `message` and (when known) `since_unix_ms`, in component order.

| Component | Blocks `ready`? | Example codes |
|---|---|---|
| `listeners` | Yes | `listener_bind_failed`, `listener_rebind_skipped`, `listeners_not_started` |
| `tls` | Yes when expired; no when expiring | `tls_acceptor_unavailable`, `tls_init_failed`, `tls_cert_expired`, `tls_cert_expiring` |
| `acme` | Yes for challenge-unavailable/expired/issuance-failed; no for renewal failure/expiring/pending | `acme_challenge_unavailable`, `acme_cert_expired`, `acme_issuance_failed`, `acme_renewal_failed`, `acme_cert_expiring`, `acme_issuance_pending`, `acme_bootstrap_cert` |
| `ha` | Yes | `ha_not_ready` (including master-loss and publish failure) |
| `filter` | Yes only when no usable snapshot exists | `filter_unavailable`/`filter_loading` when `unavailable=true`; `filter_degraded` for a retained snapshot, a rejected live apply, or a recorded last error |
| `stats` | **No** — advisory only | `stats_unavailable` |

In a build without the `ha` feature, the `ha` component is never part of the
node's role: it reports no reason and cannot block `ready`. A `[ha]` section or
`role = "slave"` cannot start at all in that build (see the build prerequisites
above).

A partial filter snapshot (some lists failed, a group lost a rule class, or
regex patterns were dropped) keeps `ready` true and reports `filter_degraded`:
the retained snapshot still answers. This also covers `FilterState::Failed`
with `unavailable == false` (a live apply was rejected while the previous
snapshot remained active) and `Loading` with a still-usable snapshot. Only
`unavailable == true` means there is no snapshot and DNS fails closed.

D12 certificate ladder:

- A current valid certificate with a failed renewal keeps serving and reports
  `acme_renewal_failed` (degraded). A certificate expiring within 30 days reports
  `acme_cert_expiring`/`tls_cert_expiring` (degraded).
- An expired or unparseable certificate reports `acme_cert_expired`/
  `tls_cert_expired` and makes `/health` unavailable.
- No ACME certificate yet and no error is `acme_issuance_pending` (degraded:
  DNS listeners still bind); an issuance failure with no certificate is
  `acme_issuance_failed` (not-ready).
- A configured static TLS certificate is checked at runtime on every
  readiness build (cached by file mtime/size) and immediately after a
  certificate-watcher reload. A process that runs past expiry therefore flips
  `/health` to not-ready, and replacing the file clears the reason without a
  rebind or restart. An ACME certificate that currently serves takes precedence
  over the static pair.

`ReadinessState` starts not-ready (nothing has been published yet). Startup
publishes listener readiness after the DNS listeners start and TLS readiness
after the acceptors are initialized. During first-boot setup-pending the DNS
listeners are intentionally not bound, so `/health` is unavailable until setup
completes; `sito healthcheck --setup-fallback` accepts that window via the
setup middleware signal. Once DNS is up, the healthcheck also probes `/health`
whenever the admin web listener answers (not only on HA nodes); an unreachable
web listener is ignored on a DNS-only node but is an error when HA is
configured.

A stats database/writer outage is advisory — resolution does not depend on
SQLite — so a stats failure never turns into a DNS outage or a `/health` 503.
`/health` does not run the stats `SELECT 1` probe at all; `/status` does (bounded
to 750 ms) and reports `stats_unavailable`.

A configured `[dns.tls]`/`[tls]` pair with no usable acceptor is a broken
listener, not a silently disabled one: `tls` blocks readiness until the
acceptors are built. An ACME-only deployment that intentionally waits for its
first real certificate (with `allow_bootstrap_cert = false`) is reported by the
`acme` component instead.


---

## 2. Manual Slave -> Master Promotion Procedure

In the event of a catastrophic or permanent failure of the master node, a slave node must be manually promoted to become the new authoritative master.

### Automatic promotion (when `[ha.promotion]` is enabled)

ADR-0010 automatic promotion removes most manual steps, but the operator still
owns the decisions the witness cannot make. With `enabled = true` on every node:

1. The configured master holds the witness lease. On master loss, the single
   designated candidate (`candidate = true`) waits the heartbeat timeout, reads
   the witness, acquires `term + 1`, writes the pending state, quiesces for
   `lease_ttl_secs`, reconciles hello-only, publishes `max(baseline + 1,
   pending_version)`, and only then becomes writable.
2. A manually started master must also acquire the lease. Do **not** hand-edit a
   term above the witness record; the witness rejects it and the correct action
   is manual witness reconciliation (`sito ha lease-admin set`, section 7 or the
   witness runbook).
3. With `require_manual_confirmation = true`, run the one-shot local
   confirmation **on the candidate** after verifying master loss:

   ```bash
   sudo -u sito sito ha confirm-promotion --confirm --config /etc/sito/config.toml
   ```

   It is accepted only on the designated candidate with
   `require_manual_confirmation = true`; otherwise the file would be inert and
   the CLI refuses. It writes `data_dir/ha_promote.confirm` (mode `0600`) and
   authorizes exactly one acquisition. It expires after the effective heartbeat
   timeout, is discarded if the master returns first, and is discarded on
   restart. It never bypasses the witness.
4. After fencing, the node stays read-only across restarts until the operator
   verifies the current master/term and clears the durable marker:

   ```bash
   sudo -u sito sito ha clear-fence --confirm --config /etc/sito/config.toml
   ```

   This removes `ha_fence.json` and `ha_fence.pending`; it does not grant a
   lease. The node still has to acquire a new term. If the service is still
   running, restart it after clearing so the in-memory fenced state is re-read.
5. Watch `GET /api/v2/ha/status` (`promotion.state`/`reason`/`term`/`version`),
   the `sito_ha_promotion_*` metrics and the `ha.promotion.*` audit records.
   A witness outage is a single point of **availability**: the master fences
   after the TTL and no promotion happens until the witness returns. DNS keeps
   serving from the last snapshot. Run the witness on a third failure domain and
   monitor it.

The manual procedure below remains the escape hatch, including when promotion
is disabled. If promotion is enabled cluster-wide, prefer the automatic path or
start the manual master with `role = "master"` and `enabled = true` so it
acquires the lease; otherwise disable promotion everywhere first (section 7).

### Prerequisites
- SSH or root terminal access to the target slave node.
- Write access to `/etc/sito/config.toml` and the data directory `/var/lib/sito`.

### Step-by-Step Procedure

1. **Assess the old master**:
   Ensure the old master node is powered off or isolated from the network to prevent split-brain confusion:
   ```bash
   # On the old master or hypervisor
   systemctl stop sito
   # Or shutdown the container/VM
   ```

2. **Edit the slave configuration**:
   Open `/etc/sito/config.toml` on the slave node:
   ```toml
   [server]
   # Change role from "slave" to "master"
   role = "master"
   instance_name = "sito-master-promoted"

   [ha]
   # Configure replication listener for downstream slaves
   replication_port = 8953
   listen_addr = "0.0.0.0"

   # Comment out or remove master_url and master_pubkey
   # master_url = "wss://192.168.1.10:8953"
   # master_pubkey = "..."
   ```

3. **Carry over the master identity and the version sequence**:
   A promoted slave is already at some configuration version `N` (visible as
   `version` in `GET /api/v2/ha/status`). Two artifacts decide whether the new
   master can keep replicating to the remaining slaves:

   - **Signing key** (`data_dir/ha_signing.key`): bundles are signed with this
     Ed25519 key. If possible, copy the *old* master's key file to the promoted
     node (mode `0600`) so the remaining slaves keep trusting
     `master_pubkey` without changes. A key is generated automatically when
     the file does not exist, but every slave must then be given the new
     public key.
   - **State file** (`data_dir/ha_state.toml`): the persisted active bundle,
     version and cluster term, plus the Ed25519 public key that wrote it
     (`signing_key_pubkey`). Restoring the old master's file keeps the
     sequence monotonic and the term unchanged. If the loaded
     `ha_signing.key` no longer matches that recorded identity, startup fails
     with an actionable error instead of silently re-signing the persisted
     state with a new key. A missing file starts a fresh sequence; a
     **corrupt, v1, foreign or partial** file is moved aside and fails closed —
     the master never resets the sequence silently. Restore a backup or
     explicitly re-seed the state (see below). A promoted master must not adopt
     a counter from its peers: it detects any replica that is ahead (same term)
     or in a newer term, marks itself `diverged`, and refuses to overwrite the
     cluster. Promote it explicitly before pointing anything at it.

     To promote a node explicitly, stop the service and create or edit
     `ha_state.toml` (JSON, mode `0600`) so that:
     - `term` is **one greater** than the highest term any replica has applied
       (a first promotion from a term-0 cluster uses `1`), and
     - `version` is greater than the highest version the remaining slaves have
       applied (the previous cluster version `N` becomes `N+1`).
     A term increase alone is **not** accepted: slaves enforce version
     continuity across a promotion and reject a higher-term bundle whose
     version is not above their applied high-water mark. That prevents a
     promoted node with a stale state file from silently rolling the cluster
     back.
     ```json
     {
       "version": 12,
       "term": 1,
       "timestamp": 1730000000000,
       "config_toml": "...",
       "custom_rules": [],
       "lists": []
     }
     ```
     Keep the rest of a copy of the old master's state (or the last pushed
     bundle) intact; only `version` and `term` need to change. Starting the
     service then restores this state and publishes subsequent mutations with
     the promoted term.

     **Upgrade order:** upgrade every slave to a build that understands terms
     and persists the term in `ha_watermark.toml` *before* promoting. A slave
     that does not know about terms can still be overwritten by a stale
     term-less master (it only compares versions), although its persisted
     watermark still prevents rollback below what it has already applied.

   To obtain the master public key for the slave configs:
   ```bash
   # All /api/v2/ha/* endpoints require an Admin token or session.
   export TOKEN='sito_...'   # Admin API token
   curl -s -H "Authorization: Bearer $TOKEN" \
     http://192.168.1.10:8080/api/v2/ha/status | jq -r .master_pubkey

   # Without it: the promoted master prints the same value in its status once running.
   ```
   Never let an unpromoted master start below or beside a newer term: it marks
   itself in `GET /api/v2/ha/status` with `"diverged": true` plus a
   `diverged_reason` and stops replicating, rather than republishing its stale
   bundle over newer configuration. Divergence is sticky per slave: it is not
   cleared by another slave's success and **not** cleared by
   `POST /api/v2/ha/resync` (a resync only re-pushes the current bundle). It
   clears only when that specific slave acknowledges the master's current
   term/version, or when the slave disconnects. A same-version payload fork is
   likewise cleared only by that slave accepting the current bundle after a
   promotion/reconciliation. Recovery is always the explicit promotion above
   (or disconnecting and fixing/re-syncing the forked replica), not waiting for
   an automatic rebase.

4. **Verify or generate master certificates**:
   `sito` uses the certificates configured in `[ha] cert`/`key` for mTLS and
   pins the peer certificate with BLAKE3 fingerprints. If the promoted node
   uses the old master's certificate and its private key, no slave changes are
   needed. Otherwise regenerate a certificate suite with ownership transferred
   to the runtime user
   (`sito ha gen-certs --dir /etc/sito/certs --master --slave --uid "$(id -u sito)" --gid "$(id -g sito)"`,
   or uid/gid `65532` for Docker) and distribute the values to every remaining
   slave:
   ```toml
   [ha]
   master_fingerprint = "blake3:<BLAKE3_FINGERPRINT_OF_NEW_MASTER_CERT>"
   master_pubkey = "<ED25519_PUBLIC_KEY_OF_NEW_MASTER>"
   ```
   Slaves reject TLS connections whose certificate does not match
   `master_fingerprint` and reject bundles signed by a key other than
   `master_pubkey`, so both values must be updated together whenever the
   identity changes. Also add each slave's certificate fingerprint to
   `pinned_slave_fingerprints` on the promoted master.

5. **Restart sito service**:
   ```bash
   # On systemd:
   systemctl restart sito

   # On Docker Compose:
   docker compose restart sito-slave
   ```

6. **Verify master status**:
   Query the local status endpoint with an authenticated token or session:
   ```bash
   curl -s -H "Authorization: Bearer $TOKEN" \
     http://localhost:8080/api/v2/ha/status | jq .
   ```
   Expected response (master):
   ```json
   {
     "role": "master",
     "instance_name": "sito-master-promoted",
     "version": 11,
     "state": "active",
     "ready": true,
     "slaves_connected": 0,
     "diverged": false,
     "master_pubkey": "9f2c...64-hex-chars"
   }
   ```
   `version` must be greater than or equal to the highest version the other
   slaves had already applied. `diverged` must be `false`; when it is `true`,
   read `diverged_reason` and follow the recovery steps above before pointing
   clients at the node. `ready` must be `true`; when it is `false`, read
   `readiness_reason` (for example an unreadable key or a listener bind
   failure) before promoting traffic to this node.

7. **Update network routing and DHCP**:
   Update your router or DHCP server (e.g. MikroTik RouterOS) to point client DNS queries to the new master's IP:
   ```routeros
   /ip dhcp-server network set [find] dns-server=192.168.1.11
   ```

8. **Re-point remaining slaves**:
   On all other slave nodes, update `master_url` in `/etc/sito/config.toml` to point to the newly promoted master, plus `master_fingerprint` and `master_pubkey` when the identity changed:
   ```toml
   [ha]
   master_url = "wss://192.168.1.11:8953"
   master_fingerprint = "blake3:<NEW_MASTER_FINGERPRINT>"
   master_pubkey = "<NEW_MASTER_PUBLIC_KEY>"
   ```
   Restart the slave service or issue a resync. Verify each slave reaches
   `"state": "synced"` with `"version"` equal to the master's version.

### Secret placeholders in replicated configuration

Replicated configuration may contain `${SECRET:name}` placeholders. On the
slave they are resolved from the process environment only:

1. `DNSD_SECRET_<name>` (the placeholder text after `SECRET:` is appended
   verbatim, e.g. `${SECRET:upstream_token}` → `DNSD_SECRET_upstream_token`),
2. `<name>` as a plain environment variable.

There is no on-disk local secret store. A bundle referencing a secret the
slave cannot resolve is rejected as a whole (the slave stays `Degraded` and
keeps its previous configuration), so provision the variables in the service
environment before pushing the config. The packaged systemd unit reads
`EnvironmentFile=-/etc/sito/sito.env` (mode `0600`, created by the installer
when absent); put the `DNSD_SECRET_*` lines there and restart the service.
Node-local secret material (`[clients] client_id_secrets`, RouterOS
credentials) is stripped from bundles and is never replicated; keep those
values in each node's own `config.toml`.

---

## 3. Certificate Rotation without Downtime

`sito` uses self-signed mTLS certificates with BLAKE3 fingerprint pinning. Follow this procedure to rotate certificates without causing replication interruption or DNS downtime.

### Step 1: Generate a New Certificate Suite
Run the built-in certificate generator with ownership transferred to the
runtime user (`sito` for systemd, uid/gid `65532` for Docker):
```bash
sudo sito ha gen-certs --dir /etc/sito/certs/next --master --slave \
  --san 192.168.1.10 --san dns-master.lan \
  --uid "$(id -u sito)" --gid "$(id -g sito)"
```
`--uid` and `--gid` must be supplied together; a failed chown aborts
generation. `--master` and `--slave` are boolean selectors for which
certificate pairs to generate; omitting both generates the complete set
(CA + master + slave).
`--san` is repeatable and adds a hostname or IP address to both certificates
(in addition to `localhost`, `sito-master` / `sito-slave`, `127.0.0.1` and
`::1`). With BLAKE3 fingerprint pinning and **no** `ca`, the certificate SAN is
not used for the replication connection. When `ca` is configured, rustls
validates the chain **and the hostname/SAN even if pinning is also configured**;
use `--san <LAN_IP_OR_HOST>` so URLs such as `wss://192.168.1.10:8953` pass
hostname verification. Do not rely on `allow_unpinned_tls = true` for a
production cluster.

Note down the new fingerprints printed by the command:
- Master cert BLAKE3 fingerprint: `a1b2c3...`
- Slave cert BLAKE3 fingerprint: `d4e5f6...`

### Step 2: Update Configurations with Dual-Fingerprint Pinning
The master accepts a list of valid slave fingerprints, so it can trust both the
old and new slave certificates during rotation. Each slave stores a **single**
`master_fingerprint`; switch that value when the master certificate changes.

On the **master** node:
```toml
[ha]
cert = "/etc/sito/certs/master.crt"
key = "/etc/sito/certs/master.key"
ca = "/etc/sito/certs/ca.crt"
# Allow both old and new slave certificates
pinned_slave_fingerprints = [
  "OLD_SLAVE_FINGERPRINT",
  "NEW_SLAVE_FINGERPRINT"
]
```

On the **slave** node:
```toml
[ha]
cert = "/etc/sito/certs/slave.crt"
key = "/etc/sito/certs/slave.key"
ca = "/etc/sito/certs/ca.crt"
# Point to master
master_fingerprint = "OLD_MASTER_FINGERPRINT"
```

### Step 3: Rotate Slave Certificate
1. Replace the slave's certificate and private key with the newly generated files:
   ```bash
   cp /etc/sito/certs/next/slave.crt /etc/sito/certs/slave.crt
   cp /etc/sito/certs/next/slave.key /etc/sito/certs/slave.key
   chmod 0600 /etc/sito/certs/slave.key
   # cp as root resets ownership: hand the key back to the runtime user.
   chown sito:sito /etc/sito/certs/slave.crt /etc/sito/certs/slave.key
   ```
   For Docker use `chown 65532:65532` instead.
2. Restart the slave:
   ```bash
   systemctl restart sito
   ```
3. Verify the slave successfully reconnects to the master.

### Step 4: Rotate Master Certificate
1. Update the slave's `master_fingerprint` to `NEW_MASTER_FINGERPRINT`.
2. Replace the master's certificate and private key:
   ```bash
   cp /etc/sito/certs/next/master.crt /etc/sito/certs/master.crt
   cp /etc/sito/certs/next/master.key /etc/sito/certs/master.key
   chmod 0600 /etc/sito/certs/master.key
   # cp as root resets ownership: hand the key back to the runtime user.
   chown sito:sito /etc/sito/certs/master.crt /etc/sito/certs/master.key
   ```
   For Docker use `chown 65532:65532` instead.
3. Restart the master:
   ```bash
   systemctl restart sito
   ```
4. Verify reconnection and state synchronization across the cluster.

### Step 5: Clean Up
Remove `OLD_SLAVE_FINGERPRINT` from `pinned_slave_fingerprints` in the master config and archive the old cert directory.

---

## 4. Slave Node Rebuild and Recovery Procedure

When a slave node fails or must be reprovisioned from bare metal:

1. **Install sito binary**:
   Deploy the `sito` binary or Docker container to the new host.
2. **Obtain Cluster CA and Slave Cert**:
   Copy `/etc/sito/certs/ca.crt` from the master, along with a valid slave certificate and private key.
3. **Configure Minimal Slave Configuration and align restart-only fields**:
   Restart-only shared settings must already match the master's
   `config.toml` before the first push. The template below uses the shipped
   `config.example.toml` values (the default `log_format = "json"` and the
   default `[auth]` policy); copy the master's values if it overrides either. A
   mismatch makes the slave reject the push with `restart_required`, enter
   `Degraded`, and keep its previous configuration and file until it is
   restarted with matching values.

   Create `/etc/sito/config.toml`. This branch uses **config v2**; if the
   source file is a v1 document, migrate it first with
   `sito config migrate --from v1 --to v2 --backup` (see the
   [2.0 migration guide](2.0-migration.md#4-config-v1--v2)). Keep the file
   `config_version = 2` before starting the node:
   ```toml
   config_version = 2

   [server]
   role = "slave"
   instance_name = "sito-slave-2"
   data_dir = "/var/lib/sito"
   # Restart-only shared value; must match the master's config.toml.
   # The default (and config.example.toml) is "json".
   log_format = "json"

   [dns]
   bind = ["0.0.0.0"]

   # Restart-only shared policy; must match the master's [auth].
   # These are the defaults (and the values in config.example.toml).
   [auth]
   session_ttl_hours = 24
   login_rate_limit = 5
   session_persist = true
   token_default_ttl_days = 90
   token_max_ttl_days = 365

   [ha]
   master_url = "wss://192.168.1.10:8953"
   master_fingerprint = "<BLAKE3_FINGERPRINT_OF_MASTER>"
   master_pubkey = "<ED25519_PUBLIC_KEY_OF_MASTER>"
   cert = "/etc/sito/certs/slave.crt"
   key = "/etc/sito/certs/slave.key"
   ca = "/etc/sito/certs/ca.crt"
   # Required when the master sets a slave_token (recommended)
   slave_token = "<SHARED_TOKEN>"
   ```

   `[web]` is node-local identity, not a shared setting: the master does not
   overwrite the slave's `enabled`, `bind`, `port`, `trusted_proxies`,
   `metrics_auth`, `public_url` or `tls_terminated_by_proxy`. A slave may keep
   `web.enabled = false` and still synchronize. The HA readiness healthcheck
   still requires the admin web listener, so a slave with it disabled can be
   `Synced` but reports not ready.
4. **Register Slave Fingerprint on Master**:
   If the master enforces pinned fingerprints, add the new slave's certificate fingerprint to `pinned_slave_fingerprints` in `/etc/sito/config.toml` on the master.
5. **Start Slave**:
   ```bash
   systemctl start sito
   ```
6. **Verify Initial Synchronization**:
   Check the slave status endpoint with an authenticated token or session:
   ```bash
   curl -s -H "Authorization: Bearer $TOKEN" \
     http://localhost:8080/api/v2/ha/status | jq .
   ```
   The slave will transition through `Connecting` -> `HelloSent` -> `Applying` -> `Synced` (or `HelloSent` -> `Synced` when it is already at the master's version) in under 2 seconds once the restart-only fields from step 3 match the master. If the first push is rejected with `restart_required`, align `server.log_format` and the `[auth]` policy with the master and restart the slave; the master keeps reporting it unsynced until then. Verify that custom rules, rewrites, and client lists match the master. `Degraded` is only cleared by a successful apply or an early ACK for the already-running version.

   If `data_dir/ha_watermark.toml` is corrupt or restored from a different
   node, the slave refuses to start rather than dropping its replay guard.
   Restore the file from backup, or delete it only when you intentionally want
   the node to accept the master's current bundle as a fresh sync. Never copy a
   watermark between slaves: it identifies this node's last applied payload.

---

## 5. Troubleshooting & Diagnostics

### Diagnostic Checklist

| Symptom | Probable Cause | Action |
|---|---|---|
| Slave state is `Degraded` | Configuration apply failed, corrupted bundle, or an unresolvable `${SECRET:...}` placeholder | Check the service journal (`journalctl -u sito`) for `apply_config_push` errors. The slave keeps its last good snapshot and reports `Degraded`; fix the configuration on the master and re-push. The reason is exposed as `degraded_reason` in `GET /api/v2/ha/status`. |
| Push rejected with `restart_required` | The master bundle changed a restart-only field that is not node-local (for example `server.log_format` or `[auth]`) | The slave kept its previous live configuration and file and ACKs `applied:false`. Restart the slave after setting the intended value locally, or change the shared setting only when a coordinated restart is acceptable. Node-local listener/TLS/`[web]`/MikroTik fields are preserved automatically and do not trigger this; web identity (including `enabled`) is node-local, so a slave may run with the admin listener disabled and still synchronize (the readiness healthcheck separately requires it). |
| Slave state is `Connecting` in loop | Network unreachable, firewall blocking 8953, or mTLS handshake failed/timed out | Check `nc -zv 192.168.1.10 8953`. Check TLS certificate expiration or fingerprint mismatch in logs. `readiness_reason` carries the last connection/handshake error. |
| `GET /api/v2/ha/status` reports `"ready": false` or the container healthcheck fails while DNS answers | The replication listener or slave worker is not operational: key/certificate unreadable by the runtime user, listener bind failure, or the slave has not reached `Synced` | Read `readiness_reason` and the service logs. Fixing certificate ownership (`chown sito:sito` or `65532:65532`, mode `0600`) and restarting restores the listener. A healthy DNS probe alone no longer marks the node healthy. |
| Master reason is `HA requires at least one synced slave` or `HA requires all slaves synced` | `ha.require_slaves`/`ha.require_all_slaves` is enabled and a connected slave is behind the current version, latched as diverged, or (for `require_all_slaves`) there are no connected slaves | Inspect `GET /api/v2/ha/slaves` (`synced_version`, `lag`, `diverged`). Wait for the ACK, issue `POST /api/v2/ha/resync`, or resolve the divergence/staleness. If the requirement is not intended, remove the flag; both default to `false`. |
| Log says `Failed to initialize mTLS ... Permission denied` | Private key is owned by root or another user that the service account cannot read | Regenerate with `--uid/--gid` for the runtime user, or `chown` the key files; keep keys mode `0600`. |
| `Signature verification failed` | Bundle signature does not match master public key | Verify that the master didn't regenerate `ha_signing.key` without updating slaves. Compare `master_pubkey` from the master's `/api/v2/ha/status` with the slave config. |
| `Incoming version <= have_version` | Out of order or replayed bundle | Normal during network blips; the master will send the latest monotonic version. After a promotion, an older-term master is rejected even with a higher version; promote the master explicitly (section 2). |
| Master reports `"diverged": true` | A slave is ahead in the same term, reports a newer term (stale/partitioned master, lost/corrupt `ha_state.toml`, or forked master), or reported a same-version payload fork | Read `diverged_reason`. Divergence is **sticky per slave**: it is not cleared by another slave applying the current version, nor by `POST /api/v2/ha/resync`. It clears when that specific slave acknowledges the master's current term/version or disconnects. A same-version fork marks that slave unsynced and visible but does **not** stop publishing to healthy replicas. Isolate the stale master, resolve the fork, restore its state file or perform the explicit promotion in section 2 (raise both `term` and `version`), then restart it. |
| Slave stays `Synced` but its master is gone / stale config | The TCP session is blackholed (no frames, no close) | The slave now treats any frame as liveness proof and requires one within `3 × ping_interval_secs` (default 45 s). On timeout it leaves `Synced`, sets `readiness_reason`, and `/health` reports not ready while DNS keeps serving the last applied configuration. Check the network path/port 8953 and the master process. |
| Slave reports `"Degraded"` with `Local configuration drift` | A shared field in `config.toml` was edited or reverted locally after the last applied bundle | The persisted `ha_watermark.toml` stores the digest of the shared projection of the applied document. Wait for the master to push the current bundle (the slave forces a full apply even for the same version) or issue a resync. If the master is unreachable the node stays degraded and `/health` false until it reconnects. |
| Slave reports a same-version payload fork | The master and slave hold different signed content for the same term and version (split brain) | The slave persists a fork latch in `ha_watermark.toml`, degrades, and rejects all same-term pushes; the master records divergence and stops showing the slave as synced. Do not retry the same version. Isolate the forked master and perform an explicit promotion with a strictly higher `term` **and** `version` (section 2); the promoted bundle clears the latch. |
| Master `/health` stays false after an external `config.toml` edit, log says the HA bundle exceeds the replication limit | The file watcher rolled the live configuration back, but the oversized external file is left on disk; publication re-reads it on every attempt | Correct or replace `config.toml` with a document under the replication limit (or restore the previous file). Until then each republish/retry re-reads the oversized document and `/health` cannot recover. The `PUT /api/v2/config` path rolls the persisted document back and is not affected. |
| API returns `409 Conflict` | Mutation attempted directly on a slave node | Perform configuration edits on the master node indicated in the `X-Dnsd-Master` header. |
| `POST /api/v2/ha/resync` returns `503` | HA replication is inactive on the node, the slave worker stopped, or (master) a push could not be queued for any of the connected slaves | Check the node's role and `GET /api/v2/ha/status`. A `429` means a resync is already queued; retry shortly. With no connected slaves and no active bundle the master still returns `200` with `slaves_notified: 0`. |

### Diagnostic Commands

The `/api/v2/*` endpoints used below require authentication. Export an Admin API
token (or use a session cookie) before running these examples:

```bash
export TOKEN='sito_...'   # Admin token: all /api/v2/ha/* endpoints require Admin
```

1. **Check HA status on Master**:
   ```bash
   curl -s -H "Authorization: Bearer $TOKEN" \
     http://192.168.1.10:8080/api/v2/ha/status | jq .
   curl -s -H "Authorization: Bearer $TOKEN" \
     http://192.168.1.10:8080/api/v2/ha/slaves | jq .
   ```
2. **Check HA status on Slave**:
   ```bash
   curl -s -H "Authorization: Bearer $TOKEN" \
     http://192.168.1.11:8080/api/v2/ha/status | jq .
   ```
   `/ha/status` fields:
   - Common: `role`, `instance_name`, `version`, `state`.
   - Master only: `slaves_connected`, `diverged`/`diverged_reason`,
     `master_pubkey` (hex; slaves must list it as `master_pubkey`).
   - Slave only: `master_url`, `last_synced_at`, `degraded_reason`.
   Connected replicas are listed separately by `GET /api/v2/ha/slaves`:
   `instance`, `remote_addr`, `synced_version`, `lag`, `diverged`,
   `last_ping_secs_ago`, `connected_at`, `bundle_hash_known`, `last_stats`
   (with `window_s` — the measured interval since the previous report — and
   window-scoped `queries`, `blocked`, `upstreams_count`; upstream RTT/error
   figures in the report are also window deltas, not lifetime totals), and
   `recent_acks` (the newest eight ACK records for that peer: `version`, `term`,
   `applied`, `conflict`, `error`, `at`).
3. **Trigger Manual Resynchronization**:
   ```bash
   # From the master (Admin token required):
   curl -s -X POST -H "Authorization: Bearer $TOKEN" \
     http://192.168.1.10:8080/api/v2/ha/resync | jq .

   # Or from a slave:
   curl -s -X POST -H "Authorization: Bearer $TOKEN" \
     http://192.168.1.11:8080/api/v2/ha/resync | jq .
   ```
   A master response includes the queueing result:
   ```json
   {
     "status": "resync_triggered",
     "role": "master",
     "version": 11,
     "active_bundle": true,
     "slaves_notified": 2
   }
   ```
   `200 OK` means the resync was accepted (a master with no connected slaves
   and no active bundle reports `slaves_notified: 0`). `503 Service Unavailable`
   means HA is not active on the node, the slave worker is not running, or
   (master) no connected slave could be queued; `429 Too Many Requests` means a
   resync request is already pending.
4. **Inspect Prometheus HA Metrics**:
   ```bash
   curl -s -H "Authorization: Bearer $TOKEN" \
     http://192.168.1.10:8080/metrics | grep sito_ha_
   ```
   `/metrics` requires authentication by default (`web.metrics_auth = true`);
   use a Viewer-or-higher token or session. Operators who deliberately expose an
   unauthenticated scrape endpoint must set `web.metrics_auth = false`.
   Look for:
    - `sito_ha_slaves_connected`: Number of active slaves connected to this master.
    - `sito_ha_config_version{instance="..."}`: Published configuration version per
      node (the master plus each replica's last acknowledged version). Lag is the
      difference between the master's version and a slave's reported version; it
      is not exported as a separate per-slave metric.
    - `sito_ha_diverged{instance="..."}`: `1` while a slave acknowledged a version
      above the master's (version continuity is broken); it returns to `0` after
      a higher version is applied and the series disappears when the slave
      disconnects.
    - `sito_ha_startup_noop_total{role,reason}`: Counts HA startup paths that left
      replication inactive (`replication_disabled`, `missing_master_url`,
      `tls_init_failed`, `bind_failed`). A non-zero value on a node expected to
      replicate means replication is not running.

---

## 6. Security Considerations: Transport Security, Certificate Pinning & Authentication

The HA replication channel synchronizes entire server configuration bundles, custom rules, DNS rewrites, and client definitions between nodes. Protecting this transport against interception, tampering, and unauthorized slave connections is critical.

### 1. Certificate Pinning & Transport Encryption
- **Pinned TLS (Recommended)**: Slave nodes connecting to `wss://` can require `master_fingerprint = "blake3:..."` matching the master's certificate. This prevents man-in-the-middle (MITM) attacks even if a rogue CA is trusted in the system certificate store.
- **CA-only TLS**: With `ca` configured and no `master_fingerprint`, the slave validates the master chain, validity and SAN/hostname against that CA. This is a supported trust mode and does **not** require `allow_unpinned_tls`. If both a pin and a CA are configured, both are enforced.
- **Explicit no-verification (`allow_unpinned_tls = true`)**:
  > [!WARNING]
  > This flag only has an effect when **neither** `master_fingerprint` nor `ca` is configured. It then trusts any server certificate: there is no pin and no chain validation. This is discouraged in production. A configured CA is still checked even when this flag is set.
- **Plaintext WebSocket (`allow_insecure_ws = true`)**:
  > [!CAUTION]
  > Plaintext `ws://` connections are refused by default. Setting `allow_insecure_ws = true` transmits replication data without TLS encryption. Do NOT enable `allow_insecure_ws` across untrusted or public networks, as configuration details, network topology, and client tokens will be exposed in cleartext. Only use for local loopback debugging.
  - The flag is the **only** way to permit plaintext. A master without `cert`/`key` refuses to start the replication listener (readiness reason names `allow_insecure_ws`), and a slave refuses a `ws://` `master_url` during configuration load and again before the runtime opens a socket. There is no "try TLS, then plaintext" path.
  - Plaintext still requires a non-empty `slave_token` on **both** ends (the master rejects a tokenless listener and a slave refuses to connect without one); it is the only peer authentication available without TLS. Client `cert`/`key` files on a plaintext slave are inert and reported as such — they only apply to `wss://`.
  - `pinned_slave_fingerprints`, `ca` and a slave-side `master_fingerprint` are TLS-only controls. Combining them with plaintext is rejected by `sito check-config`/startup instead of being silently ignored, so a configured pin or CA is always enforced ([residual R-10](phase3-security-review.md#13-residual-risk-register)).
  - `wss://` always performs the TLS handshake and honors pin, CA, SNI/server name and client certificate. A TLS failure is reported as a failure and never downgraded.
  - Automatic promotion reuses this transport policy: the candidate is validated as a master (token, TLS/plaintext consistency and pin/CA contradictions), and the listener must be active before the node becomes writable. A `wss://` candidate without a server certificate/key cannot be promoted, and a promoted master inherits `allow_insecure_ws`. `sito check-config` and startup log the risk (or report that the flag is inert because TLS is configured).


### 2. Slave Authentication Handshake (`slave_token`)
To prevent unauthorized nodes from connecting to the master replication port and receiving signed configuration bundles:
- Set `slave_token = "<PRE_SHARED_SECRET>"` in the `[ha]` section on both master and slave nodes.
- The slave transmits this token in the initial `Hello` handshake over the encrypted replication channel.
- The master validates the token and drops the connection immediately if the token is missing or mismatched.

---

## 7. HA protocol v2 upgrade and downgrade

HA protocol **v2** is implemented. It is intentionally incompatible with v1:
version negotiation, the signed bundle identity and the on-disk state/watermark
format all changed. Plan a coordinated cluster change and keep the pre-upgrade
backups described in the [migration guide](2.0-migration.md#8-ha).

### 7.1 What v2 changes

- `PROTOCOL_VERSION = 2` in the `Hello` handshake and every `ConfigPush`.
  A `Hello` without a version is treated as v1 and rejected.
- The signed `ConfigBundle` carries `protocol_version`, a BLAKE3
  `config_digest` of `config_toml`, and the master's
  `signing_key_fingerprint` (BLAKE3 of the Ed25519 public key). The slave checks
  all three against the configured `master_pubkey` before applying anything.
- `ha_watermark.toml` stores the signing-key fingerprint. A same-term push from
  a different key requires an explicit higher-term promotion.
- `ha_state.toml` and `ha_watermark.toml` use a wrapped v2 shape with a
  required `protocol_version`. A v1 file is refused with `protocol_mismatch`;
  it is never silently read or reset to version 0.
- Rejections are observable: the peer receives a WebSocket close whose reason
  starts with `protocol_mismatch:`, the local log names the action, the slave
  readiness reason carries the same text, and the master increments
  `sito_ha_protocol_rejections_total{role="master",reason="version_mismatch"}`
  (the slave uses `role="slave"`). A bad peer never makes the listener or the
  master's own readiness fail.

### 7.2 Upgrade (v1 cluster → v2)

1. **Back up every node.** Stop the service and archive `config.toml`,
   `users.toml`, the certificate/key material, `ha_state.toml` and
   `ha_watermark.toml`; keep the previous binary/container image.
2. **Install the v2 binary on every node first**, without starting it. Mixed
   v1/v2 replication is refused by design.
3. **Retire the v1 state/watermark files.** A v2 binary refuses v1 files, so
   after the backup move them aside or remove them:
   - on the master: `data_dir/ha_state.toml` (for example
     `mv /var/lib/sito/ha_state.toml /var/lib/sito/ha_state.toml.v1.bak`);
   - on every slave: `data_dir/ha_watermark.toml`
     (`mv /var/lib/sito/ha_watermark.toml /var/lib/sito/ha_watermark.toml.v1.bak`).

   There is no in-place state migration command. The consequences are
   intentional: the master starts a **new local sequence** (version/term reset
   to the configured initial values), every slave performs a **full resync/full
   apply**, and each slave's local replay guard is reset. Every slave must
   apply the master's current bundle before reporting `Synced`. Keep the v1
   files for downgrade; never hand them to a v2 node.
4. **Start the master first.** It serves v2 and rejects any v1 slave with
   `protocol_mismatch`. DNS keeps answering from each node's last applied
   configuration; replication is intentionally degraded during this window.
5. **Start slaves one at a time.** A v2 slave also rejects a v1 master, so
   start slaves only after the master is v2. Watch each slave reach `Synced`
   with the master's current term/version after the full apply.
6. **Verify convergence.** Read `ready`, `readiness_reason` and
   `diverged_reason` from `GET /api/v2/ha/status`, and per-slave
   `synced_version`/`lag` from `GET /api/v2/ha/slaves`. `/health` stays generic;
   a `protocol_mismatch` reason means a node still runs v1.
7. **Publish/verify the current bundle.** Because the master sequence and the
   slave replay guards were reset, confirm the active bundle was republished
   (or trigger `POST /api/v2/ha/resync`) and that every slave's applied version
   matches the master.

The rolling order above intentionally accepts a short replication gap. For a
strict no-gap window, stop the whole cluster, start the master, then the
slaves; DNS availability during that stop is an operational decision.

### 7.3 Downgrade (v2 → v1)

In-place downgrade is **not supported**. A v1 binary cannot read v2 state or
watermarks and will refuse them (or the operator would be tempted to delete
them, which loses the replay guard). To return to 1.9.x:

1. Stop every v2 node.
2. Restore the pre-upgrade backups of `config.toml`, `ha_state.toml`,
   `ha_watermark.toml` and the certificate/key material on every node.
3. Start the old binary on the master, then the slaves.
4. Verify `Synced` and that no `protocol_mismatch` remains in
   `GET /api/v2/ha/status`.

If the v2 state/watermark cannot be restored, the only safe recovery is a full
resync from a master whose state you trust, after an explicit version/term
promotion; deleting the state file alone silently drops the replay guard and is
not a supported downgrade.

### 7.4 Publish status, limits and trust policy

- `POST /api/v2/config`/reload responses report `ha_publish.status = "queued"`
  when at least one slave was enqueued (directly or coalesced). This is **not**
  delivery proof: `slaves_connected`, `slaves_queued` and `slaves_coalesced` are
  separate counts, and delivery is confirmed by the slave ACK shown in
  `GET /api/v2/ha/slaves`. `no_slaves` means no slave is connected. When
  slaves are connected but every channel is closed, nothing was queued and the
  status is `connected_no_delivery` (never `no_slaves` and never `queued`).
- `TooLarge` is a configuration error, not a transport error. The envelope is
  not persisted or broadcast, and it is **not retried** because retrying the
  same document cannot shrink it. Reduce the shared configuration (rules,
  rewrites, lists) and reapply.
- Limits: 1 MiB maximum WebSocket message/frame, 4 MiB per-slave queued bytes
  (500 ms/1 s writes coalesce the latest bundle), 10 s send deadline, 10 s
  handshake/connect deadline, 64 global and 8 per-source-IP concurrent
  **sessions** (the per-IP permit is held for the whole session, not only the
  handshake). Slow or silent peers are disconnected instead of pinning memory.
- Master URL: bracketed IPv6 literals are supported, for example
  `master_url = "wss://[2001:db8::10]:8953"` or
  `master_url = "wss://[::1]:8953"`. Do not omit the brackets.
- TLS trust policy: a configured `master_fingerprint` is always enforced; a
  configured `ca` always enforces chain, validity and SAN/hostname checking,
  even when a pin is also configured. `allow_unpinned_tls = true` selects the
  explicit no-verification mode only when **neither** a pin nor a CA is
  configured. CA-only is supported and does not require the opt-out. Keep the
  certificate SAN aligned with the host/IP used in `master_url`.
- Key permissions: `sito ha gen-certs` writes private keys `0600`; reusing an
  existing CA repairs `ca.key` to `0600` without rewriting it. The Ed25519
  signing key is also owner-only. A key owned by another user fails the mTLS
  listener even though DNS keeps answering.

### 7.5 Node-local vs shared fields and edit-time enforcement

Slaves persist the pushed document with node-local values merged back in. Both
the applied-watermark digest and the edit-time read-only gate use the same
**shared projection** (`sito_ha::shared_config_diff` /
`shared_config_digest`), so they cannot disagree about the boundary. A local
edit to one of these fields is node-local and does not force a full apply:

- `[ha]`;
- `server.role`, `server.instance_name`, `server.data_dir`,
  `server.log_level`, `server.log_format`;
- `[dns] bind` and `[dns.tls]`;
- the complete `[tls]` and `[acme]` sections;
- `[web] enabled`, `bind`, `port`, `trusted_proxies`, `metrics_auth`,
  `public_url`, `tls_terminated_by_proxy`;
- the complete `[integrations.mikrotik]` section;
- `[clients] client_id_secrets`.

Everything else survives HA sanitization (`[filtering]`, `[rewrites]`,
`[clients]` groups/entries/ACL, `[upstream]`, `[dns.cache]`,
`[dns.dnssec]`, `[privacy]`, `[stats]`, `[auth]` policy and the cluster-shared
`[web]` legacy ACME aliases) and is **master-managed shared configuration**.

**Editing a slave through the API/UI.** `PUT /api/v2/config` is allowed through
the slave middleware and the apply pipeline compares the candidate with the
running document before persist/apply:

- a hot-applied node-local-only change (or a formatting-only rewrite) is
  applied and persisted locally; the slave never publishes to the master and
  the HA watermark is untouched. Restart-only node-local fields keep their
  existing D11 `409 restart_required` response: edit `config.toml` and restart
  that node (for example `[web] bind/port`, `[tls]`, `[acme]`,
  `server.data_dir`);
- any shared-field change is rejected atomically with `409 Conflict`,
  `type = "urn:sito:ha:shared_config_read_only"`, a `title` of
  `HA Shared Configuration Read-Only`, and a `shared_config_fields` array of
  the changed dotted paths (for example `["upstream.servers"]`). Nothing is
  applied or persisted, including the node-local part of a mixed edit;
- a promoted effective master (`ha_write_gate` effective master) is no longer a
  replica and is not subject to the gate; a configured master is unaffected.

`shared_config_fields` replaces guessing from an opaque error: submit the named
fields to the master and let replication converge the node. An unparseable
document fails closed with `<unparseable-config>` rather than being treated as
node-local.

Other config mutation routes stay blocked by the slave middleware with
`urn:sito:ha:read-only`: `POST /api/v2/config/reload`, `/api/v2/config/restore*`,
the filtering/clients/rewrites/upstream/settings UI actions and the system
reload action. Hand-editing a shared field in `config.toml` directly cannot be
prevented by an API gate; the watcher/restart drift check still marks the node
`Degraded` and the next master push overwrites it. The Settings and System UI
pages render shared controls read-only on a replica with a “Managed by the
master” explanation and the configured master URL; the filtering, clients,
rewrites and upstreams pages still rely on the middleware 409 (UI row-level
residual, tracked in the 2.0 claim matrix).
