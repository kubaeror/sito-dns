# ADR-0010: Opt-In HA Automatic Promotion with a Lease Witness

* **Status:** Accepted
* **Date:** 2026-11-22
* **Deciders:** sito core team
* **Consulted:** HA/operations review, 2.0 release planning
* **Informed:** All contributors

## Context

[ADR-0002](0002-ha-master-slave-push.md) chose master/slave push replication
without a consensus engine. The current 2.0 implementation has:

- signed, versioned `ConfigBundle` pushes over mTLS WebSocket;
- a monotonic cluster **term** and **version** per bundle;
- node-local `ha_state.toml` (master) and `ha_watermark.toml` (slave) replay
  guards, with v1 state refused by protocol v2;
- sticky per-slave divergence/fork latching;
- read-only enforcement on slaves;
- **manual** promotion only: stop the old master, raise both `term` and
  `version`, restart the node
  ([HA runbook §2](../runbook-ha.md#2-manual-slave---master-promotion-procedure)).

There is no shared database, no quorum service, no witness and no leader
election. The normal deployment is two nodes (a primary and a secondary), so a
majority quorum is not available. The 2.0 plan requires automatic promotion to
be **opt-in, default `false`, with lease/fencing, split-brain tests,
metrics/readiness and manual override** (plan C3). A wrong default is
unacceptable: both nodes accepting configuration writes would produce two
divergent writable masters and, worse, a rollback of the cluster's
configuration sequence.

The existing safety rules are necessary but not sufficient for automatic
promotion:

- terms order masters; a stale master cannot overwrite a newer term even with a
  higher version;
- a higher term alone does not bypass version continuity: a promotion must raise
  **both** term and version above the cluster high-water mark;
- a slave's watermark prevents replay and rollback below what it has applied;
- a same-version fork latches and is not cleared by a resync.

What is missing is a **shared arbiter** that decides which node may raise the
term. A slave that merely stops receiving heartbeats cannot know whether the
master is dead or partitioned. This ADR adds that arbiter and makes automatic
promotion a supported, opt-in 2.0 feature.

The only lease-like primitive in the tree today is the single-instance service
lease: an advisory `try_lock` on `<data_dir>/sito.pid` held by the running
server so `reset-admin`/`reset-sessions` cannot mutate a live data directory.
It is local to one node's data directory, has no expiry or takeover protocol,
and its lock semantics are not a portable distributed mutual-exclusion
primitive. It prevents two processes from sharing one data directory; it
cannot arbitrate two HA nodes.

## Problem and failure modes

Automatic promotion must be safe under the failure model below. A **publisher**
is a node that holds the current lease term and is allowed to sign/publish
bundles. A **writable master** is a publisher whose mutations are accepted and
whose bundles are applied by at least one slave. A node that has lost the lease
must never be a publisher, even if its local API briefly accepts a request.

| Failure | What each side observes | Risk if promotion trusts heartbeats alone | Required response |
|---|---|---|---|
| Master crash | Candidate sees no frames; master process gone | None if only one node promotes | Promote after heartbeat timeout + lease expiry + quiesce |
| Network partition (master alive) | Both sides see the other as unreachable | Both promote; two writable masters | The witness lease must expire before takeover; the old holder self-fences |
| Asymmetric connectivity | Candidate reaches the witness but not the master; or the master cannot reach the witness | Heartbeat-only promotion is immediate; the old master still serves writes | Witness reachability is the arbiter; a node that cannot renew fences |
| Master/slave partition, witness reachable by both | The master is alive and keeps the lease; slaves see no frames | Heartbeat-only promotion would create a second master | No promotion; the master remains the only publisher, and `require_slaves` reports not-ready |
| Stale master returns | Old master has a lower term and may have a higher local version | Old master republishes and rolls the cluster back | Term + watermark + version continuity reject it; it must not re-acquire after fencing |
| Two candidates | Two slaves both miss the master | Both promote, possibly in different terms | The witness CAS grants one holder; the loser stays read-only |
| Lease expiry during a pause | The holder is suspended (VM pause, SIGSTOP, starvation) past TTL | On resume it writes while a new holder exists | Self-fence deadline before expiry; pre-publish quiesce; lower-term bundles are rejected even in the residual window |
| Clock skew | Nodes disagree about wall time | A holder believes its lease is valid longer than the witness does | Safety decisions use the witness clock for expiry and the holder's `CLOCK_BOOTTIME` for self-fencing, never cross-node wall clocks |
| In-flight publish | Master published version `V` to some slaves, then died before renewing the lease record | Candidate at `V-1` promotes at `V` with different content | Pre-publish reconciliation aborts if a reachable slave is ahead; an unreachable ahead slave is latched, never overwritten; no rollback |
| v1 node or state | v1 watermark/state or v1 peer | Promotion over an old replay guard | Protocol v2 rejection happens before any promotion logic |

The two-node topology is the hard case: there is no third vote. The design
obtains its tie-break from a dedicated witness process on a third host, not
from the two HA nodes themselves.

## Options considered

### Option 1: Manual promotion only (status quo)

- **Pros:** No new failure modes. The operator can stop/fence the old master
  before raising the term. Already documented and tested.
- **Cons:** Failover takes human time; a crashed master leaves the cluster
  read-only for configuration (DNS reads continue).
- **Why not chosen as the 2.0 design:** The 2.0 plan requires automatic
  promotion. Manual promotion remains supported, but it is no longer the only
  path.

### Option 2: Delegate promotion to an external orchestrator

- **Pros:** keepalived/VRRP, Pacemaker, Kubernetes or a hypervisor already owns
  node liveness and can run a promotion hook; no new in-process consensus.
- **Cons:** VRRP/keepalived can split-brain on a partition unless configured
  with unicast peers and strict timeouts; the orchestrator must also fence the
  old master (STONITH/power-off), not just move a virtual IP. sito cannot verify
  that the external tool did the fencing.
- **Why not chosen as the built-in design:** It remains a supported way to
  trigger/reinforce promotion and to move a stable endpoint, but it does not
  make sito's promotion automatic or safe by itself.

### Option 3: Quorum or full consensus (Raft/Paxos, embedded etcd/Consul)

- **Pros:** Strong leader election and a well-understood safety proof with three
  or more voting nodes.
- **Cons:** Requires an odd quorum and persistent votes; a two-node deployment
  loses write availability when either node fails, which is the deployment this
  project targets. Adds a new consensus system to a DNS server, plus membership,
  snapshots, log storage and upgrade rules.
- **Why rejected:** Disproportionate complexity and a topology mismatch, already
  rejected in ADR-0002. A single witness is not a consensus quorum; it is a
  single linearizable arbiter.

### Option 4: Named external CAS backend (Consul session+KV or etcd lease+txn)

- **Pros:** No new server code; uses a battle-tested linearizable store; can
  run on an existing operational cluster.
- **Cons:** Adds a heavyweight external dependency and its own consensus
  cluster, TLS/auth/ACL configuration, client library and version coupling. The
  common homelab deployment does not run etcd/Consul, so "automatic promotion"
  would require standing up a second distributed system. It also does not solve
  the stable replication endpoint or the signing-key provisioning problem.
- **Why not chosen for 2.0:** It is a valid future backend, but it makes the
  feature less self-contained for the target deployment. The witness is smaller,
  has an exact protocol under our control, and can be shipped with the binary.

### Option 5: Built-in `sito ha lease-server` witness (chosen)

- **Pros:** Self-contained in the same binary; one linearizable arbiter; exact
  CAS/term/revision/expiry semantics under our control; TLS + bearer auth;
  durable single-record state; no new consensus protocol. Works with two HA
  nodes plus a small third host.
- **Cons:** The witness is a single point of **availability** (not safety). If
  it is unreachable, the current master fences after TTL and no new promotion
  occurs until it returns. It requires a third host and certificate/token
  provisioning.
- **Why chosen:** It is the smallest mechanism that satisfies the lease
  contract without inventing consensus, and it ships with 2.0.

### Option 6: Heartbeat-only automatic promotion (rejected)

A candidate promotes after `N` missed heartbeats. This is rejected
unconditionally:

- a partition and a crash are indistinguishable from the candidate's side;
- asymmetric connectivity (candidate cannot reach the master, master still
  reaches slaves) produces two publishers;
- there is no shared arbiter, so the two nodes cannot agree who won;
- heartbeat timing is a liveness signal, not a mutual-exclusion primitive;
- lowering the timeout makes it faster and less safe; raising it only narrows
  the window.

No configuration key enables heartbeat-only promotion.

### Option 7: Plain shared file or NFS/SMB lock (rejected)

`O_CREAT|O_EXCL` can create a record, but it cannot atomically replace an
expired record without a lock; `rename` is atomic per name but is not a
compare-and-swap over content; `flock`/POSIX locks over NFS/SMB depend on
lock-manager recovery and stale attribute caches. Two candidates can both
believe they won an expired record. The old draft's `lease_path` client key is
therefore removed; a shared file is not a safe arbiter.

## Decision

1. **2.0 ships automatic promotion, opt-in and default `false`.**
   `ha.promotion.enabled = false` is the default. With the section absent or
   `enabled = false`, behavior is the current behavior, except that
   `/api/v2/ha/status` reports `promotion.state = "disabled"`; no witness
   connection, promotion thread, new file or readiness gate is created.
2. **The backend is the built-in witness:** `sito ha lease-server`, a single
   linearizable arbiter on a third host, using TLS, a bearer token, a durable
   single-record state file and CAS on `(term, revision, expiry)`.
3. **The existing cluster term is the fencing token.** The witness grants
   `term + 1` on takeover; slaves already reject lower terms and enforce version
   continuity.
4. **A master must hold the lease before accepting mutations or publishing.**
   If the witness is unreachable at startup, the master starts **read-only**
   (DNS serves the last snapshot, API mutations return 409), reports not-ready
   and retries. It does not exit.
5. **A candidate promotes only after master loss, lease acquisition, a
   pre-publish quiesce and version reconciliation.** It never publishes before
   the old holder's maximum self-fence deadline has passed, and it never
   overwrites a slave that is ahead.
6. **Manual promotion remains supported.** With promotion enabled, a manually
   promoted master must acquire the lease; otherwise the operator disables
   promotion cluster-wide first. The runbook must not hand-edit a term above the
   witness.
7. **No consensus system, no heartbeat-only mode and no plain shared-file
   backend.** Consul/etcd are a documented future backend, not 2.0.
8. **C3b implements the feature**, including the witness server, the client
   promotion state machine, the quiesce/reconciliation, the durable fence
   marker, status/metrics/audit and the behavioral test suite.

## Chosen design

### Topology

```text
                 stable replication endpoint (VIP or DNS name)
                 ┌───────────────────────────────────────────┐
                 │                                           │
        ┌────────▼────────┐                       ┌──────────▼────────┐
        │  sito master    │── mTLS WebSocket ────▶│  sito slave        │
        │  (lease holder) │                       │  (candidate)       │
        └────────┬────────┘                       └──────────┬────────┘
                 │  HTTPS + bearer                           │ HTTPS + bearer
                 └──────────────────┬────────────────────────┘
                                    ▼
                         ┌─────────────────────┐
                         │ sito ha lease-server│  third host / witness
                         │ single CAS arbiter  │  (not either HA node)
                         └─────────────────────┘
```

- The witness runs on a **third failure domain** (NAS, router, small VM,
  container on a third host). Running it on either HA node defeats the
  purpose: that node's failure takes the arbiter with it. A test/lab deployment
  may co-locate it, but the runbook must label that as non-HA.
- The witness only needs to be reachable from both HA nodes on one HTTPS port
  (default `8954`). It does not join the DNS data path and stores no
  configuration.
- The stable replication endpoint (a VIP or DNS name that follows the active
  master) is still required for remaining slaves. The witness does **not** move
  it. See "Stable replication endpoint" below.

### Configuration

Proposed exact keys:

```toml
[ha.promotion]
# Opt-in. Default false. When false, the rest of this table is inert.
enabled = false

# Exactly one slave in the cluster is the candidate.
candidate = false

# Stable identifiers. Required when enabled = true.
# cluster_id must match the witness; node_id must be unique per node and
# stable across restarts.
cluster_id = "home-dns"
node_id = "sito-node-a"

# Only "witness" is supported in 2.0.
backend = "witness"

# Lease lifetime and renewal period.
lease_ttl_secs = 30
renew_interval_secs = 10

# Candidate wait before trying the lease. Omit to derive
# max(45, 3 * ha.ping_interval_secs); an explicit value must be >= 3 * ping.
# heartbeat_timeout_secs = 90

# When true, an automatic candidate waits for an operator confirmation before
# acquiring the lease. It never bypasses the lease.
require_manual_confirmation = false

# How long a newly promoted master waits for slaves to report their
# applied term/version before its first publish.
reconcile_window_secs = 10

[ha.promotion.witness]
url = "https://witness.lan:8954"
ca = "/etc/sito/certs/witness-ca.crt"
# server_name = "witness.lan"   # default: the URL host
# fingerprint = "blake3:<64 hex>"  # optional pin in addition to CA
token_file = "/etc/sito/witness.token"  # 0600, one shared cluster token
```

| Key | Type | Default | Validation (when `enabled = true`) | Meaning |
|---|---|---|---|---|
| `enabled` | boolean | `false` | — | Master gate. When false, all promotion bounds are not validated and the feature is inert. |
| `candidate` | boolean | `false` | Requires `server.role = "slave"` | This node may try to acquire the lease after master loss. Exactly one per cluster. |
| `cluster_id` | string | none | Required; 1–64 chars `[A-Za-z0-9._-]`; must match the witness | Prevents cross-cluster lease use. |
| `node_id` | string | none | Required; 1–64 chars `[A-Za-z0-9._-]`; unique per node | Durable node identity; the witness holder is `node_id/boot_uuid`. |
| `backend` | string | `"witness"` | Must be `"witness"`; anything else is `unsupported_lease_backend` even when disabled | Backend selector. |
| `lease_ttl_secs` | integer | `30` | 5–300; ≥ 3 × `renew_interval_secs` | Witness-side lease lifetime. |
| `renew_interval_secs` | integer | `10` | 1–`lease_ttl_secs / 3` | Renewal period. |
| `heartbeat_timeout_secs` | integer | derived `max(45, 3 × ha.ping_interval_secs)` | If set: ≥ 3 × `ha.ping_interval_secs` and ≥ 1; no upper bound | Candidate wait before it may inspect/acquire the lease. |
| `require_manual_confirmation` | boolean | `false` | — | Human-in-the-loop confirmation before acquisition. Not a lease bypass. |
| `reconcile_window_secs` | integer | `10` | 1–60 | Window after quiesce for slaves to report their applied term/version. |
| `witness.url` | string | none | Required; `https://`; host present; no userinfo | Witness base URL. |
| `witness.ca` | string (path) | none | Required; absolute; readable at startup | CA bundle used to verify the witness certificate. |
| `witness.server_name` | string | URL host | Non-empty if set; must match the certificate SAN | TLS server name. |
| `witness.fingerprint` | string | none | `blake3:<64 hex>` if set; matched in addition to CA. Preimage is the DER-encoded witness server certificate | Optional certificate pin. |
| `witness.token_file` | string (path) | none | Required; absolute; mode `0600` at startup | File containing the shared bearer token. |

When `enabled = false`, the promotion field bounds are **not** validated, so an
existing config with `ha.ping_interval_secs = 30` and no promotion keys loads
unchanged. `candidate`, `require_manual_confirmation` and the witness fields
are inert (a `candidate = true` on a master logs a warning, not an error).
`backend` is the exception: its value is validated even when disabled so a typo
or unsupported backend is caught immediately. The derived heartbeat default is
`max(45, 3 × ping)`, so enabling on such a cluster yields `90` without
hand-editing. An explicit `heartbeat_timeout_secs = 45` with `ping = 30` is
rejected with an error naming the key; there is no upper bound, so
`ping > 1200` cannot make the constraint unsatisfiable.

All `[ha.promotion]` keys are startup/restart-only, consistent with the HA
worker configuration; they are not hot-reloaded.

The candidate is a **single designated node**, not an ordered list. An explicit
list would require cluster-wide membership and agreement and is rejected for
2.0. Setting `candidate = true` on more than one node is an operator error that
the witness CAS still serializes; safety holds, but the deployment docs require
exactly one.

### Validation and startup behavior

- `check-config` validates structure, types, ranges and required keys; it does
  **not** contact the witness.
- A structurally invalid config fails startup and `check-config` (for example a
  missing `witness.url`/`token_file`, a bad URL, an unsupported backend,
  `candidate = true` on a master while enabled, or an out-of-range TTL).
- A valid config with an unreachable witness does **not** exit. The process
  starts, DNS listeners start, and the HA role is **read-only** until the lease
  is acquired. The API rejects every mutation with `409 Conflict` and
  `ha_promotion_witness_unavailable`; `/health` is not ready; the status reason
  is explicit. The client retries with backoff. This applies to a master with
  `enabled = true`: it must not accept mutations outside HA while it lacks the
  lease.
- An unreadable `token_file`/`ca`, a TLS verification failure, a 401/403, or a
  `cluster_id` mismatch also produce read-only mode with a specific reason
  (`witness_auth_failed`, `witness_tls_failed`, `witness_cluster_mismatch`),
  never a silent fallback to heartbeat-only or a local file.
- The read-only state is intentional: `/health` is false, but DNS keeps serving.
  Do not configure a supervisor to restart the process solely on that health
  signal, or it will loop while the witness is down. Restart only on process
  exit or an operator action.

### Witness server

The witness is the same `sito` binary (HA feature) run as a separate process:

```bash
sito ha lease-server \
  --listen 0.0.0.0:8954 \
  --cluster-id home-dns \
  --cert /etc/sito/lease/witness.crt \
  --key /etc/sito/lease/witness.key \
  --token-file /etc/sito/lease/witness.token \
  --state-dir /var/lib/sito-lease
```

- `--listen` defaults to `0.0.0.0:8954`.
- `--cluster-id` is required.
- `--cert`/`--key` are required (TLS 1.2+); no plaintext listener. Generate the
  witness server certificate with `sito ha gen-certs --witness --san
  <witness-host>` (C3b extension) or an existing CA; the client `witness.ca` is
  the issuing CA or the self-signed certificate, and `server_name` must match
  its SAN.
- `--token-file` is required and must be mode `0600`; the token is compared in
  constant time. Generate it with a CSPRNG (for example `openssl rand -hex 32`)
  and copy the same value to every node's `witness.token_file`.
- `--state-dir` is required; created `0700`. It contains:
  - `lease.json` (mode `0600`): the current record, or absent when no lease has
    ever been granted;
  - `initialized` (mode `0600`): a sentinel written after the first successful
    grant. If `initialized` exists but `lease.json` is missing or corrupt, the
    witness **refuses to start** (`state_missing`/`state_corrupt`) instead of
    silently resetting the term. A record whose `cluster_id` differs from
    `--cluster-id` is refused as `state_cluster_mismatch`. Restore the backup or
    perform an explicit manual cluster reinitialization.
  - `lease.lock` (mode `0600`): the lifetime advisory lock used to keep the
    offline `lease-admin` tool out while the witness is running.

The witness is a single-process, single-writer server. It holds an exclusive
advisory lock on `state_dir/lease.lock` for its lifetime; the offline
`lease-admin` tool refuses while that lock is held. All operations are
serialized behind one mutex/actor, so CAS is linearizable. The record is written
atomically (temp file, `fsync`, `rename`, directory `fsync`) **before** the
successful response is sent. A crash after the write is recovered from disk; a
crash before the write is a failed request. `--state-dir` must be on local
durable storage, not NFS/SMB; putting the arbiter's state on a network share
reintroduces the stale-lock/partial-write problem the witness exists to avoid.

Rotate the bearer token or witness certificate by updating the witness and every
node together. A mismatch produces read-only mode with an auth/TLS reason; it
never falls back to plaintext or an unauthenticated request.

Record shape:

```json
{
  "schema": 1,
  "cluster_id": "home-dns",
  "holder": "sito-node-a/6f0c2f7a-...",
  "node_id": "sito-node-a",
  "term": 8,
  "revision": 13,
  "version": 128,
  "bundle_hash": "blake3:9f2c...64-hex",
  "acquired_unix_ms": 1760000000000,
  "expires_unix_ms": 1760000030000
}
```

All hash values (`bundle_hash`, `have_bundle_hash`, `published_hash`, and the
witness fingerprint pin) are normalized to 64 lowercase hexadecimal characters.
The `blake3:` prefix is accepted on input and stripped before storage or
comparison, so `blake3:<hex>` and bare `<hex>` are equivalent.

`holder` is `node_id` plus a random per-process boot UUID. The durable
`node_id` identifies the node; the boot UUID distinguishes process
incarnations. A restart is a new holder and cannot renew the previous process's
grant; it must wait for expiry and acquire `term + 1`.

`version` and `bundle_hash` identify the master's **last successfully published
active bundle**: the version and BLAKE3 signed-payload hash of the bundle
persisted to `ha_state.toml` and enqueued to every connected slave after the last
publish. They are a publish baseline, not a delivery guarantee and not a
reservation for the next version. The master renews the witness record after
each successful publish. A candidate must have applied that version with the
same hash before it may promote; a same-version different-hash candidate is a
fork and is ineligible. A master with no active bundle uses `version = 0` and
`bundle_hash = "none"`; its first publish is version 1. `"none"` is invalid for
version > 0.

**Publish baseline vs pending promotion version.** The witness record's
`(version, bundle_hash)` is always the last **published** baseline. A promotion
writes a local `ha_state.toml` at `baseline_version + 1` before publishing; that
is a **pending** version and must never be sent to the witness or used as an
acquisition baseline. The state file carries:

- `publication_state`: `pending` | `publishing` | `published`;
- `published_version` / `published_hash`: the last bundle this node knows was
  published (the prior baseline while pending);
- the pending bundle's own `version` / hash (the active state bundle).

Rules:

- During quiesce and reconciliation the node renews the witness with
  `(published_version, published_hash)`, never the pending version. The witness
  record therefore remains at the last actually published version.
- The first publish uses
  `publish_version = max(baseline_version + 1, pending_version)`; a pending
  version may be reused only if no reachable slave reports a different
  same-version hash (see reconciliation).
- After the first publish succeeds, the node atomically updates
  `publication_state = "published"`, `published_version = publish_version`,
  `published_hash = publish_hash`, then renews the witness with the new
  version/hash. Only then does the witness hold `publish_version`.
- A crash **before** the state write leaves no pending state; the record is the
  baseline.
- A crash after the state write but **before** publish leaves
  `publication_state = "pending"`; the record is still the baseline, and the
  node may reuse `publish_version`.
- A crash during publish leaves `"publishing"`; reconciliation treats a slave
  at `publish_version` with the pending hash as proof the publish succeeded, a
  different hash as a fork, and no slave at it as safe to reuse.
- A crash after publish but before the `"published"` state update is the same
  `"publishing"` case: reconciliation decides, and the node never skips a
  version or lets the witness reserve an unpublished one.

### Witness HTTP API

All `/v1/*` endpoints require `Authorization: Bearer <token>` and
`X-Sito-Cluster: <cluster_id>`, and run over TLS. Requests are JSON,
`Content-Type: application/json`, maximum body 16 KiB. Timeouts: 5 s
read/write. Unknown paths return 404; malformed bodies 400; bad auth 401; a
missing or wrong `X-Sito-Cluster` 403; a CAS mismatch 409 with the current
record; storage failure 500. `witness.url` is `https://host[:port]` with no
path, query or fragment; the client appends `/v1/...`.

| Method and path | Body / result | Semantics |
|---|---|---|
| `GET /healthz` | `200`/`503`, no auth, no detail | Process and state-dir writable. |
| `GET /v1/info` | `{lease_protocol_version: 1, cluster_id, now_unix_ms}` | Compatibility and clock hint. |
| `GET /v1/lease` | `200` record or `204` | Current record, including an expired one. |
| `POST /v1/lease/acquire` | `{holder, node_id, expected_term, expected_revision, term, version, bundle_hash, ttl_secs}` | `holder` must be `node_id/<uuid>`. Succeeds iff the record is absent with `expected_* = null`, or the record matches `(expected_term, expected_revision)` and is expired. Requires `term == current.term + 1` (or `term == 1` when absent); `version > current.version` (bounded by `current.version + 1_000_000`, the existing peer-lead limit), or `version == current.version` with the same `bundle_hash`; and a valid BLAKE3 hash, or `"none"` exactly when `version == 0`; and `5 <= ttl_secs <= 300`. On success: new holder, term, `revision + 1`, expiry = witness now + TTL. |
| `POST /v1/lease/renew` | `{holder, term, expected_revision, version, bundle_hash, ttl_secs}` | Succeeds iff the record is held by `holder` at `term` with `expected_revision` and is not expired. Requires the same version/hash and `ttl_secs` bounds as acquire. On success: same term, `revision + 1`, new expiry. |

There is no release endpoint in 2.0. A graceful master shutdown leaves the
lease until expiry; a candidate waits. This avoids a stale process resuming
after a release and is simpler to reason about.

The witness uses its own system clock for `now_unix_ms` and expiry; clients
never compare the record's `expires_unix_ms` with their own wall clock for
safety. The witness should run NTP. If its clock steps forward, a lease expires
early; the holder's local self-fence and the pre-publish quiesce still bound the
handover. If it steps backward, a lease lasts longer; the holder's local
deadline fences it and no takeover occurs. Cross-node wall-clock agreement is
not required.

### Client startup and roles

- **`enabled = false`:** no witness client, no thread, no new file, no new
  readiness gate. `/ha/status` reports `promotion.state = "disabled"`.
- **`enabled = true`, `role = "master"`:**
  1. If `data_dir/ha_fence.json` exists and is not reconciled, start read-only
     with `ha_fenced_until_reconciled`; do not acquire.
  2. Otherwise read `GET /v1/lease` and establish the local published
     baseline **before** comparing it:
     1. `state_term > record.term` → `master_term_ahead` (the witness is
        behind the state; manual witness reconciliation is required).
     2. If `publication_state` is `pending` or `publishing` and the state
        bundle's `(version, hash)` equals the witness record, the publish
        succeeded: mark it published (`published_version/hash` = the bundle)
        and continue.
     3. A state written by an older binary without
        `publication_state`/`published_*` is **unknown**: infer published only
        when the state bundle's `(version, hash)` equals the witness record;
        otherwise start read-only and reconcile.
     4. Compare the established `state.published_version`/`published_hash` with
        the record: below `record.version` is `master_state_behind`; equal with
        a different hash is `master_state_forked`. The pending bundle version
        is **not** used for these comparisons.
     5. If the published state is equal (same hash) or newer (a publish the
        witness has not recorded yet) at a term not above `record.term`, call
        `POST /v1/lease/acquire` with `version = state.published_version` and
        `bundle_hash = state.published_hash`.
     In any other case do not acquire; the operator must restore, resync or
     reconcile the correct bundle.
  3. On success, write the promoted state
     (`promotion_origin = "restart"`, `publication_state = "pending"` or the
     preserved `"publishing"` when reusing that state's pending version,
     `published_version`/`published_hash` from the acquire baseline), then
     quiesce, reconcile and publish at
     `publish_version = max(baseline_version + 1, pending_version)` (see
     below). Only after the first successful publish is the API writable.
  4. On witness/TLS/auth failure, start read-only, serve DNS from the last
     snapshot, reject mutations, report not-ready with the specific reason, and
     retry with backoff.
- **`enabled = true`, `role = "slave"`:** normal slave behavior. If it is the
  candidate, it waits for master loss. A fence marker prevents candidacy.
- A master with `enabled = true` never accepts a mutation while it lacks a
  valid lease, including during startup, witness outage, quiesce,
  reconciliation or after fencing.

### Acquisition state machine

A candidate runs this only after all eligibility gates pass.

1. Wait until no master frame has arrived for the effective
   `heartbeat_timeout_secs`. This is a liveness wait, not the safety decision.
2. `GET /v1/lease`.
   - Held by this `holder` and not expired: treat as an existing grant and go
     to renewal.
   - Held by another live holder: stay `waiting`; retry after
     `renew_interval_secs` with jitter. Never steal a live lease.
   - Absent and `max(applied_term, state_term) > 0`: refuse
     (`lease_record_missing`) **before any acquire**. A normal slave has
     `state_term = 0` but a non-zero watermark term; losing the witness record
     must not reset the cluster to term 1. Recovery is manual (restore the
     witness state or perform an explicit reinitialization).
   - If the record exists and `max(applied_term, state_term) > current.term`:
     abort `candidate_term_ahead` **before any acquire**. The witness cannot
     reject a term above its record when the record is absent, so this check is
     client-side and mandatory. A term above the witness requires manual
     witness reconciliation, never a silent jump.
   - Absent with `max(applied_term, state_term) == 0`, or expired, or
     term-reset rules allow:
     compute:
     - `next_term = current.term + 1` (or `1` if absent)
     - If `publication_state` is `pending` or `publishing` and the state
       bundle's `(version, hash)` equals the witness record, infer that the
       publish succeeded: use the bundle as `state.published_version`/
       `published_hash` for this computation (mark it published after
       re-acquisition).
     - `node_published_version = max(applied_version,
       state.published_version)` — the pending state bundle version is **not**
       part of this max unless the publishing inference above matched
     - `node_published_hash` = the hash at that version (the applied watermark
       hash, or `state.published_hash`)
     - if `node_published_version < current.version`: abort
       `candidate_behind`; the node lacks the witness's last published content
       and must not adopt a version/hash it does not have
     - if `node_published_version == current.version` and
       `node_published_hash != current.bundle_hash`: abort `candidate_forked`;
       the same version with different content is a fork
     - if `node_published_version > current.version`: the node has newer
       published content (a publish the witness has not recorded yet); this is
       allowed, and the witness acquire accepts the higher version
     - `baseline_version = node_published_version`;
       `baseline_hash = node_published_hash`
     - `pending_version` = the local state bundle version when
       `publication_state` is `pending` or `publishing`; otherwise `0`
     - `publish_version = max(baseline_version + 1, pending_version)`

     Then call `POST /v1/lease/acquire` with the observed
     `(expected_term, expected_revision)` (both `null` if absent), `term =
     next_term`, `version = baseline_version` (**the published baseline, never
     the pending version, and never a witness version the node does not have**),
     `bundle_hash = baseline_hash`, and `ttl_secs = lease_ttl_secs`.
3. On a 409, another node won or the record changed. Re-read; do not retry the
   same term/revision. Back off with jitter. The loser stays read-only.
4. On success, the candidate holds term `T`.
5. Write the promoted state to `ha_state.toml` atomically:
   the bundle (`term = T`, `version = publish_version`),
   `publication_state = "pending"` (or preserve a prior `"publishing"` when
   re-acquiring that state and reusing the same `publish_version`),
   `published_version = baseline_version`,
   `published_hash = baseline_hash`,
   the pending bundle hash, the candidate's last applied content, and audit
   fields (`promotion_origin = "automatic"`, `lease_holder`, `cluster_id`,
   `promoted_at_unix_ms`). The pending version is local only; the witness
   record still holds `baseline_version`/`baseline_hash`. If this write fails,
   do not publish; stop renewing and fence.
   - A crash **before** the state write leaves no pending state. The lease
     expires; a restarted candidate is a new holder. It re-reads the record
     (term `T`, published version `baseline`), still satisfies the version
     gate, and may re-acquire at the next term; it never publishes at `T`.
   - A crash **after** the state write but **before** publish leaves
     `publication_state = "pending"`. The record is still the baseline. On
     restart the node is a new holder: it waits for expiry, re-acquires at the
     next term against the published baseline, and may **reuse
     `publish_version`**; it does not skip to `baseline + 2`.
   - A crash **during** publish leaves `publication_state = "publishing"`
     (set immediately before the first push). On restart, after re-acquiring,
     reconciliation (step 7) decides: a reachable slave at `publish_version`
     with the pending hash means the publish succeeded; a different hash is a
     fork; no slave at it means the version is safe to reuse.
6. **Pre-publish quiesce:** wait `lease_ttl_secs` (not separately configurable
   in 2.0) without accepting writes or publishing. Continue renewing the witness
   with `(baseline_version, baseline_hash)` — the **published baseline**, never
   the pending version. This is longer than the old holder's maximum self-fence
   deadline under the stated model, so any old holder has stopped publishing
   before the new master's first publish.
7. **Hello-only reconciliation:** start the replication listener in a
   hello-only mode that accepts TLS/WebSocket, reads `Hello` and answers
   ping/pong, but **does not install an active push and does not send any
   `ConfigPush`** while the window is open. This is required because the normal
   master session enqueues the active bundle on every Hello
   (`session_state.rs`); without the gate, a forked baseline slave could apply
   `publish_version` before the checks below. Wait up to
   `reconcile_window_secs` for hellos and collect
   `have_term`/`have_version`/`have_bundle_hash`.
   - For each reachable slave, compare against **both** the witness record
     `(current.version, current.bundle_hash)` and the publish baseline
     `(baseline_version, baseline_hash)`. A same-version hash mismatch at either
     published baseline aborts (`cluster_forked`). This catches a slave forked
     at the witness's older version even when the baseline was raised by the
     node's own published state. A `0`/`"none"` baseline is not a published
     bundle and is not hash-compared; a slave at version 0 simply applies the
     first publish.
   - If any reachable slave reports `have_term > T` or `have_version >
     publish_version`, abort (`candidate_behind`). A slave at
     `publish_version` is allowed only when `publication_state = "publishing"`
     and its hash equals the pending hash (proof the prior publish succeeded);
     any other `publish_version` report is an in-flight/forked bundle and
     aborts. A reachable slave with `have_version > baseline_version` that is
     not that allowed `publish_version` case is an unknown in-flight version;
     abort (`candidate_behind`) rather than overwrite it.
   - If a reachable slave at a compared published baseline or at
     `publish_version` omits `have_bundle_hash` (an old v2 peer), abort
     (`candidate_hash_unknown`) rather than risk overwriting a fork.
     Promotion-enabled clusters must run a peer build that reports it.
   - If no slave is ahead, forked or unknown, atomically set
     `publication_state = "publishing"` (keeping `published_version`/`hash`)
     **before** the first push; if that write fails, do not publish. Publish the
     first bundle at `(T, publish_version)`, then atomically set
     `publication_state = "published"`, `published_version = publish_version`,
     `published_hash = publish_hash` in `ha_state.toml`; only then renew the
     witness with `(publish_version, publish_hash)`. The witness never holds an
     unpublished version. If the `"published"` state write fails, do not renew
     the witness; stay read-only. On restart, reconciliation can prove the
     publish from a slave at `publish_version`/pending hash (or the witness
     record can, if a later renewal succeeded before the failure).
   - A slave that reports ahead **after** the window is latched/diverged; the
     master keeps publishing to healthy slaves but never overwrites the ahead
     slave. The operator resolves the fork manually.
   - If reconciliation aborts, disconnect the hello-only listener, do not
     install an active push, stay read-only, and let the lease expire.
8. After the first successful publish and the `"published"` state update, the
   node is writable and renews every `renew_interval_secs` with the published
   version/hash.

**Role persistence.** Automatic promotion changes the **effective role** in
memory; it does not rewrite `server.role` in `config.toml`. Acquiring stops the
slave worker and starts the master listener; the node never runs both roles at
once. The promoted term/version and `promotion_origin` live in
`ha_state.toml`. On restart, a node
whose config still says `role = "slave"` starts as a candidate and only becomes
master after re-acquiring the lease; it never starts writable just because
`ha_state.toml` says it was promoted. A node whose config says
`role = "master"` must acquire the lease before writes. The runbook recommends
persisting the new role (edit `config.toml`, set `candidate = false`, restart)
for auditability.

**Master restart with promotion enabled.** A master has `ha_state.toml` rather
than a watermark. It uses `state_term`, `state.published_version` and
`state.published_hash` as its baseline: `next_term = current.term + 1`;
after confirming `state.published_version` is not below `current.version`,
`baseline_version = state.published_version` and
`publish_version = max(baseline_version + 1, pending_version)`. A pending state
bundle version is not a published baseline. A state term above the witness
record is refused as `master_term_ahead`; a published version below the witness
record or an equal published version with a different hash is refused as
`master_state_behind`/`master_state_forked`. The master must not overwrite
newer or forked content, and must not silently lower a term. Because a restart
is a new holder and
a new term must continue above the applied version, the master publishes a new
version even when the configuration did not change. This is a deliberate
safety trade-off: a restarted process never inherits an unexpired lease or
reuses a term. A master restart also quiesces (`lease_ttl_secs`) and reconciles
before its first publish; DNS reads continue, but configuration writes are
unavailable until it is writable. If the previous process still holds an
unexpired lease, the restart waits for expiry as well. With the defaults, a
master restart can be read-only for roughly TTL + quiesce + reconcile (up to
~70 s), and a promotion after master loss adds the heartbeat timeout (up to
~115 s total). Operators who cannot accept this latency, or the extra version
bump on every restart, should leave promotion disabled or tune
`ping_interval_secs`/`lease_ttl_secs`.

### Renewal, conflicts and self-fencing

- Renewal is `POST /v1/lease/renew` with the observed `(term, revision)`:
  the holder re-asserts its identity, updates `version`/`bundle_hash` and
  expiry, and leaves the term unchanged. The witness increments `revision`.
  Renewal compares against the node's **published baseline**
  (`published_version`, `published_hash`), never the pending version.
- **A 409 is not automatically "lease lost".** Re-read the record:
  - still this holder at the same term and not expired, with the witness
    `(version, bundle_hash)` exactly equal to our published baseline: adopt the
    new revision (for example a lost renewal ACK) and continue;
  - still this holder at the same term, not expired, with the witness version
    **below** our published baseline: adopt the revision and retry with our
    higher published version/hash (the witness accepts a non-decreasing
    version);
  - still this holder at the same term, not expired, but the witness version is
    **above** our published baseline, or the version is equal and the
    `bundle_hash` differs: fence with `lease_version_regression` (the journal
    names version vs hash); never renew or publish below or beside the witness
    baseline;
  - still this holder but expired: fence (the self-fence deadline should have
    fired first);
  - foreign holder or higher term: fence immediately;
  - absent: fence and report `lease_record_missing`.
- **Network/TLS/5xx errors** are retried with backoff until the self-fence
  deadline; fence only then. A 401/403 is a configuration/auth failure and
  fences immediately because no safe renewal is possible.
- Self-fence at `lease_ttl_secs - max(2, renew_interval_secs)`, measured with
  `CLOCK_BOOTTIME` from the last successful ACK. With the defaults (TTL 30,
  renew 10) the deadline is 20 s, one renewal interval before the witness
  expires the record at 30 s.
- Elapsed time never uses wall time. A detected wall-clock step larger than the
  TTL, an unavailable boot clock, or a boot-id change fences instead of
  extending the lease.
- On fencing, in this order:
  1. persist `data_dir/ha_fence.json` atomically (see below);
  2. stop publishing and close replication sessions with a `fenced` reason;
  3. reject every mutating API request with `409 Conflict` and
     `ha_promotion_fenced`;
  4. keep DNS serving from the last applied snapshot, read-only;
  5. keep `ha_state.toml` and the watermark intact (never delete the replay
     guard);
  6. report `ready: false` with `readiness_reason = ha_promotion_fenced` (or
     `ha_promotion_lease_lost`);
  7. do not re-acquire automatically, including across restarts, until the
     operator clears the fence.

### Durable fence marker

`data_dir/ha_fence.json` (mode `0600`, atomic write) records:

```json
{
  "protocol_version": 2,
  "cluster_id": "home-dns",
  "node_id": "sito-node-a",
  "fenced_term": 8,
  "reason": "lease_lost",
  "fenced_at_unix_ms": 1760000000000,
  "reconciled": false
}
```

- The marker is written **before** the node stops accepting writes. The fence
  transition first writes `ha_fence.pending` atomically, then
  `ha_fence.json`. If the final marker write fails but `pending` succeeded, the
  node is still durably fenced on restart. If **both** writes fail, the process
  becomes read-only, logs a critical error and exits non-zero; no durable fence
  distinction exists. Startup then runs a data-dir writable/parse integrity
  check: an unhealthy dir refuses; if the dir is later repaired with no marker,
  the node may acquire a **new** term only after the witness confirms no newer
  holder. The witness term remains the safety backstop, and this is the one
  residual where the no-reacquire policy cannot be recorded.
- On startup, either an unreconciled `ha_fence.json` or `ha_fence.pending`
  makes the node read-only regardless of role or lease availability
  (`ha_fenced_until_reconciled`). It does not acquire the lease and does not
  become a candidate.
- `sito ha clear-fence --confirm` removes both markers after the operator has
  verified the current master/term. It is a local CLI action; it does not grant
  a lease.
- A marker from a different `cluster_id`/`node_id` is a data-dir mix-up: refuse
  to start until resolved.

This makes "a fenced old master never re-acquires automatically" survive a
restart. A crash **before** the marker write is a narrower residual: the
process is gone and the witness record still belongs to it until expiry; a
restart is a new holder and cannot renew it, so it must wait for expiry and
acquire a new term. That is a fresh legitimate grant, not a resumption of the
fenced term.

### Candidate eligibility and identity

A candidate is eligible only if:

- it is a slave running the `ha` feature and protocol v2;
- `enabled = true`, `candidate = true`, and no unreconciled fence marker;
- its watermark is valid and it has applied the master's current published
  configuration (not merely any old bundle);
- it is not degraded, diverged, or fork-latched;
- it has no pending restart-required configuration mismatch;
- it has no stale **foreign** `ha_state.toml` ahead of the watermark. A state
  file written by this node's own in-progress automatic promotion is allowed:
  its `published_version` participates in the baseline, while its pending
  version only participates in `publish_version`. A foreign or unmarked stale
  state must be reconciled first;
- it can reach the witness, pass TLS/auth, and match `cluster_id`.

A candidate behind the witness record refuses (`candidate_behind`). If the
missing bundle existed only on the dead master, the witness cannot recover it;
the supported path is manual promotion with an operator-chosen state (the
candidate's last applied content), never a fabricated version.

**Identity and key prerequisites.** A promoted node must sign bundles and
terminate mTLS as the master identity. The candidate also needs:

- a local Ed25519 signing key whose public key matches every slave's
  `master_pubkey` and the `signing_key_pubkey` persisted in `ha_state.toml`;
- a master mTLS certificate/key that every slave pins (or a CA they trust),
  with a SAN matching the stable endpoint;
- the master-side listener material (`pinned_slave_fingerprints` or `ca`,
  `slave_token` where configured).

This is a pre-provisioning decision; promotion cannot invent the identity.
Copying the master private key to the candidate increases key exposure; per-node
signing keys would require a trust-bundle/protocol change (out of scope). The
manual procedure copies the key/cert as an explicit operator step. Automatic
promotion refuses when the identity is missing or mismatched
(`candidate_identity_mismatch`) instead of publishing bundles every slave will
reject.

### Stable replication endpoint

Remaining slaves keep their `master_url`. Automatic promotion changes the
writable master, not that URL. Therefore:

- every slave's `master_url` must reference a **stable VIP or DNS name that
  follows the active master**, not the old master node's own address;
- the promoted node must be reachable at that endpoint (the VIP/DNS move is
  external: keepalived, DHCP, DNS, or manual);
- the promoted node's certificate SAN must cover the endpoint;
- if the endpoint does not move, promotion still makes the node the writable
  master, but remaining slaves cannot replicate. `require_slaves` reports
  not-ready and the operator must re-point them.

The witness does not move the endpoint. When promotion is enabled and a
slave's `master_url` uses an IP literal, startup logs
`ha_promotion_endpoint_is_ip_literal` as a warning so the operator confirms it
is a VIP and not the old node's address. A DNS name is the clearest form.

### Interaction with `require_slaves` / `require_all_slaves`

These keys gate **master readiness**, not election safety or eligibility.
Automatic promotion does not reinterpret or bypass them:

- With `require_slaves = true`, a promoted master with no connected slaves
  reports not-ready (`HA requires at least one synced slave (0/N connected)`)
  while still serving DNS and accepting configuration writes.
- With `require_all_slaves = true`, a two-node cluster whose peer is gone (or
  fenced and not re-enrolled) reports not-ready until a slave connects and
  syncs; zero connected slaves fails the policy. DNS still serves.
- In the common two-node topology, combining automatic promotion with a strict
  slave requirement means the promoted node may not report ready until the old
  peer is re-enrolled. The ADR recommends leaving both `false` when
  `[ha.promotion]` is enabled, or accepting the not-ready state and documenting
  it in the runbook.
- `require_slaves` never makes a slave a candidate, and a candidate never
  promotes merely because `require_slaves` is unmet on the old master.

### Interaction with term, watermark, divergence and v1 rules

- **Term is the fencing token.** A promotion sets `term` from the witness CAS
  (`term + 1`), never from a peer message. A stale holder's lower term is
  rejected by every slave even when its local version is higher.
- **Both term and version rise.** `node_published_version =
  max(applied_version, state.published_version)`; it must be at least the
  witness record's version with the same hash at equality, or the candidate
  aborts. The first publish version is
  `max(node_published_version + 1, pending_version)`, strictly above the
  candidate's published baseline. The pending state version is never a witness
  baseline. A term bump alone is not accepted.
- **Watermarks are the rollback guard.** A promoted bundle below a slave's
  watermark is rejected. A candidate behind the witness record refuses. A
  reachable slave ahead of the baseline aborts the promotion; a late ahead
  slave is latched, never overwritten.
- **Divergence stays sticky.** A stranded or forked slave is not repaired by
  promotion; it keeps its watermark and requires manual reconciliation.
  Automatic promotion never clears a fork latch and never injects a peer
  counter.
- **v1 is rejected before promotion.** A v1 `ha_watermark.toml`/`ha_state.toml`
  or a v1 peer fails startup/negotiation; promotion logic never runs.
- **A fenced old master does not reset its term.** It keeps its state file and
  durable fence marker and waits for an operator.

### Manual promotion, override and confirmation

The manual runbook (§2) remains the operator escape hatch:

1. If `[ha.promotion]` is enabled anywhere, the manually promoted master must
   acquire the lease before accepting writes. The supported way is to start it
   with `role = "master"` and `enabled = true`: it acquires `term + 1`,
   quiesces, reconciles and publishes. Do **not** hand-edit a term above the
   witness; the witness will reject it (`candidate_term_ahead`/`term_mismatch`)
   and the correct action is manual witness reconciliation.
2. The manual local baseline is
   `max(applied_version, state.published_version)`, and the publish version is
   `max(baseline + 1, pending_version)`. A pending state version is not a
   baseline. Refuse to promote if the local baseline is below the witness
   record's version or matches it with a different hash. Any reachable peer
   ahead of the local baseline, or at the same version with a different hash, is
   a rejection condition to resolve first; a peer version is not a content
   source the node can publish. If a peer is ahead and unreachable, the
   operator must resolve the fork before promoting; never lower a peer's
   watermark. The master-startup formula omits `applied_version` because a
   master has no watermark and reconciles peers; both formulas use the same
   local published-baseline rule.
3. If the witness record is behind the cluster after a restore or an earlier
   operator bypass, stop the witness, back up `state_dir`, and use the offline
   `sito ha lease-admin set --state-dir <dir> --term <T> --version <V>
   --bundle-hash <hash> --confirm` tool (C3b) to raise the record above the
   cluster high-water mark with the correct content hash. The tool refuses to
   run while the witness process holds the state lock. Never hand-edit
   `ha_state.toml` above the witness.
4. Alternatively, disable `[ha.promotion]` on every node first and use the old
   term/version editing procedure. A manually promoted master that does not
   hold the lease while promotion remains enabled is an operator bypass:
   term/watermark rules still prevent a rollback on each individual slave, but
   two disjoint partitions can end up with different configuration histories.

`require_manual_confirmation = true` is the human-in-the-loop option. It uses a
**local confirmation**, not a mutating HTTP endpoint on a read-only slave:

- `sito ha confirm-promotion --confirm` runs on the candidate as the runtime
  user/root and atomically writes `data_dir/ha_promote.confirm` (mode `0600`)
  with `{protocol_version, cluster_id, node_id, requested_at_unix_ms, nonce}`.
- The running candidate consumes the file only after master loss, verifies
  `cluster_id`/`node_id`, requires the file to be no older than the effective
  `heartbeat_timeout_secs`, then removes it and authorizes **one** acquisition.
  The file is discarded if the master returns first; a restart discards an
  unconsumed file.
- A confirmation while the master is alive or the lease is held by another node
  is refused (`master_alive` / `lease_held_by_other`); the candidate simply
  does not acquire.
- No confirmation can bypass the witness. A forced promotion without a lease is
  the manual procedure with the old master stopped, not an automatic mode.
- This keeps the slave read-only API surface unchanged. If a future release
  adds an Admin API confirmation, it must be an explicit, narrowly scoped
  exception that still cannot perform any other mutation.

### Observability

`GET /api/v2/ha/status` gains a `promotion` object:

```json
{
  "promotion": {
    "enabled": true,
    "candidate": false,
    "backend": "witness",
    "cluster_id": "home-dns",
    "node_id": "sito-node-a",
    "state": "master",
    "reason": null,
    "term": 8,
    "version": 128,
    "bundle_hash": "9f2c...64-hex",
    "publication_state": "published",
    "published_version": 128,
    "lease_revision": 13,
    "lease_expires_in_secs": 22,
    "witness_reachable": true,
    "quiesce_remaining_secs": 0,
    "reconcile_remaining_secs": 0,
    "last_attempt_unix_ms": 1760000000000,
    "promoted_at_unix_ms": 1760000000000,
    "fenced": false
  }
}
```

- `state`: `disabled` | `waiting_for_master_loss` |
  `manual_confirmation_required` | `acquiring` | `quiescing` | `reconciling` |
  `publishing` | `master` | `fenced` | `aborted` | `unavailable`.
- `reason` (stable codes): `promotion_disabled`, `not_candidate`,
  `master_alive`, `lease_held_by_other`, `witness_unavailable`,
  `witness_auth_failed`, `witness_tls_failed`, `witness_cluster_mismatch`,
  `witness_protocol_mismatch`, `lease_record_missing`, `candidate_behind`,
  `candidate_forked`, `candidate_hash_unknown`, `cluster_forked`,
  `candidate_diverged`, `candidate_term_ahead`,
  `candidate_identity_mismatch`, `master_state_behind`, `master_state_forked`,
  `master_term_ahead`, `manual_confirmation_required`, `lease_lost`,
  `lease_version_regression`,
  `fenced`, `fenced_until_reconciled`, `v1_state`, `promotion_interrupted`,
  `endpoint_is_ip_literal`, `clock_step`, `state_write_failed`,
  `role_switch_failed`.
- `version`/`bundle_hash` describe the **active** bundle (which may be pending
  during a promotion); `publication_state`/`published_version` show whether
  that active bundle is pending, publishing or published. The published baseline
  is used for reconciliation and the offline witness recovery tool.
- `witness_reachable` is a last-probe boolean, not a safety input.
- The existing top-level `ready`/`readiness_reason` remain authoritative for
  health. Witness-unavailable and fencing conditions make the node not-ready;
  merely being a candidate or waiting does not.

Proposed Prometheus metrics:

- `sito_ha_promotion_enabled` (gauge 0/1)
- `sito_ha_promotion_lease_held` (gauge 0/1)
- `sito_ha_promotion_term` (gauge)
- `sito_ha_promotion_attempts_total{result}`
- `sito_ha_promotion_witness_requests_total{op,result}`
- `sito_ha_promotion_lease_renew_failures_total`
- `sito_ha_promotion_fenced_total{reason}`
- `sito_ha_promotion_refusals_total{reason}`
- `sito_ha_promotion_publish_aborts_total{reason}`
- `sito_ha_promotion_quiesce_remaining_seconds` (gauge)
- `sito_ha_promotion_reconcile_remaining_seconds` (gauge)
- `sito_ha_promotion_last_success_timestamp_seconds` (observability only)

Audit events are structured `tracing` records (node id, outcome, reason, term,
version, holder; never tokens, keys or certificate material):

- `ha.promotion.lease_acquired`
- `ha.promotion.lease_renewed`
- `ha.promotion.lease_lost`
- `ha.promotion.fenced`
- `ha.promotion.refused`
- `ha.promotion.quiesced`
- `ha.promotion.reconciled`
- `ha.promotion.completed`
- `ha.promotion.publish_aborted`
- `ha.promotion.manual_confirmation_required` / `_confirmed`

### Protocol impact

One **additive optional** field: `Hello` gains
`have_bundle_hash: Option<String>`, the slave's applied signed-payload hash
(already stored in `ha_watermark.toml`). It is `#[serde(default)]`; older v2
peers omit it and normal replication is unaffected. A promotion-enabled master
requires it at the baseline during reconciliation and aborts
(`candidate_hash_unknown`) rather than overwrite a possible fork. There is no
`PROTOCOL_VERSION` bump and no new push message. The signed bundle already
carries `term` and `version`, and slaves already enforce term monotonicity plus
version continuity.

The promotion bookkeeping in `ha_state.toml` (`publication_state`,
`published_version`, `published_hash`, and the optional audit fields) is
node-local and additive; older readers ignore it, and a downgrade that rewrites
the file loses the marker but keeps the v2 bundle's `term`/`version`. The
mandatory promotion state (the bundle's `term` and `version`) already exists in
the v2 shape. `ha_fence.json`, `ha_fence.pending` and `ha_promote.confirm` are new
node-local files owned by this feature.

## Safety argument

### Definitions

- A **lease holder** is the node named in the current witness record at term
  `T`.
- A **publisher** is a node that is signing/publishing bundles. A correct node
  publishes only while it believes it holds the lease.
- A **writable master** is a publisher that accepts mutations; replication may
  be temporarily absent (for example, in a two-node cluster after the peer
  fails).
- A **stale bundle** is a bundle from a term lower than the current witness
  term.

### Invariants

**I1 — One lease holder per term.** The witness is a single process with one
mutex/actor and a durable atomic write before response. `acquire` succeeds only
for the next term on an expired/absent record with the expected revision;
`renew` succeeds only for the current holder at the current term and revision
while not expired. Therefore at most one node holds term `T`.

**I2 — Only a lease holder can raise the term.** A node raises its term only
after a successful `acquire` (`term + 1`). Slaves reject a bundle whose term is
lower than the term they applied; a new term is accepted only when it is
strictly higher and the version continues above the watermark. A stale holder's
bundles cannot become the newest accepted term.

**I3 — The new publisher waits past the old holder's fence deadline.** The
witness grants a takeover only after the old record expires. The old holder
self-fences at `last_ack + TTL - margin`, before expiry. The new holder waits an
additional `lease_ttl_secs` (quiesce) after acquisition before its first
publish. Under the stated model (the witness clock does not jump forward by more
than the TTL, and `CLOCK_BOOTTIME` advances through pauses), the old holder has
stopped publishing before the new first publish. During that window the old
holder may have already published (or may still publish) `T` bundles to slaves
that have not seen `T+1`; those bundles are a handover artifact, not a second
current-term publisher. The new holder is silent during the window: the
listener is hello-only and sends no `ConfigPush` until reconciliation
completes, and reconciliation prevents overwriting content it lacks, including
a slave that accepted an old baseline before the window closed. This bounds the
pre-publish window the heartbeat-only design leaves fully open; the residual
unbounded-pause case is listed below.

**I4 — No content rollback.** `node_published_version = max(applied_version,
state.published_version)`. It must be at least the witness record's version,
and equal versions must have the same hash; otherwise the candidate aborts
(`candidate_behind`/`candidate_forked`). `publish_version =
max(node_published_version + 1, pending_version)`. A reachable slave ahead of
`publish_version`, at a same version with a different signed-payload hash at
either the witness record or the local published baseline, or unexpectedly at
`publish_version`, aborts the promotion before publishing; a late ahead slave
is latched and never overwritten. The master never raises its version
above content it does not have merely to beat a slave. Therefore a slave's
applied version can increase, but its newer content is not replaced by older
content; divergence is surfaced, not silently merged.

**I5 — The holder stops before the witness can grant its term elsewhere.** The
self-fence deadline is `TTL - max(2, renew_interval)`, earlier than witness
expiry under ordinary clock behavior. A holder that cannot renew stops
publishing, stops accepting mutations, and keeps DNS read-only. If the witness
clock expires the record early, the pre-publish quiesce still covers the old
holder's local deadline; if the old holder is unboundedly paused, the residual
in "What this design does not protect against" applies.

**I6 — Safety does not use cross-node wall clocks.** Expiry is decided by the
witness; self-fencing uses `CLOCK_BOOTTIME`. Wall-clock steps force a fence
rather than extending a lease.

### Failure walkthrough

- **Master crash:** the lease expires; the candidate wins the CAS at `T+1`,
  quiesces, reconciles and publishes. The old process is gone.
- **Partition:** the old master cannot renew. It fences at `TTL - margin`; the
  witness grants only after expiry; the candidate waits quiesce before its
  first publish. The old master's late bundles carry `T` and are rejected by
  slaves that have seen `T+1`.
- **Asymmetric connectivity:** the side that can reach the witness wins; the
  side that cannot renews nothing and fences. Witness reachability, not
  heartbeat delivery, is the arbiter. If both can reach the witness, the live
  holder keeps the lease and no promotion occurs.
- **Master/slave partition with a reachable witness:** the master keeps the
  lease and remains the only publisher; slaves serve their last applied
  configuration. `require_slaves` reports not-ready. No automatic promotion.
- **Two candidates:** the CAS linearizes them. One gets `T+1`; the other gets a
  409, re-reads and stays read-only. The loser cannot reuse `T+1`.
- **Stale master returns:** it holds `T`; the cluster applied `T+1`. Its
  bundles fail the term check before version comparison. It cannot renew a
  record owned by `T+1`. A durable fence marker prevents it from re-acquiring
  after a restart.
- **Pause past expiry:** on resume, the lease-guarded write path re-reads the
  witness and fences. A local mutation accepted in the residual window can only
  be published under the old term `T`; slaves that have seen `T+1` reject it,
  and a slave that sees it before `T+1` is caught by reconciliation or by the
  same-version fork latch. With quiesce, the new publisher does not overlap the
  old holder's publish interval under the bounded-pause model.
- **Clock skew:** witness expiry and holder monotonic deadlines are independent
  of cross-node wall time. A wall-clock jump fences rather than extends. If the
  witness expires early, quiesce covers the old holder's deadline; if it
  expires late, the holder fences first and no takeover occurs.
- **Crash during promotion:** state is written atomically after the CAS and
  before publishing. A restart is a new holder and must re-acquire; it never
  publishes at `T` without a live grant. A crash after the state write leaves a
  promotion-in-progress marker and publishes at a higher version.
- **In-flight publish:** the old master published `V` to some slaves before
  dying. If the candidate is at `V-1` and the witness record is `V-1`, it
  reaches reconciliation with baseline `V-1`. A reachable slave at `V` makes the
  promotion abort (`candidate_behind`); an unreachable slave at `V` latches a
  fork on later contact. If the candidate is behind the witness record, it
  refuses. No rollback; manual reconciliation may be required.
- **v1 state:** rejected before promotion logic runs.

### What this design does not protect against

- **Unbounded process pause or a witness clock anomaly beyond the model.** If a
  process is suspended in a way that does not advance `CLOCK_BOOTTIME` and
  resumes between its last lease check and a network write, it may publish a
  stale `T` bundle to slaves that have not seen `T+1`. The pre-publish quiesce
  bounds the ordinary case; eliminating the residual requires external fencing
  (STONITH, power-off, or a storage layer that rejects non-holder writes).
- **Witness data loss or corruption.** `lease.json` is the term history. A lost
  record with a client `max(applied_term, state_term) > 0` refuses
  `lease_record_missing`; the
  witness itself refuses to start if `initialized` exists but the record is
  missing. Recovery is a restore or an explicit manual cluster
  reinitialization, never a silent term reset.
- **Witness compromise or token theft.** A party with the bearer token and TLS
  access can acquire the lease. The witness is a trusted arbiter.
- **Witness unavailability.** No renewal and no promotion while it is down; the
  current master fences after TTL and DNS continues read-only. This is a
  deliberate availability trade-off; monitor the witness.
- **Operator bypass.** A manual promotion that neither acquires the lease nor
  disables promotion can create two disjoint configuration histories. Each
  slave's watermark prevents a rollback of that slave, but the histories are
  not merged automatically.
- **A stable endpoint that does not move.** Promotion does not move a VIP or
  update DNS/DHCP. Without a stable endpoint, remaining slaves cannot
  replicate; re-pointing is manual.
- **Fork merging.** A stranded or ahead slave is latched and reconciled
  manually; there is no automatic merge of divergent configuration.
- **Key distribution.** The master signing key/certificate must be provisioned
  on the candidate; automatic distribution is out of scope.
- **Compromised hosts, keys or root.** Outside the failure model.
- **Multiple witnesses / witness replication.** A single witness is a single
  point of availability, not a quorum. Replication would reintroduce consensus
  and is out of scope.

## Test plan (C3b)

C3b must implement the feature and run this suite. The behavioral tests use a
real witness process (or an in-process instance sharing the exact CAS code), not
a sleep-based file mock. Use time-compressed configs (for example TTL 5, renew
1, reconcile 1) and the existing deterministic clock/port harness where
possible; do not weaken the CAS/expiry semantics to make tests fast.

### A. Config, schema and upgrade

| Test intent | Expected |
|---|---|
| Full v2 document with `[ha.promotion]` and `[ha.promotion.witness]`, `enabled = false`, loaded through the real loader (`Config::load`/`check-config`, not `HaConfig` alone) | Parses; every key retains its value/default; no witness connection |
| Same fixture through `crates/sito-core/src/config/tests.rs` `SCHEMA_FIXTURE` and the map-drift test | No unknown-key/drift failure |
| `enabled = false` with `ha.ping_interval_secs = 30` and no heartbeat key | Loads; behavior unchanged; no bounds failure |
| `enabled = true` with `ping = 30` and no heartbeat key | Effective heartbeat is 90; loads |
| `enabled = true` with explicit `heartbeat_timeout_secs = 45` and `ping = 30` | Validation error naming `heartbeat_timeout_secs` |
| `ping > 1200` with an explicit large heartbeat | No unsatisfiable upper bound |
| Missing `cluster_id`, `node_id`, `witness.url`, `witness.ca`, `witness.token_file` when enabled | Validation error naming the key |
| `backend = "etcd"`/`"consul"`/typo | `unsupported_lease_backend` |
| `witness.url` `http://`, with userinfo, or missing host | Validation error |
| `witness.fingerprint` malformed | Validation error |
| `candidate = true` on `server.role = "master"` with `enabled = true` | Validation error; with `enabled = false` it loads with a warning |
| TTL/renew/reconcile out of range or inconsistent | Validation error naming the key |
| Unknown `[ha.promotion]`/`[ha.promotion.witness]` key | Rejected by the v2 unknown-key policy |
| No-HA build with `[ha.promotion]` | Rejected with the existing "HA feature missing" error, not unknown-key |
| No `[ha.promotion]` section | Behavior unchanged except `promotion.state = "disabled"`; existing HA tests pass |

### B. Witness server

| Scenario | Expected |
|---|---|
| Acquire on an empty state dir | Grants term 1, revision 1; persists `lease.json` and `initialized`; 200 |
| First acquire with `version = 0`, `bundle_hash = "none"` | Accepted; `"none"` at version > 0 is rejected |
| Renew by the holder | Same term, revision + 1, expiry extended; 200 |
| Renew with a stale revision / foreign holder / wrong term | 409 with the current record; no state change |
| Renew after expiry | 409; must acquire term + 1 |
| Acquire with `term != current + 1`, `version < current.version`, a version jump above the 1,000,000 peer-lead bound, or equal version with a different `bundle_hash` | 409; no state change |
| Acquire/renew with `ttl_secs` outside 5..=300 | 400; no state change |
| Two concurrent acquires on the same expired record | Exactly one 200; the other 409 |
| Hash normalization | `bundle_hash`/`have_bundle_hash` accept `blake3:<hex>` and bare lowercase hex equivalently; malformed hashes are rejected |
| TLS: wrong CA, wrong SAN, wrong pin | Client handshake fails; no fallback |
| Auth: missing/wrong bearer token | 401; no state change |
| Cluster mismatch | 403; no state change |
| Corrupt `lease.json` / missing record with `initialized` | Witness exits non-zero; no reset |
| Crash/restart after a granted acquire | Reloads the same term/revision/expiry |
| Clock forward/backward | Expiry follows the witness clock; no duplicate holder |
| Offline `lease-admin set` | Raises term/version above the cluster high-water mark after a backup; refuses while the witness is running |
| Token/certificate rotation | A mismatch is read-only (`witness_auth_failed`/`witness_tls_failed`); no plaintext fallback |
| Body over 16 KiB / malformed JSON | 413/400; server stays healthy |

### C. Client behavior

| Scenario | Expected |
|---|---|
| Master startup, witness up | Acquires, quiesces, reconciles, publishes, becomes writable; mutations accepted |
| Master startup, witness down/unreadable/bad token/bad TLS | Process runs read-only; DNS serves; mutations 409; `/health` false; retries; does not exit |
| Candidate promotion | Waits heartbeat timeout; acquires `T+1`; quiesces; reconciles; publishes at `publish_version`; slaves apply |
| Two-candidate race | Exactly one acquires; loser stays read-only; no two terms |
| Pre-publish window | Old master publishes at `T` just before fencing; candidate acquires `T+1`, quiesces, sees the slave's higher version, aborts (`candidate_behind`) and does not overwrite |
| Witness record across quiesce | With acquire baseline `V`, after the pending state is written at `V+1`, the witness record stays at `V/Vhash` through quiesce and reconciliation; only the post-publish renew moves it to `V+1` |
| Crash after pending state, before publish | Record is `V`; restart re-acquires `V`, may reuse `V+1`; a different candidate at `V` is not `candidate_behind`; no skip to `V+2` |
| Crash during publish / after publish before `"published"` | State `publishing`; a reachable slave at `V+1` with the pending hash proves success; different hash aborts; no hash/slave allows safe reuse; record never holds an unpublished version |
| Crash after `"published"` state | Baseline is `V+1`; next publish is `V+2`; no version reuse |
| `"published"` state write fails | No witness renew; stay read-only; restart infers success from a slave at `V+1`/pending hash or the witness record, then marks published |
| Pending/publishing state + witness record matches the state bundle | Restart (master or candidate) infers the publish succeeded, establishes baseline `V+1`, and publishes `V+2`; no `candidate_behind` deadlock |
| Same-version fork at baseline | A reachable slave reports the baseline version with a different `have_bundle_hash`; the promotion aborts (`cluster_forked`) and publishes nothing |
| Same-version fork at witness's older version | Baseline raised to `V+1` by published state, witness record at `V`; a reachable slave at `V` with a different hash aborts (`cluster_forked`); no `V+2` publish |
| Unknown in-flight version | Reachable slave at `V+1` while baseline is `V` and the allowed publish is `V+2`; abort (`candidate_behind`), no overwrite |
| Node behind the witness record | Node's published baseline `V`, witness record `V+1`; abort `candidate_behind`; do not adopt `V+1` as a baseline or publish its own `V+2` |
| Node at witness version, different hash | Node's published baseline `V`, witness `V` with a different hash; abort `candidate_forked` |
| Missing reconciliation hash | A reachable compared-baseline slave or a `publish_version` slave omits `have_bundle_hash`; the promotion aborts (`candidate_hash_unknown`) and publishes nothing |
| Hello-only reconciliation | A connected forked slave receives **no `ConfigPush`** during the reconcile window; abort or success happens before any push; after success exactly one first push |
| Master restart with state behind/forked/term-ahead | `state.published_version < witness.version` → `master_state_behind`; equal published version + different hash → `master_state_forked`; `state_term > witness.term` → `master_term_ahead`; all read-only, no acquire |
| Reachable slave ahead after first publish | Slave latches/diverges; master does not bump above it; manual reconciliation |
| Lease expiry / renewal failure | Fences at `TTL - margin`; 409 mutations; DNS read-only; metrics/audit; `ha_promotion_fenced` |
| Renewal 409 with our holder/term/revision-advanced, same version/hash | Re-reads, adopts revision, continues (lost ACK) |
| Renewal 409 with same holder/term/version but different hash | Fences with `lease_version_regression`; does not adopt/retry until the deadline |
| Renewal unreachable before deadline | Retries; fences only after the deadline |
| Restart after fence | Durable `ha_fence.json` (or `ha_fence.pending`) makes it read-only; no acquisition; `ha_fenced_until_reconciled` |
| Fence marker write failure | Final-marker failure with `pending` present still blocks restart; both fail → process exits non-zero; startup runs a data-dir integrity check and never resumes the fenced term (safety rests on the witness term) |
| `sito ha clear-fence --confirm` | Removes both markers; the node may acquire on the next attempt |
| `require_manual_confirmation = true` | Waits for `sito ha confirm-promotion` before acquire; a stale/wrong-node/wrong-cluster confirmation is ignored; confirm while master alive/lease held is refused; confirm + lease succeeds |
| Manual promotion with promotion enabled | Starts as master, acquires `T+1`, quiesces/reconciles, publishes; a hand-edited higher term is refused |
| Stable endpoint | `master_url` IP literal logs `ha_promotion_endpoint_is_ip_literal`; VIP/DNS works; no endpoint move leaves slaves unable to replicate but no split brain |
| `require_slaves` / `require_all_slaves` | Promoted master applies the policy; two-node + `require_all_slaves` is not-ready until a slave connects while DNS serves |
| v1 rejection | v1 watermark/state/peer refuses startup/negotiation; no term raised |
| Lease record loss | Client with `max(applied_term, state_term) > 0` refuses `lease_record_missing` before any acquire; a normal slave with `applied_term > 0`/`state_term = 0` and a lost witness state dir does **not** fall through to term 1 |
| Identity mismatch | Candidate without the trusted signing key/master certificate refuses (`candidate_identity_mismatch`) |
| No-HA feature build | `[ha.promotion]` rejected with the HA-feature error |

### D. End-to-end, soak and property checks

- Two HA nodes + one witness: random partitions, process kills, pause/SIGSTOP,
  witness restarts, clock steps, and endpoint moves. Assert:
  - no term ever has two holders;
  - no node's applied term decreases;
  - no node's watermark decreases;
  - no accepted same-version fork is overwritten by a lower-content version;
  - DNS continues serving on both nodes throughout.
- Property test on the witness state machine: acquire/renew/conflict/expiry
  boundaries, revision monotonicity, term monotonicity, restart durability.
- Promotion duration: measure heartbeat + expiry + quiesce + reconcile and
  document the observed values.
- Endpoint: VIP/DNS move during promotion; without the move, no split brain and
  a clear not-ready/re-pointing signal.

## Migration and rollback

### Default off

- No `[ha.promotion]` section, or `enabled = false`: behavior is the current
  behavior, except the status object reports `promotion.state = "disabled"`.
  No witness connection, promotion thread, file or readiness gate is created.
- Existing configs with any `ha.ping_interval_secs` load; promotion bounds are
  only validated when enabled. The derived heartbeat default avoids the
  `ping = 30` upgrade trap.
- No cluster can accidentally acquire the new behavior by upgrading.

### Enabling

1. Upgrade every HA node to the build that implements this ADR (including the
   optional `have_bundle_hash` Hello field); a promotion-enabled cluster must
   not contain a peer that omits it, or reconciliation aborts with
   `candidate_hash_unknown`. Deploy the witness on a third host (not either HA
   node). Provision its TLS certificate/key, `cluster_id`, `token_file` (`0600`)
   and `state_dir` (`0700`). Start it and verify `GET /healthz` and
   `GET /v1/info`.
2. Distribute the witness CA (and optional BLAKE3 pin) and the bearer token
   file to every HA node (`0600`, owned by the runtime user).
3. Confirm every node has a valid v2 watermark/state and the master identity
   is provisioned on the candidate.
4. Set `enabled = true` on every node, `candidate = true` only on the chosen
   slave, and the same `cluster_id`/`node_id`/witness/TTL values. Keep the
   slave `master_url` on a stable VIP/DNS endpoint.
5. Run `check-config` and start the master; verify it acquires the lease,
   quiesces, reconciles and becomes writable. Start the candidate.
6. Exercise one planned takeover in a maintenance window and verify
   `promotion.state`, metrics, DNS reads and replication convergence.

### Disabling

1. Set `enabled = false` on every node and restart the HA nodes in the normal
   order.
2. Promotion stops; a fenced node remains read-only until the operator clears
   its marker. Disabling does not auto-promote or auto-heal.
3. The witness can be stopped. Delete its `state_dir` only after every node is
   disabled and no master is running; deleting a live lease history is a
   term-reset risk and is not part of a normal rollback.

### Downgrade

- Remove `[ha.promotion]` before running a binary that predates the keys; a v2
  parser that does not know them rejects the document as unknown configuration.
- `ha_state.toml` remains valid v2 state. The promotion bookkeeping
  (`publication_state`, `published_version`, `published_hash`) and audit fields
  are ignored by older readers; if an older master rewrites the file, they are
  lost but `term`/`version`/bundle survive. On re-upgrade, a state without
  `publication_state` must be treated as **unknown** and reconciled with the
  witness/slaves; never assume its bundle version was published. Keep a backup.
- `ha_fence.json` is new; older binaries ignore it, so a downgrade can lose the
  "do not re-acquire" protection. Clear/reconcile fences before downgrading or
  keep the node stopped until the cluster is reconciled. Remove a stale
  `ha_promote.confirm` as part of the same cleanup.
- If a promotion happened, restore the pre-upgrade `config.toml`,
  `ha_state.toml`, `ha_watermark.toml` and certificates per the
  [HA runbook §7.3](../runbook-ha.md#73-downgrade-v2--v1), then verify `Synced`.
  Never copy a watermark between nodes.

## Open questions and rejected scope

- **External CAS backends (Consul/etcd) are a future option.** They are not in
  2.0. Adding one would require its own ADR for keys, ACL/TLS, failure modes and
  tests.
- **No multi-witness quorum or witness replication.** That is consensus and is
  rejected. A single witness is a single point of availability, accepted for
  the two-node target.
- **No automatic VIP/DNS/DHCP move.** The stable endpoint is a deployment
  prerequisite; external tooling or the operator moves it.
- **No automatic signing-key/certificate distribution.** Provisioning the
  master identity on the candidate is manual and has a key-exposure trade-off.
- **No automatic fork merge or peer-counter adoption.** Divergence stays
  sticky; the master never overwrites a slave that is ahead.
- **No heartbeat-only fallback and no plain shared-file backend.**
- **No witness release endpoint.** A graceful shutdown leaves the lease until
  expiry; this is simpler and avoids a stale process resuming after a release.
- **Witness deployment on an HA node** is supported only for lab/test; the
  runbook labels it non-HA because the arbiter shares the node's failure
  domain.

## Implementation checklist for C3b

C3b implements the feature.

### 1. Config model and schema inventory

- Add `PromotionConfig` (with nested `WitnessConfig`) to
  `sito-ha-types/src/config.rs`; `HaConfig.promotion: PromotionConfig` with
  `#[serde(default)]`.
- Defaults: `enabled = false`, `candidate = false`, `cluster_id = None`,
  `node_id = None`, `backend = "witness"`, `lease_ttl_secs = 30`,
  `renew_interval_secs = 10`, `heartbeat_timeout_secs = None` (derive
  `max(45, 3 * ping)`), `require_manual_confirmation = false`,
  `reconcile_window_secs = 10`; witness `url = None`, `ca = None`,
  `server_name = None`, `fingerprint = None`, `token_file = None`.
- Validation only when `enabled = true` for bounds; always reject unknown
  keys and unsupported `backend`. When enabled, `candidate` is allowed only on
  a slave; when disabled, it is inert with a warning. Required fields and
  path/URL/fingerprint checks as in the table.
- Register every key in `crates/sito-core/config-v1-to-v2-map.toml` with
  `status = "kept"`, using these exact paths:
  `ha.promotion.enabled`, `ha.promotion.candidate`, `ha.promotion.cluster_id`,
  `ha.promotion.node_id`, `ha.promotion.backend`,
  `ha.promotion.lease_ttl_secs`, `ha.promotion.renew_interval_secs`,
  `ha.promotion.heartbeat_timeout_secs`,
  `ha.promotion.require_manual_confirmation`,
  `ha.promotion.reconcile_window_secs`,
  `ha.promotion.witness.url`, `ha.promotion.witness.ca`,
  `ha.promotion.witness.server_name`, `ha.promotion.witness.fingerprint`,
  `ha.promotion.witness.token_file`.
- Add the full table to `SCHEMA_FIXTURE` in
  `crates/sito-core/src/config/tests.rs`.
- Add positive real-loader/`check-config` tests for enabled/disabled and the
  `ping = 30` upgrade case. A direct `HaConfig` deserialization test is **not**
  sufficient.
- Negative tests: missing required keys, bad URL/TLS/fingerprint, candidate on
  master, intervals, unsupported backend, unknown keys, no-HA build, and
  validation precedence (specific key errors before any witness contact).
- Run `cargo test -p sito-core config_schema`.

### 2. Witness server

- Add `sito ha lease-server` (HA feature only) with the flags and defaults
  above.
- Extend `sito ha gen-certs` with `--witness --san <host>` (server-auth
  certificate for the witness) or document the external-cert path and the
  matching client `witness.ca`/`server_name`.
- Implement TLS 1.2+, bearer auth (constant-time, `0600` token file), body
  limit, timeouts and the `/healthz`, `/v1/info`, `/v1/lease`,
  `/v1/lease/acquire`, `/v1/lease/renew` endpoints.
- Implement the single-writer CAS state machine with term/revision/expiry and
  version monotonicity. Enforce the `ttl_secs` 5..=300 bound server-side and
  normalize `bundle_hash` input to 64 lowercase hex (accept and strip a
  `blake3:` prefix). The record must never receive a client's pending version:
  the client-side rule is authoritative, and the witness stores exactly the
  baseline it is sent.
- Implement atomic persistence (`lease.json`, `initialized`, `lease.lock`,
  temp+fsync+rename, dir fsync), restart reload, corrupt/missing-with-sentinel
  refusal, cluster mismatch refusal, and `0700`/`0600` permissions.
- Add an offline `sito ha lease-admin set --state-dir <dir> --term <T>
  --version <V> --bundle-hash <hash> --confirm` recovery tool. It writes an
  **expired** record (so the next acquire can take over) with the given
  term/version/hash and a bumped revision, refuses while the witness process
  holds the state lock, and backs up the old record.
- Unit/integration tests for every witness row in the test plan, including
  concurrent CAS and restart.

### 3. Client promotion engine

- Implement a lease client with TLS/CA/pin/bearer auth, timeouts, retries and
  typed errors.
- Master startup: acquire before mutations; read-only on failure (no exit);
  retry; status/reason; no witness fallback.
- Candidate state machine: heartbeat wait, optional manual confirmation,
  acquire, `T+1`, state write, quiesce, reconciliation, first publish, renew.
- Implement the publish-baseline/pending-state model in `ha_state.toml`:
  `publication_state` (`pending|publishing|published`),
  `published_version`/`published_hash`, and the pending bundle version/hash.
  Acquisition and renewal use only the published baseline. Quiesce renews with
  the published baseline; the pending version is never sent to the witness.
  Reuse a pending/publishing version after a crash; skip to `+1` only after the
  state is `published`. Infer a successful publish when a `publishing` state's
  pending bundle `(version, hash)` equals the witness record, then mark it
  published.
- Implement lease-record-loss refusal on
  `max(applied_term, state_term) > 0` **before** any acquire, and the
  client-side `candidate_term_ahead` check before acquire (the witness cannot
  reject an absent record).
- Enforce `node_published_version = max(applied_version,
  state.published_version)` as the only content baseline: it must be at least
  `witness.version`, with the same hash at equality. Never adopt a witness
  version/hash the node has not applied, and never include the pending state
  version in the baseline.
- Extend `HaMessage::Hello` with the optional `have_bundle_hash` field
  (`#[serde(default)]`); slaves populate it from the watermark; masters use it
  during reconciliation. Keep normal v2 replication compatible with peers that
  omit it.
- Implement a **hello-only listener mode** for quiesce/reconciliation: accept
  TLS/WebSocket, read `Hello`, answer ping/pong, and send **no `ConfigPush`**
  until reconciliation completes. Only then install the active bundle and allow
  normal push-on-hello.
- Implement reconciliation against both the witness record
  `(version, bundle_hash)` and the publish baseline `(version, hash)` plus the
  pending version in `publishing` state; abort on an ahead reachable slave, any
  same-version different-hash slave at either baseline, an unknown in-flight
  version above the baseline that is not the allowed pending publish, an
  unexpected `publish_version` report, or a missing hash; latch a late ahead
  slave; never bump above it.
- Renewal conflict/unreachable handling exactly as specified (including the
  409 same-version different-hash fence with `lease_version_regression`);
  self-fence deadline with `CLOCK_BOOTTIME`; wall-step detection.
- Durable `ha_fence.json`/`ha_fence.pending` write/read, startup refusal on
  either marker, corrupt-data-dir exit when both fail, and
  `sito ha clear-fence --confirm` (removes both).
- Effective-role switching without rewriting `config.toml`; restart behavior.
- Local `sito ha confirm-promotion --confirm` and `ha_promote.confirm` file
  (one-shot, `0600`, consumed atomically, age-limited).
- Stable-endpoint IP-literal warning.
- Persist optional audit fields in `ha_state.toml`.

### 4. Observability

- Add the `promotion` object, reason codes, metrics and audit events listed
  above.
- Emit a specific reason for every read-only/fenced/aborted state.
- Ensure HA-disabled/no-HA builds do not expose misleading metrics.

### 5. Docs

- Update `docs/configuration-reference.md` §13 with all keys, defaults and the
  enabled-only validation/upgrade note. Document `heartbeat_timeout_secs` as
  the derived `max(45, 3 × ha.ping_interval_secs)` and keep the
  config-reference drift checker green (use its documented placeholder form if
  a computed default cannot be expressed).
- Update `config.example.toml` with a commented `[ha.promotion]` /
  `[ha.promotion.witness]` block.
- Update `docs/runbook-ha.md` §2: enable/disable, witness deployment, stable
  endpoint, pre-publish quiesce, fence/clear-fence, manual promotion with the
  lease, and the `require_slaves` caveat.
- Cross-link this ADR from the config reference and runbook.
- Note the feature in the 2.0 claim matrix/release notes (H5), with the witness
  availability/SPOF caveat.

### 6. Checks

- `python3 scripts/check_config_reference.py`
- `python3 scripts/check_markdown_links.py`
- `python3 scripts/check_migration_guide.py`
- `python3 scripts/check_test_matrix.py`
- `cargo test -p sito-core config_schema`
- The new witness/client/unit/integration tests
- `git diff --check`

## References

- [ADR-0002: High Availability Architecture (Master/Slave Push Replication)](0002-ha-master-slave-push.md)
- [HA runbook](../runbook-ha.md), especially
  [§2 manual promotion](../runbook-ha.md#2-manual-slave---master-promotion-procedure)
  and [§7 protocol v2 upgrade/downgrade](../runbook-ha.md#7-ha-protocol-v2-upgrade-and-downgrade)
- [Configuration reference §13 `[ha]`](../configuration-reference.md#13-ha--high-availability-masterslave-replication)
- [Config v2](../config-v2.md) and the
  [2.0 migration guide §8.2](../2.0-migration.md#82-ha-protocol-v2-upgrade)
