# ADR-0010: Opt-In HA Automatic Promotion (Lease and Fencing)

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
  `version` in `ha_state.toml`, restart the node
  ([HA runbook §2](../runbook-ha.md#2-manual-slave---master-promotion-procedure)).

There is no shared database, no quorum service, no witness and no leader
election. The normal deployment is two nodes (a primary and a secondary), so a
majority quorum is not available. The 2.0 plan asks for automatic promotion to
be **opt-in, default `false`, with fencing/lease, split-brain tests and
metrics/readiness**. A wrong default is unacceptable: both nodes accepting
configuration writes would produce two divergent writable masters and, worse, a
rollback of the cluster's configuration sequence.

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
master is dead or partitioned. This ADR decides whether sito adds such an
arbiter for 2.0.

The only lease-like primitive in the tree today is the single-instance service
lease: an advisory `try_lock` on `<data_dir>/sito.pid` held by the running
server so `reset-admin`/`reset-sessions` cannot mutate a live data directory.
It is local to one node's data directory, has no expiry or takeover protocol,
and its lock semantics are not a portable distributed mutual-exclusion
primitive. It prevents two processes from sharing one data directory; it
cannot arbitrate two HA nodes.

## Problem and failure modes

Automatic promotion must be safe under the failure model below. "Writable
master" means a node that holds the cluster's current fencing term and whose
signed bundles are not rejected by slaves (whether or not a slave is currently
connected). "Locally writable" means only that the node's own API accepts a
mutation; it may never reach a slave or hold the current term.

| Failure | What each side observes | Risk if promotion trusts heartbeats alone | Required response |
|---|---|---|---|
| Master crash | Candidate sees no frames; master process gone | None if only one node promotes | Promote only after the lease is free/expired |
| Network partition (master alive) | Both sides see the other as unreachable | Both promote; two writable masters | The lease must expire before takeover; the old holder must self-fence before that expiry |
| Asymmetric connectivity | Candidate reaches the lease store but not the master; or the master cannot reach the store | Heartbeat-only promotion is immediate; the old master still serves writes | Lease-store reachability is the arbiter. If only the master can renew, it keeps the lease and no promotion occurs; a node that cannot renew fences |
| Master/slave partition, lease reachable by both | The master is alive and keeps the lease; slaves see no frames | Heartbeat-only promotion would create a second master | No promotion; the master remains the only writer, `require_slaves` reports not-ready, and delivery resumes when the network recovers |
| Stale master returns | Old master has a lower term and may have a higher local version | Old master republishes and rolls the cluster back | Term + watermark + version continuity reject it; it must not re-acquire on its own after fencing |
| Two candidates | Two slaves both miss the master | Both promote, possibly in different terms | A linearizable lease grants one holder; the loser stays read-only |
| Lease expiry during a pause | The holder is suspended (VM pause, SIGSTOP, scheduler starvation) past TTL | On resume it writes while a new holder exists | Self-fence deadline before backend expiry; write-path lease guard; lower-term bundles are rejected even in the residual window |
| Clock skew | Nodes disagree about wall time | A holder believes its lease is valid longer than the backend does | Safety decisions never compare wall clocks; the backend owns expiry and the holder uses monotonic boot time |
| In-flight publish | Master published version `V` to some slaves, then died before renewing the lease record | Candidate at `V-1` promotes at `V` with different content | Watermark/fork latch rejects the inconsistent slave; no rollback, but manual reconciliation may be required |
| v1 node or state | v1 watermark/state or v1 peer | Promotion over an old replay guard | Protocol v2 rejection happens before any promotion logic |

The two-node topology is the hard case: there is no third vote. Any automatic
scheme must obtain its tie-break from something outside the two node processes,
or it must not promote.

## Options considered

### Option 1: Manual promotion only (status quo)

- **Pros:** No new failure modes. The operator can stop/fence the old master
  before raising the term. Already documented and tested.
- **Cons:** Failover takes human time; a crashed master leaves the cluster
  read-only for configuration (DNS reads continue).
- **Why chosen as the 2.0 behavior:** It is the only path whose safety does not
  depend on infrastructure sito does not ship or verify.

### Option 2: Delegate promotion to an external orchestrator

- **Pros:** keepalived/VRRP, Pacemaker, Kubernetes or a hypervisor already owns
  node liveness and can run a promotion hook; no new in-process consensus.
- **Cons:** VRRP/keepalived can split-brain on a partition unless configured
  with unicast peers and strict timeouts; the orchestrator must also fence the
  old master (STONITH/power-off), not just move a virtual IP. sito cannot verify
  that the external tool did the fencing.
- **Why not chosen as the built-in design:** It remains a supported way to
  *trigger* the manual procedure, but it does not make sito's promotion
  automatic or safe by itself. The ADR does not claim otherwise.

### Option 3: Quorum or full consensus (Raft/Paxos, an embedded etcd/Consul)

- **Pros:** Strong leader election and a well-understood safety proof with three
  or more voting nodes.
- **Cons:** Requires an odd quorum and persistent votes; a two-node deployment
  loses write availability when either node fails, which is the deployment this
  project targets. Adds a new consensus system to a DNS server, plus membership,
  snapshots, log storage and upgrade rules.
- **Why rejected:** Disproportionate complexity and a topology mismatch, already
  rejected in ADR-0002. Adding one silently in C3 would violate that decision.

### Option 4: Shared-storage lease + monotonic fencing (the only acceptable design)

- **Pros:** Works with two nodes; gives one shared arbiter; the fencing token is
  the existing cluster term, so slaves already reject a stale holder's bundles.
- **Cons:** Requires storage/a service with a genuinely linearizable
  compare-and-swap and an authoritative expiry clock. A plain network share
  (NFS/SMB) does **not** provide that in the general case. Nothing in the 2.0
  tree provides it; the existing `sito.pid` advisory lock has no expiry or
  takeover protocol and is not a distributed arbiter.
- **Why chosen as the design shape:** It is the minimum mechanism that can make
  automatic promotion safe without inventing a consensus protocol.

### Option 5: Heartbeat-only automatic promotion (rejected)

A candidate promotes after `N` missed heartbeats. This is rejected
unconditionally:

- a partition and a crash are indistinguishable from the candidate's side;
- asymmetric connectivity (candidate cannot reach the master, master still
  reaches slaves and the lease/fencing plane) produces two writable masters;
- there is no shared arbiter, so the two nodes cannot agree who won;
- heartbeat timing is a liveness signal, not a mutual-exclusion primitive;
- lowering the timeout makes it faster and less safe; raising it only narrows
  the window.

No configuration key in this ADR enables heartbeat-only promotion. A candidate
that cannot acquire a conforming lease stays read-only. This is final, not a
default that an operator can flip.

## Decision

1. **Manual promotion remains the supported failover path in 2.0.** The
   procedure in [HA runbook §2](../runbook-ha.md#2-manual-slave---master-promotion-procedure)
   is unchanged.
2. **Automatic promotion is opt-in and disabled by default**
   (`ha.promotion.enabled = false`). With the key absent or `false`, behavior is
   byte-for-byte the current behavior: no lease file, no promotion thread, no
   new readiness gate.
3. **Automatic promotion is unavailable in 2.0.** The only acceptable design is
   the shared lease + term fencing specified below, and no conforming lease
   provider ships in 2.0. Therefore `enabled = true` is **refused** by
   `check-config`, startup and API config writes with the stable reason
   `ha_promotion_unavailable`. The feature never falls back to heartbeat-only,
   a local file, or a best-effort path.
4. **C3b implements the schema and the fail-closed gate, not a promotion loop.**
   The exact `[ha.promotion]` keys are reserved and registered so a future
   backend can be added without another schema break. C3b must not invent a
   lease backend.
5. **The design contract is binding for any future implementation:** one
   designated candidate per cluster, a linearizable lease CAS, the lease term is
   the fencing token, a holder self-fences before expiry, and term/version
   continuity is preserved on promotion.
6. **No new consensus system is added.** Raft/Paxos/quorum membership remains
   out of scope (ADR-0002).

If an operator needs automatic failover today, the supported answer is an
external orchestrator that stops/fences the old master and then invokes the
manual promotion procedure, with `[ha.promotion]` left disabled.

## Chosen design (contract for a future conforming backend)

### Configuration

Proposed exact keys, reserved by C3b:

```toml
[ha.promotion]
# Opt-in. Refused when true until a conforming shared lease backend exists.
enabled = false

# This node is the single designated promotion candidate. Only valid on a
# slave; only one node in a cluster may set it.
candidate = false

# Lease record on shared storage. Required when enabled = true. Must not be
# inside server.data_dir (that directory is node-local).
# lease_path = "/mnt/sito-ha/lease.json"

# Lease lifetime. Must be >= 3 * renew_interval_secs.
lease_ttl_secs = 30

# Renewal period. Must be >= 1 and <= lease_ttl_secs / 3.
renew_interval_secs = 10

# How long without any master frame before the candidate may try the lease.
# Must be >= 3 * ha.ping_interval_secs (the existing slave liveness window).
heartbeat_timeout_secs = 45

# Human-in-the-loop: never promote without an authenticated Admin confirmation.
# This can delay a promotion; it can never bypass lease acquisition.
manual_override = false
```

| Key | Type | Default | Validation | Meaning |
|---|---|---|---|---|
| `enabled` | boolean | `false` | `true` is refused in 2.0 (`ha_promotion_unavailable`) | Master gate for all promotion behavior. |
| `candidate` | boolean | `false` | `true` requires `server.role = "slave"` when `enabled = true`; inert with a warning when `enabled = false` | This node may try to acquire the lease after master loss. Exactly one candidate per cluster. |
| `lease_path` | string (absolute path) | none | Required when `enabled = true`; must be absolute; parent must exist and be writable by the runtime user; must not be under `server.data_dir`; backend conformance probe must pass | Locator for the shared lease record. The path is dedicated to one cluster. |
| `lease_ttl_secs` | integer | `30` | `5..=300`; `>= 3 * renew_interval_secs` | Backend-side lease lifetime. |
| `renew_interval_secs` | integer | `10` | `1..=lease_ttl_secs / 3` | Holder renewal period. |
| `heartbeat_timeout_secs` | integer | `45` | `>= 3 * ha.ping_interval_secs`; `<= 3600` | Candidate wait before it may inspect/acquire the lease. |
| `manual_override` | boolean | `false` | Inert with a warning when `enabled = false` | When `true`, the candidate waits for an explicit Admin confirmation before publishing, even after the lease is available. |

All `[ha.promotion]` keys take effect at startup/restart, consistent with the
HA worker configuration; they are not hot-reloaded. There is no configuration
in which `enabled = true` is accepted without a configured, probed
`lease_path`.

The candidate is a **single designated node**, not an ordered list. An explicit
list would require cluster-wide membership and agreement (a consensus problem)
and is rejected for 2.0. Setting `candidate = true` on more than one node is an
operator error that the lease still serializes; safety holds. Each node with
`enabled = true` and `candidate = false` logs that it will not promote, so a
deployment review can spot a cluster with no designated candidate.

### Lease backend contract

A conforming backend exposes one record at `lease_path` with:

1. `read() -> Option<LeaseRecord>` that is linearizable with the writes.
2. `compare_and_swap(expected: Option<(Term, Revision)>, next: LeaseRecord, mode: Renew | Takeover) -> Result<LeaseRecord, Conflict>`
   that is linearizable, durable before returning success, and atomic across
   nodes. A success increments `Revision`.
   - `Renew` succeeds only when the current record has the expected
     `(term, revision)`, the caller is the current `holder`, and the record is
     not expired.
   - `Takeover` succeeds only when the current record has the expected
     `(term, revision)` and is expired, or when the record is absent and the
     expected value is `None`. The next term must be strictly greater.
3. An **authoritative expiry clock**: the backend decides whether the current
   record is expired. A renewal of an expired record must fail, not resurrect
   it.
4. Monotonic takeover: once term `T` has been granted, no later grant may be
   `<= T` unless the record was administratively reinitialized.

The `revision` is required in addition to the term. Renewal keeps the same term,
so a CAS on the term alone would let a candidate take over a **live** lease that
was renewed after the candidate's read. The revision changes on every renewal
and takeover, so a stale read cannot win. A backend that only compares the term
is non-conforming.

A plain POSIX file share does **not** meet this contract:

- `O_CREAT|O_EXCL` can create a record, but it cannot atomically replace an
  expired record without a lock;
- `rename` is atomic per name but is not a compare-and-swap over content; two
  candidates can both replace an expired record and both believe they won;
- `flock`/POSIX locks over NFS/SMB depend on lock-manager recovery and are not
  a portable mutual-exclusion primitive;
- NFS attribute caching can serve a stale `expires_at`/holder to a candidate;
- a filesystem that acknowledges a write and loses it breaks the durability
  premise.

The backend may be a file-backed provider built on a real lock/lease service, or
an external service exposing CAS. It must not be implemented as "best effort on
a network share". If sito cannot probe the contract, it must refuse to enable.

### Lease record

```json
{
  "schema": 1,
  "cluster": "sito-ha",
  "holder": "<instance_name>@<boot_id>@<process_uuid>",
  "term": 7,
  "revision": 12,
  "version": 128,
  "acquired_unix_ms": 1760000000000,
  "expires_unix_ms": 1760000030000
}
```

- `holder` combines the configured instance name, the kernel boot id (Linux
  `/proc/sys/kernel/random/boot_id`) and a random per-process UUID. The UUID is
  required because two containers on one host share a boot id and may share an
  instance name. A restarted process is a new holder and must acquire a **new**
  term; it may not silently renew the previous process's record.
- `term` is the fencing token. There is no separate epoch: the existing cluster
  term is the fencing token, so no new wire field is required.
- `version` is the master's last successfully published version. The master
  renews **after** a successful publish so candidates can verify they are not
  behind.
- `expires_unix_ms` is backend time, not holder wall time. Holders and
  candidates never compare it with their own wall clock for safety.
- `acquired_unix_ms`/`expires_unix_ms` are diagnostics and backend inputs; the
  backend is authoritative.
- The record contains no secrets. Keep it in a dedicated directory with
  restrictive permissions where the storage supports them; the safety
  properties do not depend on secrecy.
- `cluster` is a fixed diagnostic marker, not an enforced cluster identity.
  Sharing one `lease_path` between two clusters is operator error and can
  interfere with their terms; a dedicated path per cluster is required.

If the record is absent and the candidate's applied term is `0`, this is a
brand-new cluster and the candidate may create it. If the record is absent and
the candidate's applied term is greater than `0`, the candidate **refuses**
(`lease_record_missing`): losing the record could reset the term, so recovery
is manual.

### Acquisition algorithm

A candidate runs this only after all eligibility gates pass.

1. Read the lease record.
2. If the record is held by this `holder` and not expired, treat it as an
   existing grant and go to renewal.
3. If another holder's record is not expired, stay `waiting`; retry after the
   next renewal interval with jitter. Never busy-loop and never steal a live
   lease.
4. If the record is absent (and the term-reset rule allows creation) or expired,
   compute:
   - `next_term = max(record.term_or_0, applied_term, state_term) + 1`
   - `baseline_version = max(record.version_or_0, applied_version, state_version)`

   Then call `compare_and_swap(expected = None if absent else
   Some((record.term, record.revision)), next = {holder, next_term,
   version = baseline_version, ttl = lease_ttl_secs}, mode = Takeover)`. The
   record's `version` is the **last published** version, not a reservation; the
   first publish below is `baseline_version + 1`. The backend stamps
   `acquired_unix_ms`/`expires_unix_ms` with its own clock and increments
   `revision`. `applied_term`/`applied_version` are the watermark values;
   `state_term`/`state_version` are a local promotion-in-progress state written
   by this node, or `0` when there is none. A candidate that rejected a higher
   term/version is degraded or diverged and is not eligible, so there is no
   unapplied higher value it must outrun.
5. If the CAS loses, another node won. Do not retry the same term; back off with
   jitter and re-read. The loser stays read-only.
6. If the CAS wins, the candidate holds term `T = next_term`.
7. Before publishing, write the promoted state to `ha_state.toml` atomically:
   the promoted bundle (`term = T`, `version = baseline_version + 1`), the
   candidate's last applied content, and optional audit fields
   (`promotion_origin = "automatic"`, `lease_holder`, `promoted_at_unix_ms`).
   If this write fails, do not publish; stop renewing and fence.
   - A crash **before** the state write leaves no promoted state. The lease
     expires; a restarted candidate is a new holder. It re-reads the record
     (term `T`, version `baseline`), still satisfies the version gate, and may
     re-acquire at the next term (at least `T+1`); it never publishes at `T`.
   - A crash **after** the state write leaves a promotion-in-progress marker
     (`term = T`, `version = baseline + 1`). On restart the node only acts as
     master after re-acquiring the lease at `T+1`; otherwise it stays read-only
     and reports `promotion_interrupted`. It publishes at `baseline + 2` (or
     higher), never reusing a version.
8. Publish the first bundle at `(T, baseline_version + 1)` and only then renew
   `version = baseline_version + 1` in the lease record.

**Role persistence.** Automatic promotion changes the **effective role** in
memory; it does not rewrite `server.role` in `config.toml`. The promoted
term/version and the `promotion_origin` marker live in `ha_state.toml`. On
restart, a node whose config still says `role = "slave"` starts as a candidate
and only becomes master after re-acquiring the lease; it never starts writable
just because `ha_state.toml` says it was promoted. A node whose config says
`role = "master"` must acquire the lease before accepting writes. The runbook
should recommend persisting the new role (edit `config.toml`, set
`candidate = false`, restart) for auditability; without that step a restart
during a lease outage leaves the node read-only rather than silently writable.

Gates that must all hold before step 1:

- `enabled = true` and `candidate = true`, `server.role = "slave"`;
- a valid protocol-v2 `ha_watermark.toml`; no `protocol_mismatch`;
- last apply succeeded, no `degraded_reason`, no latched divergence or fork;
- no master frame for `heartbeat_timeout_secs` (this is a wait, not the safety
  decision);
- if the record exists, `max(applied_version, state_version) >=
  record.version`; otherwise the candidate is behind (`candidate_behind`) and
  must resync, not promote. The record's term is a fencing fact, not a
  catch-up gate: a higher term is safe to outrun with `next_term`, while a
  higher version means the candidate lacks published content. The `state_*`
  values let a promotion-in-progress node resume after a crash without
  pretending its watermark advanced;
- `check-config` passes and the lease backend probe passes;
- if `manual_override = true`, an authenticated Admin confirmation has been
  recorded for this master-loss episode.

### Renewal and self-fencing

- Renewal is a `Renew` CAS on the observed `(term, revision)`: the holder
  re-asserts `holder`, updates `version` and `expires_unix_ms`, and leaves
  `term` unchanged. The backend increments `revision`. On a revision conflict
  (for example a lost renewal ACK), re-read: if the record is still held by
  this holder at the same term and not expired, adopt the new revision and
  continue; otherwise fence. Retry only while inside the self-fence deadline.
- `safety_margin = max(2, renew_interval_secs)`. The holder self-fences when
  `monotonic_elapsed_since_last_successful_ack >= lease_ttl_secs - safety_margin`.
  With the defaults (TTL 30 s, renew 10 s, margin 10 s) it fences at 20 s, one
  renewal interval before the backend considers the lease free at 30 s.
- Elapsed time uses `CLOCK_BOOTTIME` (it includes suspend), never wall time and
  not plain `CLOCK_MONOTONIC`. If the clock source is unavailable or the process
  cannot prove monotonic progress (for example a detected wall-clock step larger
  than the TTL, or a boot-id change), it fences.
- A renewal CAS failure, an unreachable backend, and an expired record all mean
  **lease lost**. The node immediately:
  - stops publishing and closes replication sessions with a `fenced` reason;
  - rejects every mutating API request with `409 Conflict` and
    `ha_promotion_fenced` (it no longer claims to be the master);
  - keeps DNS serving from the last applied snapshot, read-only;
  - keeps `ha_state.toml` and the watermark intact (never deletes the replay
    guard);
  - reports `ready: false` with `readiness_reason = ha_promotion_lease_lost` or
    `ha_promotion_fenced`;
  - does not re-acquire automatically after regaining connectivity. It stays
    fenced until an operator reconciles it with the current master or the
    promotion procedure explicitly re-enables it. This prevents ping-pong
    between two nodes that both believe they were master.

A master started with `enabled = true` must acquire the lease **before** it
accepts writes. If it cannot, it starts fenced/read-only with
`ha_promotion_lease_unavailable`; DNS still serves the last snapshot. This also
means a manually promoted master must acquire the lease (or `[ha.promotion]`
must be disabled cluster-wide) before accepting writes; see
"Manual promotion interaction" below.

**Master startup with promotion enabled.** A master has `ha_state.toml` rather
than a watermark. It uses `state_term`/`state_version` as its baseline:
`next_term = max(record.term, state_term) + 1` and the first published version
is `max(record.version, state_version) + 1`. Because a restart is a new holder
and a new term must continue above the applied version, the master publishes a
new version even when the configuration did not change. This is a deliberate
safety trade-off: a restarted process never inherits an unexpired lease or
reuses a term. Operators who cannot accept an extra version bump on every
master restart should leave promotion disabled.

### Slave eligibility and promotion readiness

Only one node may be the candidate. The candidate is eligible only if:

- it is a slave running the `ha` feature and protocol v2;
- its watermark is valid and it has applied the master's current published
  configuration (not merely any old bundle);
- it is not degraded, diverged, or fork-latched;
- it has no pending restart-required configuration mismatch;
- it has no stale **foreign** `ha_state.toml` from a previous master role whose
  term/version is ahead of the watermark. A state file written by this node's
  own in-progress automatic promotion is allowed and participates as
  `state_term`/`state_version`; a foreign or unmarked stale state must be
  reconciled first;
- it can reach the lease backend and pass its conformance probe.

A candidate that is behind the lease record refuses to promote. If the missing
bundle existed only on the dead master, the lease cannot recover it; the
supported path is then manual promotion with an operator-chosen state (the
candidate's last applied content), never a fabricated version.

The candidate does **not** need `require_slaves` to be satisfied (that is a
master-only policy), but it applies its configured `[ha]` policy after
promotion.

### Identity and key prerequisites

A promoted node must be able to sign bundles and terminate mTLS as the master
identity. The candidate therefore also needs:

- a local Ed25519 signing key whose public key matches every slave's
  `master_pubkey` and the `signing_key_pubkey` persisted in `ha_state.toml`;
- a master mTLS certificate/key that every slave pins (or a CA they trust),
  with a SAN matching the URL the slaves use;
- the master-side listener material (`pinned_slave_fingerprints` or `ca`,
  `slave_token` where configured).

This is a pre-provisioning decision; promotion cannot invent the identity.
Copying the master private key to every candidate increases key exposure, and
per-node signing keys would require a trust-bundle or protocol change (out of
scope). The manual procedure copies the key/cert as an explicit operator step.
Automatic promotion must refuse when the identity is missing or mismatched
(`candidate_identity_mismatch`) instead of publishing bundles that every slave
will reject.

### Interaction with `require_slaves` / `require_all_slaves`

These keys gate **master readiness**, not election safety or election
eligibility. Automatic promotion must not reinterpret or bypass them:

- With `require_slaves = true`, a promoted master with no connected slaves
  reports not-ready (`HA requires at least one synced slave (0/N connected)`)
  while still serving DNS and accepting configuration writes.
- With `require_all_slaves = true`, a two-node cluster whose peer is gone (or
  fenced and not re-enrolled) reports not-ready forever after promotion because
  zero connected slaves already fails the policy. DNS still serves.
- Therefore the combination of automatic promotion and a strict slave
  requirement is operationally contradictory in a two-node topology: failover
  succeeds but the node never becomes ready. The ADR recommends leaving both
  `false` when `[ha.promotion]` is enabled, or accepting the not-ready state and
  documenting it in the runbook.
- `require_slaves` never makes a slave a candidate, and a candidate never
  promotes merely because `require_slaves` is unmet on the old master.

### Interaction with term, watermark, divergence and v1 rules

- **Term is the fencing token.** A promotion sets `term` from the CAS, never
  from a peer message. A stale holder's lower term is rejected by every slave
  even when its local version is higher.
- **Both term and version rise.** The first published version is
  `max(record.version, applied_version, state_version) + 1`, strictly above the
  record and the candidate's applied/attempted state. A term bump alone is not
  accepted, matching the existing rule that a promotion must continue above the
  applied version.
- **Watermarks are the rollback guard.** A promoted bundle below a slave's
  watermark is rejected. If the candidate is behind the record
  (`max(applied_version, state_version) < record.version`) it refuses to promote
  instead of publishing an older bundle.
- **Divergence stays sticky.** A stranded or forked slave is not repaired by
  promotion; it keeps its watermark, may reject the new master's same-version
  fork, and requires manual reconciliation. Automatic promotion never clears a
  fork latch and never injects a peer counter.
- **v1 is rejected before promotion.** A v1 `ha_watermark.toml`/`ha_state.toml`
  or a v1 peer fails startup/negotiation; promotion logic never runs.
- **A fenced old master does not reset its term.** It keeps its state file and
  waits for an operator. If it later rejoins as a slave, it goes through the
  normal watermark/resync path.

### Manual promotion interaction

The manual runbook (§2) remains the recovery path. Two rules keep it compatible:

1. If `[ha.promotion]` is enabled anywhere in the cluster, every effective
   master (manual or automatic) must hold the lease before accepting writes.
   The manual procedure must either acquire the lease first or disable
   `[ha.promotion]` on every node before promoting.
2. A manually promoted master that does not hold the lease is an operator
   bypass. Term/watermark rules still prevent a rollback on each individual
   slave, but two disjoint partitions can end up with different configuration
   histories. This is documented as a residual risk, not a supported mode.

`manual_override = true` is the deliberate human-in-the-loop option:

- the candidate still waits for master loss and still must acquire the lease;
- it does not publish until an authenticated Admin confirms the promotion
  (`POST /api/v2/ha/promote` with `{"confirm": true}`, Admin only; the endpoint
  is proposed for the implementation task, not added by this ADR);
- a confirmation while the master is still alive or the lease is held by
  another node is refused (`master_alive` / `lease_held_by_other`);
- no confirmation can bypass the lease. A forced promotion without a lease is
  the manual procedure with the old master stopped, not an automatic mode.

### Observability

`GET /api/v2/ha/status` gains a `promotion` object (proposed shape; C3b may
scaffold the disabled variant first):

```json
{
  "promotion": {
    "enabled": false,
    "candidate": false,
    "state": "disabled",
    "reason": "promotion_disabled",
    "term": 3,
    "lease_expires_in_secs": null,
    "last_attempt_unix_ms": null,
    "promoted_at_unix_ms": null,
    "lease_backend": "none"
  }
}
```

- `state`: `disabled` | `waiting` | `acquiring` | `lease_held` | `promoting` |
  `fenced` | `refused`.
- `reason` (stable codes): `promotion_disabled`, `not_candidate`,
  `master_alive`, `lease_held_by_other`, `lease_unavailable`,
  `lease_record_missing`, `candidate_behind`, `candidate_diverged`,
  `candidate_identity_mismatch`, `manual_override_required`, `lease_lost`,
  `fenced`, `v1_state`, `promotion_interrupted`.
- `lease_backend`: `none` | `file` | `external`; never the path itself.
- The existing top-level `ready`/`readiness_reason` remain authoritative for
  health. Fencing/unavailable conditions make the node not-ready; merely being a
  candidate or waiting does not.

Proposed Prometheus metrics:

- `sito_ha_promotion_enabled` (gauge 0/1)
- `sito_ha_promotion_lease_held` (gauge 0/1)
- `sito_ha_promotion_term` (gauge; the current fencing token)
- `sito_ha_promotion_attempts_total{result}` (counter:
  `acquired|conflict|refused|error`)
- `sito_ha_promotion_lease_renew_failures_total` (counter)
- `sito_ha_promotion_fenced_total{reason}` (counter)
- `sito_ha_promotion_refusals_total{reason}` (counter)
- `sito_ha_promotion_last_success_timestamp_seconds` (gauge; observability only,
  not a safety input)

Audit events are structured `tracing` records (node instance, outcome, reason,
term, version, lease holder; never keys, tokens or certificate material):

- `ha.promotion.lease_acquired` (info)
- `ha.promotion.lease_renewed` (debug)
- `ha.promotion.lease_lost` (warn)
- `ha.promotion.fenced` (warn/error)
- `ha.promotion.refused` (info/warn, with reason)
- `ha.promotion.completed` (info)
- `ha.promotion.manual_confirmation_required` / `_confirmed` (info)

### Protocol impact

None in 2.0. The existing signed bundle already carries `term` and `version`,
and slaves already enforce term monotonicity plus version continuity. No new
wire field, no protocol v3, and no change to `PROTOCOL_VERSION` are part of
this ADR.

The optional audit fields written into `ha_state.toml` are additive and ignored
by readers that do not know them. The mandatory promotion state (`term`,
`version`, bundle) already exists in the v2 shape, so a downgrade does not need
a new state format; it only needs `[ha.promotion]` removed from the config (see
"Migration and rollback").

### Availability in 2.0

Automatic promotion is **unavailable**. `enabled = true` fails closed:

```
ha.promotion.enabled = true requires a conforming shared lease backend
(linearizable compare-and-swap with authoritative expiry); automatic promotion
is unavailable in 2.0. Keep [ha.promotion] disabled and use the manual
promotion procedure, or an external orchestrator that fences the old master and
invokes it.
```

The failure surfaces in `check-config` (non-zero exit), startup (refuses to
start the HA role that would need it), and API config writes (rejected before
persistence). It never silently degrades to heartbeat-only or to a local file.

C3b registers the keys and this gate. It does not implement acquisition,
renewal, self-fencing, auto-role switching, the confirmation endpoint, or a
lease backend. Those are blocked on a conforming provider and a follow-up
implementation task.

For 2.0 acceptance, the evidence is the existing manual-promotion E2E plus this
fail-closed gate: automatic promotion is unreachable by configuration, so it
cannot introduce a split-brain path. The behavioral suite below is a
prerequisite for the future implementation, not a 2.0 deliverable.

## Safety argument

### Invariants

**I1 — One lease holder per term.** The backend's CAS is linearizable and
durable, and a renewal of an expired record fails. Therefore at most one node
can hold term `T` in good standing. Renewals keep `T`; only a takeover grants
`T+1`.

**I2 — Only a lease holder can produce an accepted new term.** A node raises
its term only in the acquisition step, after winning the CAS. Slaves reject a
bundle whose term is lower than the term they applied; a new term is accepted
only when it is strictly higher and the version continues above the watermark.
A stale holder's term is lower than the new holder's, so its bundles are
rejected regardless of its local version.

**I3 — No rollback.** A promotion publishes at
`max(record.version, applied_version, state_version) + 1`, so the first bundle
is strictly above every published/applied baseline this node knows. Slaves
enforce version continuity and their watermark, and a candidate behind the
lease record refuses to promote. A higher term alone cannot bypass this rule.

**I4 — A holder stops before the backend can grant its term elsewhere, under
bounded clock drift.** The self-fence deadline is `TTL - max(2,
renew_interval)`, strictly earlier than backend expiry when the backend clock
does not jump forward relative to the holder's monotonic clock. A holder that
cannot renew stops publishing, stops accepting mutations, and keeps DNS
read-only. The gap between self-fence and expiry is the safety margin for
scheduling and clock resolution. If the backend expires the record early (its
clock jumps forward), the old holder may still accept a local mutation until its
own deadline, but its term is already superseded; no slave applies its bundle.
The safety property is preserved; the local window is covered below.

**I5 — Safety does not use wall clocks.** Expiry is decided by the backend.
The holder measures elapsed time with `CLOCK_BOOTTIME`. Wall-clock steps force
a fence instead of extending a lease. Bounded NTP skew therefore does not create
two holders.

### Why the failure modes do not produce two accepted writable masters

- **Crash:** the lease is not renewed and expires; exactly one candidate wins
  the CAS at `T+1`. The old process is gone.
- **Partition:** the old master cannot renew. It fences at `TTL - margin`; the
  candidate can acquire only after backend expiry. During the overlap window the
  old master is read-only, and any late bundle has the lower term and is
  rejected.
- **Asymmetric connectivity:** the side that can reach the lease store wins;
  the side that cannot renews nothing and fences. Reachability of the lease
  store—not heartbeat delivery—is the arbiter.
- **Two candidates:** the CAS linearizes them. One gets `T+1`; the other gets a
  conflict and stays read-only. The loser's later retry cannot reuse `T+1`.
- **Stale master returns:** it holds `T`; the cluster applied `T+1`. Its
  bundles fail the term check before version comparison. It also cannot renew a
  record owned by `T+1`, so it cannot regain write status.
- **Pause past expiry:** on resume, the first lease-guarded operation re-reads
  the lease and fails; the node fences. A mutation accepted between resume and
  the guard check is local-only: the node no longer holds `T+1`, so its bundle
  is rejected by every slave. It cannot become a cluster-accepted writable
  master.
- **Clock skew:** the backend expires the lease; the holder's conservative
  monotonic deadline is independent of wall time. A wall-clock jump fences
  rather than extends. If the backend itself jumps forward, the holder may
  briefly accept local writes until its own deadline, but the new holder already
  has the higher term, so those writes are never applied.
- **Crash during promotion:** state is written atomically after the CAS and
  before publishing. A restart is a new holder (new process UUID), so it cannot
  renew the crashed process's grant; it waits for expiry and re-acquires at
  `T+1`, or stays fenced. There is no path where it publishes at `T` without a
  live grant.
- **v1 state:** rejected before promotion logic runs.

### What this design does not protect against

- **A non-conforming lease backend.** If the CAS or its expiry check is not
  linearizable, if a renewal can resurrect an expired record, if reads or the
  revision are stale, or if acknowledged writes are lost, two holders are
  possible. This is exactly why 2.0 refuses to enable the feature without a
  probed provider. A plain NFS/SMB share is not sufficient.
- **A process pause between the final lease check and a local in-memory
  mutation.** The mutation may be accepted locally but cannot be published
  under a valid higher term, so it never becomes cluster-accepted. Eliminating
  the local window requires external fencing (STONITH, power-off, or a storage
  layer that rejects writes from a non-holder), which is outside sito.
- **Operator bypass.** A manual promotion that neither acquires the lease nor
  disables `[ha.promotion]` can create two disjoint configuration histories.
  Each slave's watermark prevents a rollback of that slave, but the histories
  are not merged automatically.
- **Loss of the lease record.** A missing record with a non-zero applied term
  refuses promotion (`lease_record_missing`); recovery is manual. A record lost
  at a brand-new cluster (term 0) is just initialization.
- **In-flight publish divergence.** A candidate may promote with a version that
  another slave saw with different content; the fork latch rejects it. There is
  no automatic merge. Manual reconciliation is required.
- **Endpoint/VIP/DHCP cutover.** Promotion changes the writable master, not
  client routing. DNS clients may continue querying the old node (read-only,
  last applied configuration). A virtual IP or DHCP update remains an external
  operational step.
- **Storage/VIP split-brain below sito.** A shared mount visible to only one
  node, a partitioned virtual IP, or a compromised host defeats any in-process
  lease.
- **Compromised keys or root.** An attacker who can sign bundles or write the
  lease record is outside the failure model.
- **Availability when the lease store is down.** A candidate that cannot reach
  the store does not promote. This is intentional: no arbiter, no promotion.
- **Availability when the master is alive but cannot reach slaves.** If the
  master can still renew, it keeps the lease and no candidate promotes; slaves
  serve their last applied configuration and writes wait for delivery. This is
  intentional (the master is not dead), and `require_slaves`/`require_all_slaves`
  expose the condition as not-ready when configured.

## Test plan (for C3b)

The 2.0 gate is testable now. C3b adds the schema/fail-closed tests in part A.
The behavioral suite in part B is mandatory before any release may enable the
feature; the follow-up implementation task must run it against a conformance
fake that implements the CAS/expiry contract, never against a sleep-based file
mock.

### A. Schema and fail-closed tests (must land in C3b)

| Test intent | Expected |
|---|---|
| Full v2 document with `[ha.promotion]` and `enabled = false` loaded through the real loader (`Config::load`/`check-config`, not `HaConfig` alone) | Parses; every key retains its value/default |
| Same fixture through `crates/sito-core/src/config/tests.rs` `SCHEMA_FIXTURE` and the map-drift test | No unknown-key/drift failure |
| `enabled = true` with no `lease_path` | `check-config` and startup fail with `ha_promotion_unavailable`/missing path; config not persisted |
| `enabled = true` with a `lease_path` | Still refused with `ha_promotion_unavailable` in 2.0 (no conforming backend) |
| `candidate = true` on `server.role = "master"` with `enabled = true` | Validation error |
| `enabled = false` with all other keys set | Accepted; no new file, thread, metric or readiness gate |
| `lease_ttl_secs`/`renew_interval_secs`/`heartbeat_timeout_secs` out of bounds or inconsistent | Validation error naming the key |
| `lease_path` inside `server.data_dir`, relative, or with a missing/unwritable parent | Validation/preflight error |
| Unknown `[ha.promotion]` key | Rejected by the v2 unknown-key policy |
| No-HA build with `[ha.promotion]` | Rejected with the existing "HA feature missing" error, not an unknown-key error |
| No `[ha.promotion]` section | Byte-for-byte behavior unchanged; existing HA tests pass |

### B. Behavioral conformance (required before enabling in any release)

| Scenario | Required evidence |
|---|---|
| Partition/fork/resync | Cut the master-candidate link; candidate promotes after heartbeat timeout + lease expiry; old master resumes and its lower-term bundle is rejected; DHCP/DNS reads continue; no rollback; stranded fork visible and latched |
| Asymmetric connectivity | Candidate reaches the lease store, master does not → master fences at `TTL - margin`, candidate acquires after expiry; reverse direction → candidate cannot promote; no two holders |
| Lease expiry / renew failure | Revoke renewal; assert mutation API `409`, no publish, DNS still answers, `ha_promotion_lease_lost`, metrics/audit emitted |
| Stale master fencing | Old master publishes at `T` after a `T+1` promotion; every slave rejects; old master cannot renew; it stays fenced after reconnect |
| Candidate promotion | Term is `max(record.term, applied_term, state_term)+1`; the first published version is `max(record.version, applied_version, state_version)+1`; slaves apply; `ready` follows `require_slaves`; `ha_state.toml` has the promoted term/version |
| Two-candidate race | Two candidates CAS the same expired record; exactly one `T+1`; loser gets conflict, stays read-only; repeated retries cannot produce two terms |
| Renewal/takeover race | A candidate reads an expired-looking record, then the holder renews; the candidate's `Takeover` with the stale revision fails. Only a fresh read of an expired record can take over |
| Clock skew | Step wall clock ± during a valid lease; holder deadline is unchanged; a step beyond the fence threshold forces a fence; backend expiry decides takeover |
| Crash during promotion | Kill between CAS, state write, and first publish; restart must re-acquire as a new holder and must never publish `T` without a grant; no partial/overwritten state |
| Pause/SIGSTOP past TTL | Resume after `> TTL`; node fences before serving writes; a local mutation (if any) never reaches a slave |
| Manual override | `manual_override = true` waits for Admin confirm; confirm is refused while master is alive/lease held; confirm with the lease succeeds; no path bypasses the lease |
| Master restart with promotion enabled | A restarted master must acquire a new term before writes; it republishes at a higher version even with unchanged config. Without the lease it starts read-only (`ha_promotion_lease_unavailable`) |
| Manual/automatic interaction | Manual promotion with promotion enabled must acquire the lease or be refused; disabling promotion restores the old path |
| `require_slaves` / `require_all_slaves` | Promoted master applies the policy; two-node + `require_all_slaves` reports not-ready with zero slaves while DNS serves |
| v1 rejection | v1 watermark/state/peer refuses startup/negotiation before promotion; no term is raised |
| Lease record loss | Missing record with `applied_term > 0` refuses promotion (`lease_record_missing`); no term reset |
| Identity mismatch | Candidate without the trusted signing key/master certificate stays read-only (`candidate_identity_mismatch`); no bundle that slaves reject is published |
| Backend conformance failure | A fake with non-linearizable CAS or stale reads is refused at enable/probe; no fallback |

### C. Soak and property checks

- Random partitions, kills, pauses and clock steps across 2- and 3-node
  topologies; assert "no term ever has two holders" and "a slave's applied term
  never moves backward" for the whole run.
- Property test on the lease state machine: CAS conflicts, expiry boundaries,
  renewal at `TTL - epsilon`, takeover at `TTL + epsilon`, monotonic terms.
- Reconnect/backoff: a losing candidate does not starve the winner with CAS
  hammering.

## Migration and rollback

### Default off

- No `[ha.promotion]` section, or `enabled = false`: identical to 2.0 rc
  behavior. No new file is created, no thread runs, no metric or readiness
  reason is added. Existing clusters need no action.
- The keys are additive to config v2 once C3b registers them. A document that
  does not use them is unchanged.
- Because 2.0 refuses `enabled = true`, no cluster can accidentally acquire the
  new behavior by upgrading.

### Enabling (future, after a conforming backend ships)

1. Upgrade every node to a build that understands `[ha.promotion]`.
2. Confirm every node holds a valid v2 watermark/state.
3. Choose exactly one candidate (a slave).
4. Provision the master identity on the candidate: the Ed25519 signing key and
   the master mTLS certificate/key that every slave already trusts (or a
   planned rotation). Confirm `signing_key_pubkey` and the pinned fingerprint
   match.
5. Set `enabled = true` on every node and `candidate = true` only on the chosen
   slave. Use the same `lease_path`, TTL, renew interval and heartbeat timeout
   cluster-wide.
6. Verify the backend conformance probe and `check-config` on every node.
7. Start the master (it acquires the lease before accepting writes), then the
   candidate.
8. Verify `promotion.state`/lease metrics, and exercise one planned takeover in
   a maintenance window before relying on it.

### Disabling

1. Set `enabled = false` on every node and restart the HA nodes in the normal
   order.
2. After the restart, promotion is off; a currently fenced node remains
   read-only until an operator reconciles it. Disabling does not auto-promote
   or auto-heal.
3. The lease record is inactive. Delete it only after every node is disabled
   and the old master is confirmed stopped; deleting a live lease is an
   operator-induced split-brain risk and is not needed for rollback.

### Downgrade

- Remove `[ha.promotion]` before running a binary that predates the keys; a v2
  parser that does not know them rejects the document as unknown configuration.
- `ha_state.toml` remains valid v2 state. Optional audit fields are ignored by
  older readers; if an older master rewrites the file, the audit metadata is
  lost but `term`/`version`/bundle survive. Keep a backup before downgrading.
- If a promotion happened, restore the pre-upgrade `config.toml`,
  `ha_state.toml`, `ha_watermark.toml` and certificates per the
  [HA runbook §7.3](../runbook-ha.md#73-downgrade-v2--v1), then verify `Synced`.
  Never copy a watermark between nodes.
- Do not downgrade a fenced node into a writable master by editing only the
  role. Reconcile the term/version first; a stale state file is rejected by
  slaves but may serve stale answers locally.

## Open questions and rejected scope

- **Lease backend/provider remains open.** No provider is in scope for 2.0. A
  future ADR or implementation task must name and test one against the contract
  above before `enabled = true` can be accepted.
- **No new consensus system.** Raft/Paxos, embedded etcd/Consul, a witness node
  or a quorum membership service are rejected here and remain out of scope.
- **No multi-candidate ordering or membership list.** A single designated
  candidate avoids a membership/agreement problem. If a future design adds an
  ordered candidate list, it needs its own safety argument.
- **Candidate identity provisioning is manual.** Copying the master Ed25519
  signing key and mTLS certificate/key to the candidate (or introducing
  per-node keys with a trust bundle) is an operational decision with a real
  exposure trade-off. Automatic key distribution is out of scope.
- **No automatic demotion of a returning master.** A fenced node stays fenced
  until an operator reconciles it. Automatic rejoining could ping-pong terms.
- **No automatic fork merge or peer-counter adoption.** Divergence stays sticky;
  a stranded slave is reconciled manually by design.
- **No endpoint/VIP/DHCP automation.** External tooling remains responsible for
  moving client traffic.
- **No heartbeat-only fallback, ever.**
- **No forced promotion that bypasses the lease.** `manual_override` is
  human-in-the-loop confirmation, not a way around mutual exclusion.

## Implementation checklist for C3b

C3b is a schema/fail-closed task, not a lease implementation.

1. **Config model**
   - Add a public `PromotionConfig` (nested table) to
     `sito-ha-types/src/config.rs` with
     `#[serde(default)] pub promotion: PromotionConfig` on `HaConfig`.
   - Defaults exactly: `enabled = false`, `candidate = false`,
     `lease_path = None`, `lease_ttl_secs = 30`, `renew_interval_secs = 10`,
     `heartbeat_timeout_secs = 45`, `manual_override = false`.
   - Validation: `enabled = true` → `ha_promotion_unavailable` in 2.0;
     when `enabled = true`, `candidate` is allowed only on slaves;
     TTL/interval/heartbeat bounds; `lease_path` absolute, outside the
     canonical `data_dir`, parent writable. When `enabled = false`, the other
     keys are inert (warn for `candidate`/`manual_override`).
2. **Schema inventory**
   - Register every key in `crates/sito-core/config-v1-to-v2-map.toml` with
     `status = "kept"` and exact paths:
     `ha.promotion.enabled`, `ha.promotion.candidate`,
     `ha.promotion.lease_path`, `ha.promotion.lease_ttl_secs`,
     `ha.promotion.renew_interval_secs`,
     `ha.promotion.heartbeat_timeout_secs`,
     `ha.promotion.manual_override`.
   - Add `[ha.promotion]` with every key to `SCHEMA_FIXTURE` in
     `crates/sito-core/src/config/tests.rs`.
   - Run `cargo test -p sito-core config_schema` and fix any drift.
3. **Positive real-loader test (required)**
   - A `check-config`/`Config::load` test that writes a complete v2 TOML with
     `[ha.promotion]`, loads it through the real loader, and asserts every
     value/default. A direct `HaConfig` deserialization test is **not**
     sufficient.
   - Negative tests: `enabled = true` refused; missing/relative/inside-data_dir
     `lease_path`; candidate on master; out-of-range intervals; unknown key;
     `[ha.promotion]` in a no-HA build rejected with the HA-feature error.
4. **Docs**
   - Add the keys and defaults to `docs/configuration-reference.md` §13 (the
     drift checker requires documented `kept` paths after the struct lands).
   - Add a commented `[ha.promotion]` block to `config.example.toml`.
   - Add a runbook note in §2 that automatic promotion is unavailable in 2.0,
     manual promotion is supported, and `enabled = true` is refused.
   - Cross-link this ADR from the runbook/config reference where the feature is
     mentioned.
5. **No behavior**
   - Do not add a lease thread, acquisition, renewal, auto-role flip, status
     fields beyond the disabled scaffold, metrics, or the confirmation endpoint
     in C3b unless the controller explicitly expands the scope after a
     conforming backend exists.
   - Ensure absent/`false` config is a no-op (existing HA tests unchanged).
6. **Checks**
   - `python3 scripts/check_config_reference.py`
   - `python3 scripts/check_markdown_links.py`
   - `python3 scripts/check_migration_guide.py`
   - `python3 scripts/check_test_matrix.py`
   - `cargo test -p sito-core config_schema`
   - `git diff --check`

## References

- [ADR-0002: High Availability Architecture (Master/Slave Push Replication)](0002-ha-master-slave-push.md)
- [HA runbook](../runbook-ha.md), especially
  [§2 manual promotion](../runbook-ha.md#2-manual-slave---master-promotion-procedure)
  and [§7 protocol v2 upgrade/downgrade](../runbook-ha.md#7-ha-protocol-v2-upgrade-and-downgrade)
- [Configuration reference §13 `[ha]`](../configuration-reference.md#13-ha--high-availability-masterslave-replication)
- [Config v2](../config-v2.md) and the
  [2.0 migration guide §8.2](../2.0-migration.md#82-ha-protocol-v2-upgrade)
