# HA automatic promotion client and observability

[ADR-0010](adr/0010-ha-automatic-promotion.md) defines opt-in automatic
promotion with a single witness arbiter. The 2.0 build implements the whole
client path: configuration validation, the TLS/bearer witness client, the
acquisition/quiesce/reconcile/publish state machine, durable self-fencing, the
`promotion` status object, Prometheus metrics, structured audit records and the
local `confirm-promotion`/`clear-fence` CLI.

> **Status.** Automatic promotion is opt-in and default `false`. With
> `ha.promotion.enabled = false` no witness client, promotion thread, file,
> metric family or readiness gate is created; only the stable
> `promotion.state = "disabled"` status object is exposed. Enabling it requires a
> witness on a third host and a coordinated cluster upgrade.

## Configuration and validation

The exact keys, defaults and ranges are in
[the configuration reference §13](configuration-reference.md#13-ha--high-availability-masterslave-replication).
Validation is shared by startup, `check-config`, API writes and HA apply:

- `backend` must be `"witness"` even when promotion is disabled;
- when enabled, `cluster_id`, `node_id`, `witness.url`, `witness.ca` and
  `witness.token_file` are required, and all bounds in the reference apply;
- `candidate = true` requires `server.role = "slave"` when enabled;
- `heartbeat_timeout_secs` defaults to `max(45, 3 * ha.ping_interval_secs)`;
- `witness.url` must be `https://host[:port]` with no userinfo, path, query or
  fragment; `ca` and `token_file` must be absolute paths.

`check-config` never contacts the witness.

## Witness client

`WitnessClient` (in `sito-ha`) connects per request with a 5 s deadline and:

- verifies the witness certificate chain against `witness.ca`, always validating
  the SAN (`server_name` defaults to the URL host);
- additionally enforces `witness.fingerprint` when configured (BLAKE3 of the
  DER server certificate);
- sends `Authorization: Bearer <token>` from the `0600` `token_file` and
  `X-Sito-Cluster: <cluster_id>`;
- implements `GET /v1/info`, `GET /v1/lease`, `POST /v1/lease/acquire` and
  `POST /v1/lease/renew`;
- returns typed errors with the ADR read-only reasons
  (`witness_tls_failed`, `witness_auth_failed`, `witness_cluster_mismatch`,
  `witness_unavailable`, `witness_protocol_mismatch`) and the current record on
  a 409 conflict.

There is no plaintext, unauthenticated or unpinned fallback, and `info`
rejects a protocol-version or `cluster_id` mismatch rather than accepting it.

## Promotion state machine

The safety-critical sequence lives in `sito-ha::promotion` and is driven by the
daemon supervisor in `sito`:

1. **Boot.** An enabled master starts read-only (`ha_promotion_starting`) and
   never accepts a mutation before it holds a live lease and published a bundle.
   An unreconciled fence marker makes it `fenced`/read-only. An enabled
   candidate waits for master loss.
2. **Acquire.** After the heartbeat timeout the candidate reads the witness
   record, verifies the published baseline (`max(applied, state.published)`),
   refuses `candidate_behind`/`candidate_forked`/`candidate_term_ahead`, and
   acquires `term + 1` only with the published baseline. A configured master
   restart uses the durable `state.published_version`/hash and the same rules.
3. **Persist.** The promoted state is written atomically with
   `publication_state = "pending"` (or a preserved `"publishing"`) and the
   pending bundle version. The pending version is never sent to the witness.
4. **Quiesce.** The node waits `lease_ttl_secs` without accepting writes or
   publishing, renewing the **published** baseline.
5. **Reconcile.** A hello-only listener collects peer term/version/hash reports
   for `reconcile_window_secs` and sends no `ConfigPush`. A reachable ahead,
   forked, unknown-in-flight or hash-less peer aborts before any publish.
6. **Publish.** The node writes `"publishing"`, pushes the first bundle at
   `max(baseline + 1, pending_version)`, writes `"published"`, renews the
   witness with the new baseline, switches to the master role and becomes
   writable.
7. **Renew/fence.** Renewal uses the published baseline and the observed
   `(term, revision)`. The self-fence deadline is `TTL - max(2, renew_interval)`
   from the last ACK, measured with `CLOCK_BOOTTIME`. A lost/expired/foreign
   lease, a version regression, a clock step or an unrecoverable write failure
   persists `ha_fence.json` (+ `ha_fence.pending`) and stops writes. A restart
   stays read-only until an operator clears the marker.

A late peer that connects after reconciliation is latched/diverged; the master
never bumps its version above it and never overwrites it.

## Status

`GET /api/v2/ha/status` always includes a `promotion` object. The exact fields
and reason codes are tabulated in
[the configuration reference](configuration-reference.md#promotion-status).
The disabled shape is stable:

```json
{
  "promotion": {
    "enabled": false,
    "candidate": false,
    "backend": "witness",
    "cluster_id": null,
    "node_id": null,
    "state": "disabled",
    "reason": "promotion_disabled",
    "term": 0,
    "version": 0,
    "bundle_hash": "none",
    "publication_state": "published",
    "published_version": 0,
    "lease_revision": null,
    "lease_expires_in_secs": null,
    "witness_reachable": false,
    "quiesce_remaining_secs": 0,
    "reconcile_remaining_secs": 0,
    "last_attempt_unix_ms": null,
    "promoted_at_unix_ms": null,
    "fenced": false
  }
}
```

The shared snapshot is published by the promotion supervisor, so the API never
needs to contact the engine or the witness. An enabled master looks like:

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
    "bundle_hash": "blake3:9f2c...64-hex",
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

The top-level `ready` and `readiness_reason` stay authoritative: a witness
failure or a fence is not-ready, while a candidate that is merely waiting is
not. The object contains no tokens, keys, certificate material or witness URLs.

## Metrics

When promotion is enabled, `/metrics` adds:

| Metric | Type | Labels |
|---|---|---|
| `sito_ha_promotion_enabled` | gauge | — |
| `sito_ha_promotion_lease_held` | gauge | — |
| `sito_ha_promotion_term` | gauge | — |
| `sito_ha_promotion_attempts_total` | counter | `result` |
| `sito_ha_promotion_witness_requests_total` | counter | `op`, `result` |
| `sito_ha_promotion_lease_renew_failures_total` | counter | — |
| `sito_ha_promotion_fenced_total` | counter | `reason` |
| `sito_ha_promotion_refusals_total` | counter | `reason` |
| `sito_ha_promotion_publish_aborts_total` | counter | `reason` |
| `sito_ha_promotion_quiesce_remaining_seconds` | gauge | — |
| `sito_ha_promotion_reconcile_remaining_seconds` | gauge | — |
| `sito_ha_promotion_last_success_timestamp_seconds` | gauge | — |

Labels are bounded to fixed sets (`result`: `success`, `refused`, `conflict`,
`witness_error`, `fenced`, `other`; `op`: `info`, `lease`, `acquire`, `renew`,
`other`; `reason`: the ADR reason codes, otherwise `other`). Node IDs, holders,
tokens and cluster IDs are never labels. A configured-but-disabled cluster
exposes only `sito_ha_promotion_enabled 0`; a non-HA build exposes no promotion
series at all.

## Audit events

Structured `tracing` records use the `sito::ha::promotion` target and the fixed
fields `node_id`, `outcome`, `reason`, `term`, `version`, `holder` (no tokens,
keys or certificate material):

- `ha.promotion.lease_acquired`, `_lease_renewed`, `_lease_lost`;
- `ha.promotion.fenced`, `_refused`, `_quiesced`, `_reconciled`, `_completed`,
  `_publish_aborted`;
- `ha.promotion.manual_confirmation_required`,
  `_manual_confirmation_confirmed`.

## CLI

```bash
# On the candidate, after verifying master loss:
sudo -u sito sito ha confirm-promotion --confirm --config /etc/sito/config.toml

# After verifying the current master/term:
sudo -u sito sito ha clear-fence --confirm --config /etc/sito/config.toml
```

`confirm-promotion` writes `data_dir/ha_promote.confirm` atomically (mode
`0600`) with `{protocol_version, cluster_id, node_id, requested_at_unix_ms,
nonce}`. The candidate consumes it exactly once, after master loss, verifies the
identity and age (no older than the effective heartbeat timeout), and removes
it. A live master or another holder means it is not consumed; a restart discards
it. It never bypasses the witness and the slave API remains read-only.

`clear-fence` removes `ha_fence.json` and `ha_fence.pending` for the configured
cluster/node. It does not grant a lease; the node must still acquire a new term.
A marker belonging to a different cluster/node is refused as a data-dir mix-up.

## Hash normalization

All bundle hashes (`bundle_hash`, `have_bundle_hash`, `published_hash` and the
witness pin) are normalized to 64 lowercase hex characters. `blake3:<hex>` and
bare `<hex>` are equivalent on input. `"none"` means "no published bundle" and is
valid only at version 0. A malformed hash is rejected locally before a lease
request is sent.

The optional `have_bundle_hash` Hello field is additive: older v2 peers omit it,
which means "unknown"; a malformed present value is rejected. No
`PROTOCOL_VERSION` bump is required.

## Operational caveats

- The witness is a single point of **availability**, not safety. If it is
  unreachable, the current master fences after the TTL and no promotion occurs
  until it returns; DNS continues read-only from the last snapshot.
- Run the witness on a third failure domain. Co-locating it on either HA node
  defeats the purpose and is documented as lab-only.
- Promotion does not move a VIP/DNS endpoint or distribute the master signing
  key/certificate. Provision the master identity on the candidate and keep
  `master_url` on a stable endpoint.
- A manual promotion while promotion is enabled must acquire the lease; never
  hand-edit a term above the witness. Disable promotion cluster-wide first if
  you need the old manual term/version procedure.
