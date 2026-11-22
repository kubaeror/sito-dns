# HA promotion witness client (2.0 foundation)

[ADR-0010](adr/0010-ha-automatic-promotion.md) defines opt-in automatic
promotion with a single witness arbiter. This note describes the client-side
foundation that ships in the 2.0 build: configuration validation, the TLS/bearer
witness client and the additive `have_bundle_hash` Hello field.

> **Status.** Automatic promotion is still opt-in and default `false`. This
> foundation does not start a promotion loop, quiesce/reconcile listeners,
> fence nodes, or expose promotion status/metrics. It is the transport and
> schema layer the promotion engine builds on, and it is inert when
> `ha.promotion.enabled = false`.

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

## Client behavior

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

## Hash normalization

All bundle hashes (`bundle_hash`, `have_bundle_hash`, `published_hash` and the
witness pin) are normalized to 64 lowercase hex characters. `blake3:<hex>` and
bare `<hex>` are equivalent on input. `"none"` means "no published bundle" and is
valid only at version 0. A malformed hash is rejected locally before a lease
request is sent.

The optional `have_bundle_hash` Hello field is additive: older v2 peers omit it,
which means "unknown"; a malformed present value is rejected. No
`PROTOCOL_VERSION` bump is required.
