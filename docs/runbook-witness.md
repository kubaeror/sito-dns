# Witness Lease Server Runbook

This runbook covers the built-in witness used by **opt-in HA automatic
promotion** ([ADR-0010](adr/0010-ha-automatic-promotion.md)). The witness is a
separate `sito ha lease-server` process that grants one linearizable lease at a
time. It is not a consensus quorum, does not join the DNS data path and stores
no configuration.

> **Third failure domain required.** Run the witness on a host that is not one
> of the two HA nodes (a small VM, NAS, router or container on a third host).
> Co-locating it on an HA node is supported only for lab/test and is **not HA**:
> that node's failure takes the arbiter with it.

## 1. What the witness does

- TLS-only listener (TLS 1.2+) with a shared bearer token in
  `Authorization: Bearer <token>`.
- `X-Sito-Cluster: <cluster_id>` must match `--cluster-id` on every `/v1/*`
  request.
- One durable record (`state_dir/lease.json`) containing the holder, term,
  revision, published version/hash and expiry.
- `GET /healthz` (no auth), `GET /v1/info`, `GET /v1/lease`,
  `POST /v1/lease/acquire`, `POST /v1/lease/renew`.
- There is **no release endpoint**. A stopped holder leaves the record until it
  expires; the candidate waits.
- All operations are serialized behind one mutex and persisted atomically
  (temp file, `fsync`, `rename`, directory `fsync`) before the response.

The witness uses its own clock for expiry. Run NTP. Clients use monotonic local
time for self-fencing and never compare `expires_unix_ms` with their own wall
clock.

## 2. Provisioning

### 2.1 Directory layout

Use a dedicated directory, owned by the witness runtime user and mode `0700`.
The witness creates `state_dir` with mode `0700` if it does not exist.

```bash
sudo install -d -m 0700 -o sito -g sito /var/lib/sito-lease
sudo install -d -m 0755 -o sito -g sito /etc/sito/lease
```

`--state-dir` **must be local durable storage**, not NFS/SMB. A network share
reintroduces the stale-lock/partial-write problems the witness exists to avoid.

### 2.2 TLS certificate

The witness needs a server-auth certificate plus key:

```bash
# Standalone witness CA (fine when the HA nodes can trust a second CA).
sudo sito ha gen-certs \
  --dir /etc/sito/lease \
  --witness \
  --san witness.lan

# Or reuse the existing HA CA by generating into the directory that already
# contains ca.crt/ca.key:
sudo sito ha gen-certs \
  --dir /etc/sito/certs \
  --witness \
  --san witness.lan

sudo chown sito:sito <dir>/witness.crt <dir>/witness.key
sudo chmod 0600 <dir>/witness.key
```

`--san` must cover the host name every HA node uses in
`[ha.promotion.witness] server_name` (or the URL host). When `ca.crt`/`ca.key`
already exist in `--dir`, the witness certificate is signed by that CA; when
they do not, a new self-signed CA is created there. If you use an existing CA
outside `--dir`, issue a server-auth certificate with that SAN yourself; the
client's `[ha.promotion.witness] ca` is the issuing CA (or the self-signed
certificate). The optional `fingerprint` pin is the BLAKE3 hash of the DER
witness certificate, in addition to CA validation.

### 2.3 Bearer token

```bash
sudo openssl rand -hex 32 | sudo tee /etc/sito/lease/witness.token >/dev/null
sudo chown sito:sito /etc/sito/lease/witness.token
sudo chmod 0600 /etc/sito/lease/witness.token
```

Copy the **same** value to every HA node's
`[ha.promotion.witness] token_file` (mode `0600`, owned by the node runtime
user). The witness refuses to start if the token file is not exactly `0600`.
Treat the token as a cluster secret: anyone with TLS access and the token can
acquire the lease.

### 2.4 Start the witness

```bash
sudo -u sito sito ha lease-server \
  --listen 0.0.0.0:8954 \
  --cluster-id home-dns \
  --cert /etc/sito/lease/witness.crt \
  --key /etc/sito/lease/witness.key \
  --token-file /etc/sito/lease/witness.token \
  --state-dir /var/lib/sito-lease
```

Example systemd unit:

```ini
[Unit]
Description=sito HA witness lease server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=sito
Group=sito
ExecStart=/usr/local/bin/sito ha lease-server \
  --listen 0.0.0.0:8954 \
  --cluster-id home-dns \
  --cert /etc/sito/lease/witness.crt \
  --key /etc/sito/lease/witness.key \
  --token-file /etc/sito/lease/witness.token \
  --state-dir /var/lib/sito-lease
Restart=on-failure
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/var/lib/sito-lease
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

### 2.5 Verify

```bash
curl --fail --cacert /etc/sito/lease/ca.crt https://witness.lan:8954/healthz
curl --fail --cacert /etc/sito/lease/ca.crt \
  -H "Authorization: Bearer $(sudo cat /etc/sito/lease/witness.token)" \
  -H "X-Sito-Cluster: home-dns" \
  https://witness.lan:8954/v1/info
```

`/healthz` returns `200` only when the process is up and the state directory is
writable; otherwise `503`. It has no detail body and needs no auth.

## 3. State files and backup/restore

`state_dir` contains:

| File | Mode | Purpose |
|---|---|---|
| `lease.json` | `0600` | Current record, or absent before the first grant. |
| `initialized` | `0600` | Sentinel written after the first successful grant. |
| `lease.lock` | `0600` | Lifetime advisory lock; keeps offline tools out. |

**Never delete `initialized` to reset the term.** If `initialized` exists but
`lease.json` is missing or corrupt, the witness refuses to start with
`state_missing`/`state_corrupt`. A record from a different cluster refuses with
`state_cluster_mismatch`.

Backup:

1. Stop the witness (`systemctl stop sito-witness`). This releases
   `lease.lock`; an active lease is **not** released and remains until expiry.
2. Copy the whole state directory, preserving ownership and mode:
   `tar -C /var/lib -cpf witness-state.tar sito-lease`.
3. Store it with the cluster configuration backups.

Restore:

1. Stop every witness and every HA node.
2. Restore the directory to `--state-dir` with mode `0700`/`0600` as above.
3. Start the witness, then the HA nodes. Never copy a watermark between nodes.

A missing or lost state directory is **not** auto-reinitialized. Use a restore
first; only if no backup exists use the explicit offline tool in §5.

## 4. Rotation

Update the witness and every HA node **together**:

### Token rotation

1. Generate a new token.
2. Stop the witness.
3. Replace `witness.token` on the witness and on every node's
   `witness.token_file`.
4. Start the witness, then restart the HA nodes.

### Certificate rotation

1. Issue a new witness certificate/key with the same SAN (or a SAN matching the
   updated `server_name`).
2. Distribute the new CA (if it changed) and update `witness.ca` /
   `server_name` / optional `fingerprint` on every node.
3. Replace the witness certificate/key and restart the witness, then the nodes.

A mismatch is **read-only**, not a fallback: nodes report
`witness_auth_failed`/`witness_tls_failed`, reject mutations with `409`, keep
serving DNS from the last snapshot, and retry. There is no plaintext or
unauthenticated fallback.

## 5. Offline recovery: lease-admin set

Use this only when the witness record is **behind** the cluster: its term is
lower than the cluster's current term, or its published version is older than
the cluster's current published baseline (for example after restoring a backup
or an operator bypass). Never hand-edit `ha_state.toml` above the witness.

The record stores the **last successfully published bundle baseline**, not the
next version. Set `--version` and `--bundle-hash` to the cluster's current published `(published_version, published_hash)` — the content every master and
candidate already has. It must be strictly greater than the old witness
version, but it must **not** be above the cluster baseline:

- `acquire` requires the candidate's published version to be at least the
  witness version, and at equality the same hash. A witness version above the
  cluster makes every master/candidate fail
  `candidate_behind`/`master_state_behind`.
- Never pass the pending/publish-next version. Pass the published baseline that
  the node would send to `/v1/lease/acquire`.

Example: the old witness record is term 8 / version 127 / hash A, while the
cluster's current published baseline is version 128 / hash B.

1. Stop the witness. The tool refuses with `state_locked` while the witness
   process holds `lease.lock`.
2. Back up the state directory.
3. Raise the record to the cluster baseline:

```bash
sudo sito ha lease-admin set \
  --state-dir /var/lib/sito-lease \
  --term 9 \
  --version 128 \
  --bundle-hash blake3:<64-hex-cluster-published-hash-B> \
  --confirm
```

`--term` must be strictly greater than the old witness term (9 here); the next
acquire uses `term + 1` (10). `--version 128` is the cluster's published
baseline, not `129`: the next acquire presents `version = 128`, and the witness
accepts equality with the same hash. If the cluster has actually published
129/hash C, use `--version 129 --bundle-hash C` instead.

The tool:

- requires `--confirm`;
- refuses a term that is not **strictly greater** than the current record
  (`term_not_raised`) and, by default, a version that is not strictly greater
  (`version_not_raised`);
- backs up the previous `lease.json` (to `lease.json.bak` or
  `lease.json.bak.<unix_ms>`) before writing;
- writes an immediately expired record with the cluster id from the existing
  record, so the next acquire takes over at `term + 1`.

4. Start the witness and let the current/next master acquire.

### Term-only recovery after an offline signing-key rotation

An offline `sito ha rotate-signing-key` keeps the witness **published**
version/hash but raises the master's state term. In steady state the witness
record already has that same published version, so the strict path above fails
`version_not_raised`. Raising the witness version to the rotated pending version
is wrong: acquisition then reports `master_state_behind` because the witness is
above the cluster's published baseline.

Use the explicit term-only mode instead. It requires a strictly higher term and
the **exact** current bundle hash. The version may equal the current record (the
normal steady state) or be strictly higher under the ordinary strict-rise rule:

```bash
sudo sito ha lease-admin set \
  --state-dir /var/lib/sito-lease \
  --term <TERM >= ROTATED_TERM> \
  --version <PRESERVED_PUBLISHED_VERSION> \
  --bundle-hash <PRESERVED_PUBLISHED_HASH> \
  --allow-equal-version \
  --confirm
```

- `--allow-equal-version` (alias `--term-only`) accepts `version == current`
  only when `bundle_hash` is identical. It still refuses an equal/lower term, a
  lower version, and an equal version with a different hash
  (`term_not_raised`, `version_not_raised`, `bundle_hash_mismatch`).
- A version **higher** than the record still follows the normal strict-rise
  rule; a lower version is always refused.
- The record is expired and revision-bumped exactly like the strict path. The
  next acquire takes over at `term + 1` with the unchanged published baseline,
  then publishes the rotated pending bundle version.
- The rotation CLI prints this exact command with the preserved values; do not
  substitute the rotated pending version/hash.

The strict `sito ha lease-admin set` without `--allow-equal-version` remains
unchanged for normal recovery where the witness version is genuinely behind the
cluster baseline.

> **The tool only raises.** It cannot lower a version. If the witness was set
> above the cluster's published baseline, restore the state backup; do not try
> to “fix” it by raising the cluster or by editing `lease.json` by hand.

## 6. Failure behavior and monitoring

- **Witness unreachable:** the current master stops renewing, self-fences at its
  deadline, rejects mutations with `409`, keeps serving DNS read-only and
  retries. No promotion occurs until the witness returns. This is an
  availability trade-off, not a safety fallback.
- **Witness crash/restart:** the record reloads from `lease.json`; the existing
  term/revision/expiry are preserved. A restarted holder is a new process and
  must wait for expiry and acquire `term + 1`.
- **Clock step forward:** a lease can expire early; quiesce and self-fence still
  bound handover. **Clock step backward:** a lease lasts longer; the holder's
  local deadline still fences it and no takeover occurs. Run NTP.
- **Disk full / read-only state dir:** `/healthz` returns `503`; acquire/renew
  return `500 storage_error` and do not report success.
- Monitor `/healthz` and `/v1/info` from an external checker. Do not configure a
  supervisor to restart HA nodes solely on their `/health` signal while the
  witness is down: they intentionally run read-only, and a restart loop cannot
  restore the witness.

## 7. Upgrade, downgrade and rollback

- The witness is part of the same `sito` binary; deploy the HA-enabled build.
  The state schema is version 1.
- **Upgrade:** stop the witness, replace the binary, start it. The record is
  reloaded; no term changes.
- **Downgrade:** stop every HA node and disable `[ha.promotion]` first. Keep a
  copy of `state_dir`; do not delete `initialized` or `lease.json`.
- Disabling promotion does not clear a node's durable fence marker; use
  `sito ha clear-fence --confirm` only after verifying the current master/term.
- A disabled promotion cluster does not need the witness, but leave its state
  directory intact until every node is disabled and no master is running.

## 8. Troubleshooting

| Symptom | Meaning / action |
|---|---|
| `state_locked` on startup | Another witness process (or `lease-admin`) holds `lease.lock`. Stop it; do not delete the lock file. |
| `state_missing` | `initialized` exists without `lease.json`. Restore the backup; `lease-admin set` needs a readable record and cannot recreate one. |
| `state_corrupt` | `lease.json` is unreadable/invalid. The witness refuses to start and `lease-admin set` cannot parse the record either; restore the state backup. If no backup exists, an explicit manual reinitialization is required after every node is disabled. |
| `state_cluster_mismatch` | `--cluster-id` differs from the record. Fix the configuration or restore the matching state; never edit the cluster id in place. |
| `token_file_permissions` | `--token-file` is not exactly `0600`. |
| TLS handshake failures | Wrong CA/SAN/fingerprint, expired certificate, or client `server_name` mismatch. |
| `401` | Missing/wrong bearer token. |
| `403 cluster_mismatch` | Missing/wrong `X-Sito-Cluster`. |
| `409 cas_mismatch` | Another holder won, the revision/term changed, or the lease is still live. Re-read `GET /v1/lease`; never retry the same CAS blindly. |
| `413` | Request body exceeded 16 KiB. |
| `500 storage_error` | Atomic state write failed. Check disk, permissions and `lease.lock`. |
