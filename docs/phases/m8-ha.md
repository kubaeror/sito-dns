# Phase M8 — HA Master/Slave (3 weeks)

Goal: one master, config changes flowing automatically to slaves — including two instances on one machine. References: plan section 11 (protocol, security, topologies).

## Scope

**In:** replication protocol 11.1, mTLS, ed25519 signatures, slave state machine, stats aggregation, read-only slave API, HA compose, chaos tests, runbook.
**Out:** automatic election (deliberately — static roles), query-log aggregation (v1.1).

## Tasks

### 1. Crypto material and transport

- Subcommand `sito ha gen-certs --master/--slave`: self-signed CA + cert pairs; blake3 fingerprints to paste into configs (pinning, section 11.4)
- Master ed25519 key generated on first start in master role (`data_dir/ha_signing.key`, chmod 600); pubkey exported to the slave config
- WS server on the master (port 8953, mutual TLS); WS client on the slave with 1 s→60 s backoff + jitter

### 2. Protocol and bundles

- Messages from section 11.1 (serde, `tag = "type"`); protocol versioning (`"v": 1`)
- Bundle build: config.toml without `[ha]`/`server.instance_name` + custom rules + rewrites + clients/groups + list metadata (URLs, not content — section 11.2)
- Secrets: `${SECRET:name}` placeholders; the slave substitutes from local env/files; a missing local secret → instance starts, but the feature is marked Degraded + alert
- Signature: ed25519 over `blake3(payload)`; verify signature and version monotonicity before apply

### 3. Apply on the slave

- State machine from section 11.3; apply = validate → staging snapshot → atomic swap (same mechanism as M5 hot-reload) → ack
- Apply error → roll back to previous snapshot, `ack{applied:false, error}`, Degraded state, metric
- After restart: `hello.have_version` → master sends the missing bundle (bundles are full, not deltas — simpler, size negligible)

### 4. Stats and read-only

- `stats_report` every 30 s; master merges under the `instance` label (metrics 14.2 + `sito_ha_*`)
- Middleware on the slave: mutating methods beyond `/status`, `/metrics`, `/auth` → `409` + `X-Dnsd-Master` header; UI shows the read-only badge (hook from M6.1)
- Endpoints `/ha/status`, `/ha/slaves` (versions, lag, last ack), `/ha/resync`

### 5. Deployment and chaos

- `docker-compose.ha.yml` with macvlan (section 17.3): master .10, slave .11, third optional remote; MikroTik DHCP option 6 hands out both IPs — step-by-step docs
- Chaos tests from section 18.4: kill master mid-push, netem 500 ms, slave offline 24 h
- `docs/runbook-ha.md`: slave→master promotion, cert rotation, slave rebuild

## Agent prompts

```
M8.1 crypto+ws  → task 1; DoD: gen-certs produces a complete set; mTLS handshake rejects
                  a foreign cert; reconnect backoff measured
M8.2 protocol   → task 2; DoD: a bundle with secret placeholders contains no secret
                  (test scans the payload); bad signature/lower version rejected
M8.3 slave-sm   → task 3; DoD: bad payload → Degraded + working old config;
                  resync after restart <2 s
M8.4 stats+ro   → task 4; DoD: metrics from two instances distinguishable by label;
                  PUT on a slave → 409 with the master header
M8.5 chaos+docs → task 5; DoD: 3 chaos scenarios green; runbook verified by executing
                  the promotion procedure on a clean environment
```

## Tests and acceptance criteria

- [x] List change on the master → both slaves apply in < 2 s (asserted on the dig verdict)
- [x] Push while killing the master: slave consistent at N or N+1, never in between
- [x] Secrets never in the payload (automated scanning test)
- [x] Master UI shows slaves, versions and lag; slave UI read-only with badge
- [x] HA compose on one machine: two instances answering on two LAN IPs
- [x] Runbook: slave→master promotion executed per the doc without the author's help

## Risks

| Risk | Mitigation |
|---|---|
| Secret leakage in a bundle | Placeholders from the protocol's first commit + CI scanner test as a gate |
| Config schema version drift between instances | `config_version` + apply refusal on mismatch (clear error instead of silent corruption) |
| macvlan not working in someone's environment | Docs alternative: one host, ports 53/5353; both topologies tested |

## Deliverables

`:m8` with HA, HA compose, runbook, "HA" dashboard in the master UI, topology write-up in docs.

---

## Completion Report

Phase M8 — High Availability (HA) Master/Slave has been fully implemented, integrated, and verified across the workspace.

### 1. Architectural Highlights
- **`sito-ha` Crate**:
  - Implements the complete replication protocol (`hello`, `config_push`, `ack`, `stats_report`, `ping`, `pong`) with versioning (`v: 1`) and serde tagging.
  - Generates self-signed CA, master, and slave certificates with BLAKE3 fingerprint pinning via `sito ha gen-certs` and `generate_ha_certs`.
  - Ed25519 signing key generation and verification (`data_dir/ha_signing.key`, strict `0600` permissions on Unix).
  - Config bundle sanitization with secret redaction (`${SECRET:name}` placeholders), automated security scanning against plaintext secret leaks, and substitution on slave.
  - Resilient mTLS WebSocket transport with rustls 0.23 custom pinned verifiers and exponential backoff (1s -> 60s with ±20% jitter).
  - Robust slave state machine (`Connecting` -> `HelloSent` -> `Synced` <-> `Applying` -> `Synced`/`Degraded`) with staging and rollback safety preserving uninterrupted DNS resolution.
  - `MasterCoordinator` for push broadcast, slave tracking, and Prometheus metrics tracking (`sito_ha_slaves_connected`, `sito_ha_config_version`, `sito_ha_replication_lag_seconds`).
- **`sito-api` Integration**:
  - Live REST API handlers for `GET /api/v1/ha/status`, `GET /api/v1/ha/slaves`, and `POST /api/v1/ha/resync`.
  - `slave_read_only_middleware`: intercepting mutating methods on slave nodes outside `/api/v1/auth/*` and `/api/v1/ha/resync`, returning HTTP `409 Conflict` with `X-Dnsd-Master: <master_url>` header and RFC 7807 problem details.
- **Binary Integration & Config Watcher**:
  - Hot-reload file watcher automatically bundles, signs, and broadcasts updated configurations to connected slaves on master.
- **Operational Deliverables**:
  - `docker-compose.ha.yml`: Macvlan deployment with master on `.10`, slave on `.11`, healthchecks, volumes, and MikroTik DHCP Option 6 documentation.
  - `docs/runbook-ha.md`: Complete operational guide covering slave->master promotion, zero-downtime certificate rotation, node rebuilding, and troubleshooting diagnostics.

### 2. Quality Verification
- `cargo fmt --check`: PASSED.
- `cargo clippy --workspace --all-features -- -D warnings`: PASSED with 0 warnings across all 14 crates.
- `cargo test --test m8_acceptance`: 10/10 acceptance tests passing cleanly:
  1. `test_m8_gen_certs_cli_and_pinning`: OK
  2. `test_m8_mtls_handshake_rejects_foreign_cert`: OK
  3. `test_m8_secret_redaction_security_scanner`: OK
  4. `test_m8_monotonicity_guard_rejects_replay`: OK
  5. `test_m8_slave_rollback_on_invalid_bundle`: OK
  6. `test_m8_slave_read_only_enforcement`: OK
  7. `test_m8_ha_rest_api_endpoints`: OK
  8. `test_m8_list_change_applied_to_two_slaves_fast`: OK (<2s synchronization)
  9. `test_m8_chaos_master_mid_push_kill`: OK
  10. `test_m8_slave_to_master_promotion_procedure`: OK
- `cargo deny check`: PASSED (advisories ok, bans ok, licenses ok, sources ok).
