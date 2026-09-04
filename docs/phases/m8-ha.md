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

- [ ] List change on the master → both slaves apply in < 2 s (asserted on the dig verdict)
- [ ] Push while killing the master: slave consistent at N or N+1, never in between
- [ ] Secrets never in the payload (automated scanning test)
- [ ] Master UI shows slaves, versions and lag; slave UI read-only with badge
- [ ] HA compose on one machine: two instances answering on two LAN IPs
- [ ] Runbook: slave→master promotion executed per the doc without the author's help

## Risks

| Risk | Mitigation |
|---|---|
| Secret leakage in a bundle | Placeholders from the protocol's first commit + CI scanner test as a gate |
| Config schema version drift between instances | `config_version` + apply refusal on mismatch (clear error instead of silent corruption) |
| macvlan not working in someone's environment | Docs alternative: one host, ports 53/5353; both topologies tested |

## Deliverables

`:m8` with HA, HA compose, runbook, "HA" dashboard in the master UI, topology write-up in docs.
