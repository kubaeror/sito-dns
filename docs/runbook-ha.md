# High Availability (HA) Operational Runbook

This runbook provides step-by-step operational procedures for managing, maintaining, troubleshooting, and recovering the **sito DNS High Availability (HA)** cluster.

---

## 1. Overview and Architecture

`sito` implements an active-passive master/slave replication architecture governed by [ADR-0002](adr/0002-ha-master-slave-push-no-raft.md):
- **Master Node**: Accepts administrative REST API mutations and Web UI configurations, generates monotonic configuration bundles, signs them using an Ed25519 private key (`data_dir/ha_signing.key`, permissions `0600`), and pushes updates to connected slaves in real-time over WebSocket with mutual TLS (mTLS) on port `8953`.
- **Slave Nodes**: Connect to the master over WebSocket + mTLS, verify the master's Ed25519 signature and certificate fingerprint, enforce strict monotonic version ordering (`version > have_version`), and apply configuration snapshots atomically.
- **Continuous Resolution**: Slaves serve DNS queries continuously without downtime. If an invalid or unparsable configuration bundle is received, the slave performs an automatic rollback to its last known good snapshot and enters a `Degraded` state.
- **Read-Only Enforcement**: Slave REST API endpoints reject mutating operations (`POST`, `PUT`, `DELETE`, `PATCH`) with HTTP `409 Conflict` and return the `X-Dnsd-Master: <master_url>` header to redirect operators to the authoritative master.
- **Statistics Aggregation**: Slaves report traffic and upstream metrics to the master every 30 seconds via `stats_report`. The master merges these metrics in Prometheus tagged by the `instance` label.

---

## 2. Manual Slave -> Master Promotion Procedure

In the event of a catastrophic or permanent failure of the master node, a slave node must be manually promoted to become the new authoritative master.

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

3. **Verify or generate master Ed25519 signing key**:
   When `sito` starts with `role = "master"`, it automatically generates a new Ed25519 private key at `/var/lib/sito/ha_signing.key` if one does not already exist, with strict POSIX permissions `0600`:
   ```bash
   # Verify permissions if generated manually
   ls -la /var/lib/sito/ha_signing.key
   # Expected output: -rw------- 1 sito sito 85 ... ha_signing.key
   ```

4. **Restart sito service**:
   ```bash
   # On systemd:
   systemctl restart sito

   # On Docker Compose:
   docker compose restart sito-slave
   ```

5. **Verify master status**:
   Query the local status endpoint:
   ```bash
   curl -s http://localhost:3000/api/v1/ha/status | jq .
   ```
   Expected response:
   ```json
   {
     "role": "master",
     "instance_name": "sito-master-promoted",
     "current_version": 1,
     "connected_slaves": 0,
     "slaves": []
   }
   ```

6. **Update network routing and DHCP**:
   Update your router or DHCP server (e.g. MikroTik RouterOS) to point client DNS queries to the new master's IP:
   ```routeros
   /ip dhcp-server network set [find] dns-server=192.168.1.11
   ```

7. **Re-point remaining slaves**:
   On all other slave nodes, update `master_url` in `/etc/sito/config.toml` to point to the newly promoted master:
   ```toml
   [ha]
   master_url = "wss://192.168.1.11:8953"
   ```
   Restart the slave service or issue a resync.

---

## 3. Certificate Rotation without Downtime

`sito` uses self-signed mTLS certificates with BLAKE3 fingerprint pinning. Follow this procedure to rotate certificates without causing replication interruption or DNS downtime.

### Step 1: Generate a New Certificate Suite
Run the built-in certificate generator:
```bash
sito ha gen-certs \
  --out-dir /etc/sito/certs/next \
  --master-ip 192.168.1.10 \
  --slave-ip 192.168.1.11 \
  --days 365
```
Note down the new fingerprints printed by the command:
- Master cert BLAKE3 fingerprint: `a1b2c3...`
- Slave cert BLAKE3 fingerprint: `d4e5f6...`

### Step 2: Update Configurations with Dual-Fingerprint Pinning
Both master and slave support pinning multiple valid fingerprints during rotation:

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
   ```
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
   ```
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
3. **Configure Minimal Slave Configuration**:
   Create `/etc/sito/config.toml`:
   ```toml
   config_version = 1

   [server]
   role = "slave"
   instance_name = "sito-slave-2"
   listen_addrs = ["0.0.0.0:53"]
   data_dir = "/var/lib/sito"

   [ha]
   master_url = "wss://192.168.1.10:8953"
   master_fingerprint = "<BLAKE3_FINGERPRINT_OF_MASTER>"
   cert = "/etc/sito/certs/slave.crt"
   key = "/etc/sito/certs/slave.key"
   ca = "/etc/sito/certs/ca.crt"
   ```
4. **Register Slave Fingerprint on Master**:
   If the master enforces pinned fingerprints, add the new slave's certificate fingerprint to `pinned_slave_fingerprints` in `/etc/sito/config.toml` on the master.
5. **Start Slave**:
   ```bash
   systemctl start sito
   ```
6. **Verify Initial Synchronization**:
   Check the slave status endpoint:
   ```bash
   curl -s http://localhost:3000/api/v1/ha/status | jq .
   ```
   The slave will transition through `Connecting` -> `HelloSent` -> `Applying` -> `Synced` in under 2 seconds. Verify that custom rules, rewrites, and client lists match the master.

---

## 5. Troubleshooting & Diagnostics

### Diagnostic Checklist

| Symptom | Probable Cause | Action |
|---|---|---|
| Slave state is `Degraded` | Configuration apply failed or corrupted bundle | Check `/var/log/sito` for `apply_config_push: parse error`. Slave automatically rolled back to prior working config. Fix syntax on master and re-push. |
| Slave state is `Connecting` in loop | Network unreachable, firewall blocking 8953, or mTLS handshake failed | Check `nc -zv 192.168.1.10 8953`. Check TLS certificate expiration or fingerprint mismatch in logs. |
| `Signature verification failed` | Bundle signature does not match master public key | Verify that the master didn't regenerate `ha_signing.key` without updating slaves. |
| `Incoming version <= have_version` | Out of order or replayed bundle | Normal during network blips; master will send latest monotonic version. |
| API returns `409 Conflict` | Mutation attempted directly on a slave node | Perform configuration edits on the master node indicated in the `X-Dnsd-Master` header. |

### Diagnostic Commands

1. **Check HA status on Master**:
   ```bash
   curl -s http://192.168.1.10:3000/api/v1/ha/status | jq .
   curl -s http://192.168.1.10:3000/api/v1/ha/slaves | jq .
   ```
2. **Check HA status on Slave**:
   ```bash
   curl -s http://192.168.1.11:3000/api/v1/ha/status | jq .
   ```
3. **Trigger Manual Resynchronization**:
   ```bash
   # From the master:
   curl -s -X POST http://192.168.1.10:3000/api/v1/ha/resync | jq .

   # Or from a slave:
   curl -s -X POST http://192.168.1.11:3000/api/v1/ha/resync | jq .
   ```
4. **Inspect Prometheus HA Metrics**:
   ```bash
   curl -s http://192.168.1.10:3000/metrics | grep sito_ha_
   ```
   Look for:
    - `sito_ha_slaves_connected`: Number of active slaves connected.
    - `sito_ha_config_version{instance="sito-master"}`: Current config version.
    - `sito_ha_replication_lag_seconds{slave="sito-slave-1"}`: Replication delay.

---

## 6. Security Considerations: Transport Security, Certificate Pinning & Authentication

The HA replication channel synchronizes entire server configuration bundles, custom rules, DNS rewrites, and client definitions between nodes. Protecting this transport against interception, tampering, and unauthorized slave connections is critical.

### 1. Certificate Pinning & Transport Encryption
- **Pinned TLS (Default & Recommended)**: Slave nodes connecting to `wss://` require `master_fingerprint = "blake3:..."` matching the master's certificate. This prevents man-in-the-middle (MITM) attacks even if a rogue CA is trusted in the system certificate store.
- **Unpinned TLS (`allow_unpinned_tls = true`)**:
  > [!WARNING]
  > Setting `allow_unpinned_tls = true` allows the slave to trust any server certificate issued by the configured CA without fingerprint pinning. This is discouraged in production because any compromised certificate issued by that CA could intercept or alter the cluster configuration bundle.
- **Plaintext WebSocket (`allow_insecure_ws = true`)**:
  > [!CAUTION]
  > Plaintext `ws://` connections are refused by default. Setting `allow_insecure_ws = true` transmits replication data without TLS encryption. Do NOT enable `allow_insecure_ws` across untrusted or public networks, as configuration details, network topology, and client tokens will be exposed in cleartext. Only use for local loopback debugging.

### 2. Slave Authentication Handshake (`slave_token`)
To prevent unauthorized nodes from connecting to the master replication port and receiving signed configuration bundles:
- Set `slave_token = "<PRE_SHARED_SECRET>"` in the `[ha]` section on both master and slave nodes.
- The slave transmits this token in the initial `Hello` handshake over the encrypted replication channel.
- The master validates the token and drops the connection immediately if the token is missing or mismatched.
