# ADR-0002: High Availability Architecture (Master/Slave Push Replication)

* **Status:** Accepted
* **Date:** 2026-09-04
* **Deciders:** sito core team
* **Consulted:** Architecture and operations review
* **Informed:** All contributors

## Context

High availability (HA) in local network environments (homelabs, SMBs, edge deployments) typically consists of two nodes (e.g., primary on a bare-metal server/NAS, secondary on a Raspberry Pi). The requirements are:
- Redundant DNS query resolution (both nodes answer DNS queries simultaneously).
- Unified administrative management (filter lists, rewrite rules, clients, and upstream configurations updated in one place).
- Resilient operation during node maintenance or network partitions: if one node goes down or restarts, the other node must continue resolving DNS queries without interruption.
- Low operational complexity without requiring dedicated cluster orchestration daemons.

Consensus algorithms like Raft or Paxos require an odd number of nodes (minimum 3) to maintain quorum. In a typical two-node setup, the failure of one node causes loss of quorum, preventing any state modification.

## Decision

We adopt a **Master/Slave Push Replication** architecture without a distributed consensus engine (no Raft).

Key elements:
1. **Roles:** One node is designated as Master (authoritative for configuration updates); one or more nodes operate as Slaves.
2. **Communication:** Slaves establish persistent outbound WebSocket connections to the Master secured with mutual TLS (mTLS).
3. **State Bundles:** The Master serializes configuration and filter rule state into versioned `ConfigBundle`s, computes a BLAKE3 checksum, signs the bundle with an Ed25519 private key, and pushes it to connected Slaves.
4. **Autonomous Operation:** Slaves store the latest verified bundle on disk. If the Master is unreachable, Slaves continue to serve DNS traffic and restart cleanly from local state without degradation.
5. **Failover:** Node promotion (Slave to Master) is an explicit administrative or orchestrator action (via CLI/API or external VRRP/keepalived tooling), avoiding automated split-brain scenarios.

## Consequences

### Positive
- Works seamlessly in common two-node topologies without needing a third "witness" or "tie-breaker" node.
- Deterministic, unidirectional data flow: Master is the single source of truth for configuration changes.
- Safe rollouts: Bundles are cryptographically verified and applied atomically via `ArcSwap` snapshots.
- Minimal resource consumption: No background consensus heartbeats consuming CPU or bandwidth on low-power devices.

### Negative
- Configuration updates are disabled if the Master is offline until it recovers or a Slave is promoted.
- Automatic leader election is deliberately absent to prevent split-brain on network partitions.
- Promotion requires operator initiation or an external supervisor tool.

### Neutral / Operational
- Virtual IP failover (e.g. keepalived / CARP) can be layered on top of the nodes to share a single DNS endpoint IP.
- Master/slave synchronization protocol is detailed in plan section 11.

## Alternatives Considered

### Alternative 1: Distributed Consensus via Raft (`raft-rs` / `openraft`)
- **Pros:** Automatic leader election, strongly consistent cluster state.
- **Cons:** Strictly requires >= 3 nodes for fault tolerance. A 2-node Raft cluster cannot tolerate the failure of a single node for writes. Adds massive code complexity and failure modes.
- **Why not chosen:** Overkill for self-hosted DNS setups where 2 nodes are standard and configuration writes occur infrequently compared to query reads.

### Alternative 2: P2P Multi-Master with CRDTs
- **Pros:** Any node can accept writes; no single point of failure for updates.
- **Cons:** Complex conflict resolution for conflicting rewrite rules, IP allocations, or list subscriptions; high implementation and debugging burden.
- **Why not chosen:** Disproportionate complexity for configuration state that is normally edited by a single administrator.
