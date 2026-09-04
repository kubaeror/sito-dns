# ADR-0008: Performance Budget and Resource Constraints

* **Status:** Accepted
* **Date:** 2026-09-04
* **Deciders:** sito core team
* **Consulted:** Performance, benchmarking, and QA review
* **Informed:** All contributors

## Context

DNS resolution is on the critical path for every network request made across all devices on a network. Excessive latency, erratic jitter, or memory bloat directly harms user experience and prevents deployment on low-cost single-board computers (such as Raspberry Pi 4/5, NAS units, and small virtual machines).

To ensure deterministic performance as features are added across phases M1 through M9, the project requires clear, non-negotiable performance budgets, latency allocations per pipeline stage, and memory caps.

## Decision

We adopt the performance targets specified in plan section 16.1 as binding engineering commitments on reference hardware (8-core x86_64, 16 GB RAM):

### 1. Macro Throughput and Latency Targets

| Scenario | Target Metric |
|---|---|
| UDP, cache hits | ≥ 500,000 QPS |
| UDP, parallel forwarding (upstream 10 ms) | ≥ 100,000 QPS |
| DoT (persistent TLS connections) | ≥ 50,000 QPS |
| DoH H2 (persistent TLS connections) | ≥ 40,000 QPS |
| Added latency p99 (cached responses) | < 1.0 ms |
| Total RAM consumption (1,000,000 rules + cache) | < 512 MB |

### 2. Microsecond Pipeline Latency Budget (Hot Path)

For a cached response, the internal processing budget is allocated as follows:
- **Wire Decode (`sito-proto`):** ≤ 15 µs (zero-copy parsing where feasible)
- **Client ID & Rate Limiting (`sito-clients`):** ≤ 10 µs
- **Rewrite Table Lookup (`sito-rewrites`):** ≤ 5 µs
- **Filter Rule Matching (`sito-filter`):** ≤ 25 µs (SuffixTrie + Aho-Corasick)
- **Cache Lookup (`sito-cache`):** ≤ 20 µs (lock-free concurrent map access)
- **Wire Encode & Transmission (`sito-transport`):** ≤ 25 µs
- **Total Hot-Path Internal Processing:** ≤ 100 µs average (p99 ≤ 500 µs)

### 3. Memory Budget Invariants

- **Filter Rules (1,000,000 rules):** ≤ 200 MB via string interning and trie node compaction.
- **Cache (50,000 entries weighted):** ≤ 64 MB.
- **Runtime, buffers, SQLite WAL, metrics:** ≤ 100 MB.
- **Strict safety ceiling:** The resident set size (RSS) must never exceed 512 MB under standard production loads.

### 4. Continuous Verification

- Micro-benchmarks using `criterion` for `sito-filter` and `sito-cache` on every PR affecting the hot path.
- Macro load testing using `dnsperf` / `resperf` against Tranco top-1M domain corpora in nightly pipelines.
- Regression rule (plan section 21.3): Any pull request causing > 10% performance regression in hot-path operations will be rejected.

## Consequences

### Positive
- Concrete boundaries prevent architectural creep and premature degradation of throughput.
- Enables confident deployment on resource-constrained embedded systems (ARMv7, Raspberry Pi).
- Guarantees that query logging, metrics, and HA synchronization never starve the DNS forwarder.

### Negative
- Requires rigorous profiling and disciplined memory management (avoiding heap allocations in query loops).
- Developers must run criterion benchmarks when modifying pipeline components.

### Neutral / Operational
- Memory profiling with `dhat` / `heaptrack` and CPU profiling with `flamegraph` integrated into release validation (M9).

## Alternatives Considered

### Alternative 1: Loose or Qualitative Goals ("Make it fast")
- **Pros:** Less initial testing overhead.
- **Cons:** Inevitable gradual performance erosion as features accumulate; difficult to identify which phase introduced latency spikes.
- **Why not chosen:** Measurable, quantifiable contracts are essential for autonomous agentic and multi-contributor engineering.

### Alternative 2: Prioritizing Max Throughput Over Memory Limits
- **Pros:** Uncompressed hash tables and pre-allocated caches can achieve higher raw QPS on 64-core servers.
- **Cons:** Unusable for homelab operators running on 1 GB or 2 GB RAM devices.
- **Why not chosen:** Homelab and self-hosted deployments represent the primary target user persona.
