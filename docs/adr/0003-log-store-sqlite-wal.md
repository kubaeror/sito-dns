# ADR-0003: Query Log Storage Engine (SQLite WAL with Single Writer)

* **Status:** Accepted
* **Date:** 2026-09-04
* **Deciders:** sito core team
* **Consulted:** Storage and performance review
* **Informed:** All contributors

## Context

A filtering DNS server handles high volumes of queries (thousands to hundreds of thousands per second). Each query produces an audit record:
- Timestamp, Client ID, Client IP, Client Name
- Question Name, Question Type, Question Class
- Upstream Resolver used, Response Time (microseconds), Response Code (RCODE)
- Verdict (Allowed, Blocked, Rewritten), Matched Rule ID, Matched Filter List ID

Logging requirements:
1. **Never block the DNS query pipeline:** DNS latency must remain untouched by disk I/O.
2. **Fast query filtering and pagination:** The management UI requires sub-second filtering by client, domain substring, verdict, and date range.
3. **Retention management:** Automated pruning of records older than a configured retention threshold (e.g., 7–90 days).
4. **Zero external dependencies:** Must run out-of-the-box as a self-contained binary without requiring a separate PostgreSQL, MySQL, or ClickHouse service.

## Decision

We use **SQLite in Write-Ahead Logging (WAL) mode** (`PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;`) accessed via `sqlx`.

Architecture:
- **Dedicated Single Writer Task:** A background worker thread holds the exclusive write connection to the SQLite database.
- **Bounded Channel Ingestion:** The DNS pipeline dispatches query log events through a bounded `tokio::sync::mpsc` channel. Batches are inserted using multi-row transactions.
- **Backpressure Drop Guard:** If the channel capacity is exceeded under extreme burst loads, query log events are dropped and counted in `sito_querylog_dropped_total`. The DNS pipeline is never blocked or stalled.
- **Concurrent Read Connections:** Read-only connections for API requests and UI queries operate concurrently against the WAL without acquiring write locks or blocking insertions.

## Consequences

### Positive
- Fully embedded, zero-configuration database contained in a single `.db` file (with `.db-wal` and `.db-shm`).
- SQLite WAL mode permits simultaneous readers alongside a single active writer.
- Schema migrations managed cleanly via `sqlx-migrate`.
- Portable across Linux architectures (x86_64, aarch64, armv7) without external daemons.

### Negative
- Not suited for clustered distributed database topologies (handled instead via sito-ha application-level replication).
- Extremely large deployments (> 100M queries per day) may reach SQLite performance boundaries during heavy range scans, requiring DuckDB or external log forwarders (evaluated in M9).

### Neutral / Operational
- Requires periodic WAL checkpointing (`PRAGMA wal_checkpoint(TRUNCATE)`) during background maintenance windows.
- Retention pruning is executed as a scheduled off-peak background job (`DELETE FROM query_log WHERE created_at < ...`).

## Alternatives Considered

### Alternative 1: External Database (PostgreSQL / MySQL)
- **Pros:** Scalable to arbitrary data volumes; advanced analytical query engines.
- **Cons:** Violates the "single binary self-contained install" goal for lightweight homelab/IoT setups; requires database administration.
- **Why not chosen:** Self-hosted users prioritize zero-friction single-binary deployment.

### Alternative 2: Flat Files / In-Memory Circular Buffer Only
- **Pros:** Fast writes, simple append-only files.
- **Cons:** Searching, complex multi-field filtering, and pagination in the UI require scanning gigabytes of text or building a custom indexing engine.
- **Why not chosen:** SQLite provides proven B-tree indexing and standard SQL query capabilities with minimal overhead.

### Alternative 3: DuckDB
- **Pros:** Outstanding columnar analytical performance on large query volumes.
- **Cons:** Larger binary size, higher memory overhead on constrained devices (ARMv7), and newer async ecosystem integration.
- **Why not chosen:** SQLite WAL is lightweight and well-understood; DuckDB remains an M9 roadmap consideration for heavy analytics.
