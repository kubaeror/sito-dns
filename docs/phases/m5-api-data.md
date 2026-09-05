# Phase M5 — REST API, Auth and Data Layer (3 weeks)

Goal: full management via API, persistent query log, Prometheus metrics, backup and hot-reload. From this phase on, TOML becomes optional. References: plan sections 12, 14, 15.

## Scope

**In:** all endpoints from table 12.1 (HA as stubs), complete auth, SQLite + migrations + retention, query-log pipeline, `/metrics`, backup/restore, hot-reload, config writes via API.
**Out:** HA implementation (M8), streaming UI (M6).

## Tasks

### 1. Data layer (`sito-stats`)

- sqlx + SQLite WAL; migrations in `migrations/`; schema from section 14.1
- Query-log pipeline: 10k ring buffer → batch INSERT every 5 s/1000 entries; a single writer connection in `spawn_blocking` (section 3.2 — never block the runtime)
- Overflow → drop + `sito_querylog_dropped_total`
- Retention job (nightly) + aggregation into `stats_hourly`; weekly VACUUM

### 2. Auth (`sito-api::auth`)

- Passwords Argon2id (m=64 MiB, t=3, p=4); session cookies `HttpOnly; Secure; SameSite=Strict`, rotation after login
- TOTP: flow from section 12.2 (partial token → verify), hashed backup codes, 15 min lockout after 5 attempts
- API tokens `sito_<256bit>`, blake3 hash stored; scopes admin/operator/viewer
- RBAC middleware as an axum extractor (`Require<Operator>`); login and API rate limiting per IP

### 3. Endpoints

- Everything from table 12.1; RFC 7807 errors; cursor pagination in query log; WebSocket `/querylog/stream`
- `/filtering/check` — verdict simulation (dry pipeline run without upstream)
- `/upstream/test` — RTT measurement to candidates
- HA: stubs returning `501` with an "M8" message

### 4. OpenAPI and configuration

- `utoipa` from types; Swagger UI at `/api/docs`; `openapi.json` exported in CI (artifact — the M6 UI generates its client from it)
- Config writes: validation → atomic TOML write (tmp+rename) → snapshot swap; secrets masked `***` in GET, overwritten only when provided
- Hot-reload: `notify` on config.toml + `POST /config/reload`; a bad new config never replaces a working one
- Backup: tar.gz (config + metadata + list versions); restore requiring a confirmation token

### 5. Metrics

- Prometheus exporter, full table 14.2; labels per plan (client cardinality: name only when identified, otherwise `unknown` — protection against series explosion)

## Agent prompts

```
M5.1 db           → task 1; DoD: log survives restart; retention deletes old rows;
                    inserting 50k entries < 5 s; drops counted under overload
M5.2 auth         → task 2; DoD: full TOTP flow in a test; lockout works;
                    a viewer token cannot PUT (403 with problem+json)
M5.3 endpoints-1  → status/stats/querylog/filtering; DoD: OpenAPI conformance
                    (contract test generates requests from the schema)
M5.4 endpoints-2  → clients/rewrites/upstream/config/cache/ha-stubs/backup;
                    DoD: backup→restore roundtrip on a copy of the test config
M5.5 openapi      → utoipa + swagger + CI artifact; DoD: zero hand-written
                    paths outside the schema; reviewable openapi.json diff
M5.6 reload       → task 4 (hot-reload + write-through); DoD: list change via API
                    visible in verdicts <1 s; bad TOML via PUT rejected, old one works
```

## Tests and acceptance criteria

- [x] Swagger complete; every endpoint has a contract test
- [x] RBAC: role × endpoint matrix (3 roles × ~30 endpoints) green
- [x] Query log: filters (client/domain/status/time) + cursor work on 1M rows < 200 ms
- [x] Live tail WS delivers an entry < 500 ms after the query
- [x] Prometheus scrape contains the whole table 14.2
- [x] IP anonymization (masks /24, /56) applies before storage
- [x] Backup/restore: an instance restored from the archive gives identical verdicts

## Risks

| Risk | Mitigation |
|---|---|
| SQLite blocking tokio at high volume | Single writer in `spawn_blocking`; load test 20k qps with logging on — DNS answer p99 must not grow >10% |
| Prometheus label cardinality | Hard limit: only named clients as labels; test with 10k unique IPs |
| OpenAPI drifting from code | Generation from types + CI diff as a check |

## Deliverables

Complete API with docs, Grafana dashboard `contrib/grafana/` rendering data, `sito backup`/`restore` command + endpoints.
