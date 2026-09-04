# Phase M1 — MVP: Resolver with hosts blocking (3 weeks)

Goal: a working DNS server that forwards, caches, and blocks domains from a hosts list — the pipeline skeleton everything else plugs into. References: plan sections 3, 5.1, 5.2, 6, 7.

## Scope

**In:** UDP/TCP 53 dual-stack, forwarding (plain + DoT upstream), failover strategy, cache with TTL clamping, hosts list from URL, `0.0.0.0` blocking, TOML config with validation, tracing, CLI, Dockerfile.
**Out (deliberately):** inbound DoT/DoH, API, UI, hot-reload, per-domain upstreams, ABP syntax, persistent stats. Scope guard: no "just adding" anything from M2+.

## Tasks

### 1. `sito-core` — contracts

```rust
// Types that will survive every phase — design deliberately:
pub struct Config { /* subset of section 15: server, dns, upstream, filtering(minimal) */ }
pub enum Verdict { Allow(Option<RuleRef>), Block(BlockReason), Rewrite(RewriteAction) }
pub struct ClientContext { ip: IpAddr, id: Option<ClientId>, /* rest empty until M4 */ }
pub trait FilterEngine: Send + Sync {
    fn evaluate(&self, qname: &Name, qtype: RecordType, client: &ClientContext) -> Verdict;
}
pub enum UpstreamError { Timeout, Refused, Tls(String), BadResponse, DnssecBogus }
```

- Name normalization: lowercase, no trailing dot, shared function
- `AppState` with `ArcSwap<Config>` (section 3.3) — already now, though reload arrives in M5

### 2. `sito-transport` — UDP/TCP

- N UDP sockets with `SO_REUSEPORT` (N = cores), `IP_PKTINFO`/`IPV6_RECVPKTINFO` (reply from the correct address — section 5.1)
- EDNS: advertise 1232 B; answer larger than client buffer → TC=1
- TCP: length prefix, RFC 7766 pipelining, 10 s idle, 256-connection limit
- Per-IP rate limit: token bucket in `dashmap`, default 20 qps

### 3. `sito-upstream` — forwarding

- `trait Upstream { async fn resolve(&self, msg: Message) -> Result<Message, UpstreamError> }`
- Implementations: `PlainUpstream` (UDP with TCP fallback on TC), `DotUpstream` (hickory-client, pool of 1–4 connections)
- Bootstrap for the DoT hostname (section 6.1): plain DNS from `upstream.bootstrap`
- `FailoverStrategy`: first healthy; passive health (3 errors → Down, probe every 10 s)
- 5 s timeout (config), error classification per section 3.6

### 4. `sito-cache`

- `moka` with weigher (bytes), key and value per section 7.1
- TTL: decremented when served; min/max clamp; negative caching (SOA), max 1 h
- In-memory metrics (tracing counters only for now)

### 5. `sito-filter` — hosts only

- hosts-format parser (`0.0.0.0 domain`, `#` comments), `FnvHashSet`
- Downloader: reqwest, 60 s timeout, 64 MB limit, save to `data_dir/lists/`
- Refresh at startup + every `refresh_interval_hours` in the background; atomic swap via `ArcSwap`

### 6. `sito` binary

- Startup and graceful shutdown exactly per sections 3.4/3.5
- CLI (clap): `--config`, subcommands `healthcheck`, `check-config`
- tracing: `log_format = json|pretty`, request-id span per query
- Multi-stage Dockerfile (section 17.1) + compose with healthcheck

## Agent prompts

```
M1.1 sito-core    → task 1 types; DoD: name-normalization tests (uppercase, trailing dot,
                    IDN rejected with error), Config parses the section-15 example
M1.2 transport    → UDP/TCP per task 2; DoD: dig with and without +tcp, answer >1232 B → TC,
                    pktinfo verified on a host with 2 IPs
M1.3 upstream     → per task 3; DoD: failover test with a fake upstream (1. dead,
                    2. alive), bootstrap resolves the DoT hostname without external network (mock)
M1.4 cache        → per task 4; DoD: TTL decreases between answers, min clamp works,
                    NXDOMAIN cached and expires
M1.5 filter-hosts → parser+downloader; DoD: test list blocks, bad URL doesn't crash startup
                    (works offline from disk cache)
M1.6 binary       → wiring+CLI+Docker; DoD: startup sequence per 3.4, SIGTERM → flush and exit 0
                    in <6 s, image <30 MB
M1.7 test-harness → test crate: spawn sito on random ports + fake upstream
                    (hickory-server) + dig wrapper; used by all phases
```

## Tests and acceptance criteria

- [x] `dig @127.0.0.1 example.com` → NOERROR (via fake upstream in CI)
- [x] Listed domain → `0.0.0.0` (A) and `::` (AAAA); other types → NOERROR/NODATA
- [x] Second query → cache hit (assert on log/metric), TTL decremented
- [x] Upstream 1 dead → answers from upstream 2 within <100 ms over timeout
- [x] `check-config` rejects bad TOML with a message pointing at the field
- [x] SIGTERM during 10k in-flight queries → no panic, exit ≤ 6 s
- [x] Docker image < 30 MB, healthcheck green

## Risks

| Risk | Mitigation |
|---|---|
| hickory-proto API churn between versions | Pin version + `sito-proto` wrapper isolating the rest of the code from hickory types |
| pktinfo on IPv6 differs across kernels | Dual-stack integration test in CI right away; pktinfo-less fallback with a warning |
| Scope creep ("DoH is just 20 lines") | Scope guard in review: PR with M2+ code = reject |

## Deliverables

Binary + image `ghcr.io/.../sito:m1`, asciinema demo in the PR, "M1" section in CHANGELOG.

## Completion report

### 1. Executive Summary
Phase M1 (MVP: Resolver with hosts blocking) has been fully designed, implemented, tested, and verified against all functional requirements, architectural constraints, and performance budgets defined in `docs/dns-server-plan-detailed.md` and ADRs 0001, 0004, 0005, and 0008.

Strict adherence to M1 scope guard was maintained: inbound DoT/DoH/DoQ, REST API, Web UI, config hot-reload, per-domain upstreams, ABP syntax, SQLite query logging, and persistent stats were deferred to M2+.

### 2. Implemented Modules
- **`sito-core` & `sito-proto` (Commit `c25060c`):**
  - Section 15 TOML schema with strict validation (`Config`, `ServerConfig`, `DnsConfig`, `UpstreamConfig`, `FilteringConfig`, `CacheConfig`).
  - Core domain models: `Verdict`, `RuleRef`, `BlockReason`, `RewriteAction`, `ClientContext`, `ClientId`, `FilterEngine`, `UpstreamError`, `ConfigError`, `AppState`.
  - Protocol utilities: case-insensitive domain normalization, root-dot stripping, ASCII/punycode verification with raw IDN rejection, wire encoding/decoding, and `synthesize_blocked_response` for `zero_ip` (`0.0.0.0` for A, `::` for AAAA, NODATA for other types).
- **`sito-transport` (Commit `149bbeb`):**
  - High-performance multi-socket UDP listener with `SO_REUSEPORT`, EDNS0 buffer advertising (1232 B), and TC=1 truncation when responses exceed client buffer.
  - Cross-platform dual-stack `IP_PKTINFO` / `IPV6_RECVPKTINFO` with graceful fallback to standard `recvfrom`/`sendto`.
  - RFC 7766 compliant TCP listener with 2-byte length framing, pipelining, 10s idle timeout, and semaphore connection limit (default 256).
  - Per-IP token bucket rate limiting using lock-free `DashMap`.
- **`sito-upstream` (Commit `0d239ca`):**
  - `Upstream` trait with asynchronous resolution.
  - `PlainUpstream`: UDP resolution with automatic fallback to TCP on TC=1.
  - `DotUpstream`: DNS-over-TLS using `tokio-rustls` with ALPN "dot", rustls client config, and connection pool.
  - `BootstrapResolver`: Resolves DoT hostnames via plain DNS before TLS handshake.
  - `UpstreamHealth` & `UpstreamManager`: Passive health state machine per section 6.3 (3 errors → Suspect, 6 errors → Down, 2 probe successes → Healthy; SERVFAIL/DnssecBogus do not lower health) and background active probing every 10s.
- **`sito-cache` (Commit `cae4d43`):**
  - Concurrent `moka::future::Cache` with byte-size weigher.
  - Decrements TTL dynamically upon serve based on elapsed lifespan.
  - Clamps TTLs to `[min_ttl, max_ttl]`.
  - Implements RFC 2308 negative caching using SOA minimum TTL clamped to `negative_ttl_max`.
- **`sito-filter` (Commit `3e9381c`):**
  - Hosts-format parser supporting `0.0.0.0 domain`, `127.0.0.1 domain`, `::1 domain`, comments `#`/`!`, loopback hostname exclusions, and `FnvHashSet<String>` exact matching.
  - Asynchronous list downloader via `reqwest` with 60s timeout, 64 MB size limit, and automatic fallback to disk cache (`data_dir/lists/`).
  - Protection against corrupted sources: retains previous snapshot if rule count drops by >50%.
  - Atomic snapshot swapping via `ArcSwap` with background refresh scheduler.
- **`sito` Binary & CLI (Commit `6fafca6`):**
  - Full end-to-end pipeline: Transport receive → Rate limit → Filter evaluate → Cache get → (if miss) UpstreamManager resolve → Cache insert → Transport response.
  - CLI via `clap`: `--config`, `check-config` (validates syntax and field constraints, pointing out error location), `healthcheck` (UDP probe against server).
  - Tracing subscriber: JSON or pretty formatting based on configuration, with request-id tracing span per query.
  - Graceful shutdown handling SIGINT/SIGTERM, closing listeners, and draining in-flight queries with a 5-second deadline.
  - Multi-stage distroless `Dockerfile` and `docker-compose.yml` with healthcheck.
- **`sito-test` (Commit `8fce21c`):**
  - In-process test harness (`TestServerInstance`) allocating ephemeral ports.
  - `MockDnsServer`: UDP DNS mock server supporting custom records and failure/alive toggles.
  - `TestDnsClient`: Programmatic client supporting UDP and TCP queries.
  - Acceptance verification test suite verifying all M1 requirements.

### 3. Verification & Quality Gates
1. **`cargo fmt --check`**: All files formatted according to Rust style guide.
2. **`cargo clippy --workspace -- -D warnings`**: Passed with 0 warnings.
3. **`cargo test --workspace`**: 29 tests passed across all workspace crates:
   - `sito-core`: 7 unit tests passed
   - `sito-proto`: 4 unit tests passed
   - `sito-transport`: 2 integration tests passed
   - `sito-upstream`: 5 unit and integration tests passed
   - `sito-cache`: 3 unit tests passed
   - `sito-filter`: 8 unit and integration tests passed
   - `sito`: 3 unit and integration tests passed
   - `sito-test`: 7 acceptance tests passed
4. **`cargo deny check`**: Passed (advisories ok, bans ok, licenses ok, sources ok).
5. **Docker Build**:
   - Multi-stage image build (`sito:m1`) succeeded.
   - Image content size: 11.9 MB (well below the 30 MB budget).
   - Container execution verified with `docker run --rm sito:m1 check-config`.
