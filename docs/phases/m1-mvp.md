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

- [ ] `dig @127.0.0.1 example.com` → NOERROR (via fake upstream in CI)
- [ ] Listed domain → `0.0.0.0` (A) and `::` (AAAA); other types → NOERROR/NODATA
- [ ] Second query → cache hit (assert on log/metric), TTL decremented
- [ ] Upstream 1 dead → answers from upstream 2 within <100 ms over timeout
- [ ] `check-config` rejects bad TOML with a message pointing at the field
- [ ] SIGTERM during 10k in-flight queries → no panic, exit ≤ 6 s
- [ ] Docker image < 30 MB, healthcheck green

## Risks

| Risk | Mitigation |
|---|---|
| hickory-proto API churn between versions | Pin version + `sito-proto` wrapper isolating the rest of the code from hickory types |
| pktinfo on IPv6 differs across kernels | Dual-stack integration test in CI right away; pktinfo-less fallback with a warning |
| Scope creep ("DoH is just 20 lines") | Scope guard in review: PR with M2+ code = reject |

## Deliverables

Binary + image `ghcr.io/.../sito:m1`, asciinema demo in the PR, "M1" section in CHANGELOG.
