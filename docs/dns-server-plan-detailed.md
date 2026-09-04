# Design Document: Custom DNS Server (AdGuard Home Clone) — Expanded Edition

Working title: **sito**. Document v2 — every section expanded to detailed-spec level, ready for coding agents.

---

## 1. Requirements — Expanded

### 1.1 Goals

- A full-featured, self-contained filtering DNS server (drop-in replacement for AdGuard Home)
- One static binary: protocols + API + UI + database (like Pi-hole v6, which merged the web server and REST API into a single process)
- Designed for large scale from the first commit (sharding, zero-copy, no locks on the read path)
- Fully automatable via API/GitOps — the UI is an optional API client, never the other way around

### 1.2 Non-goals (deliberately excluded)

- Authoritative server for public zones (beyond local records/rewrites)
- Recursive resolver (forwarding only — survey decision)
- DHCP (MikroTik remains the DHCP server)
- Multi-tenancy / SaaS (one operator, many instances)
- Windows as a production host (Linux first; Windows dev-only)

### 1.3 Success criteria (measurable)

- A conformance test suite matches AdGuard Home behavior on a reference corpus
- Performance targets from section 16 met on reference hardware (8 cores, 16 GB RAM)
- Full operability via API without touching files
- Time from `docker run` to working filtering < 2 min (setup wizard)

### 1.4 Constraints

- Rust stable (no nightly), MSRV tracked in `rust-toolchain.toml`
- Zero C dependencies except optional `ring`/`aws-lc-rs` (via rustls) — eases ARM cross-compilation
- Data and config in standard XDG/FHS locations

---

## 2. Stack — Detailed Decisions

### 2.1 Why each crate

| Crate | Alternative | Why chosen |
|---|---|---|
| `tokio` | `smol`, `glommio` | Ecosystem, maturity, hickory is built on tokio; glommio (io_uring) as an M9 experiment |
| `hickory-proto` | custom wire-format parser | Completeness (EDNS0, DNSSEC types), DoT/DoH/DoQ/DoH3 via feature flags, DNSSEC validation with NSEC/NSEC3 and built-in root key; custom parser only if M9 profiling shows a hotspot |
| `axum` | `actix-web` | Native tokio/tower, easy SPA embedding, WebSocket for HA and log live-tail |
| `moka` | `lru`, `dashmap`+manual TTL | Concurrent, weighted (byte accounting), per-entry TTL, TinyLFU — better hit-rate than LRU |
| `sqlx` + SQLite | `diesel`, `duckdb` | Async, compile-time checked queries, WAL suffices for query log; consider duckdb in M9 for large-volume analytics |
| `utoipa` | hand-written OpenAPI | OpenAPI generated from types — docs always match code |
| `regex-automata` | `regex` | Build one DFA from all rule regexes; no backtracking = no ReDoS |
| `aho-corasick` | — | Substring matching of rules in a single pass |
| `arc-swap` | `RwLock` | Hot-reload of config/filter snapshots without locks on the query path |
| `rustls` | `openssl` | Pure Rust, hickory went rustls-only; shared TLS stack for DoT/DoH/DoQ/UI/HA |
| `quinn` + `h3` | — | QUIC for DoQ and DoH3 (via hickory features) |
| `tracing` | `log` | Per-query spans (request-id), OTel export later |
| `mimalloc` | system allocator | Less fragmentation with millions of small DNS record allocations (feature flag `malloc`) |
| `blake3` | sha256 | Hashes for HA config bundles — faster, sufficient security margin |
| `ed25519-dalek` | RSA | Config bundle signatures: small keys, fast verification |

### 2.2 ADR registry (to create in M0)

- ADR-001: Rust + hickory as the protocol layer
- ADR-002: HA master/slave with push replication (no Raft)
- ADR-003: SQLite (WAL) as the query log store
- ADR-004: Single TOML file as source of truth; UI writes via ConfigManager
- ADR-005: Default block response `0.0.0.0`/`::` instead of NXDOMAIN (compatibility with picky clients)
- ADR-006: DNSCrypt as a stretch goal (no mature Rust crate)

### 2.3 Dependency policy

- `cargo-deny` in CI: ban duplicate versions, license allowlist (MIT/Apache/BSD/MPL), `cargo audit` on every PR
- Dependabot weekly; critical security updates out of band
- Rule: a new dependency requires justification in the PR description

---

## 3. Architecture — Details

### 3.1 Component diagram

```
                        ┌────────────────────────────────────────────┐
                        │                  sito                       │
                        │                                            │
  UDP/53 ──┐            │  ┌───────────┐   ┌──────────────────────┐  │
  TCP/53 ──┼─ listeners │  │ Transport │──▶│  Pipeline (per query) │  │
  DoT/853 ─┤  per-core  │  │  decode   │   │  client→ratelimit→   │  │
  DoH/443 ─┤            │  └───────────┘   │  rewrite→filter→cache│  │
  DoQ/853 ─┤            │                  │  →upstream→dnssec    │  │
           │            │                  └─────────┬────────────┘  │
           │            │                            │               │
           │            │  ┌──────────┐  ┌───────────┴────────────┐  │
           │            │  │ Config   │  │ Snapshots (arc-swap):  │  │
           │            │  │ Manager  │─▶│ filters, clients,      │  │
           │            │  │ (TOML,   │  │ rewrites, upstreams    │  │
           │            │  │ hot-rel) │  └────────────────────────┘  │
           │            │  └────▲─────┘                             │
           │            │       │ push                              │
           │            │  ┌────┴─────┐   ┌───────────┐             │
           │            │  │    HA    │◀─▶│  slaves   │ (mTLS/WS)   │
           │            │  │ replic.  │   └───────────┘             │
           │            │  └──────────┘                             │
           │            │  ┌──────────┐   ┌───────────┐             │
           │            │  │ API+UI   │   │ Stats/Log │─▶ SQLite    │
           │            │  │ (axum)   │─▶│ (async)   │─▶ /metrics  │
           │            │  └──────────┘   └───────────┘             │
           │            └────────────────────────────────────────────┘
```

### 3.2 Concurrency model

- UDP listener: N sockets with `SO_REUSEPORT` (N = core count), each with its own receive task — the kernel load-balances by 4-tuple
- Hot path (decode→filter→cache→upstream) as a **sequence of `await`s in a single task**, no channels between stages — channels only for slow paths (stats, query log, HA)
- Channels with backpressure: `tokio::sync::mpsc` with capacity; on overflow the query log **drops and counts** (`sito_querylog_dropped_total`), never blocks DNS answers
- Global `Semaphore` limiting concurrent upstream queries (fd exhaustion protection); default 10,000

### 3.3 State management

```rust
struct AppState {
    config: ArcSwap<Config>,            // entire configuration
    filters: ArcSwap<FilterSnapshot>,   // compiled rules per group
    clients: ArcSwap<ClientRegistry>,   // clients + groups
    rewrites: ArcSwap<RewriteTable>,
    upstreams: ArcSwap<UpstreamManager>,// pooling + health inside
    cache: Cache,                       // moka, internal concurrency
    stats: StatsRegistry,               // lock-free counters
    ha: HaState,                        // role, config version, peers
}
```

Rule: a snapshot is swapped atomically as a whole. A query grabs an `Arc` at pipeline start — a consistent view for its whole lifetime, even if config reloads in the background.

### 3.4 Startup sequence

1. Parse CLI + load TOML + validate (error = startup refused with a clear message)
2. Init tracing, metrics, data dir, SQLite (migrations)
3. Fetch/compile blocklists (from disk cache, refresh in background)
4. Build snapshots → start listeners → start API/UI → start HA
5. `sd_notify READY=1` (systemd) / healthcheck passes

### 3.5 Graceful shutdown

1. Stop accepting new connections/queries (close listeners)
2. Finish in-flight queries (5 s timeout)
3. Flush query log and stats to SQLite
4. Close upstream pools (graceful QUIC/TLS close)
5. Persist `last_state` (HA config version)

### 3.6 Error strategy

- `thiserror` in libraries, `anyhow` only at the binary level
- Every upstream error classified: timeout / refused / SERVFAIL / DNSSEC-bogus / TLS — each affects health-score differently
- Per-query errors never panic the task; `catch_unwind` at the task boundary as the last line of defense + a panic metric

---

## 4. Filtering Engine — Details

### 4.1 Rule grammar (EBNF, AdGuard-compatible subset)

```
rule        = comment | hosts | adblock
comment     = ("#" | "!") *any
hosts       = ip SP domain            ; "0.0.0.0 ads.example.com"
adblock     = [allow] pattern [options]
allow       = "@@"
pattern     = "||" domain "^"         ; domain + subdomains
            | "|" url-like            ; prefix
            | "/" regex "/"           ; regex
            | "*" wildcard            ; wildcard
            | plain                   ; substring
options     = "$" option *("," option)
option      = "important"
            | "client" "=" (ip | cidr | name | "~" name)
            | "dnstype" "=" types
            | "dnsrewrite" "=" rcode ";" rtype ";" value
            | "denyallow" "=" domains
            | "badfilter"
```

Supported modifiers (parity with AdGuard Home docs): `$important`, `$client`, `$denyallow`, `$dnstype`, `$dnsrewrite`, `$badfilter`. Unknown modifiers: rule skipped with a log warning (fail-safe, like AdGuard).

### 4.2 Post-compilation data structures

```
FilterSnapshot {
    exact:      FnvHashSet<Box<[u8]>>,   // normalized domains (lowercase, no trailing dot)
    suffix:     SuffixTrie,              // reversed labels: com -> example -> ads ; terminal flag
    substrings: AhoCorasick<u32>,        // AC automaton, pattern → rule index
    regex:      regex_automata::dfa::regex::Regex,  // single DFA for all regexes
    rewrites:   Vec<DnsRewriteRule>,     // $dnsrewrite
    meta:       Vec<RuleMeta>,           // source (list/custom), line, modifiers
}
```

- `SuffixTrie`: node = `HashMap<Label, Node>` (labels interned — `u32` into a string table, saves RAM at millions of domains)
- Sharing between groups: base structures (global lists) built once, wrapped in `Arc`; groups add their own small structures — lookup merges results
- At 1M domains: estimate ~60–90 MB RAM (verify with a benchmark in M2)

### 4.3 Lookup algorithm (pseudocode)

```
fn evaluate(qname, qtype, client) -> Verdict {
    let fqdn = normalize(qname);                       // lowercase + strip root dot
    // 1. allowlist (separate, identical set of structures)
    if allow.match(fqdn, qtype, client).hit() { return Allow(rule); }
    // 2. $important from the blocklist
    if block.match_important(fqdn, client).hit() { return Block(rule); }
    // 3. regular blocking rules
    if let Some(m) = block.match(fqdn, qtype, client) {
        // $denyallow: domain in the exception list → do not block
        if !m.denyallow_matches(fqdn) { return Block(m.rule); }
    }
    // 4. service blocking (with schedule)
    if let Some(svc) = services.match(fqdn, client, now()) { return Block(svc); }
    // 5. parental
    if parental.enabled(client) && parental.is_blocked(fqdn) { return Block(Parental); }
    Allow(Nomatch)
}

fn SuffixTrie::match(fqdn) {
    // exact hashset → then trie over reversed labels
    // "a.b.example.com" → com→example→b→a, checking flags at each prefix
}
```

Target: stages 1–3 < 1 µs (hashset + trie); regex DFA runs only when regexes exist and earlier structures missed.

### 4.4 CNAME uncloaking

AdGuard also checks rules against CNAME targets (hiding trackers behind CNAMEs). Implementation: after the upstream answer, if a CNAME chain exists → every domain in the chain goes through `evaluate()`; a hit = answer replaced with a block + query log entry marked "via CNAME". Toggle `filtering.cname_cloaking` (default on).

### 4.5 Block response modes (config `filtering.blocking_mode`)

| Mode | Response |
|---|---|
| `zero_ip` (default) | A → `0.0.0.0`, AAAA → `::`, TTL from config |
| `nxdomain` | NXDOMAIN |
| `refused` | REFUSED |
| `custom_ip` | Configured IP (e.g., info page) |
| `null_rdata` | NOERROR with empty answer section |

For types other than A/AAAA always NOERROR/NODATA — returning an IP for HTTPS/SVCB breaks clients.

### 4.6 Subscription updates

- Scheduler: one task, heap timer on the nearest deadline; interval per list
- Fetch: reqwest with `ETag`/`If-Modified-Since`, size limit (default 64 MB), 60 s timeout, 3 retries with backoff
- Compile new version in `spawn_blocking` (CPU-bound), then atomic snapshot swap (`arc-swap`), zero downtime
- Disk cache of lists in `data_dir/lists/` — startup without internet works
- Post-compile validation: rule count dropped >50% vs previous version → warning + keep old version (protection against a broken source)

---

## 5. Transport Layer — Details

### 5.1 UDP/53

- N sockets `SO_REUSEPORT` (socket2), `IP_PKTINFO`/`IPV6_RECVPKTINFO` — reply from the correct destination address on multi-IP hosts
- EDNS buffer: advertise 1232 B (DNS flag day 2020); larger answers → TC=1, client retries over TCP
- Per-source rate limiting (token bucket in `dashmap`, default 20 qps/IP, configurable) + global limit
- Amplification protection: ANY response limits, minimize additional sections

### 5.2 TCP/53

- RFC 7766: pipelining and reuse, 10 s idle timeout, max 256 concurrent connections per listener (configurable)
- Framing: 2-byte length prefix; guard against declared size >64 KB

### 5.3 DoT (853)

- rustls, ALPN `dot`, TLS 1.3 + 1.2; session resumption enabled
- Connection reuse with limits: max 1000 queries or 5 min per connection
- Optional response padding (RFC 8467) — toggle

### 5.4 DoH (443, H2)

- RFC 8484: `POST` and `GET` (base64url `?dns=`), `Content-Type: application/dns-message`
- ClientID: path `/dns-query/{client_id}` — client identification before DNS (like AdGuard)
- Sharing 443 with panel/API: axum routing — `/dns-query*` → DoH, rest → UI/API; separate vhosts (SNI) as an option `doh.dedicated_hostname`
- Header `Alt-Svc: h3=":443"` advertises DoH3

### 5.5 DoQ (853) and DoH3 (443)

- DoQ (RFC 9250): ALPN `doq`, stream per query; **0-RTT disabled** (replay vulnerability — a DNS query is not idempotent w.r.t. stats/rate limits)
- DoH3 via hickory `dns-over-h3` (quinn + h3); sharing UDP/443 with other QUIC services excluded — docs require dedicated 443/udp
- QUIC: `max_idle_timeout` 30 s, stream limits, retry-flooding protection (address validation)

### 5.6 DNSCrypt (stretch goal, ADR-006)

- Protocol v2: provider certificate (signed by provider key, 24 h rotation), `crypto_box` (X25519 + XSalsa20-Poly1305) via `x25519-dalek` + `crypto_secretbox`
- Magic query, client nonce padding, `sdns://` stamp support
- Estimate: 1–2 weeks implementation + interoperability tests with dnscrypt-proxy

### 5.7 Common

- All TLS listeners from a single `rustls::ServerConfig` per certificate (SNI map for multiple certs)
- Per-transport metrics: `sito_transport_queries_total{proto="udp|tcp|dot|doh|doq|doh3"}`
- Tests per transport: `dig`, `kdig`, `kdog`, `q`, `curl --doh-url`

---

## 6. Upstream Manager — Details

### 6.1 Resolving upstreams (bootstrap)

Problem: `https://dns.example/dns-query` requires resolving `dns.example` before DNS works. Solution:

1. `upstream.bootstrap = ["9.9.9.9", "149.112.112.112"]` — plain DNS only for upstream hostnames
2. Results cached with TTL, refreshed in background; on startup without network — last known IPs from disk
3. Option `tls://1.1.1.1` (IP literal + SNI from `tls_server_name`) bypasses bootstrap entirely

### 6.2 Strategies — exact behavior

- **parallel**: query all healthy upstreams simultaneously; first valid answer (NOERROR/NXDOMAIN, DNSSEC OK) wins; the rest cancelled. Improves average latency at the cost of traffic — default, like AdGuard
- **load_balance**: weighted choice; weight = `1 / (ema_rtt + ε)`; EMA: `rtt = 0.8·rtt + 0.2·sample`
- **failover**: strictly first healthy; return to a higher one after `health.recover_after` (default 60 s) of stability

### 6.3 Health checking (state machine per upstream)

```
Healthy ──(3 consecutive errors)──▶ Suspect ──(3 more)──▶ Down
   ▲                                 │ (1 success)          │ active probe every 10 s
   └──────────(success)──────────────┴──────(2 probe successes)──┘
```

- Counted errors: timeout, connection refused, TLS handshake fail; **SERVFAIL and bogus do not lower health** (valid answers)
- Active probe: query for a random domain from `upstream.probe_domain` (default `health.check.sito` answered locally / `example.com` externally)
- Circuit breaker: Down = excluded from rotation until probes succeed

### 6.4 Pooling

- DoT/DoH/DoQ: connection pool per upstream (max 4, configurable), keep-alive, dead-connection detection on write
- A query reserves a connection ≤ timeout; none free → open new or wait max 50 ms

### 6.5 Per-domain upstreams

```
[[upstream.per_domain]]
domains = ["corp.internal", "*.lan", "168.192.in-addr.arpa"]
servers = ["192.168.1.1"]
```

- Matching: SuffixTrie like filters; longest match wins; no match → default group
- Reverse zones (in-addr.arpa/ip6.arpa) to MikroTik = correct PTR on the LAN

### 6.6 EDNS Client Subnet

Not sent by default (privacy). Per-upstream option: `ecs = "off" | "anonymized" (/24 or /56) | "full"` — for ECS-dependent CDNs.

---

## 7. Cache — Details

### 7.1 Key and value

```rust
struct CacheKey { qname: Box<[u8]>, qtype: u16, qclass: u16, dnssec_ok: bool }
struct CacheEntry {
    message: Message,            // full answer (compression off)
    stored_at: Instant,
    original_ttls: Vec<u32>,     // per RRset — decremented when served
    rcode: u8,
    hits: AtomicU32,
}
```

- On serve: each record's TTL = `original - elapsed`; TTL < min_ttl from config at store time → clamp
- Entry weight (moka weigher): serialized message size + overhead — cache capacity in bytes (default 64 MB), not entry count

### 7.2 Negative caching

- NXDOMAIN/NODATA cached with TTL = min(SOA TTL, SOA MINIMUM), clamp `cache.negative_ttl_max` (default 1 h)
- Separate keyspace — `flush` can clear only negatives

### 7.3 Prefetch and serve-stale

- Prefetch: entry with `hits >= 5` and remaining TTL < 10% → background refresh from upstream; client gets the old (still valid) one — zero latency
- Serve-stale: when all healthy upstreams are down, serve expired entries up to `serve_stale_hours`; log marker + metric `sito_cache_stale_served_total`
- Both as toggles in `[dns.cache]`

### 7.4 Invalidation

- API: `POST /cache/invalidate?domain=x[&subdomains=true]`, `POST /cache/flush`
- Automatic: changing rewrites/filters does not clear the upstream-answer cache (rewrites and filters run before cache — see pipeline)

---

## 8. DNSSEC — Details

### 8.1 Validation flow

1. Client may set DO=1 or not — validation happens **always** when `dnssec.validate = true` (server-side)
2. After upstream answer: hickory-resolver builds the trust chain: root anchor → DS → DNSKEY → RRSIG
3. Results: `Secure` (AD=1 to client), `Insecure` (unsigned zone — OK, pass through), `Bogus` → SERVFAIL + metric + query log entry, `Indeterminate` → treated as Insecure with debug log
4. Intermediate keys cached (separate validator cache with key TTLs)

### 8.2 Anchors and edge cases

- Root trust anchor: built-in (hickory ships the current root key); updated with sito releases; RFC 5011 — out of v1 scope
- Negative Trust Anchors: `dnssec.ntp = ["known-broken.example"]` — disables validation for listed zones, with a UI warning
- Filtering upstreams breaking DNSSEC: detectable via a spike in `sito_dnssec_bogus_total{upstream}` — UI alert "upstream X breaking DNSSEC?"

### 8.3 Tests

- `dnssec-failed.org` → SERVFAIL; `sigfail.verteiltesysteme.net` → SERVFAIL; `sigok.verteiltesysteme.net` → NOERROR+AD
- `broker.fail` NSEC3 opt-out case; zones with algorithms 8/13/15/16

---

## 9. Clients and Policies — Details

### 9.1 Data model

```toml
[[clients.entries]]
name = "Jane's Phone"
ids = ["192.168.1.20", "janes-phone", "AA:BB:CC:DD:EE:FF"]
group = "kids"
ignore_query_log = false
use_global_upstreams = true      # false → per-client upstream section

[clients.groups.kids]
lists = ["OISD", "StevenBlack", "school-list"]
custom_rules = ["||fortnite.com^$important"]
safe_search = true
parental = true
schedule_enabled = true          # entire filtering on a schedule
[[clients.groups.kids.blocked_services]]
service = "tiktok"
schedule = "0 0 15-21 * * MON-FRI"   # sec min hour dom mon dow
```

### 9.2 Identification — details

- ClientID from DoH: `/dns-query/{id}`; from DoT/DoQ: SNI `{id}.dns.yourdomain` (requires wildcard cert)
- MAC: read `ip neigh` / `/proc/net/arp`, 60 s cache; works only on the same L2
- **MikroTik integration**: every `integrations.mikrotik.interval` (default 300 s) GET `https://<router>/rest/ip/dhcp-server/lease` (auth: bearer/basic) → mapping MAC→(hostname, IP, comment); a client matched by MAC gets the RouterOS name when no manual one exists
- Data merge order: ClientID → static IP/CIDR → MAC (local) → MAC (RouterOS) → "unknown"

### 9.3 Safe search — rewrite table

| Service | Rewrite |
|---|---|
| Google (all TLDs from list) | `forcesafesearch.google.com` |
| Bing | `strict.bing.com` (CNAME) |
| YouTube | `restrict.youtube.com` or `restrictmoderate.youtube.com` (UI choice) |
| DuckDuckGo | `safe.duckduckgo.com` |

Implemented as system `$dnsrewrite` entries with highest priority, hidden from the rule editor (separate UI tab).

### 9.4 Parental control

- Local category lists (subscription format like regular lists; example source: UT1) — full privacy, works offline
- Category flags: `adult`, `gambling`, `violence`, `social_networks`... — mapped to lists in group config
- Default "adult" list bundled with the binary (updated like lists)

### 9.5 Service blocking

- Bundled `services.json` (format compatible with AdGuard hostlist-compiler: `{"tiktok": ["tiktok.com", "tiktokcdn.com", ...]}`), updated with releases + optional remote fetch
- Schedule: `croner` library (6 fields, with seconds); a schedule boundary = re-evaluation on the next query (no intermediate states)

### 9.6 Anti-DoH bypass (global toggle)

- Bundled, updatable list of known public DoH/DoT resolvers (domains + IPs)
- Mode: `off` | `block_all` | `block_except_trusted` (clients with the `trusted` flag bypass)
- Metric `sito_doh_bypass_blocked_total` + a distinct color in the query log

---

## 10. Local Records — Details

- Types: A, AAAA, CNAME, TXT, PTR, MX, SRV, HTTPS/SVCB (v1: A/AAAA/CNAME/PTR, rest in backlog)
- Wildcard `*.home.arpa` — answer synthesized per query; wildcard CNAME → chain resolved locally or upstream
- PTR: auto-generated for A/AAAA entries pointing at RFC1918/ULA (reversed into in-addr.arpa/ip6.arpa) — toggle `rewrites.auto_ptr`
- Per-client exceptions: `exception_clients = ["admin-laptop"]` — that client gets the upstream answer instead of the rewrite
- Conflicts: a rewrite beats cache and filtering (pipeline), loses to `$important` — decision documented in ADR-007, to be settled in M4

---

## 11. HA Master/Slave — Details

### 11.1 Protocol (JSON over WebSocket + mTLS)

```json
// slave → master, after TLS handshake
{ "type": "hello", "instance": "slave-pi", "have_version": 41, "capabilities": ["stats-v1"] }

// master → slave
{ "type": "config_push", "version": 42, "hash_blake3": "…", "signature_ed25519": "…",
  "payload_b64": "…", "payload_hash_blake3": "…" }

// slave → master
{ "type": "ack", "version": 42, "applied": true, "error": null }

// every 30 s slave → master
{ "type": "stats_report", "window_s": 30, "queries": 81234, "blocked": 12044,
  "upstreams": {"tls://a": {"rtt_ms": 8.2, "errors": 0}} }

// both ways every 15 s
{ "type": "ping", "ts": 169… }
```

### 11.2 Config bundle contents

All replicable state: `config.toml` (without `[ha]` and `server.instance_name`), custom rules, rewrites, client/group definitions, list metadata (URLs — each instance downloads lists itself; avoids pushing megabytes). Secrets (UI passwords, TLS keys, MikroTik token) **never** leave the master — the slave has its own local secrets; the bundle carries placeholders `${SECRET:web_password}`.

### 11.3 Slave state machine

```
Connecting → HelloSent → Synced ⇄ Applying → Synced
    │ (conn. lost)          │ (apply error: roll back to previous snapshot,
    ▼                       │  error in ack, Degraded state)
Backoff(1s→60s, jitter)
```

### 11.4 Security

- Mutual TLS: self-signed certs generated by `sito ha gen-certs`, fingerprint pinning in both configs
- ed25519 signing key on the master only; slave verifies signature + `version > have_version` (monotonicity guards against replay)
- Replication port (8953) never exposed beyond trusted networks — firewall documented in examples

### 11.5 Topologies

- **One machine, two instances**: compose with macvlan (separate LAN IPs) or one host with ports 53 and 5353; local master+slave = testing HA without a second host
- **Multi-host**: master in the homelab, slave on an RPi and a VPS
- **Master degradation**: slaves run on the last bundle; slave UI shows "master unreachable since …"; manual slave promotion = change `role` in its local config + restart (procedure in docs/runbook)

### 11.6 Stats aggregation

Master merges `stats_report` under the `instance` label; dashboard toggle "all / per instance"; query log stays local per instance (log aggregation — v1.1 backlog).

---

## 12. REST API — Full Reference

Conventions: base `/api/v1`; errors RFC 7807 (`application/problem+json`); cursor pagination (`?cursor=&limit=`, response with `next_cursor`); all times RFC 3339 UTC; versioning in path, breaking changes → `/api/v2` with a 2-release deprecation window.

### 12.1 Endpoints

| Method and path | Description | Scope |
|---|---|---|
| `GET /status` | version, uptime, HA role, listeners | viewer |
| `GET /stats?window=1h\|24h\|7d\|30d` | global aggregates | viewer |
| `GET /stats/clients` | per client | viewer |
| `GET /stats/upstreams` | RTT, errors, share % | viewer |
| `GET /querylog?client=&domain=&status=&qtype=&from=&to=&cursor=` | query log | viewer |
| `DELETE /querylog` | clear | operator |
| `GET /querylog/stream` (WS) | live tail | viewer |
| `GET/POST /filtering/lists`, `PUT/DELETE /filtering/lists/{id}` | subscription CRUD | operator |
| `POST /filtering/refresh` | force list update | operator |
| `GET/PUT /filtering/rules` | custom rules (whole) | operator |
| `POST /filtering/check?domain=&client=` | verdict simulation | viewer |
| `GET/POST/PUT/DELETE /clients[/{name}]` | clients | operator |
| `GET/PUT /clients/groups[/{name}]` | groups and policies | operator |
| `GET/POST/PUT/DELETE /rewrites[/{id}]` | local records | operator |
| `GET/PUT /upstream/config` | upstreams, strategy, per-domain | operator |
| `POST /upstream/test` | measure RTT to candidates | operator |
| `GET/PUT /config` | whole config (secrets masked `***`) | admin |
| `POST /config/reload` | hot-reload from disk | admin |
| `GET /config/backup` | tar.gz archive (config + metadata, no query log) | admin |
| `POST /config/restore` | restore (requires confirmation token) | admin |
| `GET /ha/status`, `GET /ha/slaves`, `POST /ha/resync` | HA | admin |
| `POST /cache/flush`, `POST /cache/invalidate?domain=` | cache | operator |
| `POST /auth/login`, `POST /auth/totp/verify`, `POST /auth/logout` | session | — |
| `GET/POST/DELETE /auth/tokens[/{id}]` | API tokens with scopes | admin |
| `GET /auth/totp/setup` | TOTP init (secret + otpauth:// QR) | admin |

### 12.2 Login flow with TOTP

```
POST /auth/login {user, pass}
  → 200 {session}                      (TOTP disabled)
  → 202 {partial_token, totp_required} (TOTP enabled)
POST /auth/totp/verify {partial_token, code}
  → 200 {session} | 401 (max 5 attempts → 15 min lockout, per-IP rate limit)
```

- Passwords: Argon2id (m=64 MiB, t=3, p=4); sessions: cookie `HttpOnly; Secure; SameSite=Strict`, rotation after login
- API tokens: `sito_<random-256-bit>`, only blake3 hash stored; scopes: `admin/operator/viewer` + optional endpoint-group restriction
- TOTP: RFC 6238, 30 s, ±1 window, 10 one-time backup codes (hashed)

---

## 13. Web Panel — Details

### 13.1 View map

| View | Contents |
|---|---|
| Dashboard | QPS + blocked % chart (last 24 h), cards: queries/blocked/%/clients, top 10 domains (allowed/blocked), top clients, upstream status (RTT sparklines), HA status |
| Query Log | table with filters (client, domain, status, type, time), expandable row (matched rule, upstream, DNSSEC, CNAME chain), live tail (WS), actions: "block" / "allowlist" from a row |
| Filtering | tabs: Lists (toggle, rule counts, "last updated", refresh button), Custom rules (Monaco editor with ABP syntax highlighting + live validation via `/filtering/check`), Services (tiles with schedules), Parental control |
| Clients | client table + auto-discovered (unknown from RouterOS) with "create client" button; group editor modal |
| Local records | rewrite table + inline resolution test |
| Upstreams | editor + "Test" button (per-server RTT, bar chart), health preview |
| HA | instance map (master → slaves), config versions, replication lag, push history |
| Settings | sections 1:1 with config.toml; every change → TOML diff preview before save |
| System | backup/restore, service logs, version, OSS licenses |

### 13.2 Setup wizard (first run)

1. Language selection (en/pl)
2. Admin account (+ optional TOTP right away)
3. Listener ports and interfaces (with occupied-port detection — `ss -lntup`)
4. Upstreams (presets: Quad9, Cloudflare, Google, custom) with live RTT test
5. Initial blocklists (checkboxes with recommendations)
6. Summary → save → "Done" with test `dig` commands

### 13.3 Technical

- React 18 + strict TS, Vite, TanStack Query (API cache), Zustand (UI state), React Router
- Charts: Recharts (dashboard), query-log table virtualization (TanStack Virtual) — 100k rows without lag
- Tailwind + Mantine; dark/light/auto; i18n via `react-i18next` (en.json, pl.json in repo)
- Build: `vite build` → `rust-embed` behind the `embed-ui` feature flag (dev: Vite proxy to :3000)
- Accessibility: aria-labels, keyboard navigation, AA contrast

---

## 14. Stats, Logs, Metrics — Details

### 14.1 SQLite schema

```sql
CREATE TABLE query_log (
    id INTEGER PRIMARY KEY,
    ts INTEGER NOT NULL,                 -- unix millis
    client_ip TEXT NOT NULL,             -- or masked
    client_name TEXT,
    qname TEXT NOT NULL,
    qtype INTEGER NOT NULL,
    rcode INTEGER,
    verdict TEXT NOT NULL,               -- allowed|blocked|whitelisted|rewritten|stale
    rule TEXT,                           -- matched rule
    list_source TEXT,
    upstream TEXT,
    elapsed_us INTEGER,
    dnssec TEXT,                         -- secure|insecure|bogus
    proto TEXT                           -- udp|tcp|dot|doh|doq|doh3
);
CREATE INDEX idx_ql_ts ON query_log(ts);
CREATE INDEX idx_ql_qname_ts ON query_log(qname, ts);
CREATE INDEX idx_ql_client_ts ON query_log(client_name, ts);

CREATE TABLE stats_hourly (
    hour INTEGER PRIMARY KEY,
    queries INTEGER, blocked INTEGER, cached INTEGER,
    top_domains TEXT,                    -- JSON: [[qname, count], ...] top 100
    top_clients TEXT
);
```

- Writes: 10k ring buffer → batch `INSERT` every 5 s or at 1000 entries in one transaction
- Retention: nightly job — query log older than 90 days deleted; aggregation into `stats_hourly` (after a year: compaction to daily)
- Weekly VACUUM; DB size limit with a UI alarm

### 14.2 Prometheus metrics (`GET /metrics`)

| Metric | Type | Labels |
|---|---|---|
| `sito_queries_total` | counter | proto, qtype, verdict |
| `sito_query_duration_seconds` | histogram | verdict |
| `sito_upstream_rtt_seconds` | histogram | upstream |
| `sito_upstream_errors_total` | counter | upstream, kind |
| `sito_upstream_health` | gauge | upstream |
| `sito_cache_hits_total` / `sito_cache_misses_total` | counter | — |
| `sito_cache_size_bytes` | gauge | — |
| `sito_cache_stale_served_total` | counter | — |
| `sito_filter_rules` | gauge | list |
| `sito_filter_compile_seconds` | histogram | — |
| `sito_dnssec_bogus_total` | counter | upstream |
| `sito_clients_identified_total` | counter | method |
| `sito_doh_bypass_blocked_total` | counter | — |
| `sito_ha_slaves_connected` | gauge | — |
| `sito_ha_config_version` | gauge | instance |
| `sito_querylog_dropped_total` | counter | — |
| `sito_build_info` | gauge | version, commit |

A ready Grafana dashboard in `contrib/grafana/`.

### 14.3 Privacy

- `stats.anonymize_client_ip = true` → masking to /24 (v4) and /56 (v6) before storage
- Per-client `ignore_query_log`, `ignore_stats`
- Global query-log disable (counters remain)

---

## 15. Configuration — Full Reference

```toml
config_version = 1                     # automatic migrations on schema change

[server]
role = "master"                        # master | slave
instance_name = "sito-main"
data_dir = "/var/lib/sito"
log_level = "info"                     # trace|debug|info|warn|error
log_format = "json"                    # json|pretty

[dns]
bind = ["0.0.0.0", "::"]
port = 53
dot_port = 853                         # 0 = disabled
doh_port = 443
doq_port = 853
doh_dedicated_hostname = ""            # optional DoH-only vhost
edns_udp_size = 1232
rate_limit_per_ip = 20                 # qps, 0 = off
max_tcp_connections = 256

[dns.cache]
enabled = true
size_mb = 64
min_ttl = 60
max_ttl = 86400
negative_ttl_max = 3600
prefetch = true
serve_stale_hours = 12

[dns.dnssec]
validate = true
ntp = []                               # negative trust anchors

[upstream]
servers = ["tls://dns1.example", "https://dns2.example/dns-query"]
bootstrap = ["9.9.9.9", "149.112.112.112"]
strategy = "parallel"
timeout_ms = 5000
probe_domain = "example.com"
pool_size = 4

[[upstream.per_domain]]
domains = ["*.lan", "168.192.in-addr.arpa"]
servers = ["192.168.1.1"]

[filtering]
enabled = true
refresh_interval_hours = 24
blocking_mode = "zero_ip"
blocking_ttl = 10
cname_cloaking = true
anti_doh_bypass = "off"                # off|block_all|block_except_trusted
lists = [ { name = "OISD", url = "…", enabled = true, refresh_hours = 24 } ]
custom_rules = []

[clients]  # see section 9.1

[rewrites]
auto_ptr = true
entries = [ { domain = "*.home.arpa", type = "A", answer = "192.168.1.10", exception_clients = [] } ]

[web]
port = 8080
bind = ["0.0.0.0"]
https = true
cert = "/etc/sito/cert.pem"
key = "/etc/sito/key.pem"
acme_enabled = false                   # M7+: automatic certificates

[auth]
session_ttl_hours = 24
login_rate_limit = 5                   # per minute per IP

[stats]
query_log_enabled = true
query_log_retention_days = 90
anonymize_client_ip = false
prometheus_enabled = true

[ha]
replication_port = 8953
# master: nothing more; slave:
# master_url = "wss://192.168.1.10:8953"
# master_fingerprint = "blake3:…"
# cert / key / ca — paths to mTLS material

[integrations.mikrotik]
enabled = false
url = "https://192.168.1.1"
token_env = "MIKROTIK_API_TOKEN"
interval_s = 300
```

Rules: env override `DNSD__SECTION__KEY` (double underscore); secrets only via env or file paths (`*_env`, `*_file`); `config_version` — automatic migrations with a file backup; every change via API → validation → atomic write (tmp+rename) → snapshot swap.

---

## 16. Performance and Scale — Details

### 16.1 Targets (reference hardware: 8-core x86_64, 16 GB RAM)

| Scenario | Target |
|---|---|
| UDP, cache hits | ≥ 500k QPS |
| UDP, parallel forwarding (upstream 10 ms) | ≥ 100k QPS |
| DoT (persistent connections) | ≥ 50k QPS |
| DoH H2 (persistent connections) | ≥ 40k QPS |
| Added latency p99 (cache) | < 1 ms |
| RAM at 1M rules + full cache | < 512 MB |

### 16.2 Build tuning

```toml
[profile.release]
lto = "fat"
codegen-units = 1
panic = "abort"          # after M9 security review; before that unwind + catch at task boundary
strip = true
```

- PGO (profile from dnsperf) in the release pipeline; `target-cpu=native` for self-hosted builds, generic for releases
- `mimalloc` globally behind a feature flag

### 16.3 System tuning (documented in docs/performance.md)

```
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.core.netdev_max_backlog = 250000
net.core.somaxconn = 4096
net.ipv4.udp_rmem_min = 8192
fs.file-max = 2097152
```

### 16.4 Benchmark methodology

- `dnsperf`/`resperf`: 1M real-domain corpus (Tranco), 3 runs of 5 min, report in CI as an artifact; regression > 10% = red check
- Criterion for filter/cache micro-benchmarks
- `flamegraph` + `tokio-console` for analysis; hot-path time budget documented in ADR-008

---

## 17. Deployment — Details

### 17.1 Dockerfile (multi-stage)

```dockerfile
FROM rust:1-bookworm AS builder
WORKDIR /src
COPY . .
RUN cargo build --release --locked --features embed-ui

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=builder /src/target/release/sito /usr/bin/sito
USER nonroot
EXPOSE 53/udp 53/tcp 853 443 8080 8953
VOLUME ["/var/lib/sito"]
ENTRYPOINT ["/usr/bin/sito", "--config", "/etc/sito/config.toml"]
```

Note: distroless nonroot + `CAP_NET_BIND_SERVICE` granted in compose/k8s; alternative `-rootful` tag for simplicity.

### 17.2 Compose — single instance

```yaml
services:
  sito:
    image: ghcr.io/<org>/sito:latest
    cap_add: [NET_BIND_SERVICE]
    ports: ["53:53/udp", "53:53", "853:853", "443:443", "8080:8080"]
    volumes: ["./config:/etc/sito", "sito-data:/var/lib/sito"]
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "/usr/bin/sito", "healthcheck"]
      interval: 30s
volumes: { sito-data: {} }
```

### 17.3 Compose — HA on one machine (macvlan)

```yaml
networks:
  lan:
    driver: macvlan
    driver_opts: { parent: eth0 }
    ipam: { config: [{ subnet: 192.168.1.0/24 }] }

services:
  sito-master:
    networks: { lan: { ipv4_address: 192.168.1.10 } }
    # …
  sito-slave:
    networks: { lan: { ipv4_address: 192.168.1.11 } }
    environment: [ "DNSD__HA__MASTER_URL=wss://192.168.1.10:8953" ]
    # …
```

MikroTik: DHCP option 6 hands out both addresses — clients get a redundant DNS pair.

### 17.4 systemd

```ini
[Unit]
Description=sito DNS server
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
ExecStart=/usr/bin/sito --config /etc/sito/config.toml
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/sito
LimitNOFILE=1048576
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
```

### 17.5 Installer and packages

- `install.sh`: detect arch → download binary from GitHub Releases → checksum + cosign signature verification → systemd unit → wizard pointing at the panel URL
- `.deb`/`.rpm` via cargo-dist/nfpm; APT/RPM repos in the v1.1 backlog
- Helm chart (optional, v1.1): Deployment + LoadBalancer Service with TCP/UDP (MetalLB)

### 17.6 Behind a reverse proxy

DoH and panel behind Traefik/Caddy: `web.trusted_proxies = ["10.0.0.0/8"]` — client IP from `X-Forwarded-For` only from trusted proxies; PROXY protocol v2 as an option. UDP/53 and DoT/DoQ listeners cannot go behind a typical reverse proxy — docs explain the split.

---

## 18. Tests — Details

### 18.1 Integration test matrix

Transports {udp, tcp, dot, doh2, doh3, doq} × scenarios {plain query, blocked domain, allowlist, rewrite, per-client, DNSSEC OK/bogus, cache hit} — generated parametrically in `tests/transport_matrix.rs` with docker-compose (sito + fake upstream + `q`/`kdig` clients).

### 18.2 Conformance vs AdGuard

- Corpus: 200+ rules covering every modifier + 10k random domains; oracle: dockerized AdGuard Home on the same config; verdict diff = report
- Goal: 100% parity on documented syntax; deliberate divergences (e.g., `$important` vs rewrite order) described in `docs/compatibility.md`

### 18.3 Fuzzing

- `cargo-fuzz` targets: DNS message decoder (if a custom parser ever appears), rule parser, TOML-config parser, ClientID extraction from URL/SNI
- CI: 10 min/target nightly; corpus in a separate repo

### 18.4 Chaos / HA

- Kill the master mid-`config_push` → slave consistent at version N or N+1, never in between
- 500 ms network delay (tc netem) → ack timeouts, retries, no duplicate applies
- Slave returns after 24 h offline → resync with one bundle

### 18.5 CI pipeline

```
PR: fmt → clippy -D warnings → cargo-deny → unit tests → integration (matrix) → build matrix (x86_64, aarch64, armv7)
nightly: fuzzing + load regression (dnsperf)
tag: release (cargo-dist: binaries, packages, multi-arch images, cosign signature, SBOM)
```

---

## 19. License and Governance — Details

- **GPL-3.0** (recommendation): consistent with AdGuard Home; network use without giving back code — if that's a problem, consider AGPL-3.0 (closes the SaaS loophole) — decision in ADR-009 before the first public commit, because changing the license after accepting contributions is painful
- DCO (Signed-off-by) instead of CLA — less friction
- `SECURITY.md`: reporting policy (private GitHub security advisory), 72 h response window, supported versions: last two minors
- Releases: semver, CHANGELOG from conventional commits, RC for 1 week before a major
- Badges: CI, coverage, crates.io (for library crates), ArtifactHub (helm), OpenSSF best practices (target: silver)

---

## 20. Roadmap — Tasks per Phase

### M0 Foundation (1 wk)
- repo, 13-crate workspace (empty lib.rs), rust-toolchain, deny.toml
- CI: fmt/clippy/test/build; pre-commit hooks
- ADR-001…009; LICENSE; CONTRIBUTING; SECURITY.md
- Exit: CI green on the empty skeleton; `sito --version` runs
- Risk: paralysis-by-ADR → 1 day/ADR limit

### M1 MVP (3 wk)
- hickory-proto decode/encode; UDP/TCP listeners (SO_REUSEPORT)
- UpstreamManager: plain + DoT, failover strategy, timeout
- moka cache with TTL; ConfigManager (TOML + validation, no hot-reload)
- hosts-format list parser; zero_ip blocking; tracing; Dockerfile
- Exit: `dig` works; listed domain → 0.0.0.0; cache hit in logs; image < 30 MB
- Risk: "just add DoH" temptation — scope guard: only the list above

### M2 Filtering engine (4 wk)
- Full ABP parser (section 4.1) + modifiers
- SuffixTrie + label interning; Aho-Corasick; regex DFA
- Snapshots + arc-swap; subscriptions: scheduler, ETag, disk cache, >50% drop guard
- Criterion benchmarks; CNAME uncloaking; blocking modes
- Exit: conformance suite green; lookup < 1 µs @ 1M rules; hot-swap lists without restart
- Risk: trie RAM → fallback: `qfilter`/bloom structure before trie (optimization in M9)

### M3 Encryption + DNSSEC (3 wk)
- DoT, DoH H2 (hickory features), cert management (PEM + reload without restart)
- DNSSEC validation + NTA + metrics
- Exit: `kdig @… +tls` OK; dnssec-failed.org → SERVFAIL; cert reload via SIGHUP/API
- Risk: ALPN/SNI edge cases — tests with openssl s_client and q

### M4 Clients + rewrites (4 wk)
- ClientRegistry (5 ID methods), groups, per-client policies, schedules (croner)
- Rewrites + wildcard + auto-PTR + exceptions
- Services (services.json) + safe search + parental (category lists)
- MikroTik integration (RouterOS REST)
- Exit: 2 devices, 2 groups, different verdicts; wildcard works; RouterOS clients have names in UI/API
- Risk: "who sees what" matrix complexity → policy conformance test table as an M4 artifact

### M5 API + data (3 wk)
- axum: full section 12.1; utoipa; sessions+Argon2+TOTP+tokens+RBAC
- SQLite: schema 14.1 + migrations + retention; Prometheus
- Backup/restore; hot-reload (`notify`)
- Exit: Swagger complete; query log survives restart; Grafana graphs
- Risk: SQLite blocking tokio → `spawn_blocking` + a single writer connection

### M6 UI (5 wk)
- All views 13.1 + wizard 13.2; embed; i18n en/pl; dark mode
- Exit: full operation without TOML; Lighthouse a11y ≥ 95; bundle < 1 MB gzip
- Can run partly parallel to M2–M5 (separate agent/work stream)

### M7 DoQ/DoH3 + remaining protocols (3 wk)
- DoQ, DoH3, Alt-Svc; anti-DoH bypass; optional ACME (instant-acme)
- Exit: `q --doq` and `q --doh3` work; YouTube enforces restrict; LE cert self-renews
- Stretch: DNSCrypt (ADR-006)

### M8 HA (3 wk)
- Protocol 11.1, mTLS, ed25519 signatures, state machine, stats aggregation
- Compose HA (17.3), slave promotion runbook
- Exit: push → apply < 2 s on 2 slaves; chaos suite green; UI shows lag
- Risk: secrets in bundles → `${SECRET:*}` placeholder review before M8-exit

### M9 Hardening + 1.0 (4 wk)
- Nightly fuzzing, load tests, tuning, security review (self + external if budget)
- Docs: installation, configuration reference, performance, HA runbook, compatibility
- cargo-dist release: binaries × 3 arches, packages, images, cosign, SBOM
- Exit: section 16 targets met or deviations documented; tag v1.0.0

**Total estimate: ~33 weeks** of solo work assisted by agents (M6 in parallel shortens to ~28). Dated milestones only after M1 — first data on real velocity.

---

## 21. Coding-Agent Playbook

### 21.1 Module prompt template

```
CONTEXT: docs/dns-server-plan-detailed.md (sections: X, Y), docs/adr/ADR-00*.md, crates/sito-core/src/types.rs
TASK: Implement <module> per section <N>.
REQUIREMENTS:
- Module public API: <signatures / traits>
- Tests first (TDD): <case list>
- Criteria: cargo test green, clippy -D warnings, no unwrap() outside tests
- Forbidden: changing sito-core without an ADR update; new dependencies without PR justification
DEFINITION OF DONE: <metrics, benchmarks, conformance>
```

### 21.2 Prompt order (dependencies)

`sito-core` → `sito-transport` (udp/tcp) → `sito-upstream` → `sito-cache` → `sito-filter` → M1 binary → TLS transports → `sito-clients` + `sito-rewrites` → `sito-stats` + `sito-api` → `ui` → `sito-ha`.

### 21.3 Review rules

- Diff > 800 lines → reject, ask for a split
- Every PR: a "Plan compliance" section referencing section numbers of this document
- Code diverging from the plan → update the plan in the same PR (the plan is a living artifact)
- Regression benchmark mandatory in the PR description when touching `sito-filter` or the hot path

---

## Appendix A: Glossary

- **Snapshot** — immutable, wholly-swapped state structure (filters/clients/rewrites) shared via `Arc`
- **Config bundle** — versioned, signed set of state replicated master→slave
- **Bootstrap** — plain DNS used solely to resolve encrypted-upstream hostnames
- **NTA** — Negative Trust Anchor: disables DNSSEC validation for a listed zone

## Appendix B: AdGuard syntax compatibility

Full rule → behavior table (supported / supported differently / missing) maintained in `docs/compatibility.md` from M2; the source of truth on AdGuard Home behavior is its filtering documentation and the dnsproxy/hostlist-compiler code.
