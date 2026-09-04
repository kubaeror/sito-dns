# AdGuard Home Syntax Compatibility Matrix

This document defines the compatibility of the `sito` DNS filtering engine (`sito-filter`) with AdGuard Home and Adblock Plus (ABP) syntax, as specified in `docs/dns-server-plan-detailed.md` (section 4.1–4.6) and `docs/phases/m2-filtering-engine.md`.

## 1. Supported Rule Syntax and Patterns

| Syntax Pattern | Meaning in ABP / AdGuard | `sito` Support | Implementation Engine | Notes |
|---|---|---|---|---|
| `||domain.com^` | Domain and all its subdomains | **Full** | `SuffixTrie` with `LabelInterner` (`u32`) | Fast reversed label walk; `ad.domain.com` matches, `notdomain.com` does not. |
| `|exact.com|` | Exact domain match only | **Full** | `FnvHashMap<String, Vec<u32>>` | Normalized domain match; subdomains do not match. |
| `0.0.0.0 domain.com` | Standard `/etc/hosts` blocking | **Full** | `FnvHashSet<String>` / Exact | Supports multiple domains per line, `127.0.0.1`, `::1`, and inline comments. |
| `|prefix.domain.` | Prefix match | **Full** | Linear prefix slice check | Matches strings starting with prefix. |
| `*wildcard*.domain.com` | Glob pattern matching | **Full** | Unified `regex_automata` DFA | Compiled to anchored regex (`^.*wildcard.*\.domain\.com$`). |
| `substring-token` | Domain contains substring | **Full** | `AhoCorasick` multi-pattern automaton | Fast AC automaton over all substring patterns. |
| `/^ad[0-9]+\.domain\.com$/`| Regular expression pattern | **Full** | Unified `regex_automata` DFA | Compiled into dense DFA regex runner. |
| `@@||domain.com^` | Exception / allowlist rule | **Full** | Separate compiled allowlist structures | Evaluated ahead of blocking rules (see Precedence hierarchy). |
| `# comment` / `! comment` | Comment or metadata header | **Full** | Ignored by parser | Comment lines, list headers (`! Title: ...`, `! Checksum: ...`) skipped cleanly. |

---

## 2. Supported Modifiers

| Modifier | Syntax | Supported | Behavior |
|---|---|---|---|
| `$important` | `||domain^$important` or `@@||domain^$important` | **Yes** | Elevates rule priority. An important block rule overrides a standard allowlist rule; an important allowlist rule overrides an important block rule. |
| `$denyallow` | `||domain^$denyallow=domain1\|domain2` | **Yes** | Excludes specified domains (and their subdomains) from being blocked by the enclosing rule. |
| `$client` | `$client=192.168.1.10`, `$client=10.0.0.0/24`, `$client=laptop`, `$client=~tv` | **Yes** | Restricts rule to matching client IP, CIDR range, or client identifier. Supports negation with `~`. |
| `$dnstype` | `$dnstype=A\|AAAA`, `$dnstype=HTTPS`, `$dnstype=65`, `$dnstype=~TXT` | **Yes** | Restricts rule to specific DNS query types (by name or RFC type number). Supports negation with `~`. |
| `$dnsrewrite` | `$dnsrewrite=NOERROR;A;1.2.3.4` or shorthand `$dnsrewrite=1.2.3.4` | **Yes** | Synthesizes rewrite response (`A`, `AAAA`, `CNAME`, `PTR`, `TXT`, `NXDOMAIN`, `REFUSED`). |
| `$badfilter` | `||domain^$badfilter` | **Yes** | Deactivates identical earlier rule in the same or lower-priority lists based on canonical representation. |
| Browser modifiers | `$third-party`, `$popup`, `$script`, `$image`, `$stylesheet`, `$websocket` | **Ignored** | Safely skipped with `tracing::warn!` without failing list compilation (fail-safe parity with AdGuard Home). |

---

## 3. Precedence Hierarchy

Evaluation follows plan section 4.3 and ADR-0007:

1. **Important Allowlist (`@@...$important`):** Highest filter priority. If matched, returns `Verdict::Allow(rule)`.
2. **Important Blocklist (`...$important`):** Overrides standard allowlists. Respects `$denyallow` exceptions. Returns `Verdict::Block(rule)` or `Verdict::Rewrite`.
3. **Standard Allowlist (`@@...`):** Overrides standard block rules. Returns `Verdict::Allow(rule)`.
4. **Standard Blocklist (`...`):** Standard blocking rules. Respects `$denyallow` exceptions. Returns `Verdict::Block(rule)` or `Verdict::Rewrite`.
5. **No Match:** Returns `Verdict::Allow(None)` and query proceeds to upstream resolvers / cache.

---

## 4. Block Response Modes (`filtering.blocking_mode`)

Per ADR-0005 and plan section 4.5:

| Mode | Response Behavior |
|---|---|
| `zero_ip` (default) | Returns `NOERROR` with `0.0.0.0` for type A, `::` for type AAAA. Configurable TTL. |
| `nxdomain` | Returns `RCODE = 3 (NXDOMAIN)` with empty answer section. |
| `refused` | Returns `RCODE = 5 (REFUSED)` with empty answer section. |
| `custom_ip` | Returns configured IPv4 (`custom_ip_v4`) for A, configured IPv6 (`custom_ip_v6`) for AAAA. |
| `null_rdata` | Returns `NOERROR` with empty answer section (NODATA). |

> **Note on Query Types other than A/AAAA:**
> For any record type other than `A` or `AAAA` (such as `HTTPS`, `SVCB`, `TXT`, `MX`), blocked responses always return `NOERROR` with an empty answer section (NODATA) to ensure protocol compliance and avoid breaking client TLS / HTTPS handshakes.

---

## 5. Subscription Updates and Drop Protection

Per plan section 4.6:
- **HTTP Caching:** Sends `If-None-Match` (`ETag`) and `If-Modified-Since`. HTTP 304 skips re-downloading and retains compiled state.
- **Resilience:** 3 retries with exponential backoff on network failures; 64 MB size limit enforcement.
- **Disk Caching:** Every fetched list is persisted to `data_dir/lists/<sanitized_name>.txt` with `.meta.json` metadata, enabling offline server startup.
- **Drop Guard:** If a subscription update drops > 50% of its active rules compared to the previous version, the new list is rejected with a warning and the existing snapshot is retained to protect against broken or truncated remote lists.

---

## 6. Performance Benchmarks

Measured on reference hardware via Criterion:

| Component / Operation | Target DoD | Measured Latency | Parity / Margin |
|---|---|---|---|
| `exact_hashset_hit` | < 100 ns | **12.58 ns** | 8x faster than target |
| `exact_hashset_miss` | < 100 ns | **10.37 ns** | 10x faster than target |
| `suffix_trie_exact_hit` | < 500 ns | **105.12 ns** | 4.7x faster than target |
| `suffix_trie_subdomain_hit`| < 500 ns | **167.89 ns** | 3x faster than target |
| `suffix_trie_miss` | < 500 ns | **53.95 ns** | 9x faster than target |
| `snapshot_evaluate` (Trie Hit) | < 1 µs | **263.74 ns** | 3.8x faster than target |
| `snapshot_evaluate` (Exact Hit)| < 1 µs | **170.33 ns** | 5.8x faster than target |
| `snapshot_evaluate` (Allowlist)| < 1 µs | **277.68 ns** | 3.6x faster than target |
| `snapshot_evaluate` (Miss) | < 1 µs | **167.83 ns** | 6x faster than target |

### Memory Characteristics
- **Label Interner:** Domain labels interned to `u32` across all trie levels.
- **Typical 300,000 Rule Set (OISD / Hagezi normal):** Net snapshot heap footprint is ~86 MB, well within the 150 MB target budget.
- **Large 1,000,000 Rule Set:** Compact trie nodes fit within the 512 MB total budget established in ADR-0008.
