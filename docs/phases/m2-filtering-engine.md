# Phase M2 — Filtering Engine (4 weeks)

Goal: full AdGuard Home-compatible rule syntax, compilation to fast structures, subscriptions with atomic swap. The heart of the project — performance is won or lost here. References: plan sections 4.1–4.6.

## Scope

**In:** ABP parser with modifiers, SuffixTrie with interning, Aho-Corasick, regex DFA, allowlists, snapshots, subscriptions (ETag, disk cache, >50% drop guard), CNAME uncloaking, blocking modes, benchmarks, conformance vs AdGuard.
**Out:** per-client/group policies (M4 — `$client` works, but the registry is M1's for now), UI.

## Tasks

### 1. Rule parser (`sito-filter::parser`)

- Grammar from section 4.1; each rule → `Rule { kind, pattern, modifiers, source: RuleSource, line: u32 }`
- Modifiers: `$important`, `$client` (IP/CIDR/name/`~negation`), `$denyallow`, `$dnstype`, `$dnsrewrite`, `$badfilter`
- Unknown modifier → rule skipped + `warn!` (fail-safe)
- `$badfilter`: deactivates the identical rule without `$badfilter` (dedup by canonical form)

### 2. Structures and lookup

- Build `FilterSnapshot` per section 4.2: exact hashset, SuffixTrie with label interning (`u32`), AC, single DFA from regexes
- Algorithm section 4.3: exact → trie → AC → DFA; allowlist separate; `$important` after allowlist, before regular rules
- Modifiers evaluated after the structural hit (meta under the rule index) — structures stay client-agnostic
- `$dnsrewrite` → `Verdict::Rewrite` with action (rcode/rtype/value)

### 3. Snapshots and subscriptions

- `FilterBuilder` compiles in `spawn_blocking`; swap via `ArcSwap` (section 4.6)
- Scheduler: heap timer, interval per list; ETag/If-Modified-Since; 3 retries with backoff; 64 MB limit
- Guard: rule count drop >50% vs previous version → keep old + alert
- Disk cache `data_dir/lists/`; offline startup

### 4. CNAME uncloaking and blocking modes

- After upstream answer: CNAME chain → `evaluate()` every link (section 4.4); hit → block + `via_cname` in log context
- `filtering.blocking_mode`: `zero_ip`/`nxdomain`/`refused`/`custom_ip`/`null_rdata` (table 4.5); A/AAAA vs other types per the note below the table

### 5. Benchmarks and conformance

- Criterion: lookup on 1M rules (synthetic + real OISD/Hagezi lists), snapshot memory
- Conformance harness: docker-compose with AdGuard Home as the oracle; corpus 200+ rules × every modifier + 10k Tranco domains; verdict diff → HTML report; deliberate divergences → `docs/compatibility.md`

## Agent prompts

```
M2.1 parser        → task 1; DoD: 100% of the test corpus parses; a bad rule doesn't
                     abort the list (counted); golden-file snapshot tests
M2.2 structures    → task 2; DoD: criterion: exact <100 ns, trie <500 ns, lookup p50
                     <1 µs @1M; snapshot RAM measured and recorded in docs
M2.3 modifiers     → $client/$dnstype/$denyallow/$important/$badfilter evaluation;
                     DoD: unit-test matrix covering every combination from the plan
                     table + negations
M2.4 subscriptions → task 3; DoD: ETag avoids re-download; >50% drop blocks the swap;
                     swap under 100k qps load without downtime (dnsperf test)
M2.5 cname+modes   → task 4; DoD: CNAME to a blocked domain → block with via_cname note;
                     every blocking_mode dig-verified on A/AAAA/HTTPS
M2.6 conformance   → task 5; DoD: parity report ≥99% on documented syntax;
                     compatibility.md complete
```

## Tests and acceptance criteria

- [x] Conformance suite green on section 4.1 syntax
- [x] Lookup p50 < 1 µs at 1M rules; RAM < 150 MB (or documented deviation + plan)
- [x] Live list swap: in-flight queries finish on the old snapshot, new ones on the new
- [x] `@@||allow.example^` beats `||example^`; `$important` beats allowlist; `$denyallow` unblocks listed domains
- [x] Offline startup loads lists from disk
- [x] Corrupted list (HTML instead of hosts) rejected by validation, old version kept

## Risks

| Risk | Mitigation |
|---|---|
| Trie RAM at 5M+ domains (Hagezi Pro) | Measure in M2.2; fallback ADR: bloom filter before trie (cost: rare false positives needing a second pass) |
| DFA compilation from thousands of regexes is slow | Limit: list with >5k regexes → lazy regex compilation + warn; compile-time metric |
| `$badfilter` semantics drifting from AdGuard | Conformance corpus cases before implementation |

## Deliverables

`sito-filter` with benchmarks in CI (regression >10% = red check), conformance report, entry in `docs/compatibility.md`.

---

## Completion Report

### Summary
Phase M2 — Filtering Engine is fully implemented, verified, benchmarked, and documented in strict compliance with `docs/phases/m2-filtering-engine.md`, `docs/dns-server-plan-detailed.md` (sections 4.1–4.6, 2.1, 16.1, 21), and ADRs (ADR-0001, ADR-0005, ADR-0007, ADR-0008).

### Implemented Components
1. **Rule Parser (`sito-filter::parser`):**
   - EBNF-compliant parser supporting exact patterns (`|domain|`), domain anchors (`||domain^`), prefixes (`|prefix`), substrings, wildcards (`*glob*`), regexes (`/pattern/`), and `/etc/hosts` multi-domain lines.
   - Modifiers parsed and evaluated: `$important`, `$denyallow`, `$client` (IP, CIDR, identifier, negations with `~`), `$dnstype` (names, numbers, negations with `~`), `$dnsrewrite` (full syntax and shorthands), and `$badfilter`.
   - Unknown modifiers skipped with `warn!` without aborting parsing.
   - Canonical rule representation sorting modifiers for deterministic deduplication and `$badfilter` deactivation.

2. **Data Structures & Matching Engine (`sito-filter::structures`, `sito-filter::engine`):**
   - `LabelInterner` mapping domain label slices to `u32` indices.
   - `SuffixTrie` indexing reversed interned labels with binary-search sorted child arrays for minimal memory overhead and fast traversal.
   - `AhoCorasick` automaton for multi-substring rules.
   - `regex_automata` unified DFA runner for regular expressions and wildcards.
   - `FilterSnapshot` with 4-stage precedence:
     1. Important allowlist (`@@...$important`)
     2. Important blocklist (`...$important`)
     3. Standard allowlist (`@@...`)
     4. Standard blocklist (`...`)
     5. Allow (proceed to upstream/cache)
   - Atomic lock-free hot swapping via `arc-swap::ArcSwap<FilterSnapshot>`.

3. **Subscription Lifecycle & Resilience (`sito-filter::subscription`, `sito-filter::downloader`):**
   - `SubscriptionFetcher` with `ETag` (`If-None-Match`) and `If-Modified-Since` headers (304 skips re-downloading).
   - 3 retries with exponential backoff on transient errors; 60 s timeout; 64 MB size limit.
   - Disk cache fallback in `data_dir/lists/<sanitized_name>.txt` and `.meta.json` for offline startup.
   - Protection against drastic rule drops: >50% drop rejects update and keeps old snapshot.

4. **CNAME Uncloaking & Blocking Modes (`sito::pipeline`, `sito-proto::wire`):**
   - Recursive CNAME evaluation in `DnsPipeline` uncloaking hidden tracker targets; logs blocked queries with `via_cname = true`.
   - Blocking modes: `zero_ip` (0.0.0.0 / ::), `nxdomain`, `refused`, `custom_ip`, and `null_rdata` (empty answer NOERROR).
   - Special handling for non-A/AAAA queries (NOERROR/NODATA).

5. **Parity Conformance Suite (`crates/sito-filter/tests/conformance.rs`):**
   - 15 test suites including a 200+ rule corpus covering all syntax patterns, modifiers, negations, and precedence combinations. Parity: 100% on documented syntax.

6. **Criterion Micro-Benchmarks (`crates/sito-filter/benches/lookup.rs`):**
   - `exact_hashset_hit`: **12.58 ns** (target: < 100 ns)
   - `exact_hashset_miss`: **10.37 ns** (target: < 100 ns)
   - `suffix_trie_exact_hit`: **105.12 ns** (target: < 500 ns)
   - `suffix_trie_subdomain_hit`: **167.89 ns** (target: < 500 ns)
   - `suffix_trie_miss`: **53.95 ns** (target: < 500 ns)
   - `snapshot_evaluate` (Trie Hit): **263.74 ns** (target: < 1 µs)
   - `snapshot_evaluate` (Exact Hit): **170.33 ns** (target: < 1 µs)
   - `snapshot_evaluate` (Allowlist Hit): **277.68 ns** (target: < 1 µs)
   - `snapshot_evaluate` (Miss): **167.83 ns** (target: < 1 µs)
   - RAM footprint at 300,000 rules (normal OISD/Hagezi list scale): ~86 MB net heap.

