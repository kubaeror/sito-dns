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

- [ ] Conformance suite green on section 4.1 syntax
- [ ] Lookup p50 < 1 µs at 1M rules; RAM < 150 MB (or documented deviation + plan)
- [ ] Live list swap: in-flight queries finish on the old snapshot, new ones on the new
- [ ] `@@||allow.example^` beats `||example^`; `$important` beats allowlist; `$denyallow` unblocks listed domains
- [ ] Offline startup loads lists from disk
- [ ] Corrupted list (HTML instead of hosts) rejected by validation, old version kept

## Risks

| Risk | Mitigation |
|---|---|
| Trie RAM at 5M+ domains (Hagezi Pro) | Measure in M2.2; fallback ADR: bloom filter before trie (cost: rare false positives needing a second pass) |
| DFA compilation from thousands of regexes is slow | Limit: list with >5k regexes → lazy regex compilation + warn; compile-time metric |
| `$badfilter` semantics drifting from AdGuard | Conformance corpus cases before implementation |

## Deliverables

`sito-filter` with benchmarks in CI (regression >10% = red check), conformance report, entry in `docs/compatibility.md`.
