# Phase M4 — Clients, Policies and Local Records (4 weeks)

Goal: the full "who sees what" model like AdGuard Home, plus local DNS records. References: plan sections 9, 10.

## Scope

**In:** client identification (5 methods), groups and policies, schedules, safe search, parental (category lists), service blocking, rewrites with wildcards and auto-PTR, RouterOS API integration.
**Out:** UI for all this (M6), API (M5) — configuration via TOML.

## Tasks

### 1. ClientRegistry (`sito-clients`)

- Identification chain (section 9.2): ClientID (DoH path from M3 / DoT SNI subdomain) → static IP/CIDR → local MAC → RouterOS → `unknown`
- MAC: parse `ip neigh`, 60 s cache; not on the same L2 → skip silently
- Client resolves to an `EffectivePolicy`: group policy + client overrides merged

### 2. Groups and policies

- Data model from section 9.1 (TOML); build per-group filter snapshots: shared global `Arc` + group deltas (section 4.2)
- Flags: `ignore_query_log`, `ignore_stats`, `use_global_upstreams`, `trusted` (for anti-bypass in M7)
- `$client` in rules wired to the full registry (evaluation already exists from M2)

### 3. Schedules

- `croner` (6 fields with seconds); lazy evaluation at query time (section 9.5); tests with a mocked clock — a schedule boundary must flip the verdict deterministically
- Schedules on: service blocking, whole group filtering, safe search

### 4. Safe search, parental, services

- Safe search: system rewrites from table 9.3 (Google/TLDs, Bing, YouTube strict/moderate, DDG), priority above regular rules
- Parental: category lists as regular subscriptions + a bundled starter list; category flags on the group
- Services: `services.json` (AdGuard hostlist-compiler-compatible format) bundled via `include_str!`; evaluated after filters, with schedule

### 5. Rewrites (`sito-rewrites`)

- A/AAAA/CNAME/PTR; wildcard `*.home.arpa` with answer synthesis; CNAME → local chain or upstream
- `rewrites.auto_ptr`: automatic PTR for RFC1918/ULA entries
- `exception_clients` — client bypasses the rewrite
- **Close ADR-007 here:** rewrites vs `$important` precedence — decision + conformance test

### 6. MikroTik integration

- Periodic task: GET `/rest/ip/dhcp-server/lease` (bearer from env), mapping MAC→(hostname, IP, comment)
- Detected but undefined clients → "known unidentified" list in state (for the future "create client" UI button)
- Router failure: backoff, metric, never an error in the DNS pipeline

## Agent prompts

```
M4.1 registry     → tasks 1–2; DoD: every ID method covered by a test; ClientID beats IP;
                    unknown gets the global policy
M4.2 schedules    → task 3; DoD: test with a frozen clock at the interval boundary;
                    bad cron rejected by config validation with a field number
M4.3 blocking     → task 4; DoD: forcesafesearch in the answer for the group;
                    scheduled service blocks only inside the window; parental category
                    works from a test list
M4.4 rewrites     → task 5; DoD: wildcard A + auto-PTR (dig -x); client exception;
                    CNAME chain; ADR-007 closed
M4.5 routeros     → task 6; DoD: mock RouterOS server in tests; lease names appear
                    in ClientContext; dead router = no DNS impact
M4.6 matrix       → integration tests: 3 devices × 3 groups × {block, allowlist,
                    service, safe search, rewrite} — results table as an artifact
```

## Tests and acceptance criteria

- [x] Two devices in different groups get different verdicts for the same domain
- [x] ClientID from DoH and SNI from DoT identify without IP
- [x] `dig -x 192.168.1.10` returns the PTR from the rewrite
- [x] Schedule toggles a service block at the boundary (mocked clock)
- [x] YouTube in a safe-search group → CNAME `restrict.youtube.com`
- [x] Policy matrix (M4.6) green in CI
- [x] Client TOML change + reload (manual in this phase) without restart

## Risks

| Risk | Mitigation |
|---|---|
| Policy combinatorics → "who sees what" bugs | Test matrix as a phase artifact, not an optional extra |
| RouterOS API differs between v6/v7 | Require RouterOS ≥7.1 (REST), documented; graceful degradation |
| Wildcards vs reverse zones — edge cases | PTR test corpus before implementing auto-PTR |

## Deliverables

Full client/group configuration via TOML, policy matrix in `docs/policy-matrix.md`, closed ADR-007.

---

## Completion Report

All subphases of Phase M4 (Clients, Policies and Local Records) are implemented, verified, and passing all tests:
1. **M4.1 Client Registry & Identification:** Multi-tier client identification chain (DoH path, DoT SNI subdomain, static IP/CIDR, local MAC via ARP cache, MikroTik RouterOS lease matching, unknown fallback).
2. **M4.2 Schedules:** Lazy query-time cron schedule evaluation via `croner` with 5- and 6-field cron support, minute and hour window intervals, and field-number validation.
3. **M4.3 Safe Search, Parental Control & Service Blocking:** Table 9.3 rewrites for Google, Bing, YouTube (strict/moderate), DuckDuckGo; bundled `services.json` (23 AdGuard-compatible services); bundled adult and gambling blocklists.
4. **M4.4 Local DNS Rewrites & ADR-0007 Precedence:** Exact A/AAAA/CNAME/PTR, wildcard `*.home.arpa`, local CNAME chaining, auto-PTR for RFC1918/ULA, `exception_clients` bypass. ADR-0007 ratified: `$important` blocks beat local rewrites; local rewrites beat standard filters and cache.
5. **M4.5 MikroTik RouterOS Integration:** REST API client (`GET /rest/ip/dhcp-server/lease`) with token and basic auth, automatic lease synchronization, and graceful error degradation.
6. **M4.6 Integration Test Matrix:** Complete test suite in `crates/sito-test` verifying all 3 devices × 3 groups combinations across transports and rules; formal policy matrix documented in `docs/policy-matrix.md`.
