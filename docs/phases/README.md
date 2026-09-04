# sito Roadmap — Phase Index

Each phase has its own file with: scope (in/out), tasks, coding-agent prompts, tests, risks, and exit criteria. Master plan: `dns-server-plan-detailed.md` (phase section numbers reference it).

## Overview

| Phase | File | Name | Duration | Dependencies |
|---|---|---|---|---|
| M0 | `m0-foundation.md` | Foundation: repo, CI, ADRs | 1 wk | — |
| M1 | `m1-mvp.md` | MVP: UDP/TCP + forwarding + cache + hosts | 3 wk | M0 |
| M2 | `m2-filtering-engine.md` | ABP rule engine + subscriptions | 4 wk | M1 |
| M3 | `m3-dot-doh-dnssec.md` | DoT, DoH H2, DNSSEC validation | 3 wk | M1 |
| M4 | `m4-clients-rewrites.md` | Clients, groups, policies, rewrites | 4 wk | M2, M3 |
| M5 | `m5-api-data.md` | REST API, auth, SQLite, Prometheus | 3 wk | M4 |
| M6 | `m6-ui.md` | React panel + wizard | 5 wk | M5 (API); may start parallel to M2 |
| M7 | `m7-doq-doh3-extras.md` | DoQ, DoH3, anti-bypass, ACME | 3 wk | M3, M4 |
| M8 | `m8-ha.md` | Master/slave replication | 3 wk | M5 |
| M9 | `m9-hardening-1-0.md` | Fuzzing, perf, 1.0 release | 4 wk | all |

## Dependency graph

```
M0 ──▶ M1 ──▶ M2 ──▶ M4 ──▶ M5 ──▶ M8 ──▶ M9
          │     ▲      ▲      │
          ├──▶ M3 ─────┘      ▶ M6 ──────▶ M9
          │     └──▶ M7 ────────────────▶ M9
          └──────────(M6 UI can start in parallel from M2,
                      building pages against API mocks)
```

Schedule compression: M6 in parallel (33 → ~28 weeks). M7 and M8 can swap order if HA matters more than DoQ.

## Working rules (from plan section 21)

- One phase = one work context; one module = one prompt using template 21.1
- TDD: tests before implementation; no PR merges without green tests and clippy
- Code diverging from the plan → plan updated in the same PR
- A phase completion checklist requires 100% checkmarks before the next phase starts
