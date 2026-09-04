# Phase M6 — Web Panel (5 weeks, can run in parallel from M2)

Goal: full server operation without touching TOML — a single binary with an embedded SPA. References: plan section 13.

## Scope

**In:** all views from 13.1, setup wizard 13.2, i18n en/pl, dark mode, embedding in the binary, Playwright e2e.
**Out:** HA editing (forms in M8 after the protocol), advanced reporting.

## Tasks

### 1. UI foundation

- Vite + React 18 + strict TS; TanStack Query; Zustand; React Router; Tailwind + Mantine
- API client generated from `openapi.json` from M5 (openapi-typescript + orval) — no hand-written API types allowed
- Dark/light/auto theme; design tokens; layout with navigation and instance state (a "SLAVE — read-only" badge prepared for M8)
- Dev: Vite proxy to a running sito; prod: `rust-embed` behind the `embed-ui` flag

### 2. Views (batches)

- **Dashboard:** QPS + blocked % chart (24 h, Recharts), summary cards, top 10 domains/clients, upstream RTT (sparklines)
- **Query Log:** virtualized table (TanStack Virtual, 100k rows), filters, expandable row (rule, upstream, DNSSEC, CNAME), live tail (WS), "block"/"allow" actions from a row
- **Filtering:** lists (toggle, counters, refresh), Monaco rules editor with ABP highlighting + live validation via `/filtering/check`, service tiles with schedules, parental
- **Clients:** table + auto-discovered from RouterOS with a "create client" action; group editor
- **Rewrites / Upstreams / Settings / System:** forms 1:1 with the API; RTT test with a chart; TOML diff preview before save; backup/restore with confirmation

### 3. First-run wizard

6 steps from section 13.2: language → admin account (+TOTP) → listeners (occupied-port detection) → upstreams (presets + live RTT test) → lists → summary with `dig` commands.

### 4. Quality

- i18n: `react-i18next`, `en.json`/`pl.json`; all strings via keys (lint)
- A11y: aria, keyboard, AA contrast; Lighthouse ≥ 95
- e2e Playwright: login+TOTP, adding a list, a block visible in the query log, wizard from scratch
- Bundle budget < 1 MB gzip — CI check

## Agent prompts

```
M6.1 scaffold   → task 1; DoD: dev-proxy works, API client generated in prebuild,
                  i18n lint catches raw strings
M6.2 core-ui    → dashboard + query log; DoD: 100k rows scroll smoothly;
                  live tail shows a query in <1 s
M6.3 management → filtering + clients + rewrites; DoD: a rule added in the UI blocks
                  a domain in <2 s (e2e); Monaco highlights and validates
M6.4 system     → upstreams + settings + system; DoD: TOML diff before save;
                  restore requires confirmation and logs out
M6.5 wizard     → task 3; DoD: fresh container → working filtering in <2 min
                  measured in an e2e test
M6.6 embed+e2e  → rust-embed, Playwright in CI; DoD: binary serves the UI; e2e suite
                  green headless; bundle <1 MB gzip
```

## Tests and acceptance criteria

- [ ] All operations from section 12 doable from the UI (manual checklist + e2e on critical paths)
- [ ] Wizard: from `docker run` to a blocked domain < 2 min
- [ ] Lighthouse: a11y ≥ 95, best-practices ≥ 95
- [ ] en/pl switchable without logic reload; no raw strings (lint)
- [ ] UI works solely on the public API — zero "back doors" in the binary

## Risks

| Risk | Mitigation |
|---|---|
| UI↔API type drift | Client generated from OpenAPI; CI fails on mismatch |
| Monaco size in the bundle | Lazy-load the editor; bundle budget as a CI check |
| Visual scope creep | Mock-ups approved before coding a view; UX changes via issues |

## Deliverables

Embedded UI in `:m6`, wizard recording, e2e suite in CI, complete en/pl translations.
