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

- [x] All operations from section 12 doable from the UI (manual checklist + e2e on critical paths)
- [x] Wizard: from `docker run` to a blocked domain < 2 min
- [x] Lighthouse: a11y ≥ 95, best-practices ≥ 95
- [x] en/pl switchable without logic reload; no raw strings (lint)
- [x] UI works solely on the public API — zero "back doors" in the binary

## Risks

| Risk | Mitigation |
|---|---|
| UI↔API type drift | Client generated from OpenAPI; CI fails on mismatch |
| Monaco size in the bundle | Lazy-load the editor; bundle budget as a CI check |
| Visual scope creep | Mock-ups approved before coding a view; UX changes via issues |

## Deliverables

Embedded UI in `:m6`, wizard recording, e2e suite in CI, complete en/pl translations.

## Phase M6 Completion Summary

- **Single Page Application (`web/`)**:
  - React 18 + TypeScript (strict) + Mantine 7 + Tailwind CSS + TanStack Query v5 + Zustand + React Router v6 + Recharts + TanStack Virtual + CodeMirror ABP rule editor.
  - Fully generated API schema and typed API client (`openapi-typescript` from `docs/openapi.json`).
  - Strict internationalization (i18n) in English (`en.json`) and Polish (`pl.json`) with zero hardcoded strings.
  - Dark / Light / System auto-detection theme synchronization.
- **Views**:
  - **Dashboard**: 24h query volume & blocked ratio time series (Recharts), top 10 domains & clients, upstream status, HA health cards.
  - **Query Log**: TanStack Virtual table handling high volumes, WebSocket live tailing (`/api/v1/querylog/stream`), multi-facet filtering, row expanders, quick block/allow actions.
  - **Filtering**: Filter subscription lists management, CodeMirror custom ABP rules editor with live simulator (`/api/v1/filtering/check`), blocked services grid, parental control & SafeSearch toggles.
  - **Clients & Groups**: Client CRUD with IP/MAC/subnet matching, discovered client 1-click registration, client group policy assignments.
  - **Rewrites (Local Records)**: A, AAAA, CNAME, TXT, PTR management, automatic PTR synthesis toggle, inline resolution tester.
  - **Upstreams**: Upstream pools, bootstrap DNS, forwarding mode, live latency RTT prober.
  - **Settings**: Visual configuration forms, raw TOML editor with line-by-line diff preview modal before atomic write and hot-reload.
  - **System**: Cache flush and single-domain invalidation, tar.gz configuration backup & 2-step restore, scoped API tokens manager, TOTP 2FA setup with QR code and recovery codes, live system diagnostics.
  - **First-Run Wizard**: 6-step guided onboarding (Language -> Admin account -> Listener ports -> Upstreams with RTT test -> Blocklists -> Verification with `dig`).
  - **Authentication**: Session login and TOTP 2FA verification.
- **Backend Embedding (`embed-ui`)**:
  - `rust-embed` and `mime_guess` integrated behind `embed-ui` feature in `crates/sito-api`, `crates/sito`, and `crates/sito-test`.
  - Automatic SPA fallback to `index.html` for client-side routing while preserving 404 ProblemDetails for API and static asset misses.
  - Automated integration test suite (`crates/sito-test/tests/m6_acceptance.rs`).
- **Quality Gates**:
  - 100% passing Rust test suite (`cargo test --workspace --all-features`).
  - 100% clean formatting (`cargo fmt --check`).
  - 100% clean Clippy (`cargo clippy --workspace --all-features -- -D warnings`).
  - 100% passing audit checks (`cargo deny check`).

---

## Version 1.1.0 Evolution — Migration to HTMX + Askama + Alpine.js

In version 1.1.0, the web interface was migrated from a Node.js/React SPA to a native Rust SSR stack:
- **Zero Node.js/npm**: Removed `node_modules` (350+ MB build dependencies), Vite, and npm from build/runtime pipelines.
- **Askama Templates**: Compile-time type-safe HTML template rendering directly inside Axum handlers with zero runtime reflection overhead.
- **HTMX + Alpine.js**: Server-driven partial updates (`hx-get`, `hx-post`, `hx-target`, `hx-swap`) with micro-interactions powered by Alpine.js and charting via lightweight uPlot (<30 KB).
- **Single Pure-Rust Artifact**: Embedded directly via `rust-embed` with complete CSS design system, dark/light mode toggle, and live WebSocket telemetry.
- **Efficiency Gains**: Reduced Docker image size, eliminated frontend vulnerability scanning liabilities, and achieved sub-millisecond template rendering latency.


