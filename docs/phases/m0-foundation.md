# Phase M0 — Foundation (1 week)

Goal: a repository ready for agent work — before a single line of DNS logic exists. Everything "boring" whose absence hurts painfully in M9.

## Scope

**In:** workspace, toolchain, CI, lints, ADRs, license, community docs, PR/issue templates.
**Out:** any DNS logic beyond `sito --version`.

## Tasks

### 1. Repository and workspace

- `git init`, protected `main` branch, mandatory conventional commits
- Cargo workspace with the 13 crates from plan section 3.3: empty `lib.rs` + `//!` doc-comment with the crate's responsibility
- `[workspace.lints]`: clippy `pedantic` (with an allowlist of exceptions in the file, not inline), rustfmt `edition 2024`
- `rust-toolchain.toml`: `channel = "stable"`, components `clippy`, `rustfmt`; MSRV noted in README
- `.gitignore` (target/, node_modules/, .env), `.editorconfig`

### 2. CI (GitHub Actions)

File `.github/workflows/ci.yml`, jobs:

1. `fmt` — `cargo fmt --check`
2. `clippy` — `cargo clippy --workspace -- -D warnings`
3. `test` — `cargo test --workspace`
4. `deny` — `cargo deny check` (advisories, bans, licenses: MIT/Apache-2.0/BSD-3/MPL-2.0/Unicode)
5. `build` — matrix: `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`, `armv7-unknown-linux-gnueabihf` (cross)

Pre-commit (optionally `prek`/`pre-commit`): fmt + clippy + commit-message format check.

### 3. ADRs

Template `docs/adr/0000-template.md` (Status / Context / Decision / Consequences / Alternatives). Drafts with pre-filled decisions from the plan:

| ADR | Topic | Decision to ratify |
|---|---|---|
| 001 | Stack | Rust + hickory as the protocol layer |
| 002 | HA | master/slave push, no Raft |
| 003 | Log store | SQLite WAL, single writer |
| 004 | Configuration | single TOML, UI writes via ConfigManager |
| 005 | Blocking | default `zero_ip`, not NXDOMAIN |
| 006 | DNSCrypt | stretch goal (no mature crate) |
| 007 | Precedence | rewrites vs `$important` — to decide in M4 |
| 008 | Performance budget | limits from plan section 16.1 |
| 009 | License | GPL-3.0 vs AGPL-3.0 — decision BEFORE the first public commit |

### 4. Community documents

- `LICENSE` (per ADR-009), `CONTRIBUTING.md` (TDD, DCO sign-off, PR rules from section 21.3), `CODE_OF_CONDUCT.md`, `SECURITY.md` (72 h SLA, last two minors supported)
- `README.md`: pitch, CI badges, quickstart placeholder, links to the plan
- Templates: `.github/PULL_REQUEST_TEMPLATE.md` with a "Plan compliance (section no.)" section; issue templates: bug / feature

## Agent prompts

### Prompt M0.1 — scaffolding

```
CONTEXT: dns-server-plan-detailed.md sections 2, 3.3, 21.
TASK: Create a Cargo workspace with 13 crates (names from 3.3), each with lib.rs
and a doc-comment of its responsibility. The sito binary prints its version (clap).
REQUIREMENTS: workspace lints (clippy pedantic), edition 2024, rust-toolchain.toml.
DoD: cargo build --workspace and cargo test --workspace pass; sito --version works.
```

### Prompt M0.2 — CI and quality

```
CONTEXT: plan sections 18.5, 19.
TASK: CI workflow (fmt, clippy -D warnings, test, cargo-deny, 3-arch build matrix).
deny.toml with the license allowlist from the plan. Pre-commit config.
DoD: a test PR passes all jobs; a deliberate clippy violation fails the clippy job.
```

### Prompt M0.3 — ADRs and docs

```
CONTEXT: plan sections 2.2, 19, 21.3.
TASK: ADR template + drafts ADR-001..009 per the table above; CONTRIBUTING, SECURITY,
CoC, PR/issue templates. LICENSE as a placeholder pending the ADR-009 decision (human task).
DoD: documents render correctly; relative links work.
```

## Exit criteria (checklist)

- [ ] CI green on the empty skeleton, including builds for 3 architectures
- [ ] `sito --version` works locally and in a CI container
- [ ] ADR-001..009 have status "Accepted" (009 requires your decision)
- [ ] `cargo deny check` passes
- [ ] PR template includes the plan-compliance section

## Risks

| Risk | Mitigation |
|---|---|
| Decision paralysis on ADRs | 1 day/ADR limit; decisions are reversible (status "Accepted", not "Set in stone") |
| License changed after contributions | ADR-009 settled before the repo goes public |
| Premature workspace optimization | 13 crates are a skeleton; no moving code "just in case" |
