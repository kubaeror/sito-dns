# Contributing to sito

Thank you for your interest in contributing to **sito**! We welcome bug reports, documentation enhancements, benchmarks, and code contributions.

Please review this document to ensure a smooth contribution process.

---

## 1. Code of Conduct

All contributors and participants agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md). Please report unacceptable behavior per the instructions in that document.

---

## 2. Developer Certificate of Origin (DCO)

We use the standard Linux Foundation **Developer Certificate of Origin (DCO)** instead of a proprietary CLA. Every commit must include a `Signed-off-by` trailer affirming your contribution adheres to the DCO:

```
Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```

To sign off your commit automatically with git:
```bash
git commit -s -m "feat(filter): implement label interning for SuffixTrie"
```

---

## 3. Core Development Principles

### Test-Driven Development (TDD)
- Write tests first.
- Every new feature, bugfix, or parser rule must be accompanied by comprehensive unit and/or integration tests.
- No PR merges without 100% green tests across the workspace.

### Safe Systems Programming Rules
- **No `unwrap()` or `expect()` in production code:** All errors on the query pipeline must be handled explicitly and gracefully. `unwrap()` is strictly reserved for test files (`#[cfg(test)]`).
- **Workspace Lints:** All code must pass `cargo clippy --workspace -- -D warnings` without inline `#[allow(...)]` attributes (lint allowances are centralized in `Cargo.toml`).
- **Dependencies:** Avoid adding new external dependencies unless strictly necessary and justified in the pull request description. `cargo deny check` must pass with zero violations.

---

## 4. Pull Request Rules (from Plan Section 21.3)

To ensure rapid and thorough review:

1. **Size Limit:** Pull request diffs exceeding **800 lines** of functional code will be rejected and requested to be split into logical chunks.
2. **Plan Compliance Section:** Every pull request description must include a **"Plan compliance"** section referencing relevant section numbers from `docs/dns-server-plan-detailed.md`.
3. **Living Plan Rule:** If code implementation diverges from or improves upon the architectural plan, the plan documentation must be updated in the same pull request.
4. **Performance Benchmark Requirement:** If your PR touches `sito-filter`, `sito-cache`, `sito-proto`, or any part of the query hot path, benchmark results (`criterion` or `dnsperf`) demonstrating no performance regression (> 10%) must be included in the PR description.

---

## 5. Local Setup and Workflow

### Prerequisites
- Rust stable (MSRV documented in `README.md` and `rust-toolchain.toml`)
- Components: `rustfmt`, `clippy`
- Utilities: `cargo-deny`

### Initializing Git Hooks
Run the hook setup script to configure pre-commit and commit message validation:
```bash
./scripts/setup-hooks.sh
```

### Running Verification Locally
Before submitting a pull request, run the test and lint verification:
```bash
# Code formatting check
cargo fmt --check

# Strict clippy lints
cargo clippy --workspace -- -D warnings

# Unit and integration tests
cargo test --workspace

# HA certificate ownership (root-gated; skipped in unprivileged runs)
# Generates root-owned keys, proves uid 65532 cannot read them, chowns, then
# starts the real mTLS listener and checks /health + /api/v1/ha/status.
sudo scripts/test-ha-ownership-root.sh

# License and dependency check
cargo deny check

# Run CLI verification
cargo run -p sito -- --version
```

### CI lanes

Pull requests run only the lanes their paths need. `ci-gate` is the single
required status check; jobs that are skipped because their paths did not change
count as success. Container, security, and docs are reusable workflows called by
`ci.yml` on pull requests and also run on `main` pushes when their paths match,
so they are part of the required `ci-gate` check rather than separate advisory
workflows. The full runbook, including branch protection, runner pins,
the release pipeline, and the runner-minute budget, is in
[docs/ci.md](docs/ci.md).

| Paths changed | Lane |
|---|---|
| `crates/**`, `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`, `rustfmt.toml` | CI code jobs: `fmt`, `clippy`, `test`, three-target `build` |
| `docs/openapi.json` (without crate changes) | CI `openapi` |
| `contrib/**`, `scripts/**` | CI `contrib` (shellcheck, AdGuard converter, release helpers) |
| `docs/**`, `**/*.md`, `LICENSE`, `SECURITY.md`, templates | CI `docs-check` → Docs lane (config-reference drift; `actionlint` for workflow changes) |
| `Dockerfile*`, `.dockerignore`, `docker-compose*.yml`, `config.example.toml`, `contrib/systemd/**` | CI `container-check` → Container lane (compose validation, image smoke, `Dockerfile.release` build) |
| `Cargo.toml`, `Cargo.lock`, `deny.toml`, `rust-toolchain.toml` | CI `security-check` → Security lane (`cargo-deny`); `Cargo.*` also runs the code lane |
| `.github/workflows/**` | CI `docs-check` → Docs lane with `actionlint` |

A docs-only PR never builds Rust or Docker, except `docs/openapi.json`, which
runs the `openapi` job. To force every heavy CI lane anyway,
add the `ci:full` label and then push a commit so the new pull request event
carries the label, or dispatch **CI** with `full` checked for a branch-level
run. A plain re-run does not pick up a newly added label because GitHub replays
the original event payload. The container and security lanes can also be
dispatched directly from the Actions tab.

Local parity before pushing:

```bash
cargo fmt --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features --locked
python3 scripts/check_config_reference.py
shellcheck -S warning contrib/install.sh
docker compose -f docker-compose.yml config >/dev/null
docker compose -f docker-compose.ha.yml config >/dev/null
cargo deny check
```

Scheduled fuzzing is no longer part of CI, and there is no fuzz workflow or
harness directory. See [docs/ci.md](docs/ci.md#scheduled-fuzzing-was-intentionally-removed)
for the accepted risk and the change-control rule.

---

## 6. Conventional Commits

We enforce the [Conventional Commits](https://www.conventionalcommits.org/) specification for clean git history and automated changelog generation.

Commit message format:
```
<type>(<scope>): <subject>
```

**Types:**
- `feat`: New user-facing or architectural feature
- `fix`: Bug fix
- `docs`: Documentation updates or ADR additions
- `style`: Formatting, missing semicolons, whitespace
- `refactor`: Code refactoring without changing functionality
- `perf`: Performance improvement
- `test`: Adding or improving tests
- `build`: Build system or dependency updates
- `ci`: CI configuration changes
- `chore`: Maintenance tasks, repo scaffolding

**Examples:**
- `feat(filter): add Aho-Corasick multi-substring matcher`
- `fix(transport): handle UDP SO_REUSEPORT socket rebind on Linux`
- `docs(adr): accept ADR-009 specifying GPL-3.0 license`
