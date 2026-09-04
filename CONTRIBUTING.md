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

# License and dependency check
cargo deny check

# Run CLI verification
cargo run -p sito -- --version
```

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
