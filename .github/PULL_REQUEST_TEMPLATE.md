## Description

<!-- Provide a brief description of the problem solved, changes made, and rationale. -->

## Plan Compliance

<!-- Mandatory: Cite the specific section number(s) from docs/dns-server-plan-detailed.md. -->
- **Plan Section(s):** Section X.Y (e.g. `Section 3.3`, `Section 4.1`)
- **Phase:** Phase MX (e.g. `M0`, `M1`, `M2`)
- **Living Plan Update:**
  - [ ] This PR aligns exactly with the plan specification.
  - [ ] This PR modifies or refines the plan, and `docs/dns-server-plan-detailed.md` is updated in this same PR.

## Type of Change

- [ ] `feat`: New feature or capability
- [ ] `fix`: Bug fix
- [ ] `perf`: Performance optimization
- [ ] `refactor`: Internal refactoring without behavioral change
- [ ] `docs`: Documentation or ADR updates
- [ ] `test`: Test suite additions or improvements
- [ ] `ci` / `chore`: CI or build configuration

## Review Checklist (Section 21.3)

- [ ] **Diff size:** Functional diff is under 800 lines (or split into logical PRs).
- [ ] **TDD / Tests:** Unit/integration tests added or updated; `cargo test --workspace` passes 100%.
- [ ] **Lints:** `cargo clippy --workspace -- -D warnings` passes without inline `#[allow]` suppression.
- [ ] **Formatting:** `cargo fmt --check` passes.
- [ ] **Dependencies:** `cargo deny check` passes with zero violations. (If adding a dependency, justification is included).
- [ ] **Error handling:** No `unwrap()` or `expect()` calls in production code outside tests (`#[cfg(test)]`).
- [ ] **DCO Sign-off:** Commits include `Signed-off-by` trailers (`git commit -s`).

## Performance & Benchmarks (if applicable)

<!-- Mandatory if touching sito-filter, sito-cache, sito-proto, or any part of the query hot path. -->
<!-- Include Criterion or dnsperf benchmark comparisons proving no >10% regression. -->

```
[Paste benchmark output or comparison summary here]
```
