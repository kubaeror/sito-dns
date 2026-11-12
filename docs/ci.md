# CI and Release Workflows

This document is the operational runbook for the GitHub Actions setup in
`.github/workflows/`. It describes which lane runs for which change, the
required check and branch-protection step, the runner and container-runtime
pins, the release pipeline, the PR vs nightly/release split for fuzzing and
benchmarks, the action pin policy, and the monthly runner-minute budget.

## Workflow map

| Workflow | File | Triggers | Purpose |
|---|---|---|---|
| **CI** | `ci.yml` | `pull_request` to `main`, `push` to `main`, `merge_group`, `workflow_dispatch` (`full`) | Classifies the change set and runs `fmt`, `clippy`, `test`, the three-target `build` matrix, `openapi`, `contrib`, `bench-build`, `fuzz-build`, `hygiene` (machete/udeps), `coverage`, and the reusable `docs-check`, `container-check`, `security-check` lanes. Publishes the single required check `ci-gate`. |
| **Docs** | `docs.yml` | `workflow_call` from CI, `push` to `main` on docs/workflow paths, `workflow_dispatch` | Runs the configuration-reference nested/default/type/map check, the migration-guide breaking-change check, the internal Markdown link checker, and the pinned `actionlint` container for `.github/workflows/**`. |
| **Container** | `container.yml` | `workflow_call` from CI and Weekly, `push` to `main` on container paths, `workflow_dispatch` | Validates both Compose files, builds/smoke-tests the development `Dockerfile`, and builds `Dockerfile.release` with stub binaries. |
| **Security** | `security.yml` | `workflow_call` from CI and Weekly, `push` to `main`, `workflow_dispatch` | Runs `cargo-deny check`. |
| **Weekly Quality** | `weekly.yml` | Sunday at 03:00 UTC (`schedule`), `workflow_dispatch` | Release-mode tests plus the reusable Container and Security workflows. Benchmarks moved to `bench.yml`. |
| **Fuzz** | `fuzz.yml` | Nightly at 04:17 UTC (`schedule`), `workflow_dispatch` (`fuzz_seconds`) | Builds and runs the five cargo-fuzz targets with their checked-in corpus and dictionary. Default smoke is 600 s per target; a manual `fuzz_seconds=86400` run is the 24-hour release-checklist gate. Uploads corpus/artifacts on failure. |
| **Bench** | `bench.yml` | Nightly at 05:42 UTC (`schedule`), `workflow_dispatch` (`update_baseline`) | Runs the workspace Criterion suite and fails when a benchmark is more than 10% slower than `benches/baseline.json`. `update_baseline=true` writes and uploads a replacement baseline. |
| **Release** | `release.yml` | Push of a `v*` tag only | Verifies the tag, builds and signs the three release archives, stages a draft GitHub release, verifies the artifacts, publishes the multi-arch container image, and finally publishes the release. |
| **Artifact E2E** | `artifact-e2e.yml` | `workflow_call` from Release, `workflow_dispatch` with a tag | Re-downloads a staged draft or published release and verifies checksums, signatures, and execution of every architecture in the release runtime image. |

`release.yml` deliberately has no `workflow_dispatch`: GitHub mints the OIDC
identity from the ref that started the run, and both the installer and the
self-updater only accept the identity `release.yml@refs/tags/*`. Signing from a
branch would produce artifacts that cannot be verified. Use
`artifact-e2e.yml` to re-verify an existing release without publishing.

## Which lane runs for which change

`ci.yml` classifies each pull request once in the `changes` job with
`dorny/paths-filter`. The heavy jobs consume the `code`, `api`, and `contrib`
outputs. Container, dependency, and workflow-path checks are reusable workflows
that `ci.yml` calls on pull requests (`container-check`, `security-check`,
`docs-check`) and that also run on `main` pushes when their paths match. They are
part of the required `ci-gate` check, not separate advisory workflows.

| Change | Lanes that run |
|---|---|
| Docs only (`docs/**`, `**/*.md`, `LICENSE`, `SECURITY.md`, `CODE_OF_CONDUCT.md`, issue/PR templates) | `ci.yml`: `changes`, `docs-check`, `security-check`, `ci-gate`. `docs-check` calls `docs.yml`, which runs `meta` (config-reference nested/default/type/map checks when the reference or checker changes; the migration-guide breaking-change check; and the internal link check over the repository's tracked Markdown). `security-check` calls `security.yml` (`cargo-deny`) on every PR/merge group, including docs-only changes. No Rust or Docker lanes. The `docs/openapi.json` exception below runs `openapi`. |
| Code (`crates/**`, `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`, `rustfmt.toml`, structural-size scripts, `benches/**`, `fuzz/Cargo.toml`, `fuzz/fuzz_targets/**`, `fuzz/corpus/**`, `fuzz/dictionaries/**`, `fuzz/.gitignore`, and `docs/large-functions.md`) | `ci.yml`: `changes`, `fmt`, `clippy`, `test`, `build` (x86_64, aarch64, armv7), `bench-build`, `fuzz-build`, `hygiene`, `coverage`, `security-check`, `ci-gate`. |
| OpenAPI spec only (`docs/openapi.json` without crate changes) | `ci.yml`: `changes`, `openapi`, `ci-gate`; `docs-check` also runs because the path is under `docs/`. |
| API crate (`crates/sito-api/**`) | Full code lane. `openapi` is skipped because `test` already regenerates and diffs the spec. |
| Contrib/scripts (`contrib/**`, `scripts/**`) | `ci.yml`: `changes`, `contrib`, `ci-gate`. `contrib` runs `shellcheck` on the installer and release helpers, the AdGuard converter fixture test, and the release-helper tests. The `test` lane runs the fuzz-manifest and benchmark-regression script tests when `scripts/**` changes. |
| Container (`Dockerfile`, `Dockerfile.*`, `.dockerignore`, `docker-compose*.yml`, `config.example.toml`, `contrib/systemd/**`) | `ci.yml`: `changes`, `container-check`, `ci-gate`. `container-check` calls `container.yml` (`compose`, `smoke`, and `release-image`). |
| Dependencies (`Cargo.toml`, `Cargo.lock`, `deny.toml`, `rust-toolchain.toml`) | `ci.yml`: the code lane plus `security-check`, `hygiene`, `ci-gate`; `security-check` calls `security.yml` (`cargo-deny`). `security-check` also runs on every pull request and merge group, independent of this filter, because a new advisory can affect an unchanged dependency set. `Cargo.*` and the toolchain also match the code classifier, so the full code lane runs as well. |
| Workflow files (`.github/workflows/**`) | `ci.yml`: `changes`, `docs-check`, `ci-gate`; `docs-check` calls `docs.yml` (`meta` with the Markdown link check and `actionlint`). |
| Mixed changes | Union of the matching lanes. |

The normal `test` lane also runs the bounded `proptest` suites in
`crates/sito-core/tests/domain_properties.rs` and
`crates/sito-filter/tests/parser_properties.rs` (96/64 cases each). They are
deterministic and fast enough for every pull request, so they need no separate
workflow or check; `docs/test-harness.md` documents the harness, clock, waits
and fixtures they use.

The same lane runs `crates/sito-stats/tests/prometheus_exposition.rs`, which
parses `MetricsRegistry::render_prometheus` with the real `prometheus-parse`
crate and asserts every sample belongs to a HELP/TYPE family and that no two
samples name the same series. A malformed or duplicate metric therefore fails
`cargo test`, not only a reviewer's eye.

The `test` lane also runs the fast structural checks for the two long-running
gates: `python3 scripts/check-fuzz-targets.py` (manifest, five target sources,
seed corpus and gitignore) and `python3 scripts/test_check_bench_regression.py`
(parser/tolerance/exit-code fixtures). The long workloads themselves run in
`fuzz.yml` and `bench.yml`.

`docs/openapi.json` matches both the `docs/**` filter and the `api` filter, so
it runs the `openapi` job and the docs lane. A change to
`scripts/check_config_reference.py` is also matched by the docs lane and runs
the `meta` configuration-reference check. Independently of paths, every pull
request pays the small `changes` + `ci-gate` overhead (roughly 1–2 minutes).

`actionlint` discovers and lints `.github/workflows/**` only. It does not lint
composite actions in `.github/actions/**` (there is no such directory today).
If composite actions are added later, add a dedicated validator for them rather
than relying on `actionlint`.

### Documentation checkers

Three dependency-free Python checks protect the docs contract:

| Checker | What it proves | Fast regression fixtures |
|---|---|---|
| `scripts/check_config_reference.py --github` | Every top-level and nested (`[[tls.sni_certs]]`, `[[upstream.per_domain]]`, `[[filtering.lists]]`, `[[clients.entries]]`, `[clients.groups.<name>]`, `[[clients.groups.<name>.blocked_services]]`, `[[rewrites.entries]]`, `[integrations.lists.categories.<name>]`) config field is documented with the right type, default and required/optional status. It also checks the legacy raw-section key allowlists (`[clients]`, `[rewrites]`, `[ha]`, `[integrations]`) against `crates/sito-core/config-v1-to-v2-map.toml` and verifies every kept map path / deprecated alias target is documented. A missing doc file or malformed map **fails closed** with exit 1. `--github` prints one `::error::` line per failure. | `python3 scripts/test_check_config_reference.py` (nested key/default/type/required drift, unknown map path, alias target, corrupt map, missing doc, concise annotations). |
| `scripts/check_migration_guide.py --github` | Every stable `BC-<n>` breaking-change ID declared in `docs/2.0-public-api-diff.md` has one row in the `docs/2.0-migration.md` breaking-change index with a concrete migration step and an affected doc/test. Duplicate IDs, placeholder steps and a missing index fail closed. | `python3 scripts/test_check_migration_guide.py` (missing ID, empty step, duplicate, missing table/diff, concise annotations). |
| `scripts/check_markdown_links.py --github` | Every repository-local Markdown link and heading anchor resolves. External URLs are never fetched, so the check is deterministic. | — |

The `test` lane runs the configuration-reference checker and its fixtures on
code changes; the `docs` lane runs it when the reference or checker changes and
runs the migration and link checks on every docs change. All three are cheap
enough to also run locally before pushing.

The migration checker only validates IDs that already exist in the public API
diff. It cannot infer that a new change is breaking: when adding one, assign a
new `BC-<n>` in `docs/2.0-public-api-diff.md` first, then add the migration row.
A breaking change without an ID is a review responsibility, not a checker
failure.

A docs-only pull request therefore costs roughly the two small `ci.yml` jobs
(`changes`, `ci-gate`), the `docs-check` job, and the `cargo-deny`
`security-check` lane, not a Rust rebuild. The one exception is a change to
`docs/openapi.json`, which also runs the `openapi` job.

### Behavior on `push` to `main`

The heavy `ci.yml` jobs run on a push to `main` when their path filter matches,
so `main` itself is continuously verified: `fmt`, `clippy`, `test`, `build`
(three targets), `bench-build`, `fuzz-build`, `hygiene`, `coverage`, and
`ci-gate`. This satisfies the WP-1.9 requirement that tests/clippy/fmt/deny run
on `main` and on pull requests. The path-filtered `docs.yml`, `container.yml`,
and `security.yml` workflows also run on `main` pushes when their paths match.

The cost of a main merge is therefore a second heavy code lane. If the runner
budget is tight, gate merges through the pull request (or merge queue) and use
the nightly fuzz/bench workflows for the long evidence; the main-push run
remains the post-merge proof.

`merge_group` is a first-class trigger, so merge-queue runs execute the same
heavy jobs as a pull request. A direct push to `main` is still not a substitute
for PR validation: protect `main` and merge through pull requests.

### Concurrency

Each workflow cancels superseded runs for the same pull request or ref
(`ci-<pr-or-ref>`, `docs-…`, `container-…`, `security-…`). Pushing a new commit
to a PR therefore cancels the previous in-flight CI run instead of paying for
both. `weekly.yml` uses `cancel-in-progress: false` so a scheduled run is never
truncated by a manual dispatch.

## Running every heavy lane: `ci:full`

Sometimes a change is docs-only but still needs the Rust lane, for example
after a toolchain bump or when debugging an infrastructure change. Two
overrides force the heavy `ci.yml` jobs even when the classifier says `code` or
`contrib` is false:

- Add the `ci:full` label to a pull request **and then push a commit**. The
  label must be present in the event payload when the run starts, so the push
  must create a new `synchronize` event after the label is applied.
- Run **CI → Run workflow** with `full` checked
  (`workflow_dispatch` input `full=true`). This is a branch-level run of the
  selected ref, not a run of the pull request payload.

The override applies to the code jobs (`fmt`, `clippy`, `test`, `build`,
`openapi`, `contrib`, `bench-build`, `fuzz-build`, `hygiene`, `coverage`) and
to the reusable gate jobs `docs-check`, `container-check`, and `security-check`.
It only matters for pull-request and `workflow_dispatch` runs. A push to `main`
already runs the same path-filtered heavy jobs, so `force` does not change a
main-push run. The classifier reads
`github.event.pull_request.labels` when the run starts. A plain **Re-run jobs**
replays the original event payload and does **not** pick up a label added
afterwards, so `force` stays false. If the label was added after the last push,
push another commit (or otherwise create a new pull request event) to apply it.
No workflow change is required for this procedure.

The override is implemented through `ci.yml`; it does not change the standalone
`push` runs of the reusable workflows. To run a lane on demand without the
label, dispatch `docs.yml`, `container.yml`, or `security.yml` directly from the
Actions tab; all three accept `workflow_dispatch`. The weekly run exercises the
container and security lanes together.

## Structural size budgets

The `test` job enforces the WP-1.5 module boundaries in addition to the unit
tests:

```bash
bash scripts/check-file-size.sh      # no production Rust file > 2,000 lines
bash scripts/check-function-size.sh  # no production fn > 200 lines unless documented
```

Both scripts share `scripts/rust_size.py`. "Production" excludes
`#[cfg(test)]` items (including sibling `tests.rs` files marked with a genuine
leading `#![cfg(test)]` attribute) and the test-only crates `sito-test` and
`sito-test-support`. Cargo `tests/`, `benches/`, and `examples/` targets and
parent-gated `src/tests/` modules are also test code, not production.

Attribute detection runs on masked source, so `#[cfg(test)]` or
`#![cfg(test)]` mentioned in a comment or string cannot hide production code.
`python3 scripts/test_rust_size.py` pins those forms with checked-in fixtures
and threshold cases. The function check reads `docs/large-functions.md`; a
function over 200 lines without a matching `(file, function)` row fails CI.
Changes to either script, the helper, or the exception list are classified as
code changes so the test lane re-runs them.

## Error-swallowing allowlist

`bash scripts/check-error-swallowing.sh` enforces the D14 reviewed allowlist.
`scripts/find-error-swallowing.py` scans production Rust sources (inline
`#[cfg(test)]` items and `tests/` targets are skipped) for `let _ =`/`.ok()`
around security/config-apply/persistence/readiness calls: secret writes,
`persist`/`publish`/`save`/`store`, `reload`/`flush`/`shutdown`, `lease`/
`bootstrap`, `readiness`/`health`, `lock`/`unlock`, `read`/`load`, and the
existing fsync/rename/remove-file patterns. The scanner joins a statement until
its parentheses/brackets balance and the terminating `;` is reached, so
multi-line swallows are detected; formatting macros are excluded so their
arguments are not mistaken for the swallowed operation.
`scripts/test-error-swallowing.py` pins those fixtures and runs from the
checker. Every flagged site must be handled with a typed error or listed in
`scripts/error-swallowing-allowlist.txt` with a reason in
`docs/audit6-best-effort.md`.

## Fuzz, coverage, dependency hygiene and benchmark lanes

WP-1.9 adds four PR-side lanes and moves the long-running evidence to
nightly/release workflows. This is the D14/P-7 split: expensive or
environment-sensitive work is a release-checklist item, while a PR still proves
the mechanism compiles and the cheap checks pass.

| Lane | Trigger | Command | Why it is safe for PRs |
|---|---|---|---|
| `bench-build` | Code change | `cargo bench --workspace --all-features --locked --no-run` | Compiles every Criterion target; does not measure. |
| `fuzz-build` | Code or `fuzz/**` change | `cargo +nightly-2026-11-04 fuzz build` and `cargo +nightly-2026-11-04 fmt --manifest-path fuzz/Cargo.toml --check` | Builds the five targets with a pinned nightly and checks their formatting; does not fuzz. |
| `hygiene` | Code or dependency change | `cargo machete`; `cargo +nightly-2026-11-04 udeps --workspace --all-targets` | Deterministic dependency-graph checks. |
| `coverage` | Code change | `cargo llvm-cov --workspace --all-features --locked --summary-only --fail-under-lines "$MIN_LINE_COVERAGE"` then `cargo llvm-cov report --lcov --output-path target/lcov.info` | Runs the test suite with instrumentation, enforces a configurable line floor, and uploads the LCOV report. |

The coverage floor defaults to **85%** and is configurable with the
`MIN_LINE_COVERAGE` repository variable. The full workspace measured **88.22%
lines** (and 85.97% functions) on the WP-1.9 development host; 85 leaves a
small platform-noise margin while still failing a real regression. Raise the
variable as coverage improves; lowering it needs a reviewed reason. The job
uploads `target/lcov.info` and the summary text on every run,
including failures, so a regression can be inspected without re-running.

`hygiene` installs `cargo-machete` and `cargo-udeps` at pinned versions.
`cargo-machete` checks the declared dependency edges; `cargo-udeps` compiles
every target on the pinned nightly. A new unused dependency fails the PR and
the `main`-push code lane; it is not part of the weekly workflow.

The Prometheus exposition parser check is not a separate job: it is an
integration test in `sito-stats`, so `cargo test` in the `test` lane runs it
on every code change. See `crates/sito-stats/tests/prometheus_exposition.rs`.

### PR vs nightly/release split

| Evidence | PR | Nightly | Release checklist |
|---|---|---|---|
| Fuzz targets compile | `fuzz-build` | Builds again before running | Required |
| Fuzz execution | Not run | 600 s per target (`fuzz.yml`, 04:17 UTC) | 86,400 s per target (`fuzz_seconds=86400`) |
| Benchmark compile | `bench-build` | Runs the full suite | Required |
| Benchmark threshold | Not run | `bench.yml` compares to `benches/baseline.json`; >10% fails | Required |
| Coverage | `coverage`, 85% line floor | Same lane on code changes | Required through green `ci-gate` ancestry |
| machete/udeps | `hygiene` | Same lane on code changes | Required through green `ci-gate` ancestry |

The 24-hour fuzz run and the thresholded benchmark run are **release-checklist
items** (D14). Their logs and artifacts are recorded in
`docs/release-verification.md`; a release tag is still gated by `ci-gate` and
`cargo-deny` on the tagged commit, so a release cannot be published from a
commit that never passed the PR lanes.

### Benchmark baseline

`benches/baseline.json` stores Criterion median estimates (nanoseconds) for
every benchmark, generated by `scripts/save-bench-baseline.sh`. The gate
`scripts/check-bench-regression.py` reads
`target/criterion/**/new/estimates.json`, compares each median, and exits 1
above the tolerance. The tolerance comes from the baseline's `tolerance` field
unless `--tolerance` / `BENCH_TOLERANCE` overrides it (default 10%). A missing
estimate fails closed unless `--allow-missing` is passed for a deliberate
benchmark rename.

The absolute medians are environment specific, so the checker fails closed on
an environment mismatch: the baseline's `environment.description` must equal
`--environment`, `BENCH_ENVIRONMENT`, or the automatic host description. The
only escape hatch is the explicit, documented `--reference-only` flag, which
prints a warning and must never be used by the nightly gate.

`bench.yml` refuses to run at all unless the `BENCH_RUNNER_LABEL` repository
variable names a dedicated/self-hosted runner (GitHub-hosted `ubuntu-*`,
`windows-*`, `macos-*` labels are rejected) and `BENCH_ENVIRONMENT` is set. It
then passes `--environment "$BENCH_ENVIRONMENT"`, so a stale baseline fails
immediately with an instruction to regenerate rather than producing a
false-green or false-red comparison. Run
`scripts/save-bench-baseline.sh` on that runner and commit the resulting file;
`update_baseline=true` on a manual dispatch uploads a replacement for review.

The committed baseline in this branch was generated on the WP-1.9 development
host and records `environment.description = "local-dev-x86_64-20cpu"`. The
nightly gate therefore remains **inactive until the dedicated runner is
provisioned and the baseline regenerated there**; this is an explicit residual,
not a silent threshold. Do not mix a laptop baseline with CI, and do not
regenerate the baseline to make a real regression pass.

## Required check and branch protection

`ci-gate` is the single check that should be required for `main`. It depends on
`changes`, `fmt`, `clippy`, `test`, `build`, `openapi`, `contrib`, `docs-check`,
`container-check`, `security-check`, `bench-build`, `fuzz-build`, `hygiene`, and
`coverage` and fails if any of them reports `failure` or `cancelled`. Jobs that
were skipped because their paths did not change count as success, which is what
lets a docs-only PR merge without a Rust run. Requiring every individual job
instead would make docs-only PRs wait on checks that are intentionally absent.

Branch protection is a **manual repository setting**. This change and the
workflow files do not modify repository settings. A repository administrator
must enable it once:

1. Open **Settings → Branches** (or **Settings → Rules**) and create a rule for
   `main`.
2. Enable **Require status checks to pass before merging**.
3. Add **`ci-gate`** (from the CI workflow) as a required check.
4. Optionally require branches to be up to date before merging. If a merge
   queue is enabled, keep `ci-gate` required; `ci.yml` already runs on
   `merge_group`. A merge queue adds a second heavy code lane (~35–40 minutes
   with the WP-1.9 lanes) for each queued PR, so re-evaluate the 3,400-minute
   budget before enabling one.
5. Save the rule.

Until that setting exists, `ci-gate` is advisory: reviewers can see it, but
GitHub will not block a merge when it is missing or red. The repository owner
should treat enabling it as part of adopting this workflow set. If branch
protection cannot be changed immediately, review `ci-gate` manually on every
PR in the meantime.

## Runner pin: `ubuntu-24.04`

Every job runs on GitHub's explicit `ubuntu-24.04` image, never a floating
`latest` label. This is both a reproducibility choice and a binary
compatibility requirement:

- Ubuntu 24.04 ships **glibc 2.39**. A release binary built there only requires
  symbols up to 2.39.
- Ubuntu 26.04 ships **glibc 2.43**. Building the release on that image could
  link the binary against 2.43 symbols.
- The release runtime image, `gcr.io/distroless/cc-debian13:nonroot`, ships
  **glibc 2.41**. The project's release binaries are expected to run on that
  image and on glibc 2.39-or-newer hosts.
- A binary linked against 2.43 would fail to start on the 2.41 release image
  (and would break artifact E2E before the container image could be published),
  even though the build itself would be green.

Pinning 24.04 keeps the native x86_64 build at the 2.39 ABI and prevents a
silent runner-image rollover from raising the release ABI. The aarch64 and
armv7 builds use `cross`, whose target glibc comes from the pinned cross
container rather than the runner, but those jobs still use the same explicit
runner image for consistency. When 26.04 is adopted, the release runtime image
and the supported glibc floor must be raised together and the artifact E2E
must be updated in the same change.

## Release pipeline

Release runs only from a tag push. A tag must match the workspace version in
`Cargo.toml` (`v2.0.0-alpha.1` or a prerelease such as `v2.0.0-beta.1`); a mismatch stops
the workflow before any asset is built. The order is deliberate:

1. **`verify-tag`** — checks the tag against the workspace version.
2. **`build-binaries`** — builds `x86_64-unknown-linux-gnu`,
   `aarch64-unknown-linux-gnu`, and `armv7-unknown-linux-gnueabihf` with the
   `embed-ui,mimalloc` features, runs `shellcheck` on the installer, packages
   each archive with `LICENSE`, `README.md`, `config.example.toml`, the
   systemd unit, and `contrib/install.sh`, and records per-archive SHA-256
   checksums.
3. **`sbom-and-release`** — downloads the archives, produces a unified
   `SHA256SUMS`, generates an SPDX SBOM with `cargo-sbom`, signs every archive
   with cosign keyless signing, and uploads everything to a **draft** GitHub
   release. Tags containing `-` are marked as prereleases.
4. **`artifact-e2e`** — re-downloads the staged draft (drafts require a token
   with write access) and verifies all three architectures: per-archive
   `.sha256`, the unified `SHA256SUMS` line, the cosign signature identity, and
   execution of `--version` and `check-config` on the shipped configuration.
5. **`docker-build-push`** — builds and pushes the multi-arch image, then
   verifies the digest, every generated tag, the required platforms, and the
   SLSA provenance and SPDX SBOM attestations. A final smoke test pulls the
   published image and runs `--version` and `check-config`.
6. **`publish-release`** — flips the staged draft to published only after
   `artifact-e2e` and `docker-build-push` are green. Stable tags also move
   `latest`; prereleases stay prereleases and never move `latest`.

The GitHub release is not public until `publish-release` runs. A failure in
`artifact-e2e` or `docker-build-push` leaves a recoverable draft instead of
published assets without an image. The image is published only after the tag
gate, the signed assets, the SBOM, and artifact E2E have all passed.

### Release image: prebuilt binaries and `cc-debian13`

`Dockerfile.release` does not compile Rust. It copies the already-built
release binary for the target architecture from a named build context:

```text
binaries=./prebuilt  ->  /${TARGETARCH}/sito  ->  /usr/bin/sito
```

`release.yml` extracts `sito-<tag>-<triple>.tar.gz` for each target into
`prebuilt/{amd64,arm64,arm}/sito` before Buildx runs. Because nothing foreign
is executed during the build, no QEMU is needed to assemble the multi-arch
index.

The runtime base is the pinned digest of
`gcr.io/distroless/cc-debian13:nonroot`. It provides glibc 2.41 (enough for the
2.39-built binaries), runs as uid/gid 65532, contains no shell or package
manager, and keeps the same entrypoint, healthcheck, exposed ports, and
`/var/lib/sito` volume as the development image. The same digest is pinned in
`artifact-e2e.yml` as `RUNTIME_IMAGE`, where the x86_64 archive runs natively
and the aarch64 and armv7 archives run under QEMU. That proves each packaged
binary runs in exactly the runtime the published image uses. QEMU is used only
for the ARM archives in artifact E2E, not for the image build.

The development `Dockerfile` remains a from-source build and is what
`container.yml` smoke-tests. The release image and the release archives contain
the same binaries, so image and tarball behavior match. `container.yml` also
builds `Dockerfile.release` with stub binaries on container-path PRs and weekly
runs, so path-mapping or syntax errors in the release image are caught before a
tag exists.

A code or dependency change does **not** rebuild the development `Dockerfile`
on its PR; the weekly container run is the feedback loop for code-induced image
breakage. Run `container.yml` manually from the Actions tab when a change is
likely to affect the from-source build (new system dependency, feature flag, or
build-script change).

## Fuzzing is nightly/release, not a PR gate

The earlier cost-reduction rework removed the fuzz workspace and workflow
entirely, and audit 6 (P2-64) recorded that release notes and audit documents
still claimed a harness that did not exist. WP-1.9 restores the mechanism with
a deliberate split:

- **Pull request:** `ci.yml` → `fuzz-build` runs `cargo fuzz build` for
  `dns_wire`, `abp_parser`, `dnssec_response`, `ha_bundle` and `config_toml`
  on a pinned nightly toolchain. This catches manifest/target/API drift without
  spending fuzzing time.
- **Nightly:** `.github/workflows/fuzz.yml` runs every target for 600 s with its
  checked-in corpus and dictionary, a 10 s per-input timeout, and a 26-hour job
  ceiling. A crash/timeout fails the workflow and uploads `fuzz/artifacts/` and
  the corpus.
- **Release checklist:** dispatch `fuzz.yml` with `fuzz_seconds=86400` and a
  self-hosted `runner_label` (GitHub-hosted jobs are capped at 6 hours), then
  record the run URL, commit, target list and corpus size in
  `docs/release-verification.md`. The 24-hour clean run is a D14 release gate,
  not a flaky PR job.

`fuzz/README.md` documents the targets, input bounds, corpus seeds,
dictionaries, exact commands and the 24-hour checklist. Do not reintroduce a
hidden or untracked fuzz workflow; changes go through this file and the
`fuzz/**` path filter.

## Action pin policy

Every third-party action is pinned to a **full 40-character commit SHA** with a
version comment: normally `# vX.Y.Z`, or `# master <date>` for an action that
has no release tags, such as `dtolnay/rust-toolchain`. Mutable tags and branches
are not accepted. This protects the build from a tag being retargeted upstream
and makes every workflow change reviewable as an exact commit change.

| Action | Pin | Notes |
|---|---|---|
| `actions/checkout` | `v7.0.1` | All jobs. |
| `actions/upload-artifact` | `v7.0.2` | Release archives, benchmark estimates. |
| `actions/download-artifact` | `v8.0.2` | Release SBOM and image jobs. |
| `dorny/paths-filter` | `v4.0.3` | CI change classifier. |
| `dtolnay/rust-toolchain` | `# master 2026-10-16` | The action has no release tags; the toolchain is pinned separately to **1.99.1** (or **nightly-2026-11-04** for cargo-fuzz/udeps) via `with: toolchain`. No floating `stable` or nightly refs. |
| `Swatinem/rust-cache` | `v2.9.3` | Rust build cache, per-job/key scopes. |
| `taiki-e/install-action` | `v2.90.2` | Always passed an explicit `tool:` (`cross`, `cargo-sbom@0.10.0`, `cargo-fuzz@0.13.2`, `cargo-llvm-cov@0.9.1`, `cargo-machete@0.9.2`, `cargo-udeps@0.1.61`); this version no longer injects defaults. |
| `rhysd/actionlint` | `1.7.12@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667` | Pinned Docker image, run via `docker run`; not installed by an action. |
| `EmbarkStudios/cargo-deny-action` | `v2.1.1` | Security lane. |
| `docker/setup-buildx-action` | `v4.4.1` | Container and release image builds. |
| `docker/build-push-action` | `v7.4.0` | Smoke build and release image publish. |
| `docker/login-action` | `v4.8.0` | GHCR login. |
| `docker/metadata-action` | `v6.2.0` | Release image tags and labels. |
| `docker/setup-qemu-action` | `v4.4.0` | Artifact E2E ARM execution only. |
| `sigstore/cosign-installer` | `v4.1.3` | Installs cosign **v2.6.5**; v3 changed the CLI flag surface. |
| `softprops/action-gh-release` | `v3.0.4` | Publishes the GitHub release. |

To update an action, change the SHA and the version comment in the same commit,
keep any required inputs explicit, and let the docs lane's `actionlint` validate
the workflow. Never replace a pin with a tag. Release-critical pins (cosign,
build-push, action-gh-release, download-artifact) deserve a full release
dry-run because a silent input change can break signing or attestations.

All workflows use least privilege: workflow-level `contents: read`, with only
the release jobs escalating to `contents: write`, `id-token: write`, or
`packages: write`. No workflow uses `pull_request_target`.

## Monthly runner-minute budget

The working budget is **3,400 GitHub-hosted runner-minutes per month**, with an
expected steady state of **2,800–3,200 minutes**. The increase over the previous
600-minute target is almost entirely the nightly fuzz workflow restored for
P2-64: five parallel targets at 600 s each plus the nightly toolchain build is
roughly 45–70 billed minutes per day. The PR-side rework still saves the
minutes it did before; it is not the source of the increase. 3,400 is the review
threshold: a month at or above it should be investigated. With a merge queue
enabled, each code PR also runs the heavy code lane in the merge group, adding
roughly 20–25 minutes per PR, so re-evaluate the budget before enabling one. It
is a planning target, not a GitHub-enforced limit.

Operating levers if the budget must stay lower:

- Reduce the nightly `fuzz_seconds` (the 24-hour release run remains manual).
- Run `fuzz.yml` weekly instead of nightly; keep the PR `fuzz-build`.
- Set `BENCH_RUNNER_LABEL` to a self-hosted benchmark host and remove the
  nightly bench from the GitHub-hosted budget.
- Use `ci:full` only when needed; it is an exception path.

Approximate runner-minutes per run (sum of billed jobs; parallel jobs count separately; warm caches; cold caches are higher):

| Activity | Typical minutes |
|---|---|
| Docs-only PR (`changes` + `ci-gate` + docs `meta` + `cargo-deny`) | 2–4 |
| Code PR (`changes`, `fmt`, `clippy`, `test`, `build` ×3, `ci-gate`) | 20–25 |
| Code PR extra lanes (`bench-build`, `fuzz-build`, `hygiene`, `coverage`) | 30–45 |
| OpenAPI-only PR | 2–3 |
| Contrib-only PR | 1–2 |
| Container PR (`compose` + `smoke` + `release-image` stub build) | 8–11 |
| Security-only PR (`cargo-deny`) | 1–2 |
| Weekly run (release tests, container, security, `release-image`) | 20–28 |
| Nightly fuzz (five targets × 600 s + build) | 45–70 |
| Nightly bench (full Criterion suite + comparison) | 10–20 |
| Release run (prebuilt-image pipeline) | 25–35 |

The `coverage` lane is the largest new PR cost because it re-runs the test
suite with LLVM instrumentation; `fuzz-build` and `bench-build` compile
optimized/nightly trees. They run in parallel, so the critical path grows by
roughly 10–15 minutes, not by the sum. A nightly run that also triggers the
scheduled fuzz and bench workflows adds roughly 55–90 minutes across both, but
only once per day and only on the default branch.

Standard GitHub-hosted runners are free for public repositories. This budget is
therefore a time, queue, and capacity target rather than an invoice; if the
repository becomes private or uses larger runners, confirm the rates in
Billing and treat the same numbers as billable minutes.

Dependency changes also match the code classifier, so a `Cargo.toml` or
`Cargo.lock` PR costs the code lane plus the security lane, not just the
security row.

Illustrative month using the midpoints of those ranges: ~10 code PRs (≈650),
~5 docs PRs (≈15), four weekly runs (≈96), two releases (≈60), a handful of
container/security/openapi/contrib runs (≈60), 30 nightly fuzz runs (≈1,725),
and 30 nightly bench runs (≈450), for **≈3,050 minutes**. The midpoint sits
inside the 2,800–3,200 expected band. These per-run figures are estimates from
warm-cache runs, not invoice data. Replace them with `scripts/ci_usage.py`
output after the first full month.

The largest PR-side savings still come from the docs-only classifier (no Rust or
Docker), skipping heavy jobs on `main` pushes, and cancelling superseded PR
runs. The nightly fuzz restore is a deliberate safety investment; the levers
above control its cost. If a month reaches the 3,400-minute review threshold:

1. Measure the actual split with `scripts/ci_usage.py`.
2. Check whether `test` or `build` dominates; those are the expensive jobs.
3. Prefer consolidating PRs and letting concurrency cancel stale runs over
   removing safety lanes.
4. Use `ci:full` only when needed; it is an exception path, not the default.
5. Revisit the matrix or cache strategy deliberately, with a reviewed change.

### Measuring usage with `scripts/ci_usage.py`

The script is dependency-free: it uses only the Python standard library and
calls `gh api`. It reads workflow runs created in the requested window, fetches
their jobs, computes each job's execution time from `started_at` /
`completed_at`, rounds **each job up** to a full minute (minimum one minute for
a job that ran), and aggregates by workflow and by job name. Jobs without both
timestamps (queued, skipped, or still running) are reported as missing and
excluded from the totals.

Prerequisites: an authenticated `gh` CLI (`gh auth login`, or `GH_TOKEN` with
`actions:read` for private repositories).

```bash
# Last 30 days for the current repository (inferred from gh)
python3 scripts/ci_usage.py

# Explicit repository and relative window
python3 scripts/ci_usage.py --repo kubaeror/sito-dns --since 30d

# ISO start date (UTC midnight), or an ISO timestamp
python3 scripts/ci_usage.py --since 2026-10-01
python3 scripts/ci_usage.py --since 2026-10-01T00:00:00Z --json

# Machine-readable output for a dashboard or a monthly review
python3 scripts/ci_usage.py --repo kubaeror/sito-dns --since 30d --json > ci-usage.json
```

`--since` accepts `Nd` (days), `Nw` (weeks), `Nm` (30-day months), an ISO date,
or an ISO timestamp. The default is `30d`. The text report prints a
per-workflow table, a per-job table, and a total; `--json` emits the same data
as an object with `total_minutes`, `workflows`, and `jobs`, plus a `truncated`
flag that is true when the page cap was reached and the totals are partial.

The measurement covers job execution time, not queue latency, cache storage,
artifact storage, or per-OS billing multipliers (all jobs here run Linux, so
the multiplier is 1). It is an estimate intended for trend tracking and budget
checks, not an invoice. Run it monthly, keep the JSON alongside the budget
review, and investigate any workflow or job whose share moves unexpectedly.
