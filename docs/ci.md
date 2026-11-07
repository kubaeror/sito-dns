# CI and Release Workflows

This document is the operational runbook for the GitHub Actions setup in
`.github/workflows/`. It describes which lane runs for which change, the
required check and branch-protection step, the runner and container-runtime
pins, the release pipeline, the decision to stop scheduled fuzzing, the action
pin policy, and the monthly runner-minute budget.

## Workflow map

| Workflow | File | Triggers | Purpose |
|---|---|---|---|
| **CI** | `ci.yml` | `pull_request` to `main`, `push` to `main`, `merge_group`, `workflow_dispatch` (`full`) | Classifies the change set and runs `fmt`, `clippy`, `test`, the three-target `build` matrix, `openapi`, `contrib`, and the reusable `docs-check`, `container-check`, `security-check` lanes. Publishes the single required check `ci-gate`. |
| **Docs** | `docs.yml` | `workflow_call` from CI, `push` to `main` on docs/workflow paths, `workflow_dispatch` | Runs the configuration-reference drift check and the pinned `actionlint` container for `.github/workflows/**`. |
| **Container** | `container.yml` | `workflow_call` from CI and Weekly, `push` to `main` on container paths, `workflow_dispatch` | Validates both Compose files, builds/smoke-tests the development `Dockerfile`, and builds `Dockerfile.release` with stub binaries. |
| **Security** | `security.yml` | `workflow_call` from CI and Weekly, `push` to `main` on dependency paths, `workflow_dispatch` | Runs `cargo-deny check`. |
| **Weekly Quality** | `weekly.yml` | Sunday at 03:00 UTC (`schedule`), `workflow_dispatch` | Release-mode tests, Criterion benchmarks, plus the reusable Container and Security workflows. |
| **Release** | `release.yml` | Push of a `v*` tag only | Verifies the tag, builds and signs the three release archives, publishes the GitHub release, verifies the artifacts, and publishes the multi-arch container image. |
| **Artifact E2E** | `artifact-e2e.yml` | `workflow_call` from Release, `workflow_dispatch` with a tag | Re-downloads a published release and verifies checksums, signatures, and execution of every architecture in the release runtime image. |

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
| Docs only (`docs/**`, `**/*.md`, `LICENSE`, `SECURITY.md`, `CODE_OF_CONDUCT.md`, issue/PR templates) | `ci.yml`: `changes`, `docs-check`, `ci-gate`. `docs-check` calls `docs.yml`, which runs `meta` (configuration check only if the config reference changed). No Rust, Docker, or `cargo-deny`. The `docs/openapi.json` exception below runs `openapi`. |
| Code (`crates/**`, `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`, `rustfmt.toml`) | `ci.yml`: `changes`, `fmt`, `clippy`, `test`, `build` (x86_64, aarch64, armv7), `ci-gate`. Dependency changes also run `security-check`. |
| OpenAPI spec only (`docs/openapi.json` without crate changes) | `ci.yml`: `changes`, `openapi`, `ci-gate`; `docs-check` also runs because the path is under `docs/`. |
| API crate (`crates/sito-api/**`) | Full code lane. `openapi` is skipped because `test` already regenerates and diffs the spec. |
| Contrib/scripts (`contrib/**`, `scripts/**`) | `ci.yml`: `changes`, `contrib`, `ci-gate`. `contrib` runs `shellcheck` on the installer, the AdGuard converter fixture test, and the release-helper tests. |
| Container (`Dockerfile`, `Dockerfile.*`, `.dockerignore`, `docker-compose*.yml`, `config.example.toml`, `contrib/systemd/**`) | `ci.yml`: `changes`, `container-check`, `ci-gate`. `container-check` calls `container.yml` (`compose`, `smoke`, and `release-image`). |
| Dependencies (`Cargo.toml`, `Cargo.lock`, `deny.toml`, `rust-toolchain.toml`) | `ci.yml`: the code lane plus `security-check`, `ci-gate`; `security-check` calls `security.yml` (`cargo-deny`). `Cargo.*` and the toolchain also match the code classifier, so the full code lane runs as well. |
| Workflow files (`.github/workflows/**`) | `ci.yml`: `changes`, `docs-check`, `ci-gate`; `docs-check` calls `docs.yml` (`meta` with `actionlint`). |
| Mixed changes | Union of the matching lanes. |

`docs/openapi.json` matches both the `docs/**` filter and the `api` filter, so
it runs the `openapi` job and the docs lane. A change to
`scripts/check_config_reference.py` is also matched by the docs lane and runs
the `meta` configuration-reference check. Independently of paths, every pull
request pays the small `changes` + `ci-gate` overhead (roughly 1–2 minutes).

`actionlint` discovers and lints `.github/workflows/**` only. It does not lint
composite actions in `.github/actions/**` (there is no such directory today).
If composite actions are added later, add a dedicated validator for them rather
than relying on `actionlint`.

A docs-only pull request therefore costs roughly the two small `ci.yml` jobs
(`changes`, `ci-gate`) plus the `docs-check` job, not a Rust rebuild. The one
exception is a change to `docs/openapi.json`, which also runs the `openapi` job.

### Behavior on `push` to `main`

The heavy `ci.yml` jobs include `(github.event_name != 'push' ||
github.ref != 'refs/heads/main')`, so on a push to `main` only `changes` and
`ci-gate` run. The identical tree has already been validated by the pull
request or merge-queue run; rebuilding every merge would duplicate the most
expensive work. The path-filtered `docs.yml`, `container.yml`, and
`security.yml` workflows still run on `main` pushes when their paths match, so
`main` keeps post-merge verification for those lanes.

A direct push to `main` therefore bypasses the heavy code lane; it is not a
substitute for PR validation. Protect `main` and merge through pull requests
(and optionally a merge queue) so the heavy lane runs before the change lands.

`merge_group` is a first-class trigger, so merge-queue runs execute the same
heavy jobs as a pull request.

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
`openapi`, `contrib`) and to the reusable gate jobs `docs-check`,
`container-check`, and `security-check`. It does not apply on a push to `main`,
where the heavy jobs remain skipped by design. The classifier reads
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

## Required check and branch protection

`ci-gate` is the single check that should be required for `main`. It depends on
`changes`, `fmt`, `clippy`, `test`, `build`, `openapi`, `contrib`, `docs-check`,
`container-check`, and `security-check` and fails if any of them reports
`failure` or `cancelled`. Jobs that were skipped because their paths did not
change count as success, which is what lets a docs-only PR merge without a Rust
run. Requiring every individual job instead would make docs-only PRs wait on
checks that are intentionally absent.

Branch protection is a **manual repository setting**. This change and the
workflow files do not modify repository settings. A repository administrator
must enable it once:

1. Open **Settings → Branches** (or **Settings → Rules**) and create a rule for
   `main`.
2. Enable **Require status checks to pass before merging**.
3. Add **`ci-gate`** (from the CI workflow) as a required check.
4. Optionally require branches to be up to date before merging. If a merge
   queue is enabled, keep `ci-gate` required; `ci.yml` already runs on
   `merge_group`. A merge queue adds a second heavy code lane (~20–25 minutes)
   for each queued PR, so re-evaluate the 600-minute budget before enabling
   one.
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
`Cargo.toml` (`v1.9.3` or a prerelease such as `v1.9.3-rc.1`); a mismatch stops
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
   with cosign keyless signing, and publishes the GitHub release. Stable tags
   update `latest`; tags containing `-` are published as prereleases and do not
   move `latest`.
4. **`artifact-e2e`** — re-downloads the published release and verifies all
   three architectures: per-archive `.sha256`, the unified `SHA256SUMS` line,
   the cosign signature identity, and execution of `--version` and
   `check-config` on the shipped configuration.
5. **`docker-build-push`** — builds and pushes the multi-arch image, then
   verifies the digest, every generated tag, the required platforms, and the
   SLSA provenance and SPDX SBOM attestations. A final smoke test pulls the
   published image and runs `--version` and `check-config`.

The GitHub release is published by `sbom-and-release` before `artifact-e2e`
runs; artifact E2E gates the container image, not the GitHub release. The image
is published only after the tag gate, the signed assets, the SBOM, and artifact
E2E have all passed.

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

## Scheduled fuzzing was intentionally removed

The previous scheduled fuzzing setup was removed as a deliberate decision
(variant A: zero scheduled fuzzing). There is **no fuzz workflow and no fuzz
harness directory** in this repository. This is a risk acceptance, not an
omission or an unfinished migration.

What we accept:

- Coverage-guided fuzzing can find parser, wire-decoder, and configuration
  edge cases that deterministic tests miss. Removing it reduces that specific
  coverage.
- The trade-off was made because the scheduled runs consumed a large share of
  runner minutes and required periodic upkeep, while the project already
  enforces memory-safe Rust, panic-free production paths, strict `clippy`,
  `cargo-deny`, the full workspace test suite, weekly release-mode tests and
  benchmarks, container smoke tests, and all-architecture release artifact
  execution.

Mitigations and change control:

- The test suite retains deterministic stress/sanity loops for the parser and
  wire codecs; every parser change still requires unit and integration tests.
- Weekly release-mode tests and benchmarks provide a slower feedback loop for
  regressions that only appear with optimizations.
- Reintroducing coverage-guided fuzzing requires a new plan or PR, a
  maintainer decision, and a budget review. It should not reappear implicitly
  as an untracked workflow.

Revisit this decision if a parser or decoder defect class emerges that the
existing tests cannot catch.

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
| `dtolnay/rust-toolchain` | `# master 2026-10-16` | The action has no release tags; the toolchain is pinned separately to **1.99.1** via `with: toolchain`. No floating `stable` or nightly refs. |
| `Swatinem/rust-cache` | `v2.9.3` | Rust build cache, per-job/key scopes. |
| `taiki-e/install-action` | `v2.90.2` | Always passed an explicit `tool:` (`cross`, `cargo-sbom@0.10.0`); this version no longer injects defaults. |
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

The working budget is **600 GitHub-hosted runner-minutes per month**, with an
expected steady state of **450–550 minutes**. The 600-minute ceiling assumes no
merge queue: with a merge queue enabled, each code PR also runs the heavy code
lane in the merge group, adding roughly 20–25 minutes per PR, so the budget must
be re-evaluated before enabling one. The measured baseline before this rework
was **1,743 minutes per 30 days**, so the target is a substantial reduction, not
an increase. 600 is the review threshold: a month at or above it should be
investigated. It is a planning target, not a GitHub-enforced limit.

Approximate runner-minutes per run (sum of billed jobs; parallel jobs count separately; warm caches; cold caches are higher):

| Activity | Typical minutes |
|---|---|
| Docs-only PR (`changes` + `ci-gate` + docs `meta`) | 1–2 |
| Code PR (`changes`, `fmt`, `clippy`, `test`, `build` ×3, `ci-gate`) | 20–25 |
| OpenAPI-only PR | 2–3 |
| Contrib-only PR | 1–2 |
| Container PR (`compose` + `smoke` + `release-image` stub build) | 8–11 |
| Security-only PR (`cargo-deny`) | 1–2 |
| Weekly run (release tests, benchmarks, container, security, `release-image`) | 26–36 |
| Release run (prebuilt-image pipeline) | 25–35 |

A weekly run bills `release-tests` and `perf` in parallel plus container,
security, and the `release-image` stub build, so the weekly row is the sum of
those jobs, not one critical path. The stub build adds roughly half a minute to
a minute; the live first run took 22 seconds.

Standard GitHub-hosted runners are free for public repositories. This budget is
therefore a time, queue, and capacity target rather than an invoice; if the
repository becomes private or uses larger runners, confirm the rates in
Billing and treat the same numbers as billable minutes.

Dependency changes also match the code classifier, so a `Cargo.toml` or
`Cargo.lock` PR costs the code lane plus the security lane, not just the
security row.

Illustrative month using the midpoints of those ranges: ~10 code PRs (≈225),
~5 docs PRs (≈8), four weekly runs (≈124), two releases (≈60), and a handful of
container/security/openapi/contrib runs (≈45–60), for **≈460–480 minutes**. The
midpoint sits inside the 450–550 expected band; depending on cache warmth and
actual run counts, the same mix can range from roughly 400 to 550. These per-run
figures are estimates from warm-cache runs, not invoice data; the measured
baseline of 1,743 minutes per 30 days is the reference point the rework is
reducing. Replace these estimates with `scripts/ci_usage.py` output after the
first full month.

The largest structural savings come from the docs-only classifier (no Rust or
Docker), skipping heavy jobs on `main` pushes, cancelling superseded PR runs,
and removing scheduled fuzzing. If a month reaches the 600-minute review
threshold:

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
