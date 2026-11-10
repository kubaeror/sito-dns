# sito 1.9.5 — release notes

Target release: **1.9.5** on 2026-11-10. This is a release-engineering patch.
There are **no runtime, configuration, API, database, or HA changes**; 1.9.5 is
functionally identical to 1.9.4. It exists so the tag-triggered release pipeline
publishes the container image that the v1.9.4 run skipped. The 1.9.4 archives,
checksums, signatures, and SBOM remain valid; no 1.9.4 container image was
published.

## What changed

### Multi-platform artifact E2E

The `artifact-e2e` job failed while extracting and validating the shipped
configuration:

```
docker: cannot overwrite digest sha256:08476c...
```

The job executes each release archive in the digest-pinned distroless runtime
image for its own platform (`linux/amd64`, then `linux/arm64`, then
`linux/arm/v7`). The error is consistent with the runner's Docker image store
keeping a single local reference per digest: after the first `--platform` pull,
the next platform's pull tried to replace that reference and Docker refused.
The loop now removes the local image after each platform's `--version` and
`check-config` runs, which forces a fresh pull for the next platform.
`RUNTIME_IMAGE` stays pinned to the distroless digest; it was not replaced with
a mutable tag. If the removal itself fails, the job emits a warning naming the
possible next failure instead of silently continuing.

### Draft-then-publish release

The GitHub release is now staged as a **draft** by `sbom-and-release` instead
of being published immediately. `artifact-e2e` and `docker-build-push` consume
the draft, and a new `publish-release` job flips it to published only after both
succeed. For a stable tag it also marks the release as latest; a prerelease tag
stays a prerelease and never moves `latest`.

This closes the v1.9.4 failure mode where the assets were already public when
E2E failed, leaving a published release without an image. A failure in E2E or
the image job now leaves a recoverable draft. Draft releases are only visible
to tokens with write access, so the `artifact-e2e` job runs with
`contents: write` to download the staged assets.

### Container image publication

`docker-build-push` depends on `artifact-e2e`, so the v1.9.4 failure skipped the
image job and v1.9.4 has no published container image. With the E2E fix and the
draft gate, the 1.9.5 release publishes the multi-arch image (and its scan,
signature, and attestations) as intended.

### Distroless runtime refresh

The first 1.9.5 image build was scanned successfully but failed the release gate
on two HIGH `zlib1g` CVEs in the previous distroless Debian 13 base. The runtime
base is updated to the newer digest
`sha256:cc66d222f0a7ec996b78a99fe76a969bc80b539a5016ad866c14d1949bc6d0ab`
(Debian 13.7), which scans clean for HIGH/CRITICAL vulnerabilities. The image
remains digest-pinned; no mutable tag was introduced.

## Upgrade notes

- No action is required. Configuration, databases, sessions, HA state, and API
  contracts are unchanged from 1.9.4.
- Operators already on 1.9.4 do not need to upgrade for product behavior.
  Upgrade if you want a fully green tag-triggered release pipeline and a
  published `1.9.5` container image.
- The 1.9.4 archives, checksums, signatures, and SBOM remain valid; no 1.9.4
  container image was published. 1.9.5 only fixes the release tooling.
- No new known issues. See the
  [1.9.4 release notes](release-notes-1.9.4.md#known-issues) for the known
  issues that still apply to the 1.9.x line.

## Validation

The release gates are the repository's standard commands:

```bash
cargo fmt --all --check
cargo check --workspace --all-features --locked
cargo clippy --workspace --all-features --all-targets --locked -- -D warnings
cargo deny check
python3 scripts/check_config_reference.py --github
python3 scripts/check_markdown_links.py
bash scripts/test-release-workflow.sh
```

Workflow syntax is checked with actionlint:

```bash
docker run --rm -v "$PWD:/repo:ro" -w /repo \
  rhysd/actionlint:1.7.12@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667
```

`scripts/test-release-workflow.sh` checks the release job ordering and policy:
assets are staged as a draft, `artifact-e2e` and `docker-build-push` gate the
final publish, and the image job keeps its scan/sign requirements. It does not
execute the `docker image rm` step itself. The multi-platform container
execution requires QEMU and the staged release assets, so it is exercised by
the release run rather than a local unit test.
