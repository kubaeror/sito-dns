# sito 1.9.5 — release notes

Target release: **1.9.5** on 2026-11-10. This is a release-engineering patch.
There are **no runtime, configuration, API, database, or HA changes**; 1.9.5 is
functionally identical to 1.9.4. It exists so the tag-triggered release pipeline
publishes the container image that the v1.9.4 run skipped. The 1.9.4 release
assets remain valid.

## What changed

### Multi-platform artifact E2E

The `artifact-e2e` job failed while extracting and validating the shipped
configuration:

```
docker: cannot overwrite digest sha256:08476c...
```

The job executes each release archive in the digest-pinned distroless runtime
image for its own platform (`linux/amd64`, then `linux/arm64`, then
`linux/arm/v7`). Docker keeps a single local reference per digest, so after the
first `--platform` pull, the next platform's pull tried to replace that
reference and Docker refused. The loop now removes the local image after each
platform's `--version` and `check-config` runs, which forces a fresh pull for
the next platform. `RUNTIME_IMAGE` stays pinned to the distroless digest; it
was not replaced with a mutable tag.

### Container image publication

`docker-build-push` depends on `artifact-e2e`, so the v1.9.4 failure skipped the
image job and v1.9.4 has no published container image. With the E2E fix, the
1.9.5 release publishes the multi-arch image (and its scan, signature, and
attestations) as intended.

## Upgrade notes

- No action is required. Configuration, databases, sessions, HA state, and API
  contracts are unchanged from 1.9.4.
- Operators already on 1.9.4 do not need to upgrade for product behavior.
  Upgrade if you want a fully green tag-triggered release pipeline and a
  published `1.9.5` container image.
- The 1.9.4 release assets (archives, checksums, signatures, and SBOM) remain
  valid; 1.9.5 only fixes the release tooling.

## Validation

The release gates are the repository's standard commands:

```bash
cargo fmt --all --check
cargo check --workspace --all-features --locked
cargo deny check
python3 scripts/check_config_reference.py --github
python3 scripts/check_markdown_links.py
```

The workflow change is covered by the release-workflow policy test, which
asserts that `artifact-e2e` runs before `docker-build-push`. The multi-platform
container execution itself requires QEMU and the published release assets, so
it is exercised by the release run rather than a local unit test.
