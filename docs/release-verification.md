# Release and container image verification

This page describes the release gate in
[`.github/workflows/release.yml`](../.github/workflows/release.yml) and the
commands to verify a published release and image. Releases are triggered by
pushing a `v*` tag; `workflow_dispatch` publishing is intentionally not
supported.

## Release gate order

The workflow is a dependency chain, not a set of parallel publications. A
failure in any job stops every job that depends on it, so no later artifact is
published.

| Job | What it proves | Depends on |
| --- | --- | --- |
| `verify-tag` | The tag matches the workspace version in `Cargo.toml` (`vX.Y.Z`) or is a prerelease of that version (`vX.Y.Z-<suffix>`). | — |
| `release-gate` | The tagged commit is an ancestor of the required branch (`release/1.9.x` for 1.9.x, `main` for 2.0) and has a successful `ci-gate` check and `cargo-deny` security check. | `verify-tag` |
| `build-binaries` | All three release archives build (x86_64, aarch64, armv7) and `contrib/install.sh` passes shellcheck. | `verify-tag`, `release-gate` |
| `sbom-and-release` | `SHA256SUMS`, the SPDX SBOM, and cosign keyless signatures are generated and staged as a draft GitHub release. | `verify-tag`, `release-gate`, `build-binaries` |
| `artifact-e2e` | The staged draft is downloadable (it needs a write-capable token); checksums, the cosign identity (`release.yml@refs/tags/*`), `sito --version`, and `sito check-config` all pass. | `sbom-and-release` |
| `docker-build-push` | The multi-arch image is pushed; its digest, platform list, tags, provenance, and SBOM are verified; the digest is scanned by a digest-pinned Trivy (fixed HIGH/CRITICAL gate; unfixed findings are ignored) and signed/verified with cosign keyless signing. | `verify-tag`, `release-gate`, `build-binaries`, `sbom-and-release`, `artifact-e2e` |
| `publish-release` | The staged draft is flipped to published and verified not to be a draft; stable tags are marked latest and prereleases stay prereleases. | `sbom-and-release`, `artifact-e2e`, `docker-build-push` |

Consequences:

- A tag that does not match the workspace version fails in `verify-tag`, before
  a binary, release asset, or image is produced.
- A tag whose commit is not on the required release branch, or whose CI or
  `cargo-deny` check is missing/red, fails in `release-gate` before any artifact
  is built.
- A failed signature, SBOM, download, checksum, or artifact E2E check stops the
  workflow before the image is built; the staged release remains a draft.
- A HIGH/CRITICAL image vulnerability or a missing image signature fails
  `docker-build-push`, and the staged release remains a draft.
- `docker-build-push` and `publish-release` are blocking. Neither is optional
  and neither has `continue-on-error`.

The container image is built from the already-built release binaries through
`Dockerfile.release` (`binaries=./prebuilt`); no Rust compilation happens in the
image pipeline. Artifact E2E executes all three architectures in the pinned
`cc-debian13` runtime with QEMU for arm64 and armv7.

## Tag and publication rules

| Tag | GitHub release | Docker tags |
| --- | --- | --- |
| `vX.Y.Z` (matches the workspace version) | Staged as a draft, then published and marked latest after the image passes | `X.Y.Z`, `X.Y`, `latest` |
| `vX.Y.Z-<suffix>` (same base version) | Staged as a draft, then published as a prerelease (never latest) after the image passes | `X.Y.Z-<suffix>` only |
| Anything else | Workflow fails in `verify-tag` | Nothing is pushed |

The prerelease decision is `contains(github.ref_name, '-')`. A prerelease tag
therefore cannot publish or move `latest` or the moving `<major>.<minor>` tag,
and cannot mark the GitHub release as a stable/latest release. `latest` stays
on the previous stable release.

## Verify the workflow run

After pushing a release tag:

```bash
gh run list --workflow release.yml --limit 5
gh run watch <run-id> --exit-status
```

Expected: `verify-tag`, all three `build-binaries` matrix jobs,
`sbom-and-release`, `artifact-e2e`, `docker-build-push`, and `publish-release`
are green. The `docker-build-push` log ends with
`Verified ghcr.io/<owner>/<repo>@sha256:...`, the platform list, and the
generated tags. The release is a draft until `publish-release` succeeds.

## Verify the published image

Set the release tag and derive the Docker tag, which omits the leading `v`:

```bash
RELEASE_TAG=v1.9.3
IMAGE="ghcr.io/kubaeror/sito-dns"
TAG="${RELEASE_TAG#v}"
```

### 1. Digest exists and is well formed

```bash
DIGEST="$(docker buildx imagetools inspect "${IMAGE}:${TAG}" \
  --format '{{.Manifest.Digest}}')"
printf '%s\n' "${DIGEST}"
```

Expected: `sha256:` followed by 64 lowercase hex characters, and the same value
reported by `docker-build-push` in the workflow log.

### 2. All release platforms are present

```bash
docker buildx imagetools inspect "${IMAGE}:${TAG}" \
  --format '{{range .Manifest.Manifests}}{{.Platform.OS}}/{{.Platform.Architecture}}{{with .Platform.Variant}}/{{.}}{{end}} {{end}}'
```

Expected: includes `linux/amd64`, `linux/arm64` (or the equivalent OCI/BuildKit
spelling `linux/arm64/v8`), and `linux/arm/v7`. Attestation manifests also
appear as `unknown/unknown`; they are expected and are not release platforms.
The release job runs the same allowlist through
`scripts/check-release-platforms.sh`, normalizing `linux/arm64/v8` to
`linux/arm64`; the other two platforms are still mandatory.

### 3. Provenance attestation is present

```bash
docker buildx imagetools inspect "${IMAGE}@${DIGEST}" \
  --format '{{json .Provenance}}' | grep -q '"SLSA"'
echo "provenance: $?"
```

Expected: exit status `0` and `provenance: 0`. An empty object, `null`, or a
missing key means the build did not attach provenance and the release job
should have failed.

### 4. SPDX SBOM attestation is present

```bash
docker buildx imagetools inspect "${IMAGE}@${DIGEST}" \
  --format '{{json .SBOM}}' | grep -q '"SPDX"'
echo "sbom: $?"
```

Expected: exit status `0` and `sbom: 0`.

### 5. Tags point at the same digest

```bash
check_digest() {
  local ref="$1" got
  got="$(docker buildx imagetools inspect "${ref}" --format '{{.Manifest.Digest}}')"
  printf '%s -> %s\n' "${ref}" "${got}"
  [ "${got}" = "${DIGEST}" ]
}

if [ "${RELEASE_TAG}" = "${RELEASE_TAG%-*}" ]; then
  # Stable tag: version, moving major.minor, and latest all move together.
  check_digest "${IMAGE}:${TAG}"
  check_digest "${IMAGE}:${TAG%.*}"
  check_digest "${IMAGE}:latest"
else
  # Prerelease: only the full version tag was published.
  check_digest "${IMAGE}:${TAG}"
fi
```

Expected for a stable tag: all three lines print `${DIGEST}`. Expected for a
prerelease tag: only one line, and it prints `${DIGEST}`.

Confirm that a prerelease did not move `latest` (a missing `latest` tag also
passes, because nothing was moved):

```bash
if [ "${RELEASE_TAG}" = "${RELEASE_TAG%-*}" ]; then
  # Stable: latest must be this digest.
  latest="$(docker buildx imagetools inspect "${IMAGE}:latest" \
    --format '{{.Manifest.Digest}}')"
  [ "${latest}" = "${DIGEST}" ]
  echo "latest rule: $?"
else
  # Prerelease: latest must not be this digest (or must not exist yet).
  if docker buildx imagetools inspect "${IMAGE}:latest" \
      --format '{{.Manifest.Digest}}' 2>/dev/null | grep -Fxq "${DIGEST}"; then
    echo "latest rule: 1 (latest incorrectly points at the prerelease)"
  else
    echo "latest rule: 0"
  fi
fi
```

Expected: `latest rule: 0`.

### 6. GitHub release state

`isPrerelease` is available from `gh release view`, but `isLatest` is not; the
latest-release pointer must be read from `gh release list`.

```bash
gh release view "${RELEASE_TAG}" --json tagName,isPrerelease
gh release list --limit 100 --json tagName,isLatest \
  --jq '.[] | select(.isLatest) | .tagName'
```

Expected for a stable tag: `gh release view` prints
`{"isPrerelease":false,"tagName":"vX.Y.Z"}` and the `gh release list` command
prints the same tag (`vX.Y.Z`). Expected for a prerelease tag: `gh release view`
prints `{"isPrerelease":true,"tagName":"vX.Y.Z-<suffix>"}` and `gh release list`
prints the previous stable tag (for example `vX.Y.<Z-1>`), never the prerelease
tag. If no release is marked latest, the list command prints nothing.

## Verify the signed release assets

The `artifact-e2e` job performs these checks automatically. To reproduce them
for the x86_64 archive:

```bash
mkdir -p /tmp/sito-verify && cd /tmp/sito-verify
gh release download "${RELEASE_TAG}" \
  --pattern "sito-${RELEASE_TAG}-x86_64-unknown-linux-gnu.tar.gz*" \
  --pattern 'SHA256SUMS'

archive="sito-${RELEASE_TAG}-x86_64-unknown-linux-gnu.tar.gz"
sha256sum -c "${archive}.sha256"
grep -F "  ${archive}" SHA256SUMS | sha256sum -c -

cosign verify-blob \
  --certificate "${archive}.pem" \
  --signature "${archive}.sig" \
  --certificate-identity-regexp \
    '^https://github.com/kubaeror/sito-dns/\.github/workflows/release\.yml@refs/tags/.*$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "${archive}"

tar -xzf "${archive}"
"./sito-${RELEASE_TAG}-x86_64-unknown-linux-gnu/sito" --version
"./sito-${RELEASE_TAG}-x86_64-unknown-linux-gnu/sito" check-config \
  --config "./sito-${RELEASE_TAG}-x86_64-unknown-linux-gnu/config.example.toml"
```

Expected: both checksum checks print `OK`, `cosign verify-blob` prints
`Verified OK`, and `--version` prints the version matching the tag.

## If verification fails

- **`verify-tag` failed**: nothing was published. Delete the incorrect tag and
  push a tag that matches `Cargo.toml`, or bump the workspace version. Never
  reuse a tag that already produced release assets.
- **A release/signature/SBOM verification failed**: nothing reaches
  `docker-build-push`, so no image is published and the staged release stays a
  draft. Fix the cause and use a new tag (for example a new patch or prerelease
  suffix).
- **Post-push verification failed**: the image may already be in GHCR, but the
  workflow is red and the release stays a draft. Treat the image as unpublished:
  remove the affected tag(s)/digest from GHCR, fix the problem, and publish
  again with a new tag. Do not leave `latest` pointing at an unverified digest.
