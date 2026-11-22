# Release and container image verification

This page is the explicit gate checklist for the `v2.0.0` release and the
commands to verify a published release and image. The
[2.0 release gate checklist](#20-release-gate-checklist) names every gate, its
workflow or lane, the required evidence, the pass condition and the release
candidate at which it must be green; the sections after it hold the exact
commands and expected output. Releases are triggered by pushing a `v*` tag;
`workflow_dispatch` publishing is intentionally not supported.

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
| `docker-build-push` | The multi-arch image is pushed; its digest, platform list, tags, provenance, and SBOM are verified; the digest is scanned by a digest-pinned Trivy (fixed HIGH/CRITICAL gate; unfixed findings are ignored) and signed/verified with cosign keyless signing. The attested digest is also started with a self-contained config: a local rewrite must answer and the image healthcheck must turn `healthy`. | `verify-tag`, `release-gate`, `build-binaries`, `sbom-and-release`, `artifact-e2e` |
| `publish-release` | The staged draft is flipped to published and verified not to be a draft; stable tags are marked latest and prereleases stay prereleases. | `sbom-and-release`, `artifact-e2e`, `docker-build-push` |

The 2.0 gate additionally requires one green root-gated HA ownership run on the
release candidate commit (see
[HA certificate ownership evidence](#ha-certificate-ownership-evidence-root-gated-lane)).
That lane needs `sudo` and uid/gid 65532, so it is a separate manual/weekly
workflow rather than a job in the tag-push chain.

Consequences:

- A tag that does not match the workspace version fails in `verify-tag`, before
  a binary, release asset, or image is produced.
- A tag whose commit is not on the required release branch, or whose CI or
  `cargo-deny` check is missing/red, fails in `release-gate` before any artifact
  is built.
- A failed download, checksum, or artifact E2E check stops the workflow before
  the image is built; the staged release remains a draft. A failed signature or
  SBOM generation fails earlier in `sbom-and-release`, before the draft is
  created.
- A HIGH/CRITICAL image vulnerability or a missing image signature fails
  `docker-build-push`, and the staged release remains a draft.
- `docker-build-push` and `publish-release` are blocking. Neither is optional
  and neither has `continue-on-error`.

The container image is built from the already-built release binaries through
`Dockerfile.release` (`binaries=./prebuilt`); no Rust compilation happens in the
image pipeline. Artifact E2E executes all three architectures in the pinned
`cc-debian13` runtime with QEMU for arm64 and armv7.

### Release-gate check lookup

`release-gate` runs
[`scripts/verify-release-gate.sh`](../scripts/verify-release-gate.sh) on the
tagged commit. It requires exactly two green checks, `ci-gate` and
`cargo-deny`, and ignores the release workflow's own in-progress jobs. Newer
GitHub CLI releases are queried with `gh api --paginate --slurp`; when the
installed `gh` does not know `--slurp`, the script retries once with plain
`--paginate`. Any other error (authentication, network, API) is fatal and is
never retried or hidden. Both pagination shapes are pinned by
`bash scripts/test-verify-release-gate.sh`, and the release evidence is the
green `release-gate` job plus its
`release checks are green for <sha>: ci-gate, cargo-deny` log line.

## 2.0 release gate checklist

Complete every pre-tag row before creating the `v2.0.0` tag. Rows 1 and 2 are
tag-push checks that can be pre-checked manually (tag/version and branch/check
ancestry). Rows 9, 10 and 14 are produced only by the tagged release run, so
they are verified after the tag push instead. "Stage" is the first release
candidate at which the gate must be green; evidence from an earlier candidate
carries forward only when the release manager records that no release-relevant
change landed since. A red or missing pre-tag row blocks tagging; a red
tag-push row leaves the release as a draft and blocks publication.

| # | Gate | Workflow / command | Required evidence | Pass condition | Stage (owner) |
| --- | --- | --- | --- | --- | --- |
| 1 | Tag matches the workspace version | `release.yml` → `verify-tag` | run URL, tag, `Cargo.toml` version | tag is `vX.Y.Z` or a prerelease of the workspace `X.Y.Z` | rc.3, rc.4, final (release manager) |
| 2 | Release branch and checks | `release.yml` → `release-gate` (`scripts/verify-release-gate.sh`) | run URL, tagged SHA, `release checks are green for <sha>: ci-gate, cargo-deny` | tagged commit is an ancestor of `main`; `ci-gate` and `cargo-deny` are completed and successful; no failing legacy status | rc.3, rc.4, final (release manager) |
| 3 | All-features and default test suites | `ci.yml` → `test` (`cargo test --workspace --all-features --locked`), `ha-matrix`; plus `cargo test --workspace --locked` on the candidate | green `ci-gate` run URL and the default-suite transcript | both suites green and the no-HA/HA matrix green | rc.3, rc.4, final (CI owner) |
| 4 | Dependency policy after W0-DEPS | `security.yml` → `cargo-deny` (`deny.toml`) | check-run URL and `cargo deny check` summary | advisories, bans, licenses and sources pass with no unreviewed suppression | rc.3, rc.4, final (security reviewer) |
| 5 | Docs truth | `docs.yml` → `meta` (`python3 scripts/check_test_matrix.py`) | run URL and command output | config reference, migration IDs, links and P0/P1 test-matrix names resolve; no stale 2.0 claim | rc.3, rc.4, final (docs owner) |
| 6 | Installer E2E | `ci.yml` → `contrib` → `bash contrib/tests/test-installer.sh` | green `contrib` job log | fresh install, live upgrade, backup order and failed-health rollback pass | rc.4, final if S5 changed (ops owner) |
| 7 | 1.9.5 → 2.0 migration and rollback | `bash scripts/test-migration-1.9.5.sh` | transcript ending `PASS: 1.9.5 data-dir migration and rollback acceptance` | v1.9.5 data dir migrates, v2 answers, users/TOTP/stats DB stay intact, rollback answers | rc.4, final if S2/S5 changed (ops owner) |
| 7b | Archived installer E2E (E2) | `SITO_ARCHIVE_E2E=1 bash scripts/test-installer-archive-1.9.5.sh` (manual/weekly `archive-installer-e2e.yml`) | transcript ending `PASS: real archived 1.9.5 installer upgrade, migration and rollback` | the real v1.9.5 archive installs with its packaged installer, checksum/signature verification passes, the current installer runs `db migrate` with a 0600 backup, health/DNS/users/stats rows survive, and both the operator rollback and the failed-health pairing rollback restore 1.9.5 with v1 config | rc.4, final if S2/S5 changed (ops owner) |
| 8 | Docker upgrade E2E | `bash scripts/test-docker-upgrade.sh` | transcript ending `docker upgrade E2E OK (...)` | 1.9.5 container upgrades to the candidate with healthy DNS + healthcheck, then the rollback serves again | rc.4, final if S2/S5 changed (ops owner) |
| 9 | Per-architecture image scan (E4) | `release.yml` → `docker-build-push` → `Scan the published image for vulnerabilities` | run URL, digest, one `Scanning ...` and one `No HIGH/CRITICAL unfixed vulnerabilities on ...` line per platform | all three platforms are scanned from the published digest and no fixed HIGH/CRITICAL finding remains | rc.4 image, final (security reviewer) |
| 10 | Image signature and attestations | `docker-build-push` cosign steps; [verify the published image](#verify-the-published-image) | digest, `cosign verify` output, provenance, SPDX SBOM, tag map | signature identity `release.yml@refs/tags/*`, provenance and SBOM present, tags point at the digest | rc.4 image, final (release manager) |
| 11 | Root-gated HA ownership (E5) | `ha-ownership.yml` | run URL, SHA, non-root uid, `running 1 test`, `test result: ok. 1 passed` | the m8 ownership test runs under root and passes exactly once | rc.4, final if HA changed (HA owner) |
| 12 | 24-hour fuzz | `fuzz.yml` with `fuzz_seconds=17280` and `shards=5` | run URL, SHA, five targets, per-target corpus size, empty `fuzz/artifacts/` | no crash, timeout or OOM | after rc.4 → final (ops owner) |
| 13 | Thresholded benchmark | `bench.yml` | run URL, baseline environment `github-ubuntu-24.04`, tolerance | no `REGRESSION` line above the tolerance | rc.4 → final (performance owner) |
| 14 | Live image smoke: DNS, health, API v2 and schema v2 | `docker-build-push` → `Smoke-test the published image` | log lines `release image answered smoke.test; healthcheck: healthy` and `release image API smoke: /api/v2/status=<200 or 401> (real auth response); /api/v1/status=404 (removed); fresh stats schema v2; healthcheck: healthy` | the attested digest answers a local rewrite, the image healthcheck turns healthy, API v2 is mounted (200/401, never 404), API v1 is 404, and the fresh data dir is schema v2 | rc.4 image, final (release manager) |
| 15 | Security review | `docs/phase3-security-review.md`, `docs/security-audit.md` | review signed off against the final tree with the open P0/P1 list | no open P0; every open P1 accepted with an owner and review date | final (security reviewer) |
| 16 | `latest` still on 1.9.5 | commands in [`latest` stays on 1.9.5](#latest-stays-on-195-until-the-final-tag) | `latest` image digest and GitHub latest release tag | both equal `v1.9.5` before the final tag; only `v2.0.0` moves them | rc.3, rc.4, final-before-tag (release manager) |
| 17 | Catalog release-bound integrity (F2e) | `python3 scripts/generate-catalog.py --check`; focused `sito-clients`/`sito-api` catalog tests; CI `test` job step | `catalog check passed`, green focused tests, green `Verify the embedded catalog and pin are current` step | the committed catalog matches `CATALOG_SHA256`, canonical bytes are current, and the loader has no network path | rc.4, final (catalog owner) |

The E4 per-architecture scan, E5 root HA lane and E6 release-gate fallback are
linked to their own policy tests and lanes above; this page records their
release evidence rather than redefining their internals.

### Catalog release-bound integrity (F2e)

The catalog is refreshable only by a new release. Run these on the release
candidate (and confirm the CI `test` job ran the same check on the tagged SHA):

```bash
python3 scripts/generate-catalog.py --check
cargo test -p sito-clients --all-features catalog
cargo test -p sito-api --all-features catalog
```

Expected evidence:

- `catalog check passed: ... is up to date` from the offline check. It never
  uses the network; the SHA-256 pin and canonical bytes catch any hand edit.
- The focused tests pass, including
  `catalog_module_has_no_network_path` and
  `catalog_attribution_names_embedded_source`. The no-network test is a
  source/manifest tripwire, not a formal proof.
- The green CI step `Verify the embedded catalog and pin are current` in the
  `test` job.
- If the release intentionally refreshed metadata, the same PR records the
  `catalog.json` diff, the new `CATALOG_SHA256`, the license/attribution review
  and the `catalog_version` decision from the
  [catalog refresh runbook](catalog.md#release-time-refresh-runbook). List
  bodies must still be runtime downloads; no catalog fetch or
  `sito catalog update` command may appear.

## Tag and publication rules

| Tag | GitHub release | Docker tags |
| --- | --- | --- |
| `vX.Y.Z` (matches the workspace version) | Staged as a draft, then published and marked latest after the image passes | `X.Y.Z`, `X.Y`, `latest` |
| `vX.Y.Z-<suffix>` (same base version) | Staged as a draft, then published as a prerelease (never latest) after the image passes | `X.Y.Z-<suffix>` only |
| Anything else | Workflow fails in `verify-tag` | Nothing is pushed |

The prerelease decision is `contains(github.ref_name, '-')`. A prerelease tag
therefore cannot publish or move `latest` or the moving `<major>.<minor>` tag,
and cannot mark the GitHub release as a stable/latest release.

### `latest` stays on 1.9.5 until the final tag

The rc.3 and rc.4 tags are prereleases. They may publish version-only Docker
tags and a prerelease GitHub release, but they must not move the repository's
`latest` image tag or latest release pointer. Before creating the final
`v2.0.0` tag, record:

```bash
RELEASE_TAG=v1.9.5
IMAGE="ghcr.io/kubaeror/sito-dns"
LATEST_DIGEST="$(docker buildx imagetools inspect "${IMAGE}:latest" \
  --format '{{.Manifest.Digest}}')"
STABLE_DIGEST="$(docker buildx imagetools inspect "${IMAGE}:${RELEASE_TAG#v}" \
  --format '{{.Manifest.Digest}}')"
printf 'latest=%s\n1.9.5=%s\n' "${LATEST_DIGEST}" "${STABLE_DIGEST}"
gh release list --limit 100 --json tagName,isLatest \
  --jq '.[] | select(.isLatest) | .tagName'
```

Expected before the final tag: the two digests are identical and
`gh release list` prints `v1.9.5`. After the final `v2.0.0` tag is published,
the same commands must show the `v2.0.0` image digest and `v2.0.0` as the
latest release. A prerelease that moved either pointer is a release blocker and
must be reverted before proceeding (see the prerelease checks in
[Verify the published image](#verify-the-published-image)).

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

## Per-architecture image scan (E4)

The `docker-build-push` job scans the published digest once for each promised
platform (`linux/amd64`, `linux/arm64`, `linux/arm/v7`) with the digest-pinned
Trivy image and fails on a fixed HIGH/CRITICAL finding. The scan's shape and
platform coverage are owned by E4 and pinned by
`bash scripts/test-release-workflow.sh`; this checklist records the evidence
from the `Scan the published image for vulnerabilities` step.

Record for the rc.4 and final runs:

- the run URL and the image digest;
- one `Scanning ghcr.io/<owner>/<repo>@sha256:... for linux/<platform>` line
  for each of `linux/amd64`, `linux/arm64` and `linux/arm/v7`;
- the matching `No HIGH/CRITICAL unfixed vulnerabilities on linux/...` line for
  each platform;
- the `Verified ghcr.io/<owner>/<repo>@sha256:...` line from the preceding
  verification step.

Pass condition: the job is green and every `Scanning` and `No HIGH/CRITICAL`
line names the same digest as the verified, signed image. A fixed finding on
any single platform fails the release. Unfixed findings are intentionally
ignored, as documented in the workflow.

## Upgrade, installer and Docker E2E

Four real upgrade paths must be green on the rc.4 candidate, and again on the
final commit if S2 or S5 changed after rc.4. The installer and migration
scripts are owned by E1/E2; this checklist records their evidence.

1. Installer E2E, run by the `contrib` job in CI:

   ```bash
   bash contrib/tests/test-installer.sh
   ```

   Expected: a fresh install, a live upgrade over a running binary, the config
   backup after the service stop, capability/`getcap` checks, the
   failed-health rollback, the default stats-DB migration before the new server
   starts, the 1.9.x → 1.9.x skip, the `--no-migrate` skip with forced
   `SITO_DB_AUTO_MIGRATE=0` and fail-closed rollback, partial-migration DB
   restore, pre-2.0 binary/config pairing, the “stop without a backup”
   recovery path, and the runnable v1-config recovery command all pass. Record
   the green `contrib` job URL.

2. Binary migration and rollback, against a real v1.9.5 data directory:

   ```bash
   # Either provide binaries or let the script build both trees.
   SITO_OLD_BIN=/path/to/v1.9.5/sito \
   SITO_NEW_BIN=/path/to/2.0/sito \
     bash scripts/test-migration-1.9.5.sh
   ```

   Expected transcript tail:
   `PASS: 1.9.5 data-dir migration and rollback acceptance`. Record the
   v1.9.5 version line, the migrated `/api/v2/status` version, the read-only
   `stats.db` integrity check, and the rollback rewrite answer.

3. Docker upgrade and rollback, with the previous image and candidate image
   available locally:

   ```bash
   docker build -t sito:1.9.5 <v1.9.5-worktree>
   docker build -t sito:phase3 .
   OLD_IMAGE=sito:1.9.5 NEW_IMAGE=sito:phase3 \
     bash scripts/test-docker-upgrade.sh
   ```

   Expected transcript tail:
   `docker upgrade E2E OK (sito:1.9.5 -> sito:phase3 -> rollback)`, after the
   candidate answered DNS and reported `healthy`, the `SITO_NO_MIGRATE=1` run
   stayed fail-closed without a backup, the default candidate start wrote a
   0600 `stats.db.v1.bak`, and the rollback container answered again with the
   v1 data.

4. Real archived installer, not a fabricated 1.9.5 binary. This lane needs
   network access and is therefore manual/weekly, never default PR CI:

   ```bash
   SITO_ARCHIVE_E2E=1 \
   SITO_NEW_BIN="$PWD/target/debug/sito" \
   SITO_ARCHIVE_KEEP_TMP=1 \
     bash scripts/test-installer-archive-1.9.5.sh
   ```

   Without `SITO_ARCHIVE_E2E=1` the script exits before any download. It pins
   `SITO_ARCHIVE_TAG=v1.9.5`, downloads the published archive and
   `SHA256SUMS`, always verifies the SHA-256, then installs a pinned
   checksum-verified cosign **before** extracting the archive and verifies the
   archive signature with the certificate identity
   `https://github.com/kubaeror/sito-dns/.github/workflows/release.yml@refs/tags/v1.9.5`.
   No archive content is executed before that verification.
   `SITO_ARCHIVE_ALLOW_UNSIGNED=1` is the only skip; it prints `SKIP`, still
   verifies SHA-256, and never claims a signature was verified. The script
   installs the real archive with its own packaged `install.sh` into a temp
   prefix behind a fake systemctl wrapper, seeds a v1 data directory through
   the real 1.9.5 server, migrates the config with the current binary
   (`config migrate --from v1 --to v2 --backup`, the documented
   precondition), then runs the current installer with the local 2.x binary.

   Expected transcript tail:
   `PASS: real archived 1.9.5 installer upgrade, migration and rollback`.
   Record the archived 1.9.5 `--version` line, the SHA-256 `OK` line, the
   independent cosign checksum/`Verified OK` output, the `Migrating stats
   database` and 0600 `stats.db.v1.bak` lines, the exact preserved query_log
   count, the `/api/v2/status` version, the rollback `live pid … is 'sito
   1.9.5'` and `/api/v2/status is absent (HTTP 404)` lines, and the
   `Restoring matching v1 configuration` line from the failed-health rollback.
   The same lane is available as the manual/weekly
   [`archive-installer-e2e.yml`](../.github/workflows/archive-installer-e2e.yml)
   workflow. The offline wiring/policy check is
   `bash scripts/test-installer-archive-e2e.sh` and runs in the `contrib` CI
   job; it does not download anything.

A failed or missing transcript blocks the release. Record the command, commit
SHA, date and transcript path for all four runs.

## Live DNS, health, API and schema smoke (E8)

The `Smoke-test the published image` step in `docker-build-push` starts the
exact attested digest (`${IMAGE}@${DIGEST}`, never a tag or a rebuild) with a
self-contained config, queries `smoke.test`, and waits for the image
healthcheck. It is the release-time live DNS/health gate; the `container.yml`
compose smoke remains the pull-request mechanism and does not replace it.

A second container from the same digest enables the admin web UI
(`[web] enabled = true`, host port 18080, probed at `127.0.0.1:18080`) with a
fresh data dir and a real admin account created by `reset-admin`. Both
containers use named
Docker volumes initialised from the image's 65532-owned `/var/lib/sito`
(a runner-owned host bind mount would make the container entrypoint's
post-migration ownership restore fail without `CAP_CHOWN`) and rewrite
`localhost.` locally, so the healthcheck never depends on an upstream answer.
It proves the 2.0 surface:

- `GET /api/v2/status` returns the real authentication response (`401` without
  a token, or `200` if anonymous access is ever allowed) and never `404`.
- `GET /api/v1/status` returns `404`: API v1 is removed with no alias or
  redirect.
- `GET /health` returns `200 {"status":"ok"}` and the image healthcheck turns
  `healthy` with the web listener enabled (so the DNS probe and the public
  readiness endpoint are both required).
- After the server is stopped, a read-only
  `sito db migrate --config /etc/sito/config.toml --dry-run` on the same data
  dir reports `already at schema version 2`, proving a fresh 2.0 install
  creates a schema-v2 stats database without modifying it.

Record the run URL, image digest, and both log lines:

```text
release image answered smoke.test; healthcheck: healthy
release image API smoke: /api/v2/status=401 (real auth response); /api/v1/status=404 (removed); fresh stats schema v2; healthcheck: healthy
```

Pass condition: the step is green, neither container exited early, the DNS
rewrite answered, both healthchecks are `healthy`, `/api/v2/status` is `200` or
`401`, `/api/v1/status` is `404`, and the dry run reports schema version 2.
Repeat for the rc.4 image and the final image.

Manual caveat: the smoke needs Docker with the published digest available (the
release runner logs in to GHCR for the push, so the digest pull is local). To
re-run it manually for an existing release without `docker-build-push`:

```bash
IMAGE=ghcr.io/kubaeror/sito-dns
DIGEST="$(docker buildx imagetools inspect "${IMAGE}:v2.0.0" --format '{{json .Manifest.Digest}}' | tr -d '"')"
docker run --rm --entrypoint /usr/bin/sito "${IMAGE}@${DIGEST}" --version
# Then repeat the container/config/curl/db-migrate commands from the workflow
# step; always use "${IMAGE}@${DIGEST}", never the tag.
```

## HA certificate ownership evidence (root-gated lane)

The HA key-ownership handoff is verified by
[`ha-ownership.yml`](../.github/workflows/ha-ownership.yml), which runs
`scripts/test-ha-ownership-root.sh` under `sudo -E` with `PATH`, `CARGO_HOME`,
`RUSTUP_HOME` and `CARGO_TARGET_DIR` preserved. It is a manual/weekly lane, not
a pull-request or `ci-gate` check, because GitHub-hosted runners are non-root
and the test chowns a root-owned 0600 key to uid/gid 65532 and runs a probe as
that identity.

Before publishing a 2.0 release, run it on the release candidate commit:

```bash
gh workflow run ha-ownership.yml --ref <release-commit-or-branch>
gh run list --workflow ha-ownership.yml --limit 1
gh run watch <run-id> --exit-status
```

Record in the release checklist:

- the run URL and commit SHA;
- the non-root `runner uid:` line printed before `sudo`;
- `running 1 test` and `test result: ok. 1 passed` for
  `test_m8_root_owned_key_chown_activates_ha` (a zero-test or non-root run
  fails the job; it is never a skip);
- confirmation from the test output that uid/gid 65532 could not read the
  root-owned key, that the `chown` succeeded, and that the real mTLS listener,
  `/health` and `/api/v2/ha/status` became ready.

A red or missing run blocks the 2.0 release. Locally the same check is
`sudo bash scripts/test-ha-ownership-root.sh`; the workflow itself cannot be
executed without a root-capable runner.

## Fuzz evidence (24-hour release checklist)

The nightly `fuzz.yml` smoke is not release evidence. Before publishing a 2.0
release, run the 24-hour checklist on the release candidate commit:

```bash
gh workflow run fuzz.yml \
  --ref <release-commit-or-branch> \
  -f fuzz_seconds=17280 \
  -f shards=5
gh run list --workflow fuzz.yml --limit 1
gh run watch <run-id> --exit-status
```

The workflow runs on GitHub-hosted `ubuntu-24.04` only. GitHub-hosted jobs stop
after 6 hours, so the 24-hour checklist is five parallel 4.8-hour shards per
target (≈24 target-hours aggregate); each job keeps 72 minutes of headroom for
checkout/build/setup/upload. No self-hosted runner is required.

Record in the release checklist:

- run URL and commit SHA;
- all five matrix targets (`dns_wire`, `abp_parser`, `dnssec_response`,
  `ha_bundle`, `config_toml`) completed with no crash, timeout or OOM;
- `fuzz_seconds=17280` × `shards=5` (≈24 target-hours aggregate) and the
  per-input timeout of 10 s;
- the checked-in seed-corpus size before the run and the corpus size reported
  by the job after the run (a growing corpus is expected; a crash is not);
- confirmation that `fuzz/artifacts/` is empty for every target.

A crash or timeout is a release blocker. Save the input and add it as a
`seed-*` file only after the defect is fixed. `fuzz/README.md` documents the
targets, corpus, dictionaries and exact local commands.

## Benchmark evidence (thresholded gate)

`bench.yml` runs nightly and on demand. The 2.0 release checklist requires one
green comparison on the release candidate commit (or a commit from the same
release branch with no benchmark-relevant changes):

```bash
gh workflow run bench.yml --ref <release-commit-or-branch>
gh run list --workflow bench.yml --limit 1
gh run watch <run-id> --exit-status
```

Record the run URL, the `BENCH_ENVIRONMENT` description
(`github-ubuntu-24.04`), the tolerance (`BENCH_TOLERANCE` or the baseline's
stored value, default `0.10`), and any `improved`/`new` lines. `bench.yml` runs
on GitHub-hosted `ubuntu-24.04` only; the committed baseline must be generated
on that same runner class (`update_baseline=true`, download the artifact, commit
it). The checker fails closed on an environment mismatch. A `REGRESSION` line
above the tolerance fails the job and blocks the release until it is fixed or
explicitly re-baselined on GitHub-hosted `ubuntu-24.04` with a reviewed reason.
The checklist records the baseline environment.

## Docs and migration evidence

A 2.0 release candidate must have a green docs lane. In addition to the internal
link check, the lane runs:

```bash
python3 scripts/check_config_reference.py --github
python3 scripts/test_check_config_reference.py
python3 scripts/check_migration_guide.py --github
python3 scripts/test_check_migration_guide.py
python3 scripts/check_test_matrix.py
python3 scripts/test_check_test_matrix.py
```

The configuration checker must accept every nested config struct, default,
type and legacy raw-section map entry. The migration checker must find a
concrete migration step for every `BC-<n>` ID in
[`docs/2.0-public-api-diff.md`](2.0-public-api-diff.md) in
[`docs/2.0-migration.md`](2.0-migration.md). The test-matrix checker must
resolve every backticked P0/P1 test, script and workflow name in
[`docs/audit6-test-matrix.md`](audit6-test-matrix.md). Record the command
output with the release checklist, alongside the fuzz and benchmark evidence.

## Security review

The final tag requires a security review of the final tree, not only the rc.2
review recorded in
[`docs/phase3-security-review.md`](phase3-security-review.md). Before tagging:

```bash
python3 scripts/check_test_matrix.py
python3 scripts/test_check_test_matrix.py
cargo deny check
```

Re-run the Phase 3 review against the final commit and record:

- the reviewer, date and reviewed commit SHA;
- the verdict for open P0 findings (none allowed) and open P1 findings (each
  with an owner, review date and accepted rationale in the review document);
- confirmation that every P0/P1 row in
  [`docs/audit6-test-matrix.md`](audit6-test-matrix.md) still maps to a named
  test or script and that the matrix checker resolves it;
- the `cargo deny check` result, which must match the green `cargo-deny` gate
  in row 4 of the checklist;
- confirmation that the 2.0 claim matrix
  ([`docs/2.0-claim-matrix.md`](2.0-claim-matrix.md)) matches the final tree,
  including anything still deferred.

An open P0, an unowned P1, or a claim that no longer matches the tree blocks the
release.

## Post-release monitoring (first 24–72 hours)

A release candidate is not finished when the workflow turns green. Watch these
signals after publishing `v2.0.0-rc.3`, `v2.0.0-rc.4` and the final `v2.0.0`,
and keep the previous stable binary/config backup ready for rollback:

| Area | Signal | Where | Rollback trigger |
| --- | --- | --- | --- |
| DNS availability | Query error/SERVFAIL rate, listener readiness, `/health` 503s | Prometheus, `/api/v2/status`, `sito healthcheck` | Sustained SERVFAIL/503 growth not explained by an upstream outage |
| DNSSEC | `sito_dnssec_bogus_total`, secure/insecure counts, validation fetch failures | Prometheus, query log | Bogus rate jumps on names that validated before 2.0 |
| ACME/TLS | Certificate expiry, renewal failures, readiness reasons, all-transport reload | `/api/v2/status`, ACME logs | Certificate near expiry or a transport serving a stale pair |
| HA | `protocol_mismatch`, divergence, lag, `queued` vs `connected_no_delivery`, slave `Synced` | `/api/v2/ha/status`, `/api/v2/ha/slaves`, metrics | A slave cannot reach `Synced` or divergence persists after a resync |
| Filtering | Zero-yield lists, reload errors, `degraded_groups`, rule count | `/api/v2/integrations/lists`, status page, logs | A list reload empties blocking or a group loses its previous snapshot |
| Runtime | 429/503 rate, cache hit ratio, upstream RTT/errors, query-log drops | Prometheus, dashboard | A sustained latency/error regression or dropped query-log batches |
| Supply chain | Image digest/signature, archive checksums, SBOM | `docs/release-verification.md` above | A published artifact does not verify |

The Grafana dashboard (`contrib/grafana/sito-dashboard.json`) and
[`docs/runbook-ha.md`](runbook-ha.md) contain the panel and recovery
procedures. Record the monitoring window, the on-call observer, any anomaly,
and the decision (continue, patch, or roll back) in the release checklist.

## If verification fails

- **`verify-tag` failed**: nothing was published. Delete the incorrect tag and
  push a tag that matches `Cargo.toml`, or bump the workspace version. Never
  reuse a tag that already produced release assets.
- **A download, checksum, or artifact E2E verification failed**: nothing
  reaches `docker-build-push`, so no image is published and the staged release
  stays a draft. Fix the cause and use a new tag (for example a new patch or
  prerelease suffix).
- **A signature or SBOM generation failed**: the failure is in
  `sbom-and-release`, before the draft is created, so nothing is published at
  all. Fix the cause and use a new tag.
- **Post-push verification failed**: the image may already be in GHCR, but the
  workflow is red and the release stays a draft. Treat the image as unpublished:
  remove the affected tag(s)/digest from GHCR, fix the problem, and publish
  again with a new tag. Do not leave `latest` pointing at an unverified digest.
