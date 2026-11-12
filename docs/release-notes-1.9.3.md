# sito 1.9.3 — release notes

Target release: **1.9.3** on 2026-11-06. This is a release-engineering patch.
There are **no runtime, configuration, API, or data changes**; 1.9.3 is
functionally identical to 1.9.2. The 1.9.2 artifacts and image remain valid.

## What changed

### Release attestation gate

The post-push image check now consumes the complete
`docker buildx imagetools inspect` payload before looking for `SLSA`/`SPDX`.
The previous inline check used `printf ... | grep -q`; when `grep` matched
early, `printf` could die with SIGPIPE, and `set -o pipefail` turned the
successful match into a false negative after the image had already been
published. A regression test drives a large multi-platform payload through the
helper.

### Unified checksum manifest

`SHA256SUMS` now records the SPDX SBOM as `sito.spdx.json` instead of
`release-assets/sito.spdx.json`. Download every asset into one directory and
verify with:

```bash
sha256sum -c SHA256SUMS
```

Per-archive `.sha256` files and the cosign `.sig`/`.pem` assets are unchanged.

## Upgrade notes

- No action is required. Configuration, databases, sessions, HA state, and API
  contracts are unchanged from 1.9.2.
- Operators already on 1.9.2 do not need to upgrade for product behavior.
  Upgrade if you want a fully green tag-triggered release pipeline and a
  directly verifiable unified checksum manifest.
- The 1.9.2 release artifacts and image remain valid.

## Validation

The release gates are the repository's standard commands:

```bash
cargo fmt --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked --no-fail-fast
cargo deny check
python3 scripts/check_config_reference.py --github
SITO_UPDATE_OPENAPI=1 cargo test -p sito-api test_export_openapi_json
shellcheck -S warning contrib/install.sh
python3 contrib/tests/test_adguard_to_sito.py
```

> The `cargo check --manifest-path fuzz/Cargo.toml --locked` step in the
> original 1.9.3 validation list applied only while the fuzz harness existed.
> It was removed after v1.9.3 and the 1.9.x trees have no `fuzz/` directory.
> The 2.0 branch restored it as a nightly/release mechanism; see
> [docs/ci.md](ci.md#fuzzing-is-nightlyrelease-not-a-pr-gate).

The release workflow additionally verifies the tag/version, artifact checksums,
cosign signatures, multi-arch image platforms, and SLSA/SPDX attestations.
