# Fuzz targets

This directory is an independent `cargo-fuzz` workspace. It is not a member of
the root Cargo workspace, so `cargo test`, `cargo clippy` and release builds
never compile libFuzzer. The targets were restored in WP-1.9 (audit 6 issue
P2-64) after the earlier harness was removed without a replacement.

## Targets

| Target | Production entry point | Invariant | Input bound |
|---|---|---|---|
| `dns_wire` | `sito_proto::decode_message` / `encode_message` | decode → encode → decode never panics; a decoded message re-encodes | 65,535 bytes |
| `abp_parser` | `sito_filter::parser::parse_line` / `compute_canonical` | arbitrary UTF-8 lines never panic; canonicalization is total | 8 KiB document / 4 KiB line |
| `dnssec_response` | `sito_dnssec::DnssecValidator::validate_response` (strict and log-only) | arbitrary responses never panic; no network access | 65,535 bytes |
| `ha_bundle` | `sito_ha::ConfigBundle::from_json`, `sanitized`, `sanitize_config_for_bundle` | arbitrary bundle JSON/TOML never panics; sanitization stays total | 1 MiB |
| `config_toml` | `sito_core::config::Config::from_toml_str` | arbitrary TOML never panics; unknown-key/version errors are expected | 1 MiB |

All targets return early above their input bound rather than allocating
unbounded memory. `dns_wire` asserts only that encoding succeeds and the result
re-decodes; hickory normalizes some header/name fields, so byte equality is not
a valid invariant.

## Corpus and dictionaries

Checked-in seeds live under `corpus/<target>/seed-*` and are derived from the
existing test fixtures (simple DNS query, positive and NXDOMAIN/NSEC response,
representative ABP lines, minimal config v2, and a bundle with structured
client secrets). `cargo-fuzz` writes new coverage inputs beside them; those
files are ignored by `.gitignore`, while `seed-*` stays tracked.

Optional dictionaries are in `dictionaries/`:

- `dns_wire.dict` — header/type/name tokens (also used by `dnssec_response`);
- `abp_parser.dict` — ABP operators and modifiers;
- `config_toml.dict` — section names and value literals;
- `ha_bundle.dict` — bundle JSON keys.

## Commands

```bash
# Build every target (what the PR `fuzz-build` job runs)
cargo fuzz build
# CI pins the gnu target and the toolchain so ASan does not select a musl host:
# RUSTUP_TOOLCHAIN=nightly-2026-11-04 cargo +nightly-2026-11-04 fuzz build \
#   --target x86_64-unknown-linux-gnu

# Build one target
cargo fuzz build dns_wire

# Run one target against the checked-in seeds for five minutes
cargo fuzz run dns_wire -- -max_total_time=300

# Nightly smoke shape: every target, its dictionary, and a timeout
cargo fuzz run dns_wire -- -dict=fuzz/dictionaries/dns_wire.dict -max_total_time=600 -timeout=10
cargo fuzz run abp_parser -- -dict=fuzz/dictionaries/abp_parser.dict -max_total_time=600 -timeout=10
cargo fuzz run dnssec_response -- -dict=fuzz/dictionaries/dns_wire.dict -max_total_time=600 -timeout=10
cargo fuzz run ha_bundle -- -dict=fuzz/dictionaries/ha_bundle.dict -max_total_time=600 -timeout=10
cargo fuzz run config_toml -- -dict=fuzz/dictionaries/config_toml.dict -max_total_time=600 -timeout=10

# Re-run a saved crash
cargo fuzz run dns_wire artifacts/dns_wire/crash-<hash>

# Regenerate the local structure check after changing the manifest or corpus
python3 scripts/check-fuzz-targets.py
python3 scripts/test_check_fuzz_targets.py
```

`cargo fuzz` requires a nightly toolchain and a recent `cargo-fuzz`. The
workflows pin both; locally use the installed nightly (for example
`cargo +nightly fuzz build`).

## CI split

- **Pull request (`ci.yml` → `fuzz-build`):** `cargo fuzz build` for all five
  targets. This is the fast structural gate that proves the manifest and target
  sources compile. `python3 scripts/check-fuzz-targets.py` additionally checks
  the manifest, target sources, seed corpus and `.gitignore` in the `test`
  lane.
- **Nightly (`.github/workflows/fuzz.yml`, 04:17 UTC):** every target runs for
  the workflow's `fuzz_seconds` (default 600 s) with a per-input timeout of
  10 s and its dictionary. Crashes/timeouts upload the corpus and artifacts.
- **Release checklist (manual `fuzz.yml` dispatch):** set `fuzz_seconds=86400`
  and `runner_label=<self-hosted-label>` for a 24-hour clean run per target.
  GitHub-hosted jobs have a hard 6-hour execution ceiling, so the workflow
  rejects a longer duration unless the label is a dedicated/self-hosted runner
  (GitHub-hosted `ubuntu-*`, `windows-*`, `macos-*` labels are rejected). This
  is the D14/P-7 release gate: it is deliberately not a PR gate because it is
  long and hardware-timing sensitive.

## 24-hour release checklist

1. Dispatch **Fuzz → Run workflow** on the release candidate commit with
   `fuzz_seconds=86400` and
   `runner_label=<self-hosted-linux-fuzz-label>`. Leave the target matrix as
   all five targets.
2. Confirm every matrix job completed with no crash, timeout or OOM artifact.
3. Download the `fuzz-crash-<target>-<run_id>` artifacts (if any) and confirm
   the `artifacts/` directory is empty for each target.
4. Record the run URL, the commit SHA, the five target names,
   `fuzz_seconds=86400`, the runner label, and the corpus size before/after in
   the release checklist log (`docs/release-verification.md` → “Fuzz
   evidence”).
5. A crash is a release blocker. Add the saved input to
   `fuzz/corpus/<target>/seed-*` only after the defect is fixed, so the
   regression is permanent and the seed remains small.
