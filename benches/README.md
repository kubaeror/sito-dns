# Benchmark baselines

`baseline.json` stores Criterion median estimates (nanoseconds) for every
workspace benchmark. The nightly `bench.yml` workflow compares the latest
`target/criterion/**/new/estimates.json` against it and fails when a benchmark
is more than 10% slower.

The file is **environment specific**: it records the machine class in
`environment.description`, and the checker fails closed when the current
environment (from `--environment`, `BENCH_ENVIRONMENT`, or the automatic host
description) does not match. The benchmark gate runs on GitHub-hosted
`ubuntu-24.04` only. Regenerate the baseline there by dispatching `bench.yml`
with `update_baseline=true`, downloading the `bench-<run_id>` artifact, and
committing its `benches/baseline.json` (recorded as
`environment.description = "github-ubuntu-24.04"`). For a documented
non-gating comparison across machines, pass `--reference-only`; never use it in
the nightly gate.

For a short local check without waiting for the full measurement:

```bash
cargo bench -p sito-test --bench pipeline_bench -- --quick
# ... repeat for each bench target, then:
BENCH_ENVIRONMENT=<your-baseline-environment> python3 scripts/check-bench-regression.py
```

The exact nightly/manual commands are recorded in
[`../docs/ci.md`](../docs/ci.md#benchmark-baseline):

```bash
# Nightly/manual comparison against the committed baseline
gh workflow run bench.yml
# Regenerate the baseline on GitHub-hosted ubuntu-24.04 (uploads bench-<run_id>)
gh workflow run bench.yml -f update_baseline=true
gh run download <run_id> -n bench-<run_id>   # commit benches/baseline.json
```

`crates/sito-filter/benches/lookup.rs` also measures
`filter_compile::wildcard_set_3_batches`, the three-batch pathological wildcard
compile that the unit test gates by thread CPU time (see
[`../docs/ci.md`](../docs/ci.md#load-robust-compile-timing)). It is a new
benchmark: until the next GitHub-hosted re-baseline it appears as
`new ... not in the baseline (informational)` and is not thresholded. The
committed baseline (generated 2026-11-12) was not regenerated for this change.

Never regenerate the baseline to silence a real regression, and never use a
local benchmark to claim a production SLA. Benchmark inventory and the
PR/nightly split are documented in
[`../docs/ci.md`](../docs/ci.md#benchmark-baseline).
