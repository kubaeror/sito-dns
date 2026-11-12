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

Never regenerate the baseline to silence a real regression. Benchmark
inventory and the PR/nightly split are documented in
[`../docs/ci.md`](../docs/ci.md#benchmark-baseline).
