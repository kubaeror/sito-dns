# Audit 6 — reviewed best-effort error handling (D14)

`scripts/check-error-swallowing.sh` flags `let _ =`/`.ok()` around calls that
mutate durable state: `sync_all`, `rename`, `remove_file`, `set_permissions`,
secret writes, ACME pair metadata, config persistence/publication, filter
flushes and transport reloads. Every remaining flagged site is listed in
`scripts/error-swallowing-allowlist.txt` with the exact source text, and each
category below explains why discarding the error is safe.

Run it with:

```bash
bash scripts/check-error-swallowing.sh
```

The check is intentionally narrower than a blanket ban on `let _ =`/`.ok()`.
The repository has hundreds of probe/cleanup sites (cache lookups, optional
header parsing, test fixture teardown) where an error is expected control flow;
making those fatal would be wrong and would bury the signal. The script covers
the paths where a swallowed error could lose data, publish an unpersisted
configuration, or leave a partially written secret/certificate.

## Reviewed categories

### Cleanup after a failed atomic write (`remove_file`)

`config_writer`, `auth/manager`, `downloader`, `chain_cache`, `updater`,
`subscription` and `service_lock` remove a temporary or rollback file after the
real replacement either succeeded or did not happen. A failure here leaves a
stray temp file; it cannot corrupt the live config/cache because the rename
that publishes the new file is the commit point and is handled explicitly.

### Directory/file fsync after rename (`sync_all`)

`cli::fsync_parent_dir`, `config_writer` and `acme` fsync the parent directory
after a successful rename. The data is already visible; the fsync only narrows
the crash window. A failure is logged where the caller surfaces errors, and
retrying the rename would not help.

### ACME rollback of a partial issuance (`remove_file(cert_path)`)

If writing the pair metadata or reloading the TLS transports fails, the
newly-written certificate is removed so `certificate_needs_renewal` retries
instead of serving a pair whose key/metadata may not match. The original error
is returned to the caller; the cleanup error is secondary.

### Background maintenance (`cache.flush`)

The periodic DNSSEC chain-cache flush is a durability optimisation. A failed
flush leaves the in-memory cache intact and the next interval retries. Query
correctness does not depend on the flush succeeding.

### HTTP body/stream flush

The DoH upstream flushes a diagnostic/body stream after the response has been
delivered. The transport error path reports delivery failures separately;
failing a query because a best-effort flush failed would discard a valid answer.

### Test-only cleanup

`sito-ha`'s unit-test module removes a temporary directory. It is compiled only
under `#[cfg(test)]` and cannot affect production.

## Not allowed

New `let _ =`/`.ok()` around `write_secret_file`, `reload_all`, pair metadata,
config persistence/publication, `set_permissions`, `rename`, or a successful
`flush` in production code fails the script until either the error is handled
or an explicit allowlist entry plus rationale is added here.
