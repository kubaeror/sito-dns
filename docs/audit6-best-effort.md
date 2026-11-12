# Audit 6 — reviewed best-effort error handling (D14)

`scripts/check-error-swallowing.sh` flags `let _ =`/`.ok()` around calls that
mutate durable state or report health: `sync_all`, `rename`, `remove_file`,
`set_permissions`, secret writes, ACME pair metadata, config persistence/
publication, filter flushes/reloads, listener/TLS readiness, shutdown, lease/
bootstrap paths, and `lock`/`unlock`, plus `read`/`load` paths. Every remaining
flagged production site is listed in `scripts/error-swallowing-allowlist.txt`
with the exact source text, and each category below explains why discarding the
error is safe.

Run it with:

```bash
bash scripts/check-error-swallowing.sh
```

The scanner (`scripts/find-error-swallowing.py`) is deliberately narrower than
a blanket ban on `let _ =`/`.ok()`. It joins a statement until its parentheses/
brackets balance and the terminating `;` (or block) is reached, so a multi-line
swallow is still caught. It skips inline `#[cfg(test)]` items and `tests/`
targets because those intentionally exercise failure cleanup, and it only flags
call names that match the reviewed keyword list. Formatting macros
(`writeln!`/`write!`/`format!`) are excluded: their arguments often contain
benign atomic `load()`/`store()` calls. `scripts/test-error-swallowing.py` pins
the multi-line, `cfg(test)`-range and formatting-macro fixtures and runs as part
of the checker. The repository still has hundreds of probe/cleanup sites (cache
lookups, optional header parsing, test fixture teardown) where an error is
expected control flow; making those fatal would be wrong and would bury the
signal. The script covers the paths where a swallowed error could lose data,
publish an unpersisted configuration, leave a partially written
secret/certificate, or hide a dead listener.

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

### Response write/shutdown after delivery (`shutdown`)

The DoT listener shuts down its write half after the response and the close
path either delivered the answer or already returned the transport error to the
connection task. Failing the connection again because the FIN failed cannot
change the client-visible result.

### Service lease release (`unlock`)

`ServiceLease::drop` removes the lock file and releases the advisory lock. The
process is exiting the lease; a failed `unlock` cannot be retried meaningfully
and the path is removed in the same `Drop` implementation. The next startup
treats a stale file as harmless because the lock, not the file, is
authoritative.

### Optional diagnostic/read paths (`read`, `load`)

These reads are not the commit point of a security or configuration operation,
and their failure has an explicit fail-safe fallback:

- The `healthcheck` CLI reads `config.toml` only to discover probe targets; an
  unreadable file falls back to conventional loopback targets. Server startup
  reads the config explicitly and fails closed.
- The service-status PID read only enriches `Running { pid }`; the advisory lock
  is authoritative and the PID is diagnostic.
- DNSSEC chain-cache restore (`load_with_stats`) logs a path-only warning and
  keeps the default policy; a failed restore is retried by the next flush.
- Filter list metadata is optional: an unreadable/corrupt metadata file only
  disables conditional refresh and the list is re-fetched.
- ACME pair-metadata digests treat a read error as a metadata mismatch, which
  forces renewal rather than trusting an unverifiable pair.

## Poison recovery is not a swallow

`std::sync::Mutex` poisoning (P3-4) is handled by
`sito_core::sync::lock_or_recover`, not by the allowlist. Production
readiness, HA coordinator/slave state, filter reload/list rules and API config
state use the helper, which logs the recovery once per process and returns the
last-good value instead of panicking. Security/apply/persistence paths must not
use `.lock().unwrap()`.

The only remaining production `.lock().unwrap()` sites are in
`sito-test-support`'s port-reservation registry. That crate is a test-only
harness (it is excluded from the production size metric and never linked into
the server binary), so a poison panic there fails a test and cannot abort a
release.

## Not allowed

New `let _ =`/`.ok()` around `write_secret_file`, `reload_all`, pair metadata,
config persistence/publication, `readiness`, `health`, `publish`, `persist`,
`save`, `write`, `read`, `load`, `reload`, `shutdown`, `lease`, `bootstrap`,
`set_permissions`, `rename`, or a successful `flush` in production code fails
the script until either the error is handled or an explicit allowlist entry plus
rationale is added here. `lock`/`unlock` swallows in production must use
`sito_core::sync::lock_or_recover`/`read_or_recover`/`write_or_recover` instead,
so the allowlist is only for best-effort release paths.
