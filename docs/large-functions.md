# Production functions over 200 lines

`scripts/check-function-size.sh` enforces the WP-1.5 module budget: a production
Rust function may exceed 200 lines only when it is listed here with a reason.
The metric is the physical line span from the `fn` signature to its closing
brace, excluding `#[cfg(test)]` items and the `sito-test`/`sito-test-support`
crates (the same rule the file-size checker uses).

The exceptions below are deliberate. Each is a single transactional sequence,
protocol state machine, or protocol renderer whose intermediate state is
meaningful only as a whole; extracting fragments would either pass state
through wide tuples or duplicate invariants that the WP-1.5 refactor must not
change. New code should stay under 200 lines. Adding a row here is a reviewed
change: state why the function cannot be split without changing behavior.

| Function | File | Lines | Reason |
|---|---|---|---|
| `main` | `crates/sito/src/main.rs` | 335 | CLI dispatch and startup orchestration; each arm owns process-level setup/teardown. Splitting would duplicate the async runtime and error-exit handling. |
| `run_server_with_lease` | `crates/sito/src/server/startup.rs` | 529 | Ordered startup transaction from the caller-held service lease to listener bind and watcher registration. A stage cannot be skipped or retried independently, and a failed stage must still run the corresponding cleanup. `run_server_full` is a thin convenience wrapper that acquires the lease first. |
| `init_tls_and_acme` | `crates/sito/src/server/tls.rs` | 244 | TLS/ACME bootstrap ordering: choose material, build acceptors, bind challenge listeners, then start renewal. The fail-closed decisions depend on the preceding stage's result. |
| `with_config_and_storage_full` | `crates/sito-api/src/auth/manager/construction.rs` | 239 | Auth manager construction loads and validates every persisted store (users, sessions, tokens) under one consistency contract; partial construction is not a valid state. |
| `insert_with_status_at_epoch` | `crates/sito-cache/src/cache.rs` | 212 | Cache insertion and policy-epoch check must remain atomic; splitting would expose an intermediate entry without its generation guard. |
| `ds_response_status` | `crates/sito-dnssec/src/chain.rs` | 272 | DS response classification walks answers/authorities with authenticated denial and signature checks; the classification is one decision, not independent stages. |
| `validate_with_key_fetcher` | `crates/sito-dnssec/src/verify.rs` | 209 | Validation + bounded fetch loop with a shared budget and deadline; the loop owns the decision state across iterations. |
| `build_validated_key_set` | `crates/sito-dnssec/src/verify.rs` | 240 | Builds one authenticated DNSKEY set from a chain; partial sets are invalid, so the construction is intentionally a single function. |
| `fetch_or_cached` | `crates/sito-filter/src/subscription.rs` | 371 | HTTP/cache fetch with conditional requests, size caps, and atomic cache writes; the error and cache-update paths share one bounded reader. |
| `apply_config_push` | `crates/sito-ha/src/slave/worker.rs` | 260 | Slave apply transaction: verify, persist, apply, ACK or mark degraded. Partial application must not ACK, so the sequence is one function. |
| `obtain_or_renew_certificate_for_transports` | `crates/sito-transport/src/acme.rs` | 212 | ACME order/renewal sequence with challenge selection and post-issuance reload; the reload must observe the certificate produced by the order. |
| `start_doh3_listener_with_limits` | `crates/sito-transport/src/doh3.rs` | 529 | DoH3 listener setup and per-connection loop share admission limits; the connection lifecycle spans handshake, request admission, body cap and stream handling. |
| `start_doq_listener` | `crates/sito-transport/src/doq.rs` | 314 | DoQ listener setup and stream admission are one bounded-resource contract; limits are applied before any read. |
| `handle_dot_connection` | `crates/sito-transport/src/dot.rs` | 214 | DoT connection lifecycle: handshake, length-prefixed reads, timeout and shutdown all bound one connection budget. |
