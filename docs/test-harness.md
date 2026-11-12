# Test harness, deterministic timing, and shared fixtures

This page documents the test-support layer introduced by WP-1.8. It covers the
process-wide port broker, the deterministic clock, event-driven waits, the
shared TLS/ACME/HA/DNSSEC fixtures, the property-test lanes, and the small list
of sleeps that intentionally remain wall-clock based.

The code lives in two test-only crates:

| Crate | Contents |
|---|---|
| `sito-test-support` | Port broker (`ReservedPort`, `ReservedUdpPort`, `PortReservations`, `reserve_*`, `claim_ports`), `Clock`/`SystemClock`/`ManualClock`, `wait_until`/`wait_for`. Light dependency graph so every integration test can use it. |
| `sito-test` | In-process server harness (`TestServerInstance`), mock upstream (`MockDnsServer`), and `fixtures::{tls, acme, ha, dnssec}`. |

Neither crate is linked into the production `sito` binary.

## Port broker and parallel isolation

All test listeners that need an ephemeral port must reserve it through
`sito-test-support`:

```rust
let mut reservations = PortReservations::new();
let (tcp_probe, tcp_port) = reservations.reserve_tcp()?;
let (udp_probe, udp_port) = reservations.reserve_udp()?;
// DNS binds both protocols on one number:
let (dns_tcp_probe, dns_udp_probe, dns_port) = reservations.reserve_tcp_udp()?;
```

Rules:

- Never hard-code a port. `0` means "ask the OS", `reserve_*` makes that choice
  collision-free inside the test process.
- Hold the lease for the whole test. Drop the probe socket/listener immediately
  before the component under test binds, but keep the lease alive.
- A DNS listener binds **UDP and TCP on the same number**, so use
  `reserve_tcp_udp` (or `PortReservations::reserve_tcp_udp`) instead of a TCP-only
  reservation. Reserving one protocol leaves the other open to a parallel test.
- Fixtures that must bind their own sockets use
  `fixtures::net::{bind_claimed_tcp, bind_claimed_udp}` (or `claim_ports` for the
  mock upstream). These bind an ephemeral socket, claim the number, and retry if
  another test already reserved it. `FakeMaster`, `MockAcme`,
  `MockHttp01Server`, `served_certificate`, and the raw black-hole upstream in
  `m11_dnssec_security` all use the helpers; the returned `PortClaim` releases
  the number on drop.
- `TestServerInstance` keeps its reservations until `shutdown`/drop and the mock
  upstream releases its claimed port on drop.
- `sito`'s own startup/graceful-shutdown/rebind unit tests use
  `reserve_tcp_udp_port`/`reserve_udp_port`/`reserve_port` leases as well; their
  old local probe-and-drop loops are gone.

Regression tests: `crates/sito-test-support/tests/port_broker_contract.rs`
(concurrent leases, released probe sockets, dropped leases, TCP+UDP pairs) and
`crates/sito-test/tests/harness_parallel.rs` (four servers spawned in parallel,
distinct ports, all queryable).

## Deterministic clock

`sito_test_support::clock` provides:

```rust
pub trait Clock: Debug + Send + Sync {
    fn now(&self) -> Instant;
    fn sleep(&self, duration: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>>;
}

pub struct SystemClock;                 // real tokio timer
pub struct ManualClock { /* ... */ }    // advance(), notify(), waiters(), elapsed()
```

`ManualClock` never moves on its own. A `sleep` future registers a waiter and
completes only when the test calls `advance`. `notify()` wakes waiters without
moving time (useful to interrupt a `select!` loop); `waiters()` exposes the
parked-sleeper count for sequencing assertions.

Use it when the *ordering* of two events matters, not the real duration:
mock upstream latency (`MockDnsServer::set_response_delay`) and HA heartbeat
scheduling (`FakeMaster::schedule_heartbeat`). Do **not** use `ManualClock` to
test a production timeout that is implemented with a real tokio timer — that
would test a clock the production code does not read.

## Event-driven waits

Prefer `wait_for` over `sleep`-then-assert:

```rust
wait_for("the HA slave to sync", Duration::from_secs(5), || async {
    tracker.get_state() == SlaveState::Synced
})
.await
.expect("HA slave did not sync");
```

- `wait_for(label, timeout, condition)` polls every 25 ms and returns a
  `WaitTimeout` whose `Display` names both the condition and the budget.
- `wait_until(timeout, condition) -> bool` remains for compatibility.
- The condition runs once immediately, so an already-true predicate does not
  pay a poll interval.

Never "fix" a flaky test by increasing a sleep. Either wait for the observable
event, use a manual clock, or document the residual flake in the work-package
report.

## Shared fixtures

| Fixture | API | Used by |
|---|---|---|
| TLS | `fixtures::tls::{test_certificate, expired_certificate, soon_to_expire_certificate, CertificateFiles, tls_acceptor_manager, served_certificate}` | `m11_acme`, TLS/DoT/DoH acceptance tests, certificate-reload tests |
| ACME | `fixtures::acme::{MockAcme, MockHttp01Server, DEFAULT_DOMAIN}` | `m11_acme` (directory/account/order/challenge/finalize/certificate flow, TLS-ALPN-01 and HTTP-01 selection) |
| HA | `fixtures::ha::FakeMaster` (`send`, `heartbeat`, `stop_frames`, `resume_frames`, `partition`, `schedule_heartbeat`) | `m11_ha_partition` master-loss, drift, fork and publish tests |
| DNSSEC | `fixtures::dnssec::SignedZone` (`trust_anchor`, `signed_a`, `dnskey_rrset`, `ds_for`, `nsec`, `nsec_covering(qname)`) | `m11_dnssec_security`, DNSSEC acceptance tests |
| Net | `fixtures::net::{PortClaim, bind_claimed_tcp, bind_claimed_udp}` | every fixture that binds its own listener |

`MockAcme` deliberately does not validate JWS signatures or solve challenges;
it exercises client scheduling, persistence and transport reloads, not ACME
protocol conformance. `MockHttp01Server` is a plain HTTP responder for
`/.well-known/acme-challenge/{token}`. `FakeMaster` does not implement the
master state machine either: tests drive exact frames at exact moments.

## Property tests

`proptest` is a dev-dependency of `sito-core` and `sito-filter` (workspace
version `1.12`). Iterations are bounded so the normal `cargo test` lane stays
fast:

| File | Cases | Properties |
|---|---|---|
| `crates/sito-core/tests/domain_properties.rs` | 96 | normalization idempotence/no panic, lowercase/trailing-dot equivalence, IDN punycode round-trip, wildcard preservation, invalid-char rejection, suffix reflexive/transitive/strict invariants, overlong-label rejection |
| `crates/sito-filter/tests/parser_properties.rs` | 96 / 64 | arbitrary lines never panic and parse deterministically, canonical form equals `compute_canonical`, modifier order invariance, `$badfilter` recognized and excluded from the canonical form, per-line cap skips hostile lines, byte budget rejects without partial rules |

Proptest writes `*.proptest-regressions` seeds on failure; commit them when a
failure represents a real bug so the case is replayed.

## Semantic sleeps that remain

These are intentional and must not be replaced by busy polling. The table
covers the test-support crates (`sito-test`, `sito-test-support`) and the named
integration/unit suites; production timers are not listed.

| Site | Why |
|---|---|
| `harness.rs` spawn retry backoff (`100ms × attempt`) | A real retry backoff; the loop is already bounded at 5 attempts. |
| `harness.rs` readiness poll interval (20 ms) and post-bind grace (50 ms) | TCP/DoT/DoH readiness is probed with real connects; the short grace lets the UDP listener task enter its event loop after the TCP probe succeeds. The poll loops are bounded. |
| `m11_ha_partition` master-loss test (real 3 × `ping_interval_secs` deadline) | The test asserts the production heartbeat deadline; replacing the wait with a manual clock would not exercise the real tokio timer. The test waits for the state transition (`wait_for`), not a fixed sleep. |
| `sito-ha` / `sito-transport` / `sito-upstream` unit tests that assert an elapsed-time budget or wait for a listener/event | The elapsed duration or arrival of the event is the behavior under test (timeout, retry budget, admission, startup). These are condition loops with a deadline, not fixed assertion delays. |
| `sito/src/lib.rs` graceful-shutdown retry (`150 ms`) and rebind settle (`600 ms`) | The binary restart/rebind path has no ready callback; the test polls the observable DNS answer afterwards. The delay gives the watcher a bounded window, not a fixed correctness assumption. |
| `m8_acceptance` kill-mid-push 50 ms | A bounded delay to get a WebSocket write in flight; the assertion accepts either version so it cannot be flaky. |
| `m6_acceptance` filter-refresh poll interval (50 ms) | A deadline-bounded condition poll; the loop exits on the observable state. |
| `sito-stats` writer flush waits | The writer has no completion signal; the test polls the observable database state with a bound. |

All other test sleeps in `sito-test` were replaced with `wait_for`/event polls
as part of WP-1.8. Production sleeps (timers, retry backoff, retention delays)
are not test artifacts and are unchanged.

## Stability evidence

The WP-1.8 report records the exact 20-run command for the harness/m11/HA
suite and two full-workspace runs. To repeat locally:

```bash
cargo test -p sito-test --test harness_parallel --test fixtures_contract \
  --test m11_acme --test m11_ha_partition --test m11_dnssec_security \
  --test m11_bind_defaults --test m11_no_setup -- --test-threads=8
cargo test -p sito-test-support --tests -- --test-threads=8
cargo test -p sito-cache -- --test-threads=8
cargo test -p sito-ha -- --test-threads=8
cargo test -p sito --lib -- --test-threads=8
cargo test -p sito-transport -- --test-threads=8
```

The harness suite has no fixed ports; `--test-threads` higher than 1 is
required to exercise the broker.
