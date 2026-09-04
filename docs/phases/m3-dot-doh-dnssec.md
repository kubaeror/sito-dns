# Phase M3 — DoT, DoH and DNSSEC Validation (3 weeks)

Goal: encrypted inbound transports and local DNSSEC validation. References: plan sections 5.3, 5.4, 8.

## Scope

**In:** shared TLS stack (rustls), DoT on 853, DoH H2 on 443 (axum), certificate reload without restart, ClientID in the DoH path (identification wired in M4), DNSSEC validation with NTA and metrics.
**Out:** DoQ/DoH3 (M7), ACME (M7), panel/API on 443 — for now 443 serves DoH only.

## Tasks

### 1. TLS infrastructure (`sito-transport::tls`)

- Build `rustls::ServerConfig` from PEM; SNI → certificate mapping (preparation for vhosts)
- `notify` watcher on cert/key files → atomic acceptor reload; parse error = keep old + alert
- TLS 1.3 + 1.2; session resumption on; `sito check-config` validates cert/key pairs

### 2. DoT

- Listener 853, ALPN `dot`; reuse: max 1000 queries or 5 min/connection; 30 s idle
- Optional response padding (RFC 8467), toggle `dns.dot_padding`
- Extract SNI into `ClientContext` (for ClientID `*.dns.domain` in M4)

### 3. DoH (H2)

- `/dns-query` endpoint in axum: POST (`application/dns-message`) and GET (`?dns=` base64url); correct `cache-control: no-store` headers
- Path `/dns-query/{client_id}` → stored in `ClientContext.id` (routing ready for M4)
- Decision to document in the PR: hickory `dns-over-https` vs custom handler (custom = full control over ClientID routing and future 443 sharing with the UI; recommendation: custom, ~150 lines on axum + hickory-proto for the wire format)

### 4. DNSSEC

- Validation after the upstream answer, always when `dnssec.validate` (section 8.1); root anchor from hickory
- Results: Secure → AD=1; Bogus → SERVFAIL + metric + entry for the future query log (tracing for now); Insecure/Indeterminate per 8.1
- NTA: `dnssec.ntp = [...]`; validation keys cached
- Metrics: `sito_dnssec_bogus_total{upstream}`, `sito_dnssec_validations_total{result}`

## Agent prompts

```
M3.1 tls-infra  → task 1; DoD: swapping the cert file live changes the presented
                  certificate without restart (test: openssl s_client before/after)
M3.2 dot        → task 2; DoD: kdig +tls passes; 1500 queries on one connection →
                  reconnect after 1000; padding measurable in tcpdump
M3.3 doh        → task 3; DoD: curl --doh-url and kdog work; GET and POST equivalent;
                  /dns-phone/dns-query identifies client_id (assert in tracing span)
M3.4 dnssec     → task 4; DoD: sigfail.verteiltesysteme.net → SERVFAIL,
                  sigok… → NOERROR+AD, dnssec-failed.org → SERVFAIL; NTA disables
                  validation for the listed zone; metrics visible in tracing
M3.5 hardening  → tests: wrong ALPN rejected, TLS <1.2 rejected, expired cert =
                  startup refused with a clear error; fuzz-lite of the DoH path parser
```

## Tests and acceptance criteria

- [ ] `kdig @host +tls-ca +tls-host=… example.com` → NOERROR
- [ ] `curl --doh-url https://host/dns-query` → valid answer; `no-store` header
- [ ] Three DNSSEC test domains (sigfail/sigok/dnssec-failed) as above
- [ ] Cert reload without restart and without dropping persistent DoT connections
- [ ] Blocking and cache behave identically on all 4 transports (matrix from M1.7 extended)
- [ ] DNSSEC metrics count bogus per upstream

## Risks

| Risk | Mitigation |
|---|---|
| hickory feature flags (rustls/h3) not compiling in combination | Settle in M3.1 before DoH; pin versions; fallback: hand-rolled DoH (recommended) |
| DNSSEC validation adds 5–20 ms on cold zones | Key cache; p95 before/after measured in the phase benchmark; document the cost |
| Test certificates in CI | rcgen generates CA+certs in tests; zero binary files in the repo |

## Deliverables

DoT/DoH transports in `:m3`, "Encrypted transports" README section with kdig/curl examples, DNSSEC cost report.
