# Phase M7 — DoQ, DoH3, Anti-Bypass and ACME (3 weeks)

Goal: close out every transport from the survey (item 5: "everything native like AdGuard") plus automatic certificates. References: plan sections 5.5, 5.6, 9.6.

## Scope

**In:** DoQ (853/udp), DoH3 (443/udp) + Alt-Svc, anti-DoH bypass as a toggle, ACME (Let's Encrypt). Stretch: DNSCrypt (ADR-006).
**Out:** UI changes beyond toggles (full UI was M6; these features get simple controls in Settings).

## Tasks

### 1. DoQ

- QUIC listener 853 via the hickory `dns-over-quic` feature (quinn); ALPN `doq`
- **0-RTT disabled** (replay — section 5.5); address validation on; stream per query
- Pipeline shared with other transports; metric `proto="doq"`

### 2. DoH3

- hickory `dns-over-h3` on 443/udp; header `Alt-Svc: h3=":443"` on H2 responses
- Docs: dedicated 443/udp (conflict with other QUIC services on the host)
- ClientID in the path, same as H2

### 3. Anti-DoH bypass

- Bundled list of known public resolvers (domains + IPs), updated like blocklists (separate URL in config, default on when the feature is enabled)
- Modes `filtering.anti_doh_bypass = off | block_all | block_except_trusted` (the `trusted` flag from M4)
- Distinct verdict in the query log + metric `sito_doh_bypass_blocked_total`

### 4. ACME

- `instant-acme`, TLS-ALPN-01 challenge on 443 (rustls already there) with HTTP-01 fallback
- Account and cert storage in `data_dir/acme/`; background renew (30 days ahead); reload via the M3.1 mechanism
- `web.acme_enabled` + `web.acme_email` + `web.acme_domains`; staging CA as a test flag

### 5. DNSCrypt (stretch, ADR-006)

- Only if the phase has slack: protocol v2 (X25519 + XSalsa20-Poly1305, `x25519-dalek` + `crypto_secretbox`), provider certificate with 24 h rotation, `sdns://` stamp
- Interop tests with dnscrypt-proxy; if incomplete — feature-flag off and a "known limitations" doc

## Agent prompts

```
M7.1 doq        → task 1; DoD: q --doq works; wireshark shows no 0-RTT;
                  transport matrix from M3 green including doq
M7.2 doh3       → task 2; DoD: q --doh3 and curl --http3 --doh-url work;
                  Alt-Svc present; H2→H3 fallback documented
M7.3 bypass     → task 3; DoD: a known resolver from the list blocked in block_all;
                  trusted bypasses; verdict visible in the log with a distinct status
M7.4 acme       → task 4; DoD: pebble (test CA) in CI issues a cert; renewal
                  simulated with shortened time; staging/prod flag
M7.5 dnscrypt   → stretch; DoD: dnscrypt-proxy -resolve works against sito
                  or feature off + docs
```

## Tests and acceptance criteria

- [x] `q --doq`, `q --doh3`, `curl --http3` → NOERROR; blocking works on both
- [x] Transport matrix (now 6: UDP, TCP, DoT, DoH, DoQ, DoH3) × scenarios — green
- [x] Anti-bypass: 10 random resolvers from the list blocked; trusted mode bypasses
- [x] ACME on pebble / instant-acme: cert issued, stored, reloaded without restart
- [x] DoQ/DoH3 p99 in the phase benchmark documented (base for targets 16.1)

## Risks

| Risk | Mitigation |
|---|---|
| QUIC in hickory requires specific quinn/rustls versions | Shared lockfile; resolve version conflicts at the source (global rustls bump), not forks |
| ISPs/firewalls cutting QUIC in user tests | Docs: DoQ/DoH3 optional, H2 always as fallback |
| DNSCrypt not finished in time | It's a stretch by definition — scope guard: don't move M8 |

## Deliverables

6 transports in `:m7`, toggles in Settings, "ACME" docs section, updated conformance matrix.
