# ADR-0005: Default Block Response Mode (Zero IP: 0.0.0.0 / ::)

* **Status:** Accepted
* **Date:** 2026-09-04
* **Deciders:** sito core team
* **Consulted:** Filtering and network compatibility review
* **Informed:** All contributors

## Context

When an incoming DNS query matches a blocking rule, the server must synthesize an immediate response without forwarding the request to upstream resolvers. The choice of default DNS response significantly affects client behavior:

Potential responses:
1. **`zero_ip`:** Return `NOERROR` with `0.0.0.0` (for type A) or `::` (for type AAAA).
2. **`nxdomain`:** Return `RCODE = 3 (NXDOMAIN)` (Non-Existent Domain).
3. **`refused`:** Return `RCODE = 5 (REFUSED)`.
4. **`custom_ip`:** Return a designated sinkhole IP serving an informative block page.

Client edge cases:
- Modern operating systems (Windows, macOS, iOS, Android) and browsers (Chrome, Edge) frequently interpret `NXDOMAIN` or `REFUSED` on ad or tracking domains as network resolution failures, triggering automatic fallbacks to secondary DNS interfaces, DoH providers (e.g. 8.8.8.8 / 1.1.1.1), or generating aggressive query retransmissions (query storms).
- Connecting to `0.0.0.0` or `::` fails instantly at the operating system socket layer (immediate `ECONNREFUSED` or unreachable route), preventing connection hangs while signaling to the client that the query itself resolved successfully.

## Decision

We establish **`zero_ip`** (`0.0.0.0` for A records, `::` for AAAA records) with `NOERROR` as the default blocking mode across the server (`filtering.blocking_mode = "zero_ip"`).

Key configurations:
- A configurable `blocked_ttl` (default: 60 seconds) is attached to the synthesized zero-IP answer to prevent clients from endlessly re-querying every millisecond.
- Alternative modes (`nxdomain`, `refused`, and `custom_ip`) remain supported via configuration for specialized use cases or per-client group policies.

## Consequences

### Positive
- Prevents smart devices, operating systems, and browsers from failing over to secondary unblocked DNS servers.
- Eliminates query storm cascades caused by aggressive client retries on `NXDOMAIN`.
- Instant client-side TCP connection rejection without waiting for socket timeouts.
- Consistent with established best practices in AdGuard Home and Pi-hole.

### Negative
- Does not display a human-readable "Site Blocked" web page in browsers (which is largely obsolete today due to HTTPS/HSTS certificate warning intercepts anyway).
- Certain non-standard internal applications expecting `NXDOMAIN` for absent internal records must be configured via explicit rewrite rules rather than filter blocks.

### Neutral / Operational
- Supported blocking modes: `zero_ip` (default), `nxdomain`, `refused`, and `custom_ip = "192.168.1.X"`.

## Alternatives Considered

### Alternative 1: Default to NXDOMAIN
- **Pros:** Conceptually represents "domain does not exist".
- **Cons:** Triggers secondary DNS fallback mechanisms on Windows and mobile devices, defeating ad-blocking; causes client retry bursts.
- **Why not chosen:** Real-world network compatibility heavily favors zero IP.

### Alternative 2: Default to HTTP Block Page (Sinkhole Server)
- **Pros:** Displays an explanatory blocked page to users in a web browser.
- **Cons:** Over 95% of web traffic uses HTTPS with HSTS; directing HTTPS requests to a sinkhole IP produces catastrophic SSL certificate warning screens rather than a clean block page, requiring installation of private root CA certificates on all client devices.
- **Why not chosen:** Intrusive and breaks TLS security expectations on modern networks.
