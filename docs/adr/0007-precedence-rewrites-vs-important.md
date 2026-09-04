# ADR-0007: Rule Precedence Architecture (Local Rewrites vs $important Rules)

* **Status:** Accepted
* **Date:** 2026-09-04
* **Deciders:** sito core team
* **Consulted:** Rule engine and local network operations review
* **Informed:** All contributors

## Context

In an ad-blocking and filtering DNS server, conflicting verdicts can occur for a single requested domain:
- **Local DNS Rewrites:** Explicit operator-defined mappings (e.g., in `/etc/hosts` or the web UI) directing domains to local IP addresses (e.g. `printer.lan`, `nas.home.arpa`, or development domain intercepts).
- **Standard Filter Rules:** Subscription-based blocking rules (`||tracker.example^`) and exception rules (`@@||tracker.example^`).
- **`$important` Modifier Rules:** In AdGuard syntax, the `$important` modifier elevates a rule above normal priority, specifically intended to prevent subscription rules from being superseded by standard exceptions.

Conflict scenarios arise:
- If an upstream subscription contains a block rule with `$important` for a domain that the local network administrator has explicitly rewritten to an internal server IP.
- If a user whitelists a service, but an upstream list marks an ad sub-resource as `$important`.

Prematurely freezing the exact edge-case precedence before the filtering engine (M2) and client/rewrite engines (M4) are built risks incompatible behavior with AdGuard Home expectations or breaking local homelab network operations.

## Decision

We formally **ratify and finalize the pipeline precedence architecture** for Phase M4 (Clients and Rewrites):

### Final Pipeline Precedence Order:
1. **Client Exemptions:** Client-level bypass policies (e.g. `exception_clients` bypassing local rewrites, unmanaged devices).
2. **Important Rules:**
   - **Important Exceptions:** Filter exception rules with `$important` (`@@||domain^$important`) grant immediate allowlist clearance.
   - **Important Block Rules:** Filter blocking rules with `$important` (`||domain^$important`) take precedence over local rewrites.
     *Security Invariant:* An administrator's explicit `$important` block cannot be subverted or circumvented by a local DNS rewrite or standard exception.
3. **Local DNS Rewrites & Auto-PTR (`sito-rewrites`):**
   - Exact and wildcard local mappings (`printer.lan`, `*.home.arpa`, auto-generated PTR records) take precedence over standard public filter subscriptions and cache, ensuring local LAN reachability is never disrupted by external adblock lists.
4. **Standard Filter Rules, Safe Search, Parental & Services:**
   - Standard exception rules (`@@||domain^`).
   - Standard blocking rules (`||domain^`).
   - Safe search system rewrites (Google, Bing, YouTube, DuckDuckGo).
   - Parental control category blocks (adult, gambling).
   - Service blocks (TikTok, Steam, etc., with schedules).
5. **DNS Cache Lookup:** Returning cached non-expired responses.
6. **Upstream Forwarding & DNSSEC Validation:** Resolving external queries via configured upstream providers.

This order is verified in conformance integration tests (`tests/precedence.rs` and `crates/sito-test/src/lib.rs`).

## Consequences

### Positive
- Strict security guarantees: malicious or rogue local records cannot bypass critical administrator security blocks marked with `$important`.
- Homelab reliability: local network hostnames and RFC1918 auto-PTR records reliably resolve even if public third-party filter subscriptions contain false-positive standard blocking rules.
- 100% adherence to AdGuard Home rule evaluation and ABP ecosystem expectations.

### Negative
- Administrators must be aware that adding an `$important` blocking rule will intercept queries even if a local rewrite exists for that domain.

### Neutral / Operational
- Conformance test table in `docs/policy-matrix.md` and integration test matrix document and verify all edge cases.

## Alternatives Considered

### Alternative 1: Local Rewrites Overriding Everything (Including `$important`)
- **Pros:** Homelab rewrites are always unconditionally respected.
- **Cons:** Violates the fundamental security invariant where an operator attempts to block a dangerous domain network-wide using an explicit `$important` custom rule, only to have it bypassed by a local or imported rewrite entry.
- **Why not chosen:** Security invariant requires `$important` blocks to have absolute veto power.

### Alternative 2: Disallow the `$important` Modifier Completely
- **Pros:** Simplifies the filtering engine and precedence resolution.
- **Cons:** Breaks compatibility with major filter lists (e.g., AdGuard Base, OISD, Hagezi lists) that rely on `$important` to resolve complex anti-adblock unblocking rules.
- **Why not chosen:** High compatibility with established AdGuard/ABP filter lists is a core design goal.

