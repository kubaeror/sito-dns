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

We establish the **provisional pipeline evaluation order** in M0, and formally schedule final ratification and edge-case conformance testing for **Phase M4 (Clients and Rewrites)**:

Provisional Pipeline Precedence:
1. **Client Exemptions:** Client-level bypass policies (e.g. unmanaged clients, parental control exempt devices).
2. **Local Rewrites / Hosts:** Local administrator mappings take precedence over public filter list subscriptions by default, ensuring internal network connectivity is never severed by external blocklists.
3. **Important Exceptions:** Filter exception rules with the `$important` modifier (`@@||domain^$important`).
4. **Important Block Rules:** Filter blocking rules with the `$important` modifier (`||domain^$important`).
5. **Standard Exceptions:** Normal filter exception rules (`@@||domain^`).
6. **Standard Block Rules:** Normal filter blocking rules (`||domain^`).
7. **Upstream Forwarding & Cache:** Resolving and caching external queries.

During Phase M4, this order will be verified against a comprehensive matrix of conformance tests (`tests/conformance/precedence_matrix.rs`) and, if required, a configuration toggle (`filtering.rewrites_override_important = true | false`) will be exposed.

## Consequences

### Positive
- Prevents development deadlock during M0–M3 while establishing clear expectations for early pipeline prototypes.
- Guarantees that local administrative DNS overrides are protected against unexpected breakages caused by third-party blocklist updates.
- Dedicates a formal milestone (M4) to edge-case validation with real AdGuard filter test suites.

### Negative
- Exact behavior for rare combinations of `$important` + local rewrites remains provisional until M4 integration testing.

### Neutral / Operational
- Conformance test table in M4 documentation will serve as the living source of truth for all precedence edge cases.

## Alternatives Considered

### Alternative 1: Strict `$important` Dominance Over Everything (Including Local Rewrites)
- **Pros:** Literal interpretation of the word "important" in ABP syntax.
- **Cons:** A rogue or over-broad subscription list rule could hijack or block a user's internal router, NAS, or smart home device, causing severe outages on local LANs.
- **Why not chosen:** Local network administrators must always maintain authoritative control over their own internal network boundaries.

### Alternative 2: Disallow the `$important` Modifier Completely
- **Pros:** Simplifies the filtering engine and precedence resolution.
- **Cons:** Breaks compatibility with major filter lists (e.g., AdGuard Base, OISD, Hagezi lists) that rely on `$important` to resolve complex anti-adblock unblocking rules.
- **Why not chosen:** High compatibility with established AdGuard/ABP filter lists is a core design goal.
