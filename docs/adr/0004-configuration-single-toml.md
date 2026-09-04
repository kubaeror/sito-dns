# ADR-0004: Configuration System (Single TOML with Centralized ConfigManager)

* **Status:** Accepted
* **Date:** 2026-09-04
* **Deciders:** sito core team
* **Consulted:** Architecture and security review
* **Informed:** All contributors

## Context

`sito` is designed for dual operational paradigms:
1. **Infrastructure as Code / Sysadmin:** Operators editing configuration files directly via text editors, Ansible, or Docker volumes (e.g., `/etc/sito/sito.toml`).
2. **Web UI / REST API Management:** Operators making changes through the interactive management dashboard or automated API calls.

Requirements:
- Single canonical source of truth for persistent configuration.
- Prevention of configuration corruption during server crashes or abrupt power loss.
- Hot-reloading of configuration updates without restarting the DNS service or interrupting active queries.
- Strict validation: invalid configurations must never take effect or replace valid running configurations.

## Decision

We designate a **single TOML file** (`sito.toml`) as the primary persistent configuration source.

Architecture:
1. **Centralized `ConfigManager`:** All mutations initiated from the REST API or UI must pass through `ConfigManager`. Direct raw disk writes from outside the daemon are monitored via `notify` file watching and SIGHUP signals.
2. **Pre-commit Validation:** Before writing to disk or applying changes, the new configuration is fully parsed and validated against schema constraints and network invariants. If validation fails, changes are rejected with actionable error messages.
3. **Atomic Disk Writes:** Changes are written to a temporary sibling file (`sito.toml.tmp`) with `fsync`, then atomically moved to `sito.toml` via `rename(2)`.
4. **Lock-Free Pipeline Updates:** Validated configurations are converted into immutable snapshot structs and atomically installed into `AppState` using `arc-swap::ArcSwap`. In-flight queries retain references to their initial snapshot without lock contention.

## Consequences

### Positive
- TOML provides a human-readable, strongly typed syntax familiar to the Rust and systems ecosystem.
- Atomic file replacements ensure that power loss mid-write never leaves a zero-byte or corrupt configuration file.
- `ArcSwap` guarantees zero-downtime hot-reloading for upstream servers, filter lists, and client mappings.
- Clean separation of concerns: API handlers do not manipulate files directly.

### Negative
- Direct manual file edits made while the daemon is actively receiving simultaneous UI edits require conflict handling.
- Programmatic rewriting of TOML can strip out arbitrary user comments unless round-trip preserving parsers (e.g. `toml_edit`) are employed.

### Neutral / Operational
- Default configuration path: `/etc/sito/sito.toml` (Linux) or `./sito.toml` (local development).
- CLI flag `--config <path>` overrides default location.

## Alternatives Considered

### Alternative 1: YAML
- **Pros:** Widely used in cloud-native tooling (Kubernetes, Docker Compose).
- **Cons:** Complex specification, whitespace-sensitive syntax prone to human copy-paste indentation bugs, ambiguous typing (e.g. "no" parsed as false).
- **Why not chosen:** TOML offers unambiguous types, clear table sections, and superior ergonomics for systems utilities.

### Alternative 2: Multi-File Directory Layout (`conf.d/*.toml`)
- **Pros:** Modular breakdown of separate concerns (upstream, filters, clients).
- **Cons:** Atomic replacement of multiple files across a directory is non-trivial without filesystem transactions; harder to export, import, and replicate across HA nodes.
- **Why not chosen:** Single-file configuration is easier to back up, restore, replicate in HA bundles, and map in Docker containers.

### Alternative 3: Database-Only Configuration (SQLite table)
- **Pros:** Easy programmatic CRUD operations.
- **Cons:** Incompatible with Infrastructure-as-Code workflows; cannot be easily inspected or modified using standard text editors while the service is stopped.
- **Why not chosen:** Sysadmins expect human-editable config files for core server parameters.
