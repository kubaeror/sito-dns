---
name: Bug Report
about: Create a report to help us fix an issue in sito
title: '[BUG] '
labels: ['bug', 'triage']
assignees: ''
---

## Describe the Bug

A clear and concise description of what the bug is.

## Steps to Reproduce

Steps to reproduce the behavior:
1. Start `sito` with configuration '...'
2. Send DNS query `dig @127.0.0.1 -p 53 ...`
3. Observe output '....'
4. Expected behavior '....'

## Configuration (`sito.toml`)

```toml
# Paste relevant parts of your sito.toml here
```

## Logs and Tracing

```text
# Run with RUST_LOG=debug and paste relevant logs here
```

## Environment

- **sito version:** (e.g. `0.1.0` or commit hash)
- **OS / Distro:** (e.g. Ubuntu 24.04, Debian 12, Alpine 3.20)
- **Architecture:** (e.g. `x86_64`, `aarch64`, `armv7`)
- **Deployment:** (e.g. native systemd, Docker container, Kubernetes)

## Additional Context

Add any other context about the problem here (e.g. network topology, upstream providers).
