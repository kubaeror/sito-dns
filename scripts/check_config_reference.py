#!/usr/bin/env python3
"""Drift check for docs/configuration-reference.md against Rust config structs.

The reference tables are hand-written (they carry prose and examples), while
the authoritative field list lives in the Rust structs. This script extracts
``pub`` fields (honouring ``#[serde(rename = ...)]``) from the config structs
in every crate and verifies both directions:

* every key documented in a table exists in the corresponding struct;
* every struct field is documented (so new settings cannot be added silently).

Run with ``--github`` for a compact CI-friendly failure summary.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOC = ROOT / "docs" / "configuration-reference.md"

# section number -> (title fragment, [(source file, struct name), ...])
SECTIONS: dict[int, tuple[str, list[tuple[str, str]]]] = {
    1: ("Top-Level Options", [("crates/sito-core/src/config.rs", "Config")]),
    2: ("`[server]`", [("crates/sito-core/src/config.rs", "ServerConfig")]),
    3: ("`[dns]`", [("crates/sito-core/src/config.rs", "DnsConfig")]),
    4: ("`[dns.cache]`", [("crates/sito-core/src/config.rs", "CacheConfig")]),
    5: ("`[dns.dnssec]`", [("crates/sito-core/src/config.rs", "DnssecConfig")]),
    6: (
        "`[tls]` and `[acme]`",
        [
            ("crates/sito-core/src/config.rs", "TlsConfig"),
            ("crates/sito-core/src/config.rs", "AcmeConfig"),
        ],
    ),
    7: ("`[upstream]`", [("crates/sito-core/src/config.rs", "UpstreamConfig")]),
    8: ("`[filtering]`", [("crates/sito-core/src/config.rs", "FilteringConfig")]),
    9: ("`[clients]`", [("crates/sito-clients/src/config.rs", "ClientsConfig")]),
    10: ("`[rewrites]`", [("crates/sito-rewrites/src/config.rs", "RewritesConfig")]),
    11: (
        "`[web]` & `[auth]`",
        [
            ("crates/sito-core/src/config.rs", "WebConfig"),
            ("crates/sito-core/src/config.rs", "AuthConfig"),
        ],
    ),
    12: (
        "`[stats]`",
        [
            ("crates/sito-core/src/config.rs", "StatsConfig"),
            ("crates/sito-core/src/config.rs", "PrivacyConfig"),
        ],
    ),
    13: ("`[ha]`", [("crates/sito-ha/src/config.rs", "HaConfig")]),
    14: ("`[integrations.mikrotik]`", [("crates/sito-clients/src/routeros.rs", "RouterOsConfig")]),
}

SECTION_RE = re.compile(r"^##\s+(\d+)\.\s")
ROW_RE = re.compile(r"^\|([^|]+)\|")
STRUCT_RE = re.compile(r"^\s*pub struct\s+(\w+)")
FIELD_RE = re.compile(r"^\s*pub\s+([a-z_][a-z0-9_]*)\s*:")
RENAME_RE = re.compile(r'#\[serde\([^]]*rename\s*=\s*"([^"]+)"')


def parse_struct_fields(path: Path) -> dict[str, set[str]]:
    """Return {struct_name: {toml_key, ...}} for all pub fields in *path*."""
    structs: dict[str, set[str]] = {}
    current: str | None = None
    pending_rename: str | None = None
    brace_depth = 0
    for raw in path.read_text().splitlines():
        line = raw.split("//")[0]
        if current is None:
            m = STRUCT_RE.match(line)
            if m:
                current = m.group(1)
                structs.setdefault(current, set())
                brace_depth = line.count("{") - line.count("}")
                pending_rename = None
            continue

        rename = RENAME_RE.search(line)
        if rename:
            pending_rename = rename.group(1)
        field = FIELD_RE.match(line)
        if field:
            structs[current].add(pending_rename or field.group(1))
            pending_rename = None
        brace_depth += line.count("{") - line.count("}")
        if brace_depth <= 0 and "}" in line:
            current = None
    return structs


def parse_doc_rows() -> dict[int, list[str]]:
    """Return {section_number: [documented key, ...]} from the markdown tables."""
    rows: dict[int, list[str]] = {}
    section: int | None = None
    for raw in DOC.read_text().splitlines():
        head = SECTION_RE.match(raw)
        if head:
            section = int(head.group(1))
            rows.setdefault(section, [])
            continue
        if section is None or not raw.startswith("|"):
            continue
        m = ROW_RE.match(raw)
        if not m:
            continue
        cell = m.group(1)
        keys = re.findall(r"`([^`]+)`", cell)
        if not keys or (len(keys) == 1 and keys[0].lower() in {"key", "setting"}):
            continue
        for key in keys:
            if " / " in key:
                rows[section].extend(part.strip() for part in key.split(" / "))
            else:
                rows[section].append(key.strip())
    return rows


def struct_for_key(key: str, structs: dict[str, set[str]]) -> set[str]:
    """Find the struct(s) owning a documented key (dotted prefix aware)."""
    if "." not in key:
        return {name for name in structs if key in structs[name]}
    prefix, _, leaf = key.rpartition(".")
    candidates = {
        name
        for name, fields in structs.items()
        if leaf in fields
        and name.lower().replace("config", "") in prefix.lower().replace(".", "")
    }
    return candidates or {
        name for name, fields in structs.items() if leaf in fields
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--github", action="store_true", help="annotate failures for GitHub Actions")
    args = parser.parse_args()

    field_cache: dict[Path, dict[str, set[str]]] = {}
    errors: list[str] = []

    doc_rows = parse_doc_rows()
    documented_by_section = doc_rows

    # Fields that are containers for other documented sections or documented
    # inline inside array-of-table rows, so they have no table row of their own.
    skip_reverse_by_section = {
        1: {
            "server", "dns", "upstream", "filtering", "tls", "acme", "privacy",
            "clients", "rewrites", "web", "auth", "stats", "ha", "integrations",
        },
        3: {"cache", "dnssec", "tls"},
        # Nested/array-of-table structs documented inline in a single row.
        7: {"per_domain"},
        9: {"entries", "groups"},
        10: {"entries"},
        6: {"sni_certs"},
    }

    for number, (title, sources) in SECTIONS.items():
        structs: dict[str, set[str]] = {}
        for rel, struct_name in sources:
            path = ROOT / rel
            if path not in field_cache:
                field_cache[path] = parse_struct_fields(path)
            structs[struct_name] = field_cache[path].get(struct_name, set())

        documented = set(documented_by_section.get(number, []))

        for key in sorted(documented):
            if not struct_for_key(key, structs):
                errors.append(f"section {number} ({title}): documented key `{key}` not found in structs")

        # Reverse direction: every pub field of the section structs must appear.
        expected: set[str] = set()
        for struct_name in structs:
            prefix = ""
            if len(structs) > 1:
                prefix = struct_name.lower().removesuffix("config") + "."
            expected |= {prefix + field for field in structs[struct_name]}
        skip_reverse = skip_reverse_by_section.get(number, set())

        for key in sorted(expected - documented - skip_reverse):
            errors.append(f"section {number} ({title}): struct field `{key}` is not documented")

    if errors:
        print("configuration reference drift detected:", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
            if args.github:
                print(f"::error::{err}")
        print(
            "\nUpdate docs/configuration-reference.md (or the structs) so both stay in sync.",
            file=sys.stderr,
        )
        return 1

    total = sum(len(v) for v in documented_by_section.values())
    print(f"configuration reference OK ({total} documented keys checked)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
