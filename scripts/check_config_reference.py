#!/usr/bin/env python3
"""Drift check for docs/configuration-reference.md against Rust config structs.

The reference tables are hand-written (they carry prose and examples), while
the authoritative field list lives in the Rust structs. This script extracts
``pub`` fields (honouring ``#[serde(rename = ...)]``) from the config structs
in every crate and verifies both directions:

* every key documented in a table exists in the corresponding struct;
* every struct field is documented (so new settings cannot be added silently).

Run with ``--github`` for a compact CI-friendly failure summary. Run with
``--write`` to append placeholder rows for newly added struct fields (existing
prose is preserved and the author fills in the description afterwards).
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
    15: (
        "`[integrations.lists]`",
        [("crates/sito-clients/src/runtime_lists.rs", "ListCategoriesConfig")],
    ),
}

# Fields that are containers for other documented sections or documented
# inline inside array-of-table rows, so they have no table row of their own.
SKIP_REVERSE_BY_SECTION = {
    1: {
        "server", "dns", "upstream", "filtering", "tls", "acme", "privacy",
        "clients", "rewrites", "web", "auth", "stats", "ha", "integrations",
    },
    3: {"cache", "dnssec", "tls"},
    # Nested/array-of-table structs documented inline in a single row.
    6: {"sni_certs"},
    7: {"per_domain"},
    9: {"entries", "groups"},
    10: {"entries"},
}

SECTION_RE = re.compile(r"^##\s+(\d+)\.\s")
ROW_RE = re.compile(r"^\|([^|]+)\|")
STRUCT_RE = re.compile(r"^\s*pub struct\s+(\w+)")
FIELD_RE = re.compile(r"^\s*pub\s+([a-z_][a-z0-9_]*)\s*:\s*(.+?),?\s*$")
RENAME_RE = re.compile(r'#\[serde\([^]]*rename\s*=\s*"([^"]+)"')


def parse_struct_fields(path: Path) -> dict[str, dict[str, dict[str, str]]]:
    """Return {struct: {toml_key: {"type": ..., "doc": ...}}} for pub fields."""
    structs: dict[str, dict[str, dict[str, str]]] = {}
    current: str | None = None
    pending_rename: str | None = None
    pending_doc: list[str] = []
    brace_depth = 0
    for raw in path.read_text().splitlines():
        stripped = raw.strip()
        if stripped.startswith("///"):
            pending_doc.append(stripped.removeprefix("///").strip())
            continue
        line = raw.split("//")[0]
        if current is None:
            m = STRUCT_RE.match(line)
            if m:
                current = m.group(1)
                structs.setdefault(current, {})
                brace_depth = line.count("{") - line.count("}")
                pending_rename = None
                pending_doc = []
            continue

        rename = RENAME_RE.search(line)
        if rename:
            pending_rename = rename.group(1)
        field = FIELD_RE.match(line)
        if field:
            key = pending_rename or field.group(1)
            structs[current][key] = {
                "type": field.group(2).strip(),
                "doc": " ".join(pending_doc),
            }
            pending_rename = None
            pending_doc = []
        elif line.strip() and not line.strip().startswith("#["):
            pending_doc = []
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


def rust_type_to_doc(rust_type: str) -> str:
    """Maps a Rust field type to the reference's human-readable type column."""
    compact = rust_type.replace(" ", "")
    while compact.startswith("Option<") and compact.endswith(">"):
        compact = compact[len("Option<") : -1]
    if compact == "bool":
        return "boolean"
    if compact.startswith("Vec<") and compact.endswith(">"):
        element = compact[4:-1]
        if element in {"String", "PathBuf"}:
            return "array of strings"
        if element == "IpAddr":
            return "array of IP addresses"
        if element.endswith("Config"):
            return "array of tables"
        return "array"
    if compact in {"String", "PathBuf"}:
        return "string"
    if compact == "IpAddr":
        return "string (IP address)"
    if compact in {
        "u8", "u16", "u32", "u64", "usize",
        "i8", "i16", "i32", "i64", "isize",
    }:
        return "integer"
    if compact.startswith("toml::") or compact == "toml::Value":
        return "table"
    return "value"


def write_missing_rows() -> list[str]:
    """Appends placeholder rows for undocumented struct fields.

    Existing rows, prose and TOML examples are preserved; only new rows with a
    TODO description are added, so authors can fill in wording without the CI
    check failing on the intermediate state.
    """
    field_cache: dict[Path, dict[str, dict[str, dict[str, str]]]] = {}
    lines = DOC.read_text().splitlines()
    documented = parse_doc_rows()
    added: list[str] = []

    for number, (title, sources) in SECTIONS.items():
        structs: dict[str, dict[str, dict[str, str]]] = {}
        for rel, struct_name in sources:
            path = ROOT / rel
            if path not in field_cache:
                field_cache[path] = parse_struct_fields(path)
            structs[struct_name] = field_cache[path].get(struct_name, {})

        documented_keys = set(documented.get(number, []))
        skip_reverse = SKIP_REVERSE_BY_SECTION.get(number, set())
        expected: dict[str, dict[str, str]] = {}
        for struct_name, fields in structs.items():
            prefix = ""
            if len(structs) > 1:
                prefix = struct_name.lower().removesuffix("config") + "."
            for field, meta in fields.items():
                expected[prefix + field] = meta

        missing = {
            key: meta
            for key, meta in expected.items()
            if key not in documented_keys and key not in skip_reverse
        }
        if not missing:
            continue

        heading = next(
            (i for i, line in enumerate(lines) if line.startswith(f"## {number}.")),
            None,
        )
        if heading is None:
            continue
        section_end = next(
            (
                i
                for i in range(heading + 1, len(lines))
                if lines[i].startswith("## ")
            ),
            len(lines),
        )
        table_end = next(
            (
                i
                for i in range(section_end - 1, heading, -1)
                if lines[i].startswith("|")
            ),
            None,
        )
        if table_end is None:
            continue

        new_rows = [
            "| `{key}` | {kind} | `—` | {description} |".format(
                key=key,
                kind=rust_type_to_doc(meta["type"]),
                description=(
                    meta["doc"].replace("|", "\\|")
                    if meta["doc"]
                    else f"TODO: describe `{key}`."
                ),
            )
            for key, meta in sorted(missing.items())
        ]
        lines[table_end + 1 : table_end + 1] = new_rows
        added.extend(new_rows)

    if added:
        DOC.write_text("\n".join(lines) + "\n")
    return added


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--github", action="store_true", help="annotate failures for GitHub Actions")
    parser.add_argument(
        "--write",
        action="store_true",
        help="append placeholder rows for undocumented fields before checking",
    )
    args = parser.parse_args()

    if args.write:
        added = write_missing_rows()
        for row in added:
            print(f"added placeholder row: {row}")

    field_cache: dict[Path, dict[str, dict[str, dict[str, str]]]] = {}
    errors: list[str] = []

    doc_rows = parse_doc_rows()
    documented_by_section = doc_rows

    for number, (title, sources) in SECTIONS.items():
        structs: dict[str, set[str]] = {}
        for rel, struct_name in sources:
            path = ROOT / rel
            if path not in field_cache:
                field_cache[path] = parse_struct_fields(path)
            structs[struct_name] = field_cache[path].get(struct_name, {})

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
        skip_reverse = SKIP_REVERSE_BY_SECTION.get(number, set())

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
