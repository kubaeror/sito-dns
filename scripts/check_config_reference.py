#!/usr/bin/env python3
"""Drift check for docs/configuration-reference.md against Rust config structs.

The reference tables are hand-written (they carry prose and examples), while
the authoritative field list lives in the Rust structs. This script extracts
``pub`` fields (honouring ``#[serde(rename = ...)]``/``default``) from the config
structs in every crate and verifies:

* every key documented in a table exists in the corresponding struct;
* every struct field is documented (so new settings cannot be added silently);
* documented *types* match the Rust field type where the mapping is
  unambiguous;
* documented *defaults* match the serde/default value where it can be extracted
  safely (explicit literal default functions and simple zero/`None` values).

Defaults that use custom enum/struct constructors are skipped rather than
guessed. Run with ``--github`` for a compact CI-friendly failure summary. Run
with ``--write`` to append placeholder rows for newly added struct fields
(existing prose is preserved and the author fills in the description afterwards).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOC = ROOT / "docs" / "configuration-reference.md"

# section number -> (title fragment, [(source file, struct name), ...])
SECTIONS: dict[int, tuple[str, list[tuple[str, str]]]] = {
    1: ("Top-Level Options", [("crates/sito-core/src/config/schema.rs", "Config")]),
    2: ("`[server]`", [("crates/sito-core/src/config/schema.rs", "ServerConfig")]),
    3: ("`[dns]`", [("crates/sito-core/src/config/schema.rs", "DnsConfig")]),
    4: ("`[dns.cache]`", [("crates/sito-core/src/config/schema.rs", "CacheConfig")]),
    5: ("`[dns.dnssec]`", [("crates/sito-core/src/config/schema.rs", "DnssecConfig")]),
    6: (
        "`[tls]` and `[acme]`",
        [
            ("crates/sito-core/src/config/schema.rs", "TlsConfig"),
            ("crates/sito-core/src/config/schema.rs", "AcmeConfig"),
        ],
    ),
    7: ("`[upstream]`", [("crates/sito-core/src/config/schema.rs", "UpstreamConfig")]),
    8: (
        "`[filtering]`",
        [
            ("crates/sito-core/src/config/schema.rs", "FilteringConfig"),
            ("crates/sito-core/src/config/schema.rs", "FilterListConfig"),
        ],
    ),
    9: ("`[clients]`", [("crates/sito-clients/src/config.rs", "ClientsConfig")]),
    10: ("`[rewrites]`", [("crates/sito-rewrites/src/config.rs", "RewritesConfig")]),
    11: (
        "`[web]` & `[auth]`",
        [
            ("crates/sito-core/src/config/schema.rs", "WebConfig"),
            ("crates/sito-core/src/config/schema.rs", "AuthConfig"),
        ],
    ),
    12: (
        "`[stats]`",
        [
            ("crates/sito-core/src/config/schema.rs", "StatsConfig"),
            ("crates/sito-core/src/config/schema.rs", "PrivacyConfig"),
        ],
    ),
    13: ("`[ha]`", [("crates/sito-ha/src/config.rs", "HaConfig")]),
    14: ("`[integrations.mikrotik]`", [("crates/sito-clients/src/routeros.rs", "RouterOsConfig")]),
    15: (
        "`[integrations.lists]`",
        [("crates/sito-clients/src/runtime_lists.rs", "ListCategoriesConfig")],
    ),
}

# Explicit table prefixes for sections that combine several structs or document
# array-of-table entries. Without an entry the single-struct section is
# unprefixed and multi-struct sections use a lowercased struct-name prefix.
PREFIX_BY_STRUCT: dict[tuple[int, str], str] = {
    (6, "TlsConfig"): "tls.",
    (6, "AcmeConfig"): "acme.",
    (8, "FilteringConfig"): "",
    (8, "FilterListConfig"): "lists.",
    (11, "WebConfig"): "web.",
    (11, "AuthConfig"): "auth.",
    (12, "StatsConfig"): "stats.",
    (12, "PrivacyConfig"): "privacy.",
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
    15: {"categories"},
}

SECTION_RE = re.compile(r"^##\s+(\d+)\.\s")
STRUCT_RE = re.compile(r"^\s*pub struct\s+(\w+)")
FIELD_RE = re.compile(r"^\s*pub\s+([a-z_][a-z0-9_]*)\s*:\s*(.+?),?\s*$")
RENAME_RE = re.compile(r'#\[serde\([^]]*rename\s*=\s*"([^"]+)"')
DEFAULT_FN_RE = re.compile(r'#\[serde\([^]]*default\s*=\s*"([^"]+)"')
NUMERIC_TYPES = {
    "u8", "u16", "u32", "u64", "usize",
    "i8", "i16", "i32", "i64", "isize",
    "f32", "f64",
}

UNKNOWN = object()
REQUIRED = object()


def rust_unwrap_option(rust_type: str) -> str:
    compact = rust_type.replace(" ", "")
    while compact.startswith("Option<") and compact.endswith(">"):
        compact = compact[len("Option<") : -1]
    return compact


def rust_type_to_doc(rust_type: str) -> str:
    """Maps a Rust field type to the reference's human-readable type column."""
    compact = rust_unwrap_option(rust_type)
    if compact == "bool":
        return "boolean"
    if compact.startswith("Vec<") and compact.endswith(">"):
        element = compact[4:-1]
        if element in {"String", "PathBuf"}:
            return "array of strings"
        if element == "IpAddr":
            return "array of IP addresses"
        if element.endswith("Config") or element.endswith("Upstream"):
            return "array of tables"
        return "array"
    if compact in {"String", "PathBuf"}:
        return "string"
    if compact == "IpAddr":
        return "string (IP address)"
    if compact in NUMERIC_TYPES:
        return "integer"
    if compact.startswith("HashMap<") and compact.endswith(">"):
        return "table"
    if compact.startswith("toml::") or compact == "toml::Value":
        return "table"
    if compact.endswith("Config") or compact.endswith("Upstream"):
        return "table"
    return "value"


def normalize_doc_type(doc_type: str) -> str:
    value = doc_type.strip().strip("`").strip().lower()
    if value.startswith("array of ip"):
        return "array of IP addresses"
    if value.startswith("array of string"):
        return "array of strings"
    if value.startswith("array of table"):
        return "array of tables"
    if value.startswith("array"):
        return "array"
    if value.startswith("string (ip"):
        return "string (IP address)"
    if value.startswith("string"):
        return "string"
    if value.startswith("boolean"):
        return "boolean"
    if value.startswith("integer"):
        return "integer"
    if value.startswith("table"):
        return "table"
    return value


def split_top_level(text: str) -> list[str]:
    items: list[str] = []
    depth = 0
    start = 0
    in_string = False
    escaped = False
    for index, char in enumerate(text):
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char in "(<[{":
            depth += 1
        elif char in ")>]}":
            depth -= 1
        elif char == "," and depth == 0:
            items.append(text[start:index].strip())
            start = index + 1
    tail = text[start:].strip()
    if tail:
        items.append(tail)
    return items


def eval_default_scalar(expr: str):
    expr = expr.strip().rstrip(";").strip()
    if expr == "None":
        return None
    if expr in {"true", "false"}:
        return expr == "true"
    if re.fullmatch(r"[0-9_]+", expr):
        return int(expr.replace("_", ""))
    if re.fullmatch(r"[0-9_+\-*/().\s]+", expr) and any(c in expr for c in "+-*/"):
        try:
            return int(eval(expr, {"__builtins__": {}}, {}))  # noqa: S307 - digits/operators only
        except (SyntaxError, ValueError, ZeroDivisionError):
            return UNKNOWN
    match = re.fullmatch(r'"([^"]*)"\.to_string\(\)', expr)
    if match:
        return match.group(1)
    match = re.fullmatch(r'PathBuf::from\("([^"]*)"\)', expr)
    if match:
        return match.group(1)
    if re.fullmatch(r"String::new\(\)", expr):
        return ""
    match = re.fullmatch(r'IpAddr::from_str\("([^"]+)"\)\.expect\([^)]*\)', expr)
    if match:
        return match.group(1)
    if re.fullmatch(r"IpAddr::V4\(std::net::Ipv4Addr::UNSPECIFIED\)", expr):
        return "0.0.0.0"
    if re.fullmatch(r"IpAddr::V6\(std::net::Ipv6Addr::UNSPECIFIED\)", expr):
        return "::"
    match = re.fullmatch(r"Some\((.*)\)", expr, re.S)
    if match:
        return eval_default_scalar(match.group(1))
    match = re.fullmatch(r"vec!\[(.*)\]", expr, re.S)
    if match:
        items = split_top_level(match.group(1))
        values = []
        for item in items:
            if not item:
                continue
            value = eval_default_scalar(item)
            if value is UNKNOWN:
                return UNKNOWN
            values.append(value)
        return values
    return UNKNOWN


def parse_default_fns(path: Path) -> dict[str, object]:
    text = path.read_text()
    defaults: dict[str, object] = {}
    for match in re.finditer(r"fn\s+(\w+)\s*\(\)\s*->[^{]+\{", text):
        name = match.group(1)
        start = match.end()
        depth = 1
        index = start
        in_string = False
        escaped = False
        while index < len(text) and depth > 0:
            char = text[index]
            if in_string:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    in_string = False
            elif char == '"':
                in_string = True
            elif char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
            index += 1
        body = text[start : index - 1]
        body = re.sub(r"//[^\n]*", "", body)
        value = eval_default_scalar(body)
        if value is not UNKNOWN:
            defaults[name] = value
    return defaults


def infer_zero_default(rust_type: str):
    compact = rust_unwrap_option(rust_type)
    if rust_type.replace(" ", "").startswith("Option<"):
        return None
    if compact == "bool":
        return False
    if compact in NUMERIC_TYPES:
        return 0
    if compact == "String":
        return ""
    if compact.startswith("Vec<"):
        return []
    if compact.startswith("HashMap<"):
        return {}
    return UNKNOWN


def parse_struct_fields(path: Path) -> dict[str, dict[str, dict[str, object]]]:
    """Return {struct: {toml_key: {"type", "doc", "default", "has_default"}}}."""
    structs: dict[str, dict[str, dict[str, object]]] = {}
    default_fns = parse_default_fns(path)
    current: str | None = None
    pending_rename: str | None = None
    pending_default_fn: str | None = None
    pending_has_default = False
    pending_doc: list[str] = []
    brace_depth = 0
    for raw in path.read_text().splitlines():
        stripped = raw.strip()
        if stripped.startswith("///"):
            pending_doc.append(stripped.removeprefix("///").strip())
            continue
        line = raw.split("//")[0]
        if current is None:
            match = STRUCT_RE.match(line)
            if match:
                current = match.group(1)
                structs.setdefault(current, {})
                brace_depth = line.count("{") - line.count("}")
                pending_rename = None
                pending_default_fn = None
                pending_has_default = False
                pending_doc = []
            continue

        if line.strip().startswith("#["):
            rename = RENAME_RE.search(line)
            if rename:
                pending_rename = rename.group(1)
            default_fn = DEFAULT_FN_RE.search(line)
            if default_fn:
                pending_default_fn = default_fn.group(1)
                pending_has_default = True
            elif re.search(r"\bdefault\b", line):
                pending_has_default = True
            brace_depth += line.count("{") - line.count("}")
            continue

        field = FIELD_RE.match(line)
        if field:
            key = pending_rename or field.group(1)
            field_type = field.group(2).strip()
            if pending_default_fn:
                default_value = default_fns.get(pending_default_fn, UNKNOWN)
            elif pending_has_default:
                default_value = infer_zero_default(field_type)
            elif field_type.replace(" ", "").startswith("Option<"):
                default_value = None
            else:
                default_value = UNKNOWN
            structs[current][key] = {
                "type": field_type,
                "doc": " ".join(pending_doc),
                "default": default_value,
                "has_default": pending_has_default or pending_default_fn is not None,
            }
            pending_rename = None
            pending_default_fn = None
            pending_has_default = False
            pending_doc = []
        elif line.strip():
            pending_doc = []
        brace_depth += line.count("{") - line.count("}")
        if brace_depth <= 0 and "}" in line:
            current = None
    return structs


def parse_doc_table() -> list[dict[str, object]]:
    """Return documented rows: section, key, type, default, line number."""
    rows: list[dict[str, object]] = []
    section: int | None = None
    for line_number, raw in enumerate(DOC.read_text().splitlines(), start=1):
        head = SECTION_RE.match(raw)
        if head:
            section = int(head.group(1))
            continue
        if section is None or not raw.startswith("|"):
            continue
        cells = [cell.strip() for cell in raw.strip().strip("|").split("|")]
        if len(cells) < 3:
            continue
        keys = re.findall(r"`([^`]+)`", cells[0])
        if not keys or (len(keys) == 1 and keys[0].lower() in {"key", "setting"}):
            continue
        doc_type = cells[1].strip().strip("`").strip()
        default_raw = cells[2].strip().strip("`").strip()
        description = cells[3].strip() if len(cells) > 3 else ""
        for key in keys:
            parts = [part.strip() for part in key.split(" / ")] if " / " in key else [key.strip()]
            for part in parts:
                rows.append(
                    {
                        "section": section,
                        "key": part,
                        "type": doc_type,
                        "default_raw": default_raw,
                        "description": description,
                        "line": line_number,
                    }
                )
    return rows


def parse_documented_keys() -> dict[int, list[str]]:
    keys: dict[int, list[str]] = {}
    for row in parse_doc_table():
        assert isinstance(row["section"], int)
        keys.setdefault(row["section"], []).append(str(row["key"]))
    return keys


def struct_for_key(key: str, structs: dict[str, dict[str, dict[str, object]]]) -> set[str]:
    """Find the struct(s) owning a documented key (dotted prefix aware)."""
    if "." not in key:
        return {name for name, fields in structs.items() if key in fields}
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


def owner_for_key(
    section: int, key: str, structs: dict[str, dict[str, dict[str, object]]]
) -> str | None:
    """Pick the struct that owns a documented key using explicit table prefixes."""
    best: tuple[int, str] | None = None
    leaf = key.rpartition(".")[2] if "." in key else key
    for name, fields in structs.items():
        if leaf not in fields:
            continue
        prefix = prefix_for(section, name, len(structs))
        if prefix:
            if key.startswith(prefix):
                candidate = (len(prefix), name)
                if best is None or candidate > best:
                    best = candidate
        elif "." not in key:
            candidate = (0, name)
            if best is None or candidate > best:
                best = candidate
    if best is not None:
        return best[1]
    matches = struct_for_key(key, structs)
    return sorted(matches)[0] if matches else None


def parse_doc_default(raw: str):
    value = raw.strip().strip("`").strip()
    if value.lower() in {"none", "unset", "—", "-", ""}:
        return None
    if value.lower() == "required":
        return REQUIRED
    if value.startswith(("[", "{")):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return UNKNOWN
    if value.startswith('"') and value.endswith('"'):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value.strip('"')
    if value in {"true", "false"}:
        return value == "true"
    if re.fullmatch(r"-?[0-9_]+", value):
        return int(value.replace("_", ""))
    if re.fullmatch(r"[0-9_+\-*/().\s]+", value) and any(c in value for c in "+-*/"):
        try:
            return int(eval(value, {"__builtins__": {}}, {}))  # noqa: S307
        except (SyntaxError, ValueError, ZeroDivisionError):
            return UNKNOWN
    return value


def format_doc_default(value) -> str:
    """Render a Rust/default value for a generated Markdown table cell."""
    if value is UNKNOWN:
        return "—"
    if value is None:
        return "None"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        return json.dumps(value)
    if isinstance(value, (list, dict)):
        return json.dumps(value, ensure_ascii=False)
    return str(value)


def defaults_equal(expected, documented) -> bool | None:
    """Return True/False, or None when the comparison is not meaningful."""
    if expected is UNKNOWN:
        return None
    if expected is None or documented is None:
        return expected is None and documented is None
    if documented is REQUIRED:
        return False
    if isinstance(expected, bool) or isinstance(documented, bool):
        return expected is documented
    if isinstance(expected, (int, float)) or isinstance(documented, (int, float)):
        return expected == documented
    if isinstance(expected, list) or isinstance(documented, list):
        return expected == documented
    if isinstance(expected, dict) or isinstance(documented, dict):
        return expected == documented
    return str(expected) == str(documented)


def prefix_for(section: int, struct_name: str, struct_count: int) -> str:
    explicit = PREFIX_BY_STRUCT.get((section, struct_name))
    if explicit is not None:
        return explicit
    if struct_count > 1:
        return struct_name.lower().removesuffix("config") + "."
    return ""


def write_missing_rows() -> list[str]:
    """Appends placeholder rows for undocumented struct fields.

    Existing rows, prose and TOML examples are preserved; only new rows with a
    TODO description are added, so authors can fill in wording without the CI
    check failing on the intermediate state.
    """
    field_cache: dict[Path, dict[str, dict[str, dict[str, object]]]] = {}
    lines = DOC.read_text().splitlines()
    documented = parse_documented_keys()
    added: list[str] = []

    for number, (title, sources) in SECTIONS.items():
        structs: dict[str, dict[str, dict[str, object]]] = {}
        for rel, struct_name in sources:
            path = ROOT / rel
            if path not in field_cache:
                field_cache[path] = parse_struct_fields(path)
            structs[struct_name] = field_cache[path].get(struct_name, {})

        documented_keys = set(documented.get(number, []))
        skip_reverse = SKIP_REVERSE_BY_SECTION.get(number, set())
        expected: dict[str, dict[str, object]] = {}
        for struct_name, fields in structs.items():
            prefix = prefix_for(number, struct_name, len(structs))
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
        # Insert into the section's *main* table, not a later nested sub-table
        # (for example `[[filtering.lists]]`). The first table after the heading
        # is the main key/default table.
        table_start = next(
            (
                i
                for i in range(heading + 1, section_end)
                if lines[i].startswith("|")
            ),
            None,
        )
        if table_start is None:
            continue
        table_end = next(
            (
                i
                for i in range(table_start, section_end)
                if not lines[i].startswith("|")
            ),
            section_end,
        ) - 1

        new_rows = [
            "| `{key}` | {kind} | `{default}` | {description} |".format(
                key=key,
                kind=rust_type_to_doc(str(meta["type"])),
                default=format_doc_default(meta["default"]),
                description=(
                    str(meta["doc"]).replace("|", "\\|")
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

    field_cache: dict[Path, dict[str, dict[str, dict[str, object]]]] = {}
    errors: list[str] = []
    rows = parse_doc_table()
    documented_by_section: dict[int, list[str]] = {}
    for row in rows:
        documented_by_section.setdefault(int(row["section"]), []).append(str(row["key"]))

    for number, (title, sources) in SECTIONS.items():
        structs: dict[str, dict[str, dict[str, object]]] = {}
        for rel, struct_name in sources:
            path = ROOT / rel
            if path not in field_cache:
                field_cache[path] = parse_struct_fields(path)
            structs[struct_name] = field_cache[path].get(struct_name, {})

        documented = set(documented_by_section.get(number, []))

        for row in [r for r in rows if int(r["section"]) == number]:
            key = str(row["key"])
            owner = owner_for_key(number, key, structs)
            if owner is None:
                errors.append(
                    f"section {number} ({title}) line {row['line']}: documented key `{key}` not found in structs"
                )
                continue
            meta = structs[owner][key.rpartition(".")[2] if "." in key else key]

            expected_type = rust_type_to_doc(str(meta["type"]))
            documented_type = normalize_doc_type(str(row["type"]))
            if expected_type != "value" and documented_type != expected_type:
                errors.append(
                    f"section {number} ({title}) line {row['line']}: `{key}` is typed "
                    f"`{row['type']}` in docs but `{expected_type}` in Rust ({meta['type']})"
                )

            expected_default = meta["default"]
            documented_default = parse_doc_default(str(row["default_raw"]))
            is_todo_placeholder = str(row.get("description", "")).strip().startswith("TODO:")
            placeholder_default = str(row["default_raw"]).strip().strip("`").strip() == "—"
            if is_todo_placeholder and placeholder_default:
                # `--write` emits `—` only when the Rust default is not safely
                # extractable. The author must replace it when filling the row.
                match = None
            else:
                match = defaults_equal(expected_default, documented_default)
            if match is False:
                if expected_default is UNKNOWN:
                    expected_display = "required/not extractable"
                else:
                    expected_display = repr(expected_default)
                errors.append(
                    f"section {number} ({title}) line {row['line']}: `{key}` default is "
                    f"`{row['default_raw']}` in docs but {expected_display} in Rust"
                )

        # Reverse direction: every pub field of the section structs must appear.
        expected_keys: set[str] = set()
        for struct_name in structs:
            prefix = prefix_for(number, struct_name, len(structs))
            expected_keys |= {prefix + field for field in structs[struct_name]}
        skip_reverse = SKIP_REVERSE_BY_SECTION.get(number, set())

        for key in sorted(expected_keys - documented - skip_reverse):
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
    print(
        f"configuration reference OK ({total} documented keys checked; "
        "types and extractable defaults validated)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
