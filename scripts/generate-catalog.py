#!/usr/bin/env python3
"""Generate the release-bound filter/service catalog embedded in ``sito-clients``.

The catalog is built from the AdGuard HostlistsRegistry indexes:

* ``filters.json`` -- filter metadata (names, categories, descriptions, URLs);
* ``services.json`` -- blocked-service metadata and their small block rules.

Only **metadata** is embedded. Filter-list bodies (the downloadable ``.txt``
lists) are never read or included. ``services.json`` rules are short
``||domain^`` service-block rules and are part of the catalog; SVG icons are
deliberately omitted from the 2.0 catalog.

The output is deterministic: stable key order, sorted categories/filters/
services/groups/rules/languages, no generation timestamps or other volatile
data. Re-running the generator against the same indexes must produce identical
bytes.

Usage::

    python3 scripts/generate-catalog.py                     # fetch and write
    python3 scripts/generate-catalog.py --filters-file F \\
        --services-file S                                   # write from files
    python3 scripts/generate-catalog.py --check             # offline tamper check

``--check`` never touches the network. Without ``--filters-file`` and
``--services-file`` it is an offline tamper/canonicalization guard: the
committed catalog's raw bytes must match the pinned ``CATALOG_SHA256`` digest,
and its structure must match the canonical bytes the generator would emit for
that data. Removed or changed filters/services, changed names/URLs/
descriptions/versions, unknown fields, unsorted entries, CRLF line endings and
any other formatting change all fail.

When both local index files are supplied it re-generates the catalog from them
and compares that output with the committed file. Use this (or a normal
generation run against the live indexes) for the release-time upstream drift
check. After an intentional catalog change, regenerate and update
``CATALOG_SHA256`` to the digest printed by the generator.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUT = ROOT / "crates" / "sito-clients" / "src" / "catalog" / "catalog.json"

FILTERS_URL = "https://adguardteam.github.io/HostlistsRegistry/assets/filters.json"
SERVICES_URL = "https://adguardteam.github.io/HostlistsRegistry/assets/services.json"

CATALOG_VERSION = 1
CATALOG_LICENSE = "GPL-3.0-only"

# SHA-256 of the exact committed catalog bytes. The no-input ``--check`` path
# compares the file against this pin, so any content or formatting edit fails
# even when the result still parses and canonicalises cleanly. Update this
# value whenever the catalog is intentionally regenerated; the generator
# prints the new digest.
CATALOG_SHA256 = "957d814e1e0c64c486014d1a164f6535cdaf7b5ab600333e86a49d0d4998adde"

# AdGuard HostlistsRegistry filter group ids -> stable sito category ids.
FILTER_GROUP_CATEGORIES = {
    1: "general",
    2: "other",
    3: "regional",
    4: "security",
}

TOP_LEVEL_FIELDS = (
    "catalog_version",
    "source",
    "categories",
    "service_groups",
    "filters",
    "services",
)
SOURCE_FIELDS = ("filters", "services", "license")
CATEGORY_FIELDS = ("id", "name", "display_number")
FILTER_FIELDS = (
    "id",
    "name",
    "category",
    "description",
    "homepage",
    "download_url",
    "subscription_url",
    "version",
    "expires_secs",
    "display_number",
    "languages",
    "deprecated",
)
SERVICE_FIELDS = ("id", "name", "group", "rules")

# Fields that would indicate filter-list text/body leaked into the catalog.
FORBIDDEN_FILTER_FIELDS = frozenset(
    {
        "body",
        "content",
        "filter_text",
        "list",
        "raw",
        "rules",
        "source_text",
        "text",
    }
)


class CatalogError(RuntimeError):
    """Raised when upstream data or the committed catalog is invalid."""


def _require_object(value: Any, context: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CatalogError(f"{context} must be a JSON object")
    return value


def _require_list(value: Any, context: str) -> list[Any]:
    if not isinstance(value, list):
        raise CatalogError(f"{context} must be a JSON array")
    return value


def _require_str(
    obj: dict[str, Any], key: str, context: str, *, allow_empty: bool = False
) -> str:
    value = obj.get(key)
    if not isinstance(value, str):
        raise CatalogError(f"{context}.{key} must be a string")
    text = value.strip()
    if not text and not allow_empty:
        raise CatalogError(f"{context}.{key} must not be empty")
    return text


def _require_int(obj: dict[str, Any], key: str, context: str) -> int:
    value = obj.get(key)
    if not isinstance(value, int) or isinstance(value, bool):
        raise CatalogError(f"{context}.{key} must be an integer")
    return value


def _require_str_list(value: Any, context: str, *, require_nonempty: bool) -> list[str]:
    items = _require_list(value, context)
    if require_nonempty and not items:
        raise CatalogError(f"{context} must not be empty")
    result: list[str] = []
    for index, item in enumerate(items):
        if not isinstance(item, str) or not item.strip():
            raise CatalogError(f"{context}[{index}] must be a non-empty string")
        result.append(item.strip())
    return result


def _check_exact_fields(obj: dict[str, Any], fields: tuple[str, ...], context: str) -> None:
    expected = set(fields)
    actual = set(obj)
    missing = expected - actual
    extra = actual - expected
    if missing:
        raise CatalogError(f"{context} is missing field(s): {', '.join(sorted(missing))}")
    if extra:
        raise CatalogError(f"{context} has unexpected field(s): {', '.join(sorted(extra))}")


def _fetch_json(url: str) -> Any:
    request = urllib.request.Request(
        url, headers={"User-Agent": f"sito-catalog-generator/{CATALOG_VERSION}"}
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:  # noqa: S310
            payload = response.read()
    except (urllib.error.URLError, OSError) as exc:
        raise CatalogError(f"could not fetch {url}: {exc}") from exc
    try:
        return json.loads(payload)
    except json.JSONDecodeError as exc:
        raise CatalogError(f"{url} is not valid JSON: {exc}") from exc


def _load_json(path: Path) -> Any:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise CatalogError(f"could not read {path}: {exc}") from exc
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise CatalogError(f"{path} is not valid JSON: {exc}") from exc


def _build_categories(filters_doc: dict[str, Any]) -> list[dict[str, Any]]:
    groups = _require_list(filters_doc.get("groups"), "filters index 'groups'")
    categories: list[dict[str, Any]] = []
    seen_groups: set[int] = set()
    for index, raw in enumerate(groups):
        group = _require_object(raw, f"filters index groups[{index}]")
        group_id = _require_int(group, "groupId", f"groups[{index}]")
        if group_id in seen_groups:
            raise CatalogError(f"duplicate filter group id {group_id}")
        seen_groups.add(group_id)
        category_id = FILTER_GROUP_CATEGORIES.get(group_id)
        if category_id is None:
            raise CatalogError(
                f"unknown filter group id {group_id}; known ids are "
                f"{', '.join(str(key) for key in sorted(FILTER_GROUP_CATEGORIES))}"
            )
        display_number = _require_int(group, "displayNumber", f"groups[{index}]")
        if display_number <= 0:
            raise CatalogError(f"groups[{index}].displayNumber must be positive")
        categories.append(
            {
                "id": category_id,
                "name": _require_str(group, "groupName", f"groups[{index}]"),
                "display_number": display_number,
            }
        )

    expected = set(FILTER_GROUP_CATEGORIES.values())
    actual = {category["id"] for category in categories}
    if actual != expected:
        missing = ", ".join(sorted(expected - actual)) or "none"
        raise CatalogError(f"filters index is missing category group(s): {missing}")
    return categories


def _build_filters(
    filters_doc: dict[str, Any], category_ids: set[str]
) -> list[dict[str, Any]]:
    raw_filters = _require_list(filters_doc.get("filters"), "filters index 'filters'")
    if not raw_filters:
        raise CatalogError("filters index contains no filters")

    filters: list[dict[str, Any]] = []
    seen_keys: set[str] = set()
    seen_ids: set[int] = set()
    for index, raw in enumerate(raw_filters):
        context = f"filters[{index}]"
        entry = _require_object(raw, context)
        filter_key = _require_str(entry, "filterKey", context)
        numeric_id = _require_int(entry, "filterId", context)
        if filter_key in seen_keys:
            raise CatalogError(f"duplicate filter key '{filter_key}'")
        if numeric_id in seen_ids:
            raise CatalogError(f"duplicate filter id {numeric_id}")
        seen_keys.add(filter_key)
        seen_ids.add(numeric_id)

        group_id = _require_int(entry, "groupId", context)
        category = FILTER_GROUP_CATEGORIES.get(group_id)
        if category is None:
            raise CatalogError(
                f"{context} references unknown filter group id {group_id}"
            )
        if category not in category_ids:
            raise CatalogError(
                f"{context} maps to category '{category}' missing from groups"
            )

        expires_secs = _require_int(entry, "expires", context)
        if expires_secs <= 0:
            raise CatalogError(f"{context}.expires must be positive")
        display_number = _require_int(entry, "displayNumber", context)
        if display_number <= 0:
            raise CatalogError(f"{context}.displayNumber must be positive")

        deprecated = entry.get("deprecated", False)
        if not isinstance(deprecated, bool):
            raise CatalogError(f"{context}.deprecated must be a boolean")

        languages = _require_str_list(
            entry.get("languages", []), f"{context}.languages", require_nonempty=False
        )
        filters.append(
            {
                "id": filter_key,
                "name": _require_str(entry, "name", context),
                "category": category,
                "description": _require_str(entry, "description", context),
                "homepage": _require_str(entry, "homepage", context),
                "download_url": _require_str(entry, "downloadUrl", context),
                "subscription_url": _require_str(entry, "subscriptionUrl", context),
                "version": _require_str(entry, "version", context),
                "expires_secs": expires_secs,
                "display_number": display_number,
                "languages": sorted(set(languages)),
                "deprecated": deprecated,
            }
        )
    return filters


def _build_services(services_doc: dict[str, Any]) -> tuple[list[str], list[dict[str, Any]]]:
    raw_groups = _require_list(services_doc.get("groups"), "services index 'groups'")
    service_groups: list[str] = []
    seen_groups: set[str] = set()
    for index, raw in enumerate(raw_groups):
        group = _require_object(raw, f"services index groups[{index}]")
        group_id = _require_str(group, "id", f"services index groups[{index}]")
        if group_id in seen_groups:
            raise CatalogError(f"duplicate service group id '{group_id}'")
        seen_groups.add(group_id)
        service_groups.append(group_id)
    if not service_groups:
        raise CatalogError("services index contains no groups")

    raw_services = _require_list(
        services_doc.get("blocked_services"), "services index 'blocked_services'"
    )
    if not raw_services:
        raise CatalogError("services index contains no blocked services")

    services: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for index, raw in enumerate(raw_services):
        context = f"blocked_services[{index}]"
        entry = _require_object(raw, context)
        service_id = _require_str(entry, "id", context)
        if service_id in seen_ids:
            raise CatalogError(f"duplicate service id '{service_id}'")
        seen_ids.add(service_id)

        group_id = _require_str(entry, "group", context)
        if group_id not in seen_groups:
            raise CatalogError(
                f"{context} references unknown service group '{group_id}'"
            )
        rules = _require_str_list(
            entry.get("rules"), f"{context}.rules", require_nonempty=True
        )
        services.append(
            {
                "id": service_id,
                "name": _require_str(entry, "name", context),
                "group": group_id,
                "rules": sorted(set(rules)),
            }
        )
    return sorted(service_groups), services


def build_catalog(filters_doc: Any, services_doc: Any) -> dict[str, Any]:
    """Builds and validates a canonical catalog from the two upstream indexes."""
    filters_index = _require_object(filters_doc, "filters index")
    services_index = _require_object(services_doc, "services index")

    categories = _build_categories(filters_index)
    category_ids = {category["id"] for category in categories}
    filters = _build_filters(filters_index, category_ids)
    if not filters:
        raise CatalogError("catalog contains no filters")
    service_groups, services = _build_services(services_index)

    catalog = {
        "catalog_version": CATALOG_VERSION,
        "source": {
            "filters": FILTERS_URL,
            "services": SERVICES_URL,
            "license": CATALOG_LICENSE,
        },
        "categories": categories,
        "service_groups": service_groups,
        "filters": filters,
        "services": services,
    }
    return canonicalize_output(catalog)


def validate_output(catalog: Any) -> None:
    """Validates the generated catalog schema and every invariant."""
    root = _require_object(catalog, "catalog")
    _check_exact_fields(root, TOP_LEVEL_FIELDS, "catalog")

    version = _require_int(root, "catalog_version", "catalog")
    if version != CATALOG_VERSION:
        raise CatalogError(
            f"unsupported catalog_version {version}; expected {CATALOG_VERSION}"
        )

    source = _require_object(root.get("source"), "catalog.source")
    _check_exact_fields(source, SOURCE_FIELDS, "catalog.source")
    if _require_str(source, "filters", "catalog.source") != FILTERS_URL:
        raise CatalogError("catalog.source.filters does not match the generator URL")
    if _require_str(source, "services", "catalog.source") != SERVICES_URL:
        raise CatalogError("catalog.source.services does not match the generator URL")
    if _require_str(source, "license", "catalog.source") != CATALOG_LICENSE:
        raise CatalogError("catalog.source.license does not match the generator license")

    raw_categories = _require_list(root.get("categories"), "catalog.categories")
    if not raw_categories:
        raise CatalogError("catalog.categories must not be empty")
    category_ids: set[str] = set()
    for index, raw in enumerate(raw_categories):
        context = f"catalog.categories[{index}]"
        category = _require_object(raw, context)
        _check_exact_fields(category, CATEGORY_FIELDS, context)
        category_id = _require_str(category, "id", context)
        if category_id in category_ids:
            raise CatalogError(f"duplicate category id '{category_id}'")
        category_ids.add(category_id)
        _require_str(category, "name", context)
        display_number = _require_int(category, "display_number", context)
        if display_number <= 0:
            raise CatalogError(f"{context}.display_number must be positive")

    expected_categories = set(FILTER_GROUP_CATEGORIES.values())
    if category_ids != expected_categories:
        raise CatalogError(
            "catalog.categories must contain exactly "
            + ", ".join(sorted(expected_categories))
        )

    raw_filters = _require_list(root.get("filters"), "catalog.filters")
    if not raw_filters:
        raise CatalogError("catalog.filters must not be empty")
    filter_ids: set[str] = set()
    used_categories: set[str] = set()
    for index, raw in enumerate(raw_filters):
        context = f"catalog.filters[{index}]"
        entry = _require_object(raw, context)
        forbidden = FORBIDDEN_FILTER_FIELDS.intersection(entry)
        if forbidden:
            raise CatalogError(
                f"{context} contains filter-body field(s): {', '.join(sorted(forbidden))}"
            )
        _check_exact_fields(entry, FILTER_FIELDS, context)

        filter_id = _require_str(entry, "id", context)
        if filter_id in filter_ids:
            raise CatalogError(f"duplicate filter id '{filter_id}'")
        filter_ids.add(filter_id)

        category = _require_str(entry, "category", context)
        if category not in category_ids:
            raise CatalogError(
                f"{context} references unknown category '{category}'"
            )
        used_categories.add(category)

        for field in (
            "name",
            "description",
            "homepage",
            "download_url",
            "subscription_url",
            "version",
        ):
            _require_str(entry, field, context)
        expires_secs = _require_int(entry, "expires_secs", context)
        if expires_secs <= 0:
            raise CatalogError(f"{context}.expires_secs must be positive")
        display_number = _require_int(entry, "display_number", context)
        if display_number <= 0:
            raise CatalogError(f"{context}.display_number must be positive")
        _require_str_list(
            entry.get("languages"), f"{context}.languages", require_nonempty=False
        )
        deprecated = entry.get("deprecated")
        if not isinstance(deprecated, bool):
            raise CatalogError(f"{context}.deprecated must be a boolean")

    missing_categories = category_ids - used_categories
    if missing_categories:
        raise CatalogError(
            "catalog category/categories without filters: "
            + ", ".join(sorted(missing_categories))
        )

    raw_groups = _require_list(root.get("service_groups"), "catalog.service_groups")
    if not raw_groups:
        raise CatalogError("catalog.service_groups must not be empty")
    service_groups: set[str] = set()
    for index, raw in enumerate(raw_groups):
        if not isinstance(raw, str) or not raw.strip():
            raise CatalogError(
                f"catalog.service_groups[{index}] must be a non-empty string"
            )
        group_id = raw.strip()
        if group_id in service_groups:
            raise CatalogError(f"duplicate service group id '{group_id}'")
        service_groups.add(group_id)

    raw_services = _require_list(root.get("services"), "catalog.services")
    if not raw_services:
        raise CatalogError("catalog.services must not be empty")
    service_ids: set[str] = set()
    for index, raw in enumerate(raw_services):
        context = f"catalog.services[{index}]"
        entry = _require_object(raw, context)
        _check_exact_fields(entry, SERVICE_FIELDS, context)
        service_id = _require_str(entry, "id", context)
        if service_id in service_ids:
            raise CatalogError(f"duplicate service id '{service_id}'")
        service_ids.add(service_id)
        _require_str(entry, "name", context)
        group_id = _require_str(entry, "group", context)
        if group_id not in service_groups:
            raise CatalogError(
                f"{context} references unknown service group '{group_id}'"
            )
        _require_str_list(
            entry.get("rules"), f"{context}.rules", require_nonempty=True
        )


def canonicalize_output(catalog: dict[str, Any]) -> dict[str, Any]:
    """Returns the fully sorted, fixed-key-order representation of a catalog."""
    validate_output(catalog)

    categories = [
        {
            "id": category["id"],
            "name": category["name"],
            "display_number": category["display_number"],
        }
        for category in sorted(
            catalog["categories"],
            key=lambda item: (item["display_number"], item["id"]),
        )
    ]
    category_order = {
        category["id"]: category["display_number"] for category in categories
    }
    filters = [
        {
            "id": entry["id"],
            "name": entry["name"],
            "category": entry["category"],
            "description": entry["description"],
            "homepage": entry["homepage"],
            "download_url": entry["download_url"],
            "subscription_url": entry["subscription_url"],
            "version": entry["version"],
            "expires_secs": entry["expires_secs"],
            "display_number": entry["display_number"],
            "languages": sorted(set(entry["languages"])),
            "deprecated": entry["deprecated"],
        }
        for entry in sorted(
            catalog["filters"],
            key=lambda item: (
                category_order[item["category"]],
                item["display_number"],
                item["id"],
            ),
        )
    ]
    services = [
        {
            "id": entry["id"],
            "name": entry["name"],
            "group": entry["group"],
            "rules": sorted(set(entry["rules"])),
        }
        for entry in sorted(catalog["services"], key=lambda item: item["id"])
    ]
    return {
        "catalog_version": catalog["catalog_version"],
        "source": {
            "filters": catalog["source"]["filters"],
            "services": catalog["source"]["services"],
            "license": catalog["source"]["license"],
        },
        "categories": categories,
        "service_groups": sorted(set(catalog["service_groups"])),
        "filters": filters,
        "services": services,
    }


def render(catalog: dict[str, Any]) -> str:
    """Serialises a catalog to the committed on-disk format."""
    return json.dumps(catalog, ensure_ascii=False, indent=2, sort_keys=False) + "\n"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _describe_drift(expected: str, actual: str) -> str:
    expected_lines = expected.splitlines()
    actual_lines = actual.splitlines()
    for line_number, (want, got) in enumerate(
        zip(expected_lines, actual_lines), start=1
    ):
        if want != got:
            return (
                f"first difference at line {line_number}:\n"
                f"  committed: {got[:200]}\n"
                f"  generated: {want[:200]}"
            )
    if len(expected_lines) != len(actual_lines):
        return (
            f"committed file has {len(actual_lines)} lines, "
            f"generated output has {len(expected_lines)}"
        )
    return "byte-level difference (for example, a missing final newline)"


def run_generate(args: argparse.Namespace) -> int:
    filters_doc = (
        _load_json(Path(args.filters_file))
        if args.filters_file
        else _fetch_json(FILTERS_URL)
    )
    services_doc = (
        _load_json(Path(args.services_file))
        if args.services_file
        else _fetch_json(SERVICES_URL)
    )
    catalog = build_catalog(filters_doc, services_doc)
    rendered = render(catalog)
    rendered_bytes = rendered.encode("utf-8")

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    if out.exists() and out.read_bytes() == rendered_bytes:
        print(f"catalog unchanged: {out}")
    else:
        out.write_bytes(rendered_bytes)
        print(
            f"wrote {len(catalog['filters'])} filters and "
            f"{len(catalog['services'])} services to {out}"
        )

    digest = _sha256(rendered_bytes)
    if digest != CATALOG_SHA256:
        print(
            "note: catalog SHA-256 changed; update CATALOG_SHA256 in "
            f"scripts/generate-catalog.py to {digest}",
            file=sys.stderr,
        )
    return 0


def run_check(args: argparse.Namespace) -> int:
    if bool(args.filters_file) != bool(args.services_file):
        raise CatalogError(
            "--check requires both --filters-file and --services-file, or neither"
        )

    out = Path(args.out)
    if not out.exists():
        raise CatalogError(f"committed catalog does not exist: {out}")
    committed_bytes = out.read_bytes()
    digest = _sha256(committed_bytes)
    if digest != CATALOG_SHA256:
        print(
            f"catalog tamper detected: {out} SHA-256 {digest} "
            f"does not match pinned {CATALOG_SHA256}",
            file=sys.stderr,
        )
        print(
            "If this change is intentional, run "
            "`python3 scripts/generate-catalog.py` and update CATALOG_SHA256 "
            "to the digest it prints.",
            file=sys.stderr,
        )
        return 1
    try:
        committed = committed_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CatalogError(f"{out} is not valid UTF-8: {exc}") from exc

    if args.filters_file:
        generated = render(
            build_catalog(
                _load_json(Path(args.filters_file)),
                _load_json(Path(args.services_file)),
            )
        )
    else:
        try:
            document = json.loads(committed)
        except json.JSONDecodeError as exc:
            raise CatalogError(f"{out} is not valid JSON: {exc}") from exc
        generated = render(canonicalize_output(document))

    if committed != generated:
        print(
            f"catalog drift detected: {out} is not the generated output",
            file=sys.stderr,
        )
        print(_describe_drift(generated, committed), file=sys.stderr)
        print(
            "Run `python3 scripts/generate-catalog.py` and commit the result.",
            file=sys.stderr,
        )
        return 1

    print(f"catalog check passed: {out} is up to date")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Generate or check the embedded HostlistsRegistry metadata catalog."
        )
    )
    parser.add_argument(
        "--filters-file",
        help="local filters.json (default: fetch the HostlistsRegistry index)",
    )
    parser.add_argument(
        "--services-file",
        help="local services.json (default: fetch the HostlistsRegistry index)",
    )
    parser.add_argument(
        "--out",
        default=str(DEFAULT_OUT),
        help=f"catalog output path (default: {DEFAULT_OUT})",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify the committed catalog without network access",
    )
    args = parser.parse_args(argv)

    try:
        if args.check:
            return run_check(args)
        return run_generate(args)
    except CatalogError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
