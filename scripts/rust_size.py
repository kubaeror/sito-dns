#!/usr/bin/env python3
"""Shared Rust production-size helpers for the structural CI checks.

"Production" means source that is compiled into the shipped binary/library:
items gated behind ``#[cfg(test)]`` (modules, functions, imports, statics) and
the test-only crates ``sito-test``/``sito-test-support`` are excluded. Blank
lines are counted, so the metric is conservative and matches how a reviewer
reads a file.

The parser is intentionally dependency-free. It masks comments and string
literals, tracks brace spans, and records the line span of every
``#[cfg(test)]`` item. Both checkers consume the same data so they cannot
disagree about what counts as production code.
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
TEST_ONLY_CRATES = {"sito-test", "sito-test-support"}
TEST_ATTR_RE = re.compile(r"^\s*#\[cfg\(test\)\]\s*$")

# Items that end with a semicolon rather than a braced body.
SEMICOLON_ITEMS = (
    "use ",
    "pub use ",
    "const ",
    "pub const ",
    "static ",
    "pub static ",
    "type ",
    "pub type ",
    "extern crate ",
    "mod ",
    "pub mod ",
)
BRACED_ITEMS = (
    "fn ",
    "pub fn ",
    "pub(crate) fn ",
    "pub(super) fn ",
    "async fn ",
    "pub async fn ",
    "pub(crate) async fn ",
    "pub(super) async fn ",
    "const fn ",
    "pub const fn ",
    "unsafe fn ",
    "pub unsafe fn ",
    "mod ",
    "pub mod ",
    "impl",
    "struct ",
    "pub struct ",
    "enum ",
    "pub enum ",
    "union ",
    "pub union ",
    "trait ",
    "pub trait ",
    "macro_rules!",
)


@dataclass(frozen=True)
class FunctionSpan:
    name: str
    line_start: int  # 1-based, signature line
    line_end: int  # 1-based, closing brace line
    body_start: int  # 1-based line containing the opening brace
    body_end: int  # 1-based line containing the closing brace

    @property
    def line_count(self) -> int:
        return self.line_end - self.line_start + 1


def mask_rust(source: str) -> str:
    """Replace comments/strings with spaces while preserving newlines/offsets."""
    out = list(source)
    i = 0
    n = len(source)

    def blank(start: int, end: int) -> None:
        for j in range(start, min(end, n)):
            if out[j] != "\n":
                out[j] = " "

    while i < n:
        ch = source[i]
        nxt = source[i + 1] if i + 1 < n else ""
        if ch == "/" and nxt == "/":
            end = source.find("\n", i)
            if end == -1:
                end = n
            blank(i, end)
            i = end
            continue
        if ch == "/" and nxt == "*":
            depth = 1
            j = i + 2
            while j < n and depth:
                if source.startswith("/*", j):
                    depth += 1
                    j += 2
                elif source.startswith("*/", j):
                    depth -= 1
                    j += 2
                else:
                    j += 1
            blank(i, j)
            i = j
            continue
        # Raw strings: r"..." or r#"..."# (optionally b/br prefixed).
        if ch in ("r", "b") and (nxt in ('"', "#") or (ch == "b" and source.startswith('r"', i))):
            start = i
            if ch == "b" and source.startswith('r"', i):
                j = i + 2
                hashes = 0
            elif ch == "r":
                j = i + 1
                hashes = 0
                while j < n and source[j] == "#":
                    hashes += 1
                    j += 1
                if j >= n or source[j] != '"':
                    i += 1
                    continue
            elif source.startswith('b"', i):
                j = i + 1
                hashes = -1  # normal byte string
            else:
                i += 1
                continue
            if hashes == -1:
                # Normal byte string, handled by the plain string path below.
                i += 1
                continue
            j += 1  # opening quote
            closing = '"' + "#" * hashes
            end = source.find(closing, j)
            end = n if end == -1 else end + len(closing)
            blank(start, end)
            i = end
            continue
        if ch == '"':
            start = i
            j = i + 1
            while j < n:
                if source[j] == "\\":
                    j += 2
                elif source[j] == '"':
                    j += 1
                    break
                else:
                    j += 1
            blank(start, j)
            i = j
            continue
        if ch == "'":
            # Char literal or lifetime. A lifetime has no closing quote.
            if nxt == "\\":
                end = source.find("'", i + 2)
                end = n if end == -1 else end + 1
                blank(i, end)
                i = end
                continue
            if i + 2 < n and source[i + 2] == "'":
                blank(i, i + 3)
                i += 3
                continue
        i += 1
    return "".join(out)


def _match_brace(masked: str, open_index: int) -> int:
    depth = 0
    for j in range(open_index, len(masked)):
        if masked[j] == "{":
            depth += 1
        elif masked[j] == "}":
            depth -= 1
            if depth == 0:
                return j
    return len(masked) - 1


def _line_of(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


ITEM_KEYWORDS = (
    "fn",
    "mod",
    "use",
    "impl",
    "struct",
    "enum",
    "union",
    "trait",
    "const",
    "static",
    "type",
    "extern",
    "macro_rules!",
    "pub",
    "async",
    "unsafe",
)


def _find_item_end(masked: str, start: int) -> int:
    """Return the exclusive end index of the item starting at ``start``.

    ``#[cfg(test)]`` can gate items, imports, fields, enum variants, match arms,
    and statements. Items end at a braced body or semicolon; everything else
    (a struct field, variant, match arm, or statement) ends at the top-level
    comma/semicolon, or just before the enclosing closing brace.
    """
    # Skip leading attributes and doc comments. Only the single-line form is
    # used for cfg(test); other attributes may be multi-line and are skipped
    # line by line until the item body begins.
    while True:
        match = re.match(r"\s*(#\[[^\n]*\]|///[^\n]*|//!\[[^\n]*\])", masked[start:])
        if not match:
            break
        start += match.end()
    start += re.match(r"\s*", masked[start:]).end()
    line_end = masked.find("\n", start)
    first_line = masked[start:] if line_end == -1 else masked[start:line_end]
    stripped = first_line.lstrip()
    first_word = re.match(r"[A-Za-z_][A-Za-z0-9_!]*", stripped)
    is_item = bool(first_word and first_word.group(0) in ITEM_KEYWORDS)
    block_statement = bool(
        re.match(r"(if|match|for|while|loop|unsafe)\b", stripped)
    )
    if stripped.startswith("{") or block_statement:
        # `#[cfg(test)] if ... {}` and friends are expression statements with
        # no trailing semicolon. End at the block (plus any `else` arms)
        # instead of scanning forward to the next unrelated semicolon, which
        # would blank production code and distort both size metrics.
        brace = masked.find("{", start)
        if brace == -1:
            return start
        end = _match_brace(masked, brace) + 1
        while True:
            rest = masked[end:]
            match = re.match(r"\s*else\b", rest)
            if not match:
                break
            next_brace = masked.find("{", end + match.end())
            if next_brace == -1:
                break
            end = _match_brace(masked, next_brace) + 1
        return end
    if is_item:
        semicolon_first = any(stripped.startswith(prefix) for prefix in SEMICOLON_ITEMS)
        # `mod x;` and `use ...;` have no body even if a later `{` exists.
        if semicolon_first:
            semi = masked.find(";", start)
            brace = masked.find("{", start)
            if semi != -1 and (brace == -1 or semi < brace):
                return semi + 1
        brace = masked.find("{", start)
        semi = masked.find(";", start)
        if brace != -1 and (semi == -1 or brace < semi):
            return _match_brace(masked, brace) + 1
        return (semi + 1) if semi != -1 else len(masked)

    # Field / variant / match arm / statement: scan to a top-level terminator.
    depth = 0
    j = start
    n = len(masked)
    while j < n:
        ch = masked[j]
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                # Do not blank the enclosing closing brace.
                return max(start, j - 1)
            depth -= 1
        elif ch == "," and depth == 0:
            return j + 1
        elif ch == ";" and depth == 0:
            return j + 1
        j += 1
    return n


def test_spans(source: str, masked: str) -> list[tuple[int, int]]:
    """Return ``(start_line, end_line)`` spans for every ``#[cfg(test)]`` item.

    Detection runs on the masked text so an attribute mentioned in a comment or
    string cannot hide production code from the size gate.
    """
    spans: list[tuple[int, int]] = []
    offset = 0
    for line in masked.splitlines(keepends=True):
        if TEST_ATTR_RE.match(line.rstrip("\n")):
            start = offset
            end = _find_item_end(masked, offset + len(line))
            spans.append((_line_of(source, start), _line_of(source, end)))
        offset += len(line)
    return spans


def production_source(source: str) -> tuple[str, list[tuple[int, int]]]:
    """Mask out test-only items; return masked production text and the spans."""
    masked = mask_rust(source)
    spans = test_spans(source, masked)
    chars = list(masked)
    for start_line, end_line in spans:
        start_offset = _offset_of_line(masked, start_line)
        end_offset = _offset_of_line(masked, end_line + 1) if end_line < len(source.splitlines()) else len(chars)
        for j in range(start_offset, end_offset):
            if chars[j] != "\n":
                chars[j] = " "
    return "".join(chars), spans


def _offset_of_line(text: str, line: int) -> int:
    if line <= 1:
        return 0
    offset = 0
    for _ in range(line - 1):
        nl = text.find("\n", offset)
        if nl == -1:
            return len(text)
        offset = nl + 1
    return offset


def production_line_count(source: str, spans: list[tuple[int, int]]) -> int:
    lines = source.splitlines()
    excluded: set[int] = set()
    for start, end in spans:
        excluded.update(range(start, end + 1))
    return sum(1 for number in range(1, len(lines) + 1) if number not in excluded)


def find_functions(masked: str) -> list[FunctionSpan]:
    """Find function items in masked source and measure their line spans."""
    functions: list[FunctionSpan] = []
    for match in re.finditer(r"(?<![A-Za-z0-9_])fn\s+([A-Za-z_][A-Za-z0-9_]*)", masked):
        # Skip function-pointer types (`fn(...)`) and trait method declarations.
        before = masked[max(0, match.start() - 24) : match.start()]
        if re.search(r"\btype\s+\w+\s*=\s*$", before):
            continue
        name = match.group(1)
        open_index = masked.find("{", match.end())
        semi_index = masked.find(";", match.end())
        if open_index == -1 or (semi_index != -1 and semi_index < open_index):
            continue  # declaration without a body
        close_index = _match_brace(masked, open_index)
        functions.append(
            FunctionSpan(
                name=name,
                line_start=_line_of(masked, match.start()),
                line_end=_line_of(masked, close_index),
                body_start=_line_of(masked, open_index),
                body_end=_line_of(masked, close_index),
            )
        )
    return functions


def _declares_test_module(parent: Path) -> bool:
    """True when ``parent`` has a ``#[cfg(test)] mod tests;`` declaration."""
    if not parent.is_file():
        return False
    masked = mask_rust(parent.read_text(encoding="utf-8"))
    return re.search(
        r"(?m)^\s*#\[cfg\(test\)\]\s*\n"
        r"(?:\s*#\[[^\n]*\]\s*\n)*"
        r"\s*(?:pub\s+)?mod\s+tests\s*;",
        masked,
    ) is not None


def _src_tests_parent_gated(root: Path, rel: Path) -> bool:
    """Verify the parent module gate for a ``src/.../tests/`` module."""
    parts = rel.parts
    try:
        src = parts.index("src")
    except ValueError:
        return False
    rest = parts[src + 1 :]
    try:
        tests = rest.index("tests")
    except ValueError:
        return False
    if tests + 1 >= len(rest):
        return False
    crate_root = root / "crates" / parts[0] / "src"
    modules = rest[:tests]
    parents: list[Path] = []
    if not modules:
        parents = [crate_root / "lib.rs", crate_root / "main.rs"]
    else:
        directory = crate_root.joinpath(*modules)
        parents = [directory / "mod.rs", directory.with_suffix(".rs")]
    return any(_declares_test_module(parent) for parent in parents)


def rust_files(root: Path = REPO_ROOT) -> list[Path]:
    files: list[Path] = []
    for path in sorted((root / "crates").rglob("*.rs")):
        rel = path.relative_to(root / "crates")
        if rel.parts and rel.parts[0] in TEST_ONLY_CRATES:
            continue
        # Cargo test/bench/example targets are test code.
        if len(rel.parts) > 2 and rel.parts[1] in {"tests", "benches", "examples"}:
            continue
        # `src/tests/` is test code only when its parent module is gated with
        # `#[cfg(test)] mod tests;`.
        if "src" in rel.parts and "tests" in rel.parts[rel.parts.index("src") + 1 :]:
            if _src_tests_parent_gated(root, rel):
                continue
        files.append(path)
    return files


def has_file_test_gate(masked: str) -> bool:
    """True only for a genuine leading ``#![cfg(test)]`` inner attribute."""
    return re.match(r"\s*#!\[cfg\(test\)\]", masked) is not None


def analyse(path: Path) -> tuple[int, list[FunctionSpan]]:
    source = path.read_text(encoding="utf-8")
    masked = mask_rust(source)
    # A sibling test module carries a leading `#![cfg(test)]`; the whole file
    # is test-only. Comments and strings are already masked, so a mention
    # inside them cannot turn a production file into zero lines.
    if has_file_test_gate(masked):
        return 0, []
    production, spans = production_source(source)
    return production_line_count(source, spans), find_functions(production)


def file_size_violations(limit: int, root: Path = REPO_ROOT) -> list[tuple[Path, int]]:
    violations = []
    for path in rust_files(root):
        count, _ = analyse(path)
        if count > limit:
            violations.append((path.relative_to(root), count))
    return violations


def function_violations(limit: int, root: Path = REPO_ROOT) -> list[tuple[Path, int, FunctionSpan]]:
    violations = []
    for path in rust_files(root):
        _, functions = analyse(path)
        for function in functions:
            if function.line_count > limit:
                violations.append((path.relative_to(root), function.line_count, function))
    return violations


def parse_allowlist(path: Path) -> set[tuple[str, str]]:
    """Parse a Markdown table: | Function | File | ... |."""
    if not path.exists():
        return set()
    entries: set[tuple[str, str]] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip().startswith("|"):
            continue
        cells = [cell.strip().strip("`") for cell in line.strip().strip("|").split("|")]
        if len(cells) < 2:
            continue
        function, file = cells[0], cells[1]
        if function.lower() in {"function", "---"} or set(function) <= {"-", ":", " "}:
            continue
        entries.add((file, function))
    return entries


def main(argv: list[str]) -> int:
    args = list(argv[1:])
    root = REPO_ROOT
    if "--root" in args:
        index = args.index("--root")
        if index + 1 >= len(args):
            print("usage: rust_size.py {files|functions} [--root PATH]", file=sys.stderr)
            return 2
        root = Path(args[index + 1]).resolve()
        del args[index : index + 2]
    if len(args) != 1 or args[0] not in {"files", "functions"}:
        print("usage: rust_size.py {files|functions} [--root PATH]", file=sys.stderr)
        return 2
    if args[0] == "files":
        violations = file_size_violations(2000, root)
        if not violations:
            print("OK: no production Rust file exceeds 2000 lines")
            return 0
        print("FAIL: production Rust files over 2000 lines:")
        for path, count in violations:
            print(f"  {count:>6}  {path}")
        return 1

    allowlist = parse_allowlist(root / "docs" / "large-functions.md")
    all_violations = function_violations(200, root)
    undocumented = [
        (path, count, function)
        for path, count, function in all_violations
        if (str(path), function.name) not in allowlist
    ]
    if not all_violations:
        print("OK: no production Rust function exceeds 200 lines")
        return 0
    for path, count, function in all_violations:
        suffix = "" if (str(path), function.name) in allowlist else "  (undocumented)"
        print(f"{path}:{function.line_start}-{function.line_end} {function.name} ({count} lines){suffix}")
    if undocumented:
        print("FAIL: undocumented production functions over 200 lines (add them to docs/large-functions.md)")
        return 1
    print("OK: every production function over 200 lines is documented in docs/large-functions.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
