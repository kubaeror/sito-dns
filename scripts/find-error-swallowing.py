#!/usr/bin/env python3
"""Find error-swallowing sites on security/apply/persistence/readiness paths.

Prints `path:line:source` for every `let _ = ...` or `... .ok()` statement whose
callee name matches a reviewed keyword. A `let _ =` window is joined until its
parentheses/brackets balance and the statement terminates, so a multi-line
swallow is still detected. Inline `#[cfg(test)]` items and `tests/` targets are
skipped: tests may intentionally exercise failure cleanup without production
error policy. The shell wrapper adds the allowlist check and the human-readable
failure message.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

KEYWORDS = (
    "write_secret_file",
    "reload_all",
    "persist",
    "publish",
    "flush",
    "sync_all",
    "set_permissions",
    "rename",
    "remove_file",
    "write_pair_metadata",
    "record_bootstrap_cert",
    "readiness",
    "health",
    "save",
    "store",
    "unlock",
    "lock",
    "reload",
    "shutdown",
    "lease",
    "bootstrap",
    "write",
    "read",
    "load",
)

IDENT_START = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_")
IDENT_CONT = IDENT_START | set("0123456789")

CALLEE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")
# Formatting macros are not persistence/security operations. Their arguments
# often contain benign atomic `load()`/`store()` calls, which must not be
# mistaken for the swallowed operation.
FORMATTING_MACROS = ("writeln!", "write!", "format!", "print!", "println!", "eprintln!")


def _skip_string(text: str, index: int) -> int:
    """Return the index after a string/char/raw-string starting at `index`."""
    char = text[index]
    if char == "r" and index + 1 < len(text) and text[index + 1] in "#\"":
        cursor = index + 1
        hashes = 0
        while cursor < len(text) and text[cursor] == "#":
            hashes += 1
            cursor += 1
        if cursor < len(text) and text[cursor] == '"':
            cursor += 1
            closing = '"' + "#" * hashes
            end = text.find(closing, cursor)
            return len(text) if end == -1 else end + len(closing)
        return index + 1
    if char == '"':
        cursor = index + 1
        while cursor < len(text):
            if text[cursor] == "\\":
                cursor += 2
                continue
            if text[cursor] == '"':
                return cursor + 1
            cursor += 1
        return cursor
    if char == "'":
        end = text.find("'", index + 2, min(len(text), index + 10))
        if end != -1:
            return end + 1
        return index + 1
    return index + 1


def mask_non_code(text: str) -> str:
    """Replace comments and strings with spaces, preserving newlines."""
    out = list(text)
    index = 0
    while index < len(text):
        char = text[index]
        if char == "/" and index + 1 < len(text) and text[index + 1] == "/":
            end = text.find("\n", index)
            end = len(text) if end == -1 else end
            for pos in range(index, end):
                out[pos] = " "
            index = end
            continue
        if char == "/" and index + 1 < len(text) and text[index + 1] == "*":
            end = text.find("*/", index + 2)
            end = len(text) if end == -1 else end + 2
            for pos in range(index, end):
                if out[pos] != "\n":
                    out[pos] = " "
            index = end
            continue
        if char in ('"', "'") or (
            char == "r" and index + 1 < len(text) and text[index + 1] in "#\""
        ):
            end = _skip_string(text, index)
            for pos in range(index, end):
                if out[pos] != "\n":
                    out[pos] = " "
            index = end
            continue
        index += 1
    return "".join(out)


def _balanced_depth(text: str) -> tuple[int, int, int, bool]:
    """Return (paren, bracket, brace, saw_terminator) for masked text."""
    paren = bracket = brace = 0
    terminator = False
    for char in text:
        if char == "(":
            paren += 1
        elif char == ")":
            paren = max(0, paren - 1)
        elif char == "[":
            bracket += 1
        elif char == "]":
            bracket = max(0, bracket - 1)
        elif char == "{":
            brace += 1
        elif char == "}":
            brace -= 1
        elif char == ";" and paren == 0 and bracket == 0 and brace <= 0:
            terminator = True
    return paren, bracket, brace, terminator


def cfg_test_ranges(source: str) -> list[tuple[int, int]]:
    """Character ranges of `#[cfg(test)]` items, including their bodies."""
    ranges: list[tuple[int, int]] = []
    index = 0
    while True:
        found = source.find("#[cfg(test)]", index)
        if found == -1:
            return ranges
        line_start = source.rfind("\n", 0, found) + 1
        if source[line_start:found].lstrip().startswith("//"):
            index = found + 1
            continue

        cursor = found + len("#[cfg(test)]")
        while True:
            while cursor < len(source) and source[cursor].isspace():
                cursor += 1
            if cursor < len(source) and source[cursor] == "#":
                open_bracket = source.find("[", cursor)
                if open_bracket == -1:
                    break
                depth = 0
                pos = open_bracket
                while pos < len(source):
                    if source[pos] == "[":
                        depth += 1
                    elif source[pos] == "]":
                        depth -= 1
                        if depth == 0:
                            pos += 1
                            break
                    pos += 1
                cursor = pos
                continue
            break

        end = _item_end(source, cursor)
        ranges.append((found, end))
        index = max(end, found + 1)


def _item_end(source: str, start: int) -> int:
    """End offset of the item beginning at `start` (brace/semicolon/comma)."""
    paren = 0
    bracket = 0
    brace = 0
    index = start
    while index < len(source):
        char = source[index]
        if char in ('"', "'") or (
            char == "r" and index + 1 < len(source) and source[index + 1] in "#\""
        ):
            index = _skip_string(source, index)
            continue
        if char == "/" and index + 1 < len(source) and source[index + 1] == "/":
            newline = source.find("\n", index)
            index = len(source) if newline == -1 else newline
            continue
        if char == "/" and index + 1 < len(source) and source[index + 1] == "*":
            close = source.find("*/", index + 2)
            index = len(source) if close == -1 else close + 2
            continue
        if char == "(":
            paren += 1
        elif char == ")":
            paren = max(0, paren - 1)
        elif char == "[":
            bracket += 1
        elif char == "]":
            bracket = max(0, bracket - 1)
        elif char == "{":
            brace += 1
        elif char == "}":
            brace -= 1
            if brace == 0 and paren == 0 and bracket == 0:
                return index + 1
        elif char == ";" and paren == 0 and bracket == 0 and brace == 0:
            return index + 1
        elif char == "," and paren == 0 and bracket == 0 and brace == 0:
            return index + 1
        index += 1
    return len(source)


def _callee_matches(name: str) -> bool:
    lowered = name.lower()
    return any(lowered.startswith(keyword) for keyword in KEYWORDS)


def _let_window(lines: list[str], start: int) -> tuple[int, str]:
    """Join a `let _ =` statement until balanced and terminated."""
    window = []
    for offset in range(start, min(len(lines), start + 30)):
        window.append(lines[offset])
        masked = mask_non_code("\n".join(window))
        paren, bracket, brace, terminator = _balanced_depth(masked)
        if terminator and paren == 0 and bracket == 0 and brace <= 0:
            return offset, "\n".join(window)
    return min(len(lines) - 1, start + 29), "\n".join(window)


def _ok_window(lines: list[str], start: int) -> tuple[int, str]:
    """Join a method chain ending in `.ok()` (up to a few preceding lines)."""
    first = start
    while first > 0 and start - first < 6:
        previous = lines[first - 1].strip()
        current = lines[first].strip()
        if previous.endswith((".", "(", "?", ",", "+")) or current.startswith("."):
            first -= 1
        else:
            break
    return first, "\n".join(lines[first : start + 1])


def _line_of(text: str, offset: int, base_line: int) -> int:
    return base_line + text.count("\n", 0, offset)


def scan_source(source: str) -> list[tuple[int, str]]:
    """Return `(line, source_line)` for each production swallow."""
    lines = source.splitlines()
    source_line_offsets = []
    offset = 0
    for line in lines:
        source_line_offsets.append(offset)
        offset += len(line) + 1
    cfg_ranges = cfg_test_ranges(source)
    findings: set[tuple[int, str]] = set()

    def in_cfg(line_number: int) -> bool:
        if not (1 <= line_number <= len(lines)):
            return False
        offset = source_line_offsets[line_number - 1]
        return any(start <= offset < end for start, end in cfg_ranges)

    def add(line_number: int) -> None:
        if 1 <= line_number <= len(lines) and not in_cfg(line_number):
            findings.add((line_number, lines[line_number - 1].strip()))

    for index, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("//"):
            continue

        if "let _ =" in stripped:
            end, window = _let_window(lines, index)
            masked = mask_non_code(window)
            rhs_offset = masked.find("let _ =") + len("let _ =")
            rhs = masked[rhs_offset:].lstrip()
            if rhs.startswith(FORMATTING_MACROS):
                # Formatting macros swallow only their own write result; their
                # arguments are not the persistence/security operation.
                pass
            else:
                callees = list(CALLEE.finditer(rhs))
                if callees:
                    first = callees[0]
                    if _callee_matches(first.group(1)):
                        add(_line_of(window, rhs_offset + first.start(), index + 1))
                    elif first.group(1) in ("spawn_blocking", "spawn"):
                        # A spawned maintenance closure is still best-effort
                        # work; inspect its body for the flush/reload/etc.
                        for match in callees[1:]:
                            if _callee_matches(match.group(1)):
                                add(_line_of(window, rhs_offset + match.start(), index + 1))
            index = max(index, end)

        if ".ok()" in stripped:
            first, window = _ok_window(lines, index)
            masked = mask_non_code(window)
            ok_offset = masked.rfind(".ok()")
            if ok_offset != -1:
                prefix = masked[:ok_offset]
                callees = list(CALLEE.finditer(prefix))
                if callees and _callee_matches(callees[-1].group(1)):
                    add(_line_of(window, callees[-1].start(), first + 1))

    return sorted(findings)


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else ".")
    for path in sorted(root.glob("crates/**/src/**/*.rs")):
        parts = set(path.parts)
        if "tests" in parts or path.name == "tests.rs":
            continue
        try:
            source = path.read_text()
        except OSError:
            continue
        for line, text in scan_source(source):
            print(f"{path.relative_to(root)}:{line}:{text}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
