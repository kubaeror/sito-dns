#!/usr/bin/env python3
"""Check internal links and heading anchors in tracked Markdown files.

External URLs (http/https/mailto/etc.) are deliberately **not** fetched: a
network link check is flaky and would make docs CI depend on third-party
availability. This checker only verifies repository-local files and `#anchors`
using GitHub's heading-slug rules.

Run with ``--github`` to annotate failures for GitHub Actions.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import unicodedata
from pathlib import Path
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parent.parent
SKIP_DIRS = {
    ".git", ".hg", ".svn", "target", "vendor", "node_modules",
    ".opencode", ".superpowers", "__pycache__",
}
LINK_RE = re.compile(r"!?\[[^\]]*\]\(\s*(?:<([^>]+)>|([^)\s]+))")
HEADING_RE = re.compile(r"^(#{1,6})\s+(.*)$")
FENCE_RE = re.compile(r"^\s*(```|~~~)")
EXTERNAL_SCHEMES = {
    "http", "https", "mailto", "tel", "ftp", "ftps", "ssh", "git",
    "data", "javascript", "urn",
}


def tracked_markdown() -> list[Path]:
    try:
        output = subprocess.run(
            ["git", "ls-files", "-z", "*.md"],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        files = [ROOT / name for name in output.split("\0") if name]
        if files:
            return sorted(files)
    except (OSError, subprocess.CalledProcessError):
        pass
    return sorted(
        path
        for path in ROOT.rglob("*.md")
        if not any(part in SKIP_DIRS for part in path.relative_to(ROOT).parts)
    )


def github_slug(text: str) -> str:
    """Approximate GitHub's heading anchor (emoji/punctuation removed)."""
    text = re.sub(r"<[^>]+>", "", text)
    text = text.strip().lower()
    text = unicodedata.normalize("NFKC", text)
    # Keep unicode word characters, spaces and hyphens; drop punctuation/emoji.
    text = re.sub(r"[^\w\- ]", "", text, flags=re.UNICODE)
    return text.replace(" ", "-")


def headings_for(path: Path) -> set[str]:
    anchors: set[str] = set()
    counts: dict[str, int] = {}
    in_fence = False
    for line in path.read_text(errors="replace").splitlines():
        if FENCE_RE.match(line):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        match = HEADING_RE.match(line)
        if not match:
            continue
        slug = github_slug(match.group(2))
        if slug in counts:
            counts[slug] += 1
            anchors.add(f"{slug}-{counts[slug]}")
        else:
            counts[slug] = 0
            anchors.add(slug)
    return anchors


def links_in(path: Path) -> list[tuple[int, str]]:
    links: list[tuple[int, str]] = []
    in_fence = False
    for line_number, line in enumerate(path.read_text(errors="replace").splitlines(), start=1):
        if FENCE_RE.match(line):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        for match in LINK_RE.finditer(line):
            target = match.group(1) or match.group(2)
            if target:
                links.append((line_number, target.strip()))
    return links


def check_link(source: Path, target: str) -> str | None:
    if not target or target.startswith("#"):
        destination = source
        fragment = unquote(target[1:]) if target.startswith("#") else ""
    else:
        parsed = urlsplit(target)
        if parsed.scheme.lower() in EXTERNAL_SCHEMES:
            return None
        if parsed.scheme and parsed.scheme.lower() not in {"file"}:
            return None
        raw_path = unquote(parsed.path)
        if not raw_path:
            destination = source
        elif raw_path.startswith("/"):
            destination = ROOT / raw_path.lstrip("/")
        else:
            destination = (source.parent / raw_path).resolve()
        fragment = unquote(parsed.fragment)

    try:
        destination.relative_to(ROOT)
    except ValueError:
        return f"link escapes the repository: {target}"

    if not destination.exists():
        return f"missing file: {target}"
    if fragment and destination.is_file() and destination.suffix.lower() == ".md":
        anchors = headings_for(destination)
        if fragment not in anchors:
            return f"missing heading anchor: {target}"
    return None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--github", action="store_true", help="annotate failures for GitHub Actions")
    args = parser.parse_args()

    errors: list[str] = []
    files = tracked_markdown()
    for path in files:
        if not path.is_file():
            continue
        for line_number, target in links_in(path):
            problem = check_link(path, target)
            if problem:
                relative = path.relative_to(ROOT)
                errors.append(f"{relative}:{line_number}: {problem}")

    if errors:
        print("internal Markdown link check failed:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
            if args.github:
                print(f"::error::{error}")
        return 1

    print(f"internal Markdown links OK ({len(files)} files checked)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
