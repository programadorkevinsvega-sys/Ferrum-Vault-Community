#!/usr/bin/env python3
"""Validate repository-local Markdown links and heading anchors without dependencies."""

from __future__ import annotations

import html
import re
import sys
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
EXCLUDED = {".git", "target", "node_modules", ".venv", "vendor"}
FENCE = re.compile(r"^\s{0,3}(`{3,}|~{3,})")


class LinkHTMLParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[tuple[str, int]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        for key, value in attrs:
            if value and key.lower() in {"href", "src"}:
                self.links.append((html.unescape(value), self.getpos()[0]))


def markdown_without_code(text: str) -> str:
    output: list[str] = []
    fence_char = ""
    fence_len = 0
    for line in text.splitlines():
        match = FENCE.match(line)
        if match:
            marker = match.group(1)
            if not fence_char:
                fence_char, fence_len = marker[0], len(marker)
                output.append("")
                continue
            if marker[0] == fence_char and len(marker) >= fence_len:
                fence_char, fence_len = "", 0
                output.append("")
                continue
        output.append("" if fence_char else line)
    return "\n".join(output)


def heading_slug(value: str) -> str:
    value = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", value)
    value = re.sub(r"<[^>]+>", "", value)
    value = re.sub(r"[\*_~`]", "", value)
    value = value.strip().lower()
    value = re.sub(r"[^\w\s-]", "", value, flags=re.UNICODE)
    return re.sub(r"\s+", "-", value).strip("-")


def anchors_for(path: Path) -> set[str]:
    text = markdown_without_code(path.read_text(encoding="utf-8"))
    found: set[str] = set()
    seen: dict[str, int] = {}
    for match in re.finditer(r"^\s{0,3}#{1,6}\s+(.+?)\s*#*\s*$", text, re.MULTILINE):
        base = heading_slug(match.group(1))
        if not base:
            continue
        duplicate = seen.get(base, 0)
        seen[base] = duplicate + 1
        found.add(base if duplicate == 0 else f"{base}-{duplicate}")
    for match in re.finditer(r"<(?:a|[^>]+)\b[^>]*?\b(?:id|name)=[\"']([^\"']+)[\"']", text, re.IGNORECASE):
        found.add(html.unescape(match.group(1)))
    return found


def markdown_destinations(text: str) -> list[tuple[str, int]]:
    found: list[tuple[str, int]] = []
    # Inline links and images; balance nested parentheses in unquoted destinations.
    for match in re.finditer(r"!?(?:\[[^\]]*\])\(", text):
        pos = match.end()
        while pos < len(text) and text[pos].isspace():
            pos += 1
        if pos >= len(text):
            continue
        if text[pos] == "<":
            end = text.find(">", pos + 1)
            if end < 0:
                continue
            destination = text[pos + 1:end]
        else:
            start = pos
            depth = 0
            escaped = False
            while pos < len(text):
                char = text[pos]
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == "(":
                    depth += 1
                elif char == ")":
                    if depth == 0:
                        break
                    depth -= 1
                elif char.isspace() and depth == 0:
                    break
                pos += 1
            destination = text[start:pos]
        if destination:
            found.append((destination, text.count("\n", 0, match.start()) + 1))

    for match in re.finditer(r"^\s{0,3}\[[^\]]+\]:\s*(?:<([^>]+)>|(\S+))", text, re.MULTILINE):
        found.append((match.group(1) or match.group(2), text.count("\n", 0, match.start()) + 1))
    parser = LinkHTMLParser()
    parser.feed(text)
    found.extend(parser.links)
    return found


def resolve_local(source: Path, destination: str) -> tuple[Path | None, str | None]:
    destination = html.unescape(destination.strip())
    if not destination or destination.startswith("#"):
        return source, destination[1:] if destination.startswith("#") else None
    parsed = urlsplit(destination)
    if parsed.scheme or parsed.netloc:
        return None, None
    raw_path = unquote(parsed.path)
    target = (source.parent / raw_path).resolve() if raw_path else source.resolve()
    try:
        target.relative_to(ROOT)
    except ValueError:
        return target, parsed.fragment or None
    if target.is_dir():
        candidates = (target / "README.md", target / "index.md")
        target = next((candidate for candidate in candidates if candidate.is_file()), target)
    return target, unquote(parsed.fragment) if parsed.fragment else None


def main() -> int:
    markdown_files = sorted(
        path for path in ROOT.rglob("*.md")
        if not any(part in EXCLUDED for part in path.relative_to(ROOT).parts)
    )
    anchor_cache: dict[Path, set[str]] = {}
    failures: list[str] = []
    checked = 0

    for source in markdown_files:
        content = markdown_without_code(source.read_text(encoding="utf-8"))
        for destination, line in markdown_destinations(content):
            target, fragment = resolve_local(source, destination)
            if target is None:
                continue
            checked += 1
            relative_source = source.relative_to(ROOT)
            if not target.is_file():
                failures.append(f"{relative_source}:{line}: missing target: {destination}")
                continue
            if fragment and target.suffix.lower() == ".md":
                if target not in anchor_cache:
                    anchor_cache[target] = anchors_for(target)
                if fragment not in anchor_cache[target]:
                    failures.append(
                        f"{relative_source}:{line}: missing anchor '{fragment}' in "
                        f"{target.relative_to(ROOT)}"
                    )

    if failures:
        print("\n".join(failures), file=sys.stderr)
        print(f"FAILED: {len(failures)} broken local link(s); checked {checked} reference(s).", file=sys.stderr)
        return 1
    print(
        f"PASS: checked {checked} local Markdown/HTML references across "
        f"{len(markdown_files)} Markdown files; no broken targets or anchors."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
