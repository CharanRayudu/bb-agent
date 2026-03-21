#!/usr/bin/env python3
"""Walk the repo: validate UTF-8 for text files and flag common mojibake patterns."""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

SKIP_DIRS = {
    ".git",
    "node_modules",
    "vendor",
    "dist",
    ".vite",
    "reference_projects",
    "tmp_mirage",
    "__pycache__",
    ".idea",
    "logs",  # runtime screenshots and other artifacts
}

TEXT_SUFFIXES = {
    ".go",
    ".py",
    ".md",
    ".yaml",
    ".yml",
    ".json",
    ".jsx",
    ".js",
    ".css",
    ".html",
    ".sh",
    ".ps1",
    ".bat",
    ".toml",
    ".conf",
    ".mod",
    ".sum",
    ".txt",
    ".editorconfig",
    ".gitignore",
    ".dockerignore",
}

BINARY_SUFFIXES = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".ico",
    ".webp",
    ".woff",
    ".woff2",
    ".eot",
    ".ttf",
    ".otf",
    ".pdf",
    ".zip",
    ".exe",
    ".dll",
    ".so",
    ".dylib",
    ".pyc",
}

SPECIAL_TEXT_NAMES = {"dockerfile", "makefile", "license", "readme", "copying"}

# UTF-8 bytes E2 80 xx misread as Windows-1252 become U+00E2 U+20AC plus the CP1252 char for
# the third byte (not the same as the correctly decoded Unicode punctuation).
_MOJIBAKE_3RD_CP1252 = (
    "\u201c\u201d\u2019\u2018"  # 0x93-0x94 range common smart quotes
    "\u2122\u00a6"  # 0x99 (tm), 0xa6 (ellipsis misread tail)
)
MOJIBAKE_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile("\u00e2\u20ac[" + _MOJIBAKE_3RD_CP1252 + "]"),
        "UTF-8 punctuation misread as Windows-1252 (E2 80 xx triple)",
    ),
    (re.compile("\uFFFD"), "Unicode replacement character U+FFFD"),
]


def is_probably_binary(data: bytes) -> bool:
    if b"\x00" in data[:16384]:
        return True
    sample = data[: min(len(data), 8000)]
    if not sample:
        return False
    ctrl = sum(1 for b in sample if b < 32 and b not in (9, 10, 13))
    return ctrl > len(sample) * 0.15


def should_scan(path: Path) -> bool:
    for part in path.parts:
        if part in SKIP_DIRS:
            return False
        if part.startswith(".") and part not in (".", ".."):
            if part in (".editorconfig", ".gitignore", ".dockerignore", ".env.example"):
                continue
            if part.startswith(".env"):
                return False
    suf = path.suffix.lower()
    name = path.name.lower()
    if suf in BINARY_SUFFIXES:
        return False
    if name in ("thumbs.db", ".ds_store"):
        return False
    return True


def main() -> int:
    invalid_utf8: list[tuple[str, str]] = []
    mojibake_hits: list[tuple[str, str, str]] = []
    binary_suspicious: list[str] = []
    scanned = 0

    all_files = sorted(ROOT.rglob("*"))
    for path in all_files:
        if not path.is_file():
            continue
        if not should_scan(path):
            continue
        rel = path.relative_to(ROOT)
        try:
            data = path.read_bytes()
        except OSError as e:
            print("READ_FAIL", rel, e, file=sys.stderr)
            continue
        if not data:
            continue

        suf = path.suffix.lower()
        name_lower = path.name.lower()
        prob_bin = is_probably_binary(data)

        is_named_text = name_lower in SPECIAL_TEXT_NAMES or name_lower.startswith("dockerfile")
        if prob_bin and suf not in TEXT_SUFFIXES and not is_named_text:
            continue
        if prob_bin and (suf in TEXT_SUFFIXES or is_named_text):
            binary_suspicious.append(str(rel))

        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError as e:
            invalid_utf8.append((str(rel), str(e)))
            continue

        scanned += 1
        if len(data) > 2_000_000:
            continue

        for rx, label in MOJIBAKE_PATTERNS:
            for m in rx.finditer(text):
                start = max(0, m.start() - 50)
                snip = text[start : m.end() + 50].replace("\n", "\\n")
                mojibake_hits.append((str(rel), label, snip[:240]))

    # Raw C1 control chars sometimes indicate mixed encodings
    cp1252_glue: list[str] = []
    for path in all_files:
        if not path.is_file() or not should_scan(path):
            continue
        if path.suffix.lower() in BINARY_SUFFIXES:
            continue
        if path.stat().st_size > 2_000_000:
            continue
        try:
            t = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        if "\x92" in t or "\x93" in t or "\x94" in t:
            cp1252_glue.append(str(path.relative_to(ROOT)))

    print("=== UTF-8 / mojibake scan ===")
    print("Root:", ROOT)
    print("Files successfully decoded as UTF-8:", scanned)
    print()

    if invalid_utf8:
        print("--- INVALID UTF-8 ---")
        for p, e in invalid_utf8:
            print(f"{p} | {e}")
        print()
    else:
        print("--- INVALID UTF-8: none ---")
        print()

    if binary_suspicious:
        print("--- BINARY HEURISTIC ON APPARENT TEXT FILES (review) ---")
        for p in binary_suspicious:
            print(p)
        print()

    if mojibake_hits:
        print("--- MOJIBAKE HEURISTIC MATCHES ---")
        seen: set[tuple[str, str, str]] = set()
        for p, label, snip in mojibake_hits:
            key = (p, label, snip)
            if key in seen:
                continue
            seen.add(key)
            print(p)
            print(" ", label)
            print(" ", repr(snip))
            print()
    else:
        print("--- MOJIBAKE HEURISTIC MATCHES: none ---")
        print()

    if cp1252_glue:
        print("--- C1 / CP1252 GLUE CHARS (0x92-0x94) IN UTF-8 TEXT ---")
        for p in cp1252_glue:
            print(p)
        print()

    return 1 if (invalid_utf8 or mojibake_hits) else 0


if __name__ == "__main__":
    raise SystemExit(main())
