"""Forbidden-terms scanner for the DPKG repository.

Scans text files (.md, .yml, .yaml, .json, .jsonl, .py, .toml) for any term
listed in .forbidden-terms.txt (case-insensitive). Skips binary blobs,
VCS metadata, build artifacts, caches, and the .omc/baselines directory.
Exits 0 on clean, 1 on any match. Emits file:line:match to stdout.

Pure stdlib; safe to run inside CI and pre-commit hooks.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


TEXT_SUFFIXES = frozenset(
    {".md", ".yml", ".yaml", ".json", ".jsonl", ".py", ".toml", ".txt"}
)

SKIP_DIR_NAMES = frozenset(
    {
        ".git",
        ".pytest_cache",
        "__pycache__",
        "dist",
        "build",
        "node_modules",
        ".venv",
        "venv",
        "htmlcov",
    }
)

SKIP_DIR_SUFFIXES = (".egg-info",)

SKIP_RELATIVE_DIRS = (
    Path(".omc"),
    Path("htmlcov"),
)

# The scanner itself and the terms list mention the forbidden terms literally.
SELF_EXEMPT_RELATIVE = frozenset(
    {
        Path(".forbidden-terms.txt"),
        Path("scripts") / "check_forbidden_terms.py",
        Path("tests") / "test_forbidden_terms.py",
        Path("spec") / "reserved-namespaces.md",
    }
)


def _load_terms(terms_file: Path) -> list[str]:
    lines = terms_file.read_text(encoding="utf-8").splitlines()
    terms = []
    for raw in lines:
        term = raw.strip()
        if not term or term.startswith("#"):
            continue
        terms.append(term)
    if not terms:
        raise SystemExit(f"{terms_file}: no terms loaded (empty file?)")
    return terms


def _should_skip_dir(path: Path) -> bool:
    if path.name in SKIP_DIR_NAMES:
        return True
    for suffix in SKIP_DIR_SUFFIXES:
        if path.name.endswith(suffix):
            return True
    return False


def _iter_files(root: Path) -> list[Path]:
    files: list[Path] = []
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            entries = list(current.iterdir())
        except (PermissionError, OSError):
            continue
        for entry in entries:
            if entry.is_dir():
                if _should_skip_dir(entry):
                    continue
                rel = entry.relative_to(root)
                if any(str(rel).startswith(str(skip)) for skip in SKIP_RELATIVE_DIRS):
                    continue
                stack.append(entry)
            elif entry.is_file() and entry.suffix.lower() in TEXT_SUFFIXES:
                files.append(entry)
    return files


def _scan(file_path: Path, pattern: re.Pattern[str]) -> list[tuple[int, str]]:
    try:
        text = file_path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return []
    hits: list[tuple[int, str]] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        for match in pattern.finditer(line):
            hits.append((lineno, match.group(0)))
    return hits


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Forbidden-terms scanner.")
    parser.add_argument(
        "root",
        nargs="?",
        default=".",
        help="Repository root to scan (defaults to cwd).",
    )
    parser.add_argument(
        "--terms-file",
        default=".forbidden-terms.txt",
        help="Path to the forbidden-terms list (relative to root).",
    )
    args = parser.parse_args(argv)

    root = Path(args.root).resolve()
    terms_file = (root / args.terms_file).resolve()
    if not terms_file.is_file():
        print(f"error: terms file not found: {terms_file}", file=sys.stderr)
        return 2

    terms = _load_terms(terms_file)
    # Word-boundary match to avoid substring false positives
    # (e.g. "med" inside "immediately"/"reaffirmed"/"emitted"). Hyphens
    # inside a term are already handled because \b sits at the
    # alphanumeric/non-alphanumeric transition.
    pattern = re.compile(
        r"\b(?:" + "|".join(re.escape(t) for t in terms) + r")\b",
        flags=re.IGNORECASE,
    )

    violations = 0
    for path in _iter_files(root):
        rel = path.relative_to(root)
        if rel in SELF_EXEMPT_RELATIVE:
            continue
        for lineno, match in _scan(path, pattern):
            violations += 1
            print(f"{rel.as_posix()}:{lineno}:{match}")
    if violations:
        print(f"forbidden-terms: {violations} match(es) found", file=sys.stderr)
        return 1
    print("forbidden-terms: clean")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
