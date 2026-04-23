"""Invokes scripts/check_forbidden_terms.py as a subprocess against the repo."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SCANNER = REPO_ROOT / "scripts" / "check_forbidden_terms.py"


def test_scanner_exits_clean_on_repo():
    assert SCANNER.is_file(), f"scanner not found at {SCANNER}"
    result = subprocess.run(
        [sys.executable, str(SCANNER), str(REPO_ROOT)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, (
        f"forbidden-terms scan failed (exit {result.returncode})\n"
        f"STDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
    )


def test_scanner_detects_violation(tmp_path: Path):
    terms = tmp_path / ".forbidden-terms.txt"
    terms.write_text("badword\n", encoding="utf-8")
    offender = tmp_path / "notes.md"
    offender.write_text("this contains BadWord inline.\n", encoding="utf-8")
    result = subprocess.run(
        [sys.executable, str(SCANNER), str(tmp_path)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 1
    assert "notes.md:1:BadWord" in result.stdout or "notes.md:1:badword" in result.stdout.lower()
