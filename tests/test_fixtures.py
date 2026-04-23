"""Golden fixture tests driving the CLI against ~32 cases.

Fixtures are materialized to tests/fixtures/ at session start, so you can
inspect them on disk after a test run.
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import shutil
from pathlib import Path
from typing import Optional

import pytest

from aphelion.cli import main as cli_main
from tests._fixture_factory import CASES, materialize_all


ROOT = Path(__file__).resolve().parent
FIXTURES = ROOT / "fixtures"


@pytest.fixture(scope="session", autouse=True)
def _materialize_fixtures() -> None:
    FIXTURES.mkdir(exist_ok=True)
    materialize_all(FIXTURES)


def _run_cli(argv: list[str]) -> tuple[int, str, str]:
    out_buf = io.StringIO()
    err_buf = io.StringIO()
    with contextlib.redirect_stdout(out_buf), contextlib.redirect_stderr(err_buf):
        try:
            code = cli_main(argv)
        except SystemExit as exc:
            code = exc.code if isinstance(exc.code, int) else 2
    return code, out_buf.getvalue(), err_buf.getvalue()


def _extract_error_code(stderr: str) -> Optional[str]:
    for line in stderr.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict) and "code" in parsed:
            return parsed["code"]
    return None


# ---------- valid ----------

@pytest.mark.parametrize(
    "name", [c.name for c, _ in CASES if c.category == "valid"]
)
def test_valid_validate_passes(name: str) -> None:
    src = FIXTURES / "valid" / name
    code, _, err = _run_cli(["validate", str(src)])
    assert code == 0, f"expected exit 0, got {code}; stderr={err!r}"


@pytest.mark.parametrize(
    "name", [c.name for c, _ in CASES if c.category == "valid"]
)
def test_valid_pack_and_verify(tmp_path: Path, name: str) -> None:
    src = FIXTURES / "valid" / name
    archive = tmp_path / f"{name}.aphelion.tar"
    code, _, err = _run_cli(["pack", str(src), str(archive)])
    assert code == 0, err
    dest = tmp_path / "unpacked"
    code, _, err = _run_cli(["unpack", str(archive), str(dest)])
    assert code == 0, err
    code, _, err = _run_cli(["verify", str(dest)])
    assert code == 0, err


# ---------- invalid-syntax ----------

@pytest.mark.parametrize(
    "case",
    [c for c, _ in CASES if c.category == "invalid-syntax"],
    ids=lambda c: c.name,
)
def test_invalid_syntax_rejected(case) -> None:
    src = FIXTURES / "invalid-syntax" / case.name
    code, _, err = _run_cli(["validate", str(src)])
    assert code == 3, f"{case.name}: expected exit 3, got {code}; stderr={err!r}"
    assert _extract_error_code(err) == case.expected_code, (
        f"{case.name}: expected {case.expected_code}, got stderr={err!r}"
    )


# ---------- invalid-semantic ----------

@pytest.mark.parametrize(
    "case",
    [c for c, _ in CASES if c.category == "invalid-semantic"],
    ids=lambda c: c.name,
)
def test_invalid_semantic_rejected(tmp_path: Path, case) -> None:
    src = FIXTURES / "invalid-semantic" / case.name
    # Semantic failures may surface at validate (for chain) or verify (for hash/fileset/ref)
    # Strategy: try validate first - if exit 0, copy source_dir and run verify on it.
    code, _, err = _run_cli(["validate", str(src)])
    if code == 3:
        got = _extract_error_code(err)
    else:
        # Prepare an unpacked tree (copy source as-is, since verify reads from a dir)
        copy_dir = tmp_path / "copy"
        shutil.copytree(src, copy_dir)
        code, _, err = _run_cli(["verify", str(copy_dir)])
        got = _extract_error_code(err)
    assert code == 3, f"{case.name}: expected exit 3, got {code}; stderr={err!r}"
    assert got == case.expected_code, f"{case.name}: expected {case.expected_code}, got {got!r}"


# ---------- archive-security ----------

@pytest.mark.parametrize(
    "case",
    [c for c, _ in CASES if c.category == "archive-security"],
    ids=lambda c: c.name,
)
def test_archive_security_rejected(tmp_path: Path, case) -> None:
    archive = FIXTURES / "archive-security" / case.name / "evil.tar"
    dest = tmp_path / "dest"
    code, _, err = _run_cli(["unpack", str(archive), str(dest)])
    assert code == 3, f"{case.name}: expected exit 3, got {code}; stderr={err!r}"
    got = _extract_error_code(err)
    assert got == case.expected_code, f"{case.name}: expected {case.expected_code}, got {got!r}"


# ---------- round-trip ----------

@pytest.mark.parametrize(
    "name", [c.name for c, _ in CASES if c.category == "round-trip"]
)
def test_round_trip_byte_equal(tmp_path: Path, name: str) -> None:
    src = FIXTURES / "round-trip" / name
    arc1 = tmp_path / "a.tar"
    code, _, err = _run_cli(["pack", str(src), str(arc1)])
    assert code == 0, err

    dest = tmp_path / "dest"
    code, _, err = _run_cli(["unpack", str(arc1), str(dest)])
    assert code == 0, err

    arc2 = tmp_path / "b.tar"
    code, _, err = _run_cli(["pack", str(dest), str(arc2)])
    assert code == 0, err

    h1 = hashlib.sha256(arc1.read_bytes()).hexdigest()
    h2 = hashlib.sha256(arc2.read_bytes()).hexdigest()
    assert h1 == h2, f"{name}: pack->unpack->pack not byte-equal: {h1} vs {h2}"
