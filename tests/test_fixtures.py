"""Golden fixture tests driving the CLI against ~32 cases.

Fixtures are materialized to tests/fixtures/ at session start, so you can
inspect them on disk after a test run.
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
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


# ---------- materialize ----------
#
# materialize_all runs at every session start into the tracked tests/fixtures, so
# it has to converge on the factory output while writing only what differs: a
# tree that already matches must come out of a run untouched, or every run
# dirties a checkout whose bytes were already right.

_STAMP_NS = 1_000_000_000 * 1_000_000_000  # 2001-09-09; any write moves a file past it


def _tree(root: Path) -> dict[str, Optional[bytes]]:
    """Every path under root, mapped to its bytes (None for a directory)."""
    return {
        p.relative_to(root).as_posix(): p.read_bytes() if p.is_file() else None
        for p in root.rglob("*")
    }


def test_materialize_second_run_writes_nothing(tmp_path: Path) -> None:
    materialize_all(tmp_path)
    files = [p for p in tmp_path.rglob("*") if p.is_file()]
    for p in files:
        os.utime(p, ns=(_STAMP_NS, _STAMP_NS))
    materialize_all(tmp_path)
    written = [
        p.relative_to(tmp_path).as_posix()
        for p in files
        if not p.is_file() or p.stat().st_mtime_ns != _STAMP_NS
    ]
    assert written == [], f"second run rewrote {len(written)} of {len(files)} files"


def test_materialize_rewrites_a_fixture_whose_bytes_differ(tmp_path: Path) -> None:
    materialize_all(tmp_path)
    expected = _tree(tmp_path)
    target = tmp_path / "valid" / "minimal-single-claim" / "manifest.json"
    # The form a core.autocrlf=true checkout hands over.
    target.write_bytes(target.read_bytes().replace(b"\n", b"\r\n"))
    assert _tree(tmp_path) != expected
    materialize_all(tmp_path)
    assert _tree(tmp_path) == expected


def test_materialize_removes_a_file_the_factory_does_not_produce(tmp_path: Path) -> None:
    materialize_all(tmp_path)
    expected = _tree(tmp_path)
    case = tmp_path / "valid" / "minimal-single-claim"
    (case / "stray.md").write_bytes(b"not a factory output\n")
    (case / "stray-dir").mkdir()
    (case / "stray-dir" / "stray.json").write_bytes(b"{}\n")
    materialize_all(tmp_path)
    assert _tree(tmp_path) == expected


def test_materialize_recreates_a_missing_file(tmp_path: Path) -> None:
    materialize_all(tmp_path)
    expected = _tree(tmp_path)
    (tmp_path / "valid" / "minimal-single-claim" / "provenance.jsonl").unlink()
    materialize_all(tmp_path)
    assert _tree(tmp_path) == expected


# A link in the fixture tree points outside it. Following one would delete what the
# factory does not produce and write fixture bytes there, so each is replaced by
# the real entry and whatever it pointed at is left exactly as it was.
_LINKS = [
    pytest.param("valid", "dir", id="category-dir-symlink"),
    pytest.param("valid/minimal-single-claim", "dir", id="case-dir-symlink"),
    pytest.param("valid/minimal-single-claim/claims", "dir", id="subdir-symlink"),
    pytest.param("valid/minimal-single-claim/manifest.json", "file", id="file-symlink"),
    pytest.param("valid/minimal-single-claim/manifest.json", "dangling", id="dangling-file-symlink"),
]
if os.name == "nt":
    # A junction needs no symlink privilege and is not a symlink to Path.is_symlink().
    _LINKS.append(pytest.param("valid/minimal-single-claim", "junction", id="case-dir-junction"))


@pytest.mark.parametrize(("rel", "kind"), _LINKS)
def test_materialize_replaces_a_destination_link_without_following_it(
    tmp_path: Path, rel: str, kind: str
) -> None:
    fixtures = tmp_path / "fixtures"
    materialize_all(fixtures)
    expected = _tree(fixtures)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "sentinel.md").write_bytes(b"not a fixture\n")
    untouched = _tree(outside)
    link = fixtures / rel
    if link.is_dir():
        shutil.rmtree(link)
    else:
        link.unlink()
    if kind == "junction":
        import _winapi

        _winapi.CreateJunction(str(outside), str(link))
    else:
        target = {"dir": outside, "file": outside / "sentinel.md", "dangling": outside / "absent.md"}
        try:
            link.symlink_to(target[kind], target_is_directory=kind == "dir")
        except OSError:
            pytest.skip("this platform/user cannot create symlinks")
    materialize_all(fixtures)
    assert _tree(outside) == untouched
    assert not link.is_symlink()
    assert _tree(fixtures) == expected


# A fixture file hard-linked to a file outside the tree shares that file's bytes:
# writing the factory bytes through it would overwrite the outside file too, so a
# differing file is replaced by a new one, never rewritten in place.
def test_materialize_replaces_a_hard_linked_fixture_instead_of_writing_through_it(
    tmp_path: Path,
) -> None:
    fixtures = tmp_path / "fixtures"
    materialize_all(fixtures)
    expected = _tree(fixtures)
    outside = tmp_path / "outside" / "shared.json"
    outside.parent.mkdir()
    outside.write_bytes(b"not a fixture\n")
    target = fixtures / "valid" / "minimal-single-claim" / "manifest.json"
    target.unlink()
    os.link(outside, target)
    assert os.path.samefile(outside, target)
    materialize_all(fixtures)
    assert outside.read_bytes() == b"not a fixture\n"
    assert not os.path.samefile(outside, target)
    assert _tree(fixtures) == expected


# Names are compared exactly. On a case-insensitive filesystem an entry that differs
# from the factory's only by case resolves to it, and would otherwise keep the wrong
# name; on a case-sensitive one it is simply an entry the factory does not produce.
@pytest.mark.parametrize(
    "rel",
    [
        pytest.param("valid/minimal-single-claim/manifest.json", id="file"),
        pytest.param("valid/minimal-single-claim/claims", id="dir"),
    ],
)
def test_materialize_restores_the_exact_name_of_an_entry_that_differs_only_by_case(
    tmp_path: Path, rel: str
) -> None:
    materialize_all(tmp_path)
    expected = _tree(tmp_path)
    right = tmp_path / rel
    wrong = right.with_name(right.name.upper())
    right.rename(wrong)
    assert wrong.name in os.listdir(right.parent)
    materialize_all(tmp_path)
    names = os.listdir(right.parent)
    assert right.name in names and wrong.name not in names
    assert _tree(tmp_path) == expected
