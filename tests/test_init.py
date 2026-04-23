"""Unit tests for ``aphelion init`` (initializer + CLI wiring)."""

from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path

import pytest

from aphelion.canonical_json import loads
from aphelion.cli import main as cli_main
from aphelion.error_codes import ErrorCode
from aphelion.errors import SchemaError
from aphelion.initializer import InitOptions, init_skeleton
from aphelion.validator import validate_package


def _run(argv: list[str]) -> tuple[int, str, str]:
    out = io.StringIO()
    err = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = cli_main(argv)
        except SystemExit as exc:
            code = exc.code if isinstance(exc.code, int) else 2
    return code, out.getvalue(), err.getvalue()


def _error_code(stderr: str) -> str | None:
    for line in stderr.splitlines():
        try:
            parsed = json.loads(line.strip())
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict) and "code" in parsed:
            return parsed["code"]
    return None


def test_init_creates_skeleton_in_empty_dir(tmp_path: Path) -> None:
    code, out, err = _run(["init", str(tmp_path / "pkg")])
    assert code == 0, err
    assert "Initialized empty Aphelion skeleton" in out
    assert (tmp_path / "pkg" / "manifest.json").is_file()
    assert (tmp_path / "pkg" / "provenance.jsonl").is_file()
    assert (tmp_path / "pkg" / "claims").is_dir()


def test_init_output_is_validate_clean(tmp_path: Path) -> None:
    dest = tmp_path / "pkg"
    init_skeleton(InitOptions(dest=dest, spec_version="0.2.1"))
    manifest = loads((dest / "manifest.json").read_bytes())
    validate_package(manifest, [])


def test_init_refuses_when_manifest_exists(tmp_path: Path) -> None:
    dest = tmp_path / "pkg"
    init_skeleton(InitOptions(dest=dest))
    # Second call without force should refuse.
    code, _, err = _run(["init", str(dest)])
    assert code == 3
    assert _error_code(err) == ErrorCode.INIT_REFUSES_EXISTING.value


def test_init_force_without_confirmation_refused(tmp_path: Path) -> None:
    dest = tmp_path / "pkg"
    init_skeleton(InitOptions(dest=dest))
    code, _, err = _run(["init", str(dest), "--force"])
    assert code == 3
    assert _error_code(err) == ErrorCode.INIT_MISSING_CONFIRMATION.value


def test_init_force_with_confirmation_overwrites(tmp_path: Path) -> None:
    dest = tmp_path / "pkg"
    init_skeleton(InitOptions(dest=dest))
    code, _, err = _run(
        ["init", str(dest), "--force", "--i-know-what-im-doing"]
    )
    assert code == 0, err


def test_init_accepts_supported_spec_versions(tmp_path: Path) -> None:
    init_skeleton(InitOptions(dest=tmp_path / "a", spec_version="0.2.0"))
    init_skeleton(InitOptions(dest=tmp_path / "b", spec_version="0.2.1"))


def test_init_rejects_unsupported_spec_version(tmp_path: Path) -> None:
    with pytest.raises(SchemaError) as exc:
        init_skeleton(InitOptions(dest=tmp_path / "x", spec_version="9.9.9"))
    assert exc.value.code == ErrorCode.UNSUPPORTED_SPEC_VERSION


def test_init_deterministic_with_fixed_inputs(tmp_path: Path) -> None:
    """Fixing package_id + created_at must produce byte-identical manifest."""
    opts_a = InitOptions(
        dest=tmp_path / "a",
        package_id="0191aaaa-0000-7000-8000-000000000001",
        created_at="2026-04-21T00:00:00Z",
    )
    opts_b = InitOptions(
        dest=tmp_path / "b",
        package_id="0191aaaa-0000-7000-8000-000000000001",
        created_at="2026-04-21T00:00:00Z",
    )
    init_skeleton(opts_a)
    init_skeleton(opts_b)
    a = (tmp_path / "a" / "manifest.json").read_bytes()
    b = (tmp_path / "b" / "manifest.json").read_bytes()
    assert a == b


def test_init_refuses_when_dest_is_a_file(tmp_path: Path) -> None:
    dest = tmp_path / "not-a-dir"
    dest.write_text("I'm a regular file")
    with pytest.raises(SchemaError) as exc:
        init_skeleton(InitOptions(dest=dest))
    assert exc.value.code == ErrorCode.INIT_REFUSES_EXISTING


def test_init_writes_spec_version_extension(tmp_path: Path) -> None:
    init_skeleton(InitOptions(dest=tmp_path / "pkg", spec_version="0.2.1"))
    manifest = loads((tmp_path / "pkg" / "manifest.json").read_bytes())
    assert manifest["extensions"]["dpkg_spec_version"] == "0.2.1"


# ---------- Override pre-validation (UUID_V7_RE / TIMESTAMP_RE) ----------


def test_init_rejects_invalid_package_id_override(tmp_path: Path) -> None:
    with pytest.raises(SchemaError) as exc:
        init_skeleton(InitOptions(dest=tmp_path / "pkg", package_id="not-a-uuid"))
    assert exc.value.code == ErrorCode.PATTERN_MISMATCH
    assert exc.value.path == "package_id"
    # Fail-fast: nothing written to disk.
    assert not (tmp_path / "pkg").exists()


def test_init_rejects_non_v7_uuid_package_id(tmp_path: Path) -> None:
    # Well-formed UUID v4 but not v7 — the 13th hex digit is not 7.
    v4 = "0191aaaa-0000-4000-8000-000000000001"
    with pytest.raises(SchemaError) as exc:
        init_skeleton(InitOptions(dest=tmp_path / "pkg", package_id=v4))
    assert exc.value.code == ErrorCode.PATTERN_MISMATCH


def test_init_rejects_invalid_created_at_override(tmp_path: Path) -> None:
    with pytest.raises(SchemaError) as exc:
        init_skeleton(InitOptions(dest=tmp_path / "pkg", created_at="yesterday"))
    assert exc.value.code == ErrorCode.PATTERN_MISMATCH
    assert exc.value.path == "created_at"
    assert not (tmp_path / "pkg").exists()


def test_init_rejects_created_at_without_trailing_z(tmp_path: Path) -> None:
    with pytest.raises(SchemaError) as exc:
        init_skeleton(
            InitOptions(
                dest=tmp_path / "pkg",
                created_at="2026-04-21T00:00:00+00:00",
            )
        )
    assert exc.value.code == ErrorCode.PATTERN_MISMATCH


def test_init_accepts_valid_overrides(tmp_path: Path) -> None:
    # Positive path: valid UUID v7 + valid RFC3339 UTC timestamp.
    init_skeleton(
        InitOptions(
            dest=tmp_path / "pkg",
            package_id="0191aaaa-0000-7000-8000-000000000001",
            created_at="2026-04-21T00:00:00Z",
        )
    )
    manifest = loads((tmp_path / "pkg" / "manifest.json").read_bytes())
    assert manifest["package_id"] == "0191aaaa-0000-7000-8000-000000000001"
    assert manifest["created_at"] == "2026-04-21T00:00:00Z"
