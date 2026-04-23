"""CLI error-branch tests.

Covers the exception handling paths in ``dpkg.cli.main`` that the fixture
suite does not naturally exercise:

  * blank line in provenance.jsonl (``continue``)
  * malformed JSON line in provenance.jsonl -> SchemaError with decorated path
  * argparse SystemExit pass-through for usage errors
  * FileNotFoundError -> MISSING_FILE
  * catch-all Exception -> UNKNOWN with exit 1
  * ``python -m dpkg`` module entrypoint
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from dpkg.canonical_json import dumps, normalize
from dpkg.error_codes import ErrorCode
from dpkg.errors import SchemaError

from conftest import run_cli as _run


UUID_PKG = "0191aaaa-0000-7000-8000-000000000001"
UUID_CLAIM_A = "0191aaaa-0000-7000-8000-00000000aaaa"
UUID_INSTANCE_A = "0191aaaa-0000-7000-8000-aaaaaaaaaaaa"
UUID_EVENT_1 = "0191aaaa-0000-7000-8000-eeee00000001"


def _error_payload(stderr: str) -> dict | None:
    for line in stderr.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict) and "code" in parsed:
            return parsed
    return None


def _minimal_source(dest: Path) -> Path:
    import hashlib

    (dest / "claims").mkdir(parents=True, exist_ok=True)
    claim = (
        "---\n"
        '"body_format": "markdown"\n'
        f'"claim_id": "{UUID_CLAIM_A}"\n'
        '"title": "hi"\n'
        "---\n"
    ).encode("utf-8")
    (dest / f"claims/{UUID_CLAIM_A}.md").write_bytes(claim)
    manifest = {
        "claims": [
            {
                "claim_id": UUID_CLAIM_A,
                "claim_instance_id": UUID_INSTANCE_A,
                "hash": hashlib.sha256(claim).hexdigest(),
                "path": f"claims/{UUID_CLAIM_A}.md",
                "state": "active",
            }
        ],
        "created_at": "2026-04-21T00:00:00Z",
        "format_version": "1.0",
        "license": "Apache-2.0",
        "package_id": UUID_PKG,
        "producer": "dpkg-test",
        "provenance_path": "provenance.jsonl",
    }
    (dest / "manifest.json").write_bytes(dumps(normalize(manifest)))
    event = {
        "actor": "t",
        "claim_id": UUID_CLAIM_A,
        "claim_instance_id": UUID_INSTANCE_A,
        "event_id": UUID_EVENT_1,
        "event_type": "create",
        "timestamp": "2026-04-21T00:00:00Z",
    }
    (dest / "provenance.jsonl").write_bytes(dumps(normalize(event)))
    return dest


# ---------- _cmd_validate: blank line skip (line 65) ----------


def test_validate_skips_blank_lines_in_provenance(tmp_path: Path) -> None:
    src = _minimal_source(tmp_path / "pkg")
    # Insert blank + whitespace-only lines around the real event; both are skipped.
    event_line = (src / "provenance.jsonl").read_bytes()
    (src / "provenance.jsonl").write_bytes(b"\n   \n" + event_line + b"\n")
    code, _, err = _run(["validate", str(src)])
    assert code == 0, err


# ---------- _cmd_validate: malformed JSON in provenance (lines 68-70) ----------


def test_validate_malformed_provenance_line_decorates_path(tmp_path: Path) -> None:
    src = _minimal_source(tmp_path / "pkg")
    (src / "provenance.jsonl").write_bytes(b"not-json-at-all\n")
    code, _, err = _run(["validate", str(src)])
    assert code == 3, err
    payload = _error_payload(err)
    assert payload is not None
    assert payload["code"] == ErrorCode.PARSE_ERROR.value
    assert payload["path"] == "provenance.jsonl:1"


# ---------- main(): argparse SystemExit pass-through (lines 162-164) ----------


def test_main_invalid_subcommand_returns_usage_exit_code() -> None:
    # argparse raises SystemExit(2) for unknown subcommands; main() forwards it.
    code, _, _ = _run(["not-a-real-subcommand"])
    assert code == 2


def test_main_missing_required_arg_returns_usage_exit_code() -> None:
    # `validate` requires a positional `source`; argparse -> SystemExit(2).
    code, _, _ = _run(["validate"])
    assert code == 2


# ---------- main(): FileNotFoundError branch (lines 170-174) ----------


def test_main_missing_manifest_emits_missing_file(tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    code, _, err = _run(["validate", str(empty)])
    assert code == 3, err
    payload = _error_payload(err)
    assert payload is not None
    assert payload["code"] == ErrorCode.MISSING_FILE.value


# ---------- main(): generic Exception branch (lines 175-179) ----------


def test_main_generic_exception_emits_unknown(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    src = _minimal_source(tmp_path / "pkg")

    def _boom(_manifest: dict, _events: list, **_kwargs) -> None:
        raise RuntimeError("unexpected boom")

    # Monkeypatch inside the lazily-imported module used by _cmd_validate.
    import dpkg.validator as validator_mod

    monkeypatch.setattr(validator_mod, "validate_package", _boom)

    code, _, err = _run(["validate", str(src)])
    assert code == 1, err  # EXIT_GENERIC for unexpected exceptions
    payload = _error_payload(err)
    assert payload is not None
    assert payload["code"] == ErrorCode.UNKNOWN.value
    assert "RuntimeError" in payload["msg"]


# ---------- SchemaError SystemExit handling preserves exit code ----------


def test_main_schema_error_from_command_returns_exit_3(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    src = _minimal_source(tmp_path / "pkg")

    def _fail(_manifest: dict, _events: list, **_kwargs) -> None:
        raise SchemaError(code=ErrorCode.TYPE_MISMATCH, msg="boom")

    import dpkg.validator as validator_mod

    monkeypatch.setattr(validator_mod, "validate_package", _fail)
    code, _, err = _run(["validate", str(src)])
    assert code == 3, err
    payload = _error_payload(err)
    assert payload is not None
    assert payload["code"] == ErrorCode.TYPE_MISMATCH.value


# ---------- __main__ entrypoint (line 183) ----------


def test_module_entrypoint_runs_via_python_dash_m(tmp_path: Path) -> None:
    """`python -m dpkg --version` exits cleanly via the __main__ block."""
    repo_root = Path(__file__).resolve().parent.parent
    env = {
        **dict(__import__("os").environ),
        "PYTHONPATH": str(repo_root / "src"),
    }
    result = subprocess.run(
        [sys.executable, "-m", "dpkg", "--version"],
        capture_output=True,
        text=True,
        env=env,
        cwd=str(repo_root),
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "dpkg" in result.stdout.lower()
