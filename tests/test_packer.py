"""Direct unit tests for ``aphelion.packer`` error paths and optional files."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from aphelion.canonical_json import dumps, normalize
from aphelion.canonical_tar import read_members
from aphelion.error_codes import ErrorCode
from aphelion.errors import SchemaError
from aphelion.packer import _load_events, _read_bytes, pack


UUID_PKG = "0191aaaa-0000-7000-8000-000000000001"
UUID_CLAIM_A = "0191aaaa-0000-7000-8000-00000000aaaa"
UUID_INSTANCE_A = "0191aaaa-0000-7000-8000-aaaaaaaaaaaa"
UUID_EVENT_1 = "0191aaaa-0000-7000-8000-eeee00000001"


def _build_minimal(dest: Path) -> Path:
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
        "producer": "aphelion-test",
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


# ---------- _read_bytes FileNotFoundError (lines 18-19) ----------


def test_read_bytes_missing_file_raises_schema_error(tmp_path: Path) -> None:
    missing = tmp_path / "not-there.json"
    with pytest.raises(SchemaError) as exc:
        _read_bytes(missing)
    assert exc.value.code == ErrorCode.MISSING_FILE
    assert exc.value.path == str(missing)


# ---------- _load_events blank-line skip (line 31) ----------


def test_load_events_skips_blank_and_whitespace_lines(tmp_path: Path) -> None:
    path = tmp_path / "provenance.jsonl"
    event = {
        "actor": "t",
        "claim_id": UUID_CLAIM_A,
        "claim_instance_id": UUID_INSTANCE_A,
        "event_id": UUID_EVENT_1,
        "event_type": "create",
        "timestamp": "2026-04-21T00:00:00Z",
    }
    line = dumps(normalize(event))
    # Mix leading blank, trailing blank, and whitespace-only line.
    path.write_bytes(b"\n   \n" + line + b"\n  \n")
    events = _load_events(path)
    assert len(events) == 1
    assert events[0]["event_id"] == UUID_EVENT_1


# ---------- _load_events malformed line path decoration (lines 34-36) ----------


def test_load_events_malformed_line_decorates_path(tmp_path: Path) -> None:
    path = tmp_path / "provenance.jsonl"
    path.write_bytes(b"{\n")  # unterminated JSON
    with pytest.raises(SchemaError) as exc:
        _load_events(path)
    assert exc.value.path == "provenance.jsonl:1"


def test_load_events_path_decoration_tracks_line_number(tmp_path: Path) -> None:
    path = tmp_path / "provenance.jsonl"
    good = {
        "actor": "t",
        "claim_id": UUID_CLAIM_A,
        "claim_instance_id": UUID_INSTANCE_A,
        "event_id": UUID_EVENT_1,
        "event_type": "create",
        "timestamp": "2026-04-21T00:00:00Z",
    }
    path.write_bytes(dumps(normalize(good)) + b"garbage\n")
    with pytest.raises(SchemaError) as exc:
        _load_events(path)
    assert exc.value.path == "provenance.jsonl:2"


# ---------- pack() includes NOTICE when present (line 79) ----------


def test_pack_includes_notice_file_when_present(tmp_path: Path) -> None:
    src = _build_minimal(tmp_path / "src")
    (src / "NOTICE").write_bytes(b"Copyright Owner\n")
    out = tmp_path / "out.aphelion.tar"
    pack(src, out)

    unpacked = read_members(out.read_bytes())
    member_names = {m.path for m in unpacked}
    assert "NOTICE" in member_names
    notice = next(m for m in unpacked if m.path == "NOTICE")
    assert notice.data == b"Copyright Owner\n"


def test_pack_skips_notice_when_absent(tmp_path: Path) -> None:
    src = _build_minimal(tmp_path / "src")
    out = tmp_path / "out.aphelion.tar"
    pack(src, out)
    unpacked = read_members(out.read_bytes())
    member_names = {m.path for m in unpacked}
    assert "NOTICE" not in member_names


# ---------- pack() surfaces MISSING_FILE when manifest is absent ----------


def test_pack_missing_manifest_surfaces_missing_file(tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(SchemaError) as exc:
        pack(empty, tmp_path / "out.tar")
    assert exc.value.code == ErrorCode.MISSING_FILE
