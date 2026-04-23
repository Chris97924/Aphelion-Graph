"""Deterministic pack command: source_dir -> *.aphelion.tar."""

from __future__ import annotations

import hashlib
from pathlib import Path

from aphelion.canonical_json import dumps, loads, normalize
from aphelion.canonical_tar import TarMember, pack as tar_pack
from aphelion.error_codes import ErrorCode
from aphelion.errors import SchemaError
from aphelion.validator import validate_package


def _read_bytes(path: Path) -> bytes:
    try:
        return path.read_bytes()
    except FileNotFoundError as exc:
        raise SchemaError(
            code=ErrorCode.MISSING_FILE,
            msg=str(exc),
            path=str(path),
        ) from exc


def _load_events(path: Path) -> list[dict]:
    raw = _read_bytes(path)
    events: list[dict] = []
    for idx, line in enumerate(raw.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            events.append(loads(line))
        except SchemaError as e:
            e.path = f"{path.name}:{idx}"
            raise
    return events


def pack(source_dir: Path | str, out_path: Path | str) -> Path:
    """Pack source_dir into a canonical .aphelion.tar file at out_path.

    source_dir must contain:
      * manifest.json
      * provenance.jsonl
      * claims/<claim_id>.md for every manifest claim entry

    Raises SchemaError / SemanticError on any inconsistency detectable at pack time.
    The output is byte-deterministic: same input -> identical bytes.
    """
    source = Path(source_dir)
    out = Path(out_path)

    manifest_raw = _read_bytes(source / "manifest.json")
    manifest_obj = loads(manifest_raw)
    events = _load_events(source / "provenance.jsonl")
    validate_package(manifest_obj, events)

    # Recompute hashes and re-serialize manifest canonically
    manifest_obj = normalize(manifest_obj)
    claim_files: list[TarMember] = []
    for entry in manifest_obj["claims"]:
        claim_path = source / entry["path"]
        blob = _read_bytes(claim_path)
        entry["hash"] = hashlib.sha256(blob).hexdigest()
        claim_files.append(TarMember(path=entry["path"], data=blob, is_dir=False))

    # Re-canonicalize manifest after hash recomputation
    manifest_bytes = dumps(manifest_obj)
    # Re-canonicalize provenance (one JSON object per line + LF)
    provenance_bytes = b"".join(dumps(normalize(ev)) for ev in events)

    members: list[TarMember] = [
        TarMember(path="manifest.json", data=manifest_bytes, is_dir=False),
        TarMember(path="provenance.jsonl", data=provenance_bytes, is_dir=False),
        *claim_files,
    ]
    if (source / "NOTICE").exists():
        members.append(
            TarMember(path="NOTICE", data=_read_bytes(source / "NOTICE"), is_dir=False)
        )

    archive = tar_pack(members)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(archive)
    return out
