"""Semantic checks in ``aphelion.verifier.verify`` required by spec/validator.md.

Covers the ERR-SEM rules that verify() did not implement before A6:

  * ERR-SEM-005 duplicate ``claim_instance_id`` (manifest; identity I-2 for events)
  * ERR-SEM-006 duplicate ``event_id`` in provenance.jsonl (identity I-3)
  * ERR-SEM-013 manifest terminal state disagrees with the provenance last event
  * instance-id references that were never established (lifecycle §5.5)
  * two manifest claims sharing one claim file (packaging path rule 4)
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

import pytest

from aphelion.canonical_json import dumps, normalize
from aphelion.error_codes import ErrorCode
from aphelion.errors import AphelionError
from aphelion.verifier import verify

PKG = "0192cccc-0000-7000-8000-000000000001"
CLAIM_A = "0192cccc-0000-7000-8000-00000000aaaa"
CLAIM_B = "0192cccc-0000-7000-8000-00000000bbbb"
INST_A1 = "0192cccc-0000-7000-8000-aaaaaaaa0001"
INST_A2 = "0192cccc-0000-7000-8000-aaaaaaaa0002"
INST_B1 = "0192cccc-0000-7000-8000-bbbbbbbb0001"
UNKNOWN_INST = "0192cccc-0000-7000-8000-ffffffffffff"


def _ev(n: int) -> str:
    return f"0192cccc-0000-7000-8000-eeee{n:08d}"


def _ts(n: int) -> str:
    return f"2026-04-21T00:00:{n:02d}Z"


def _claim(claim_id: str, title: str) -> bytes:
    return (
        "---\n"
        '"body_format": "markdown"\n'
        f'"claim_id": "{claim_id}"\n'
        f'"title": "{title}"\n'
        "---\n"
    ).encode("utf-8")


def _entry(claim_id: str, instance: str, body: bytes, **extra: Any) -> dict[str, Any]:
    entry = {
        "claim_id": claim_id,
        "claim_instance_id": instance,
        "hash": hashlib.sha256(body).hexdigest(),
        "path": f"claims/{claim_id}.md",
        "state": "active",
    }
    entry.update(extra)
    return entry


def _create(n: int, claim_id: str, instance: str) -> dict[str, Any]:
    return {
        "actor": "t",
        "claim_id": claim_id,
        "claim_instance_id": instance,
        "event_id": _ev(n),
        "event_type": "create",
        "timestamp": _ts(n),
    }


def _follow(
    n: int, claim_id: str, etype: str, prev: int, target: str, **extra: Any
) -> dict[str, Any]:
    ev = {
        "actor": "t",
        "claim_id": claim_id,
        "event_id": _ev(n),
        "event_type": etype,
        "prev_event_id": _ev(prev),
        "target_claim_instance_id": target,
        "timestamp": _ts(n),
    }
    ev.update(extra)
    return ev


def _write(
    root: Path,
    entries: list[dict[str, Any]],
    events: list[dict[str, Any]],
    files: dict[str, bytes],
) -> Path:
    (root / "claims").mkdir(parents=True, exist_ok=True)
    for rel, body in files.items():
        (root / rel).write_bytes(body)
    manifest = {
        "aphelion_spec_version": "0.4.0",
        "claims": entries,
        "created_at": "2026-04-21T00:00:00Z",
        "format_version": "2.0",
        "license": "Apache-2.0",
        "package_id": PKG,
        "producer": "aphelion-test",
        "provenance_path": "provenance.jsonl",
    }
    (root / "manifest.json").write_bytes(dumps(normalize(manifest)))
    (root / "provenance.jsonl").write_bytes(
        b"".join(dumps(normalize(ev)) for ev in events)
    )
    return root


def _code(exc: pytest.ExceptionInfo[AphelionError]) -> str:
    code = exc.value.code
    return code.value if isinstance(code, ErrorCode) else code


BODY_A = _claim(CLAIM_A, "A")
BODY_B = _claim(CLAIM_B, "B")


# ---------- baseline: the builder produces a package verify() accepts ----------


def test_two_claim_package_with_revise_and_withdraw_verifies(tmp_path: Path) -> None:
    _write(
        tmp_path,
        [
            _entry(CLAIM_A, INST_A2, BODY_A),
            _entry(CLAIM_B, INST_B1, BODY_B, state="withdrawn"),
        ],
        [
            _create(1, CLAIM_A, INST_A1),
            _create(2, CLAIM_B, INST_B1),
            _follow(3, CLAIM_A, "revise", 1, INST_A1, claim_instance_id=INST_A2),
            _follow(4, CLAIM_A, "reaffirm", 3, INST_A2),
            _follow(5, CLAIM_B, "withdraw", 2, INST_B1),
        ],
        {f"claims/{CLAIM_A}.md": BODY_A, f"claims/{CLAIM_B}.md": BODY_B},
    )
    verify(tmp_path)


# ---------- ERR-SEM-013: manifest state vs provenance last event ----------


def test_manifest_active_but_provenance_ends_with_withdraw(tmp_path: Path) -> None:
    _write(
        tmp_path,
        [_entry(CLAIM_A, INST_A1, BODY_A, state="active")],
        [_create(1, CLAIM_A, INST_A1), _follow(2, CLAIM_A, "withdraw", 1, INST_A1)],
        {f"claims/{CLAIM_A}.md": BODY_A},
    )
    with pytest.raises(AphelionError) as exc:
        verify(tmp_path)
    assert _code(exc) == ErrorCode.MANIFEST_STATE_MISMATCH.value


def test_manifest_active_but_provenance_ends_with_supersede(tmp_path: Path) -> None:
    _write(
        tmp_path,
        [
            _entry(CLAIM_A, INST_A1, BODY_A, state="active"),
            _entry(CLAIM_B, INST_B1, BODY_B),
        ],
        [
            _create(1, CLAIM_A, INST_A1),
            _create(2, CLAIM_B, INST_B1),
            _follow(
                3, CLAIM_A, "supersede", 1, INST_A1,
                claim_instance_id=INST_A2, superseded_by_claim_id=CLAIM_B,
            ),
        ],
        {f"claims/{CLAIM_A}.md": BODY_A, f"claims/{CLAIM_B}.md": BODY_B},
    )
    with pytest.raises(AphelionError) as exc:
        verify(tmp_path)
    assert _code(exc) == ErrorCode.MANIFEST_STATE_MISMATCH.value


def test_manifest_withdrawn_but_provenance_never_withdraws(tmp_path: Path) -> None:
    _write(
        tmp_path,
        [_entry(CLAIM_A, INST_A1, BODY_A, state="withdrawn")],
        [_create(1, CLAIM_A, INST_A1)],
        {f"claims/{CLAIM_A}.md": BODY_A},
    )
    with pytest.raises(AphelionError) as exc:
        verify(tmp_path)
    assert _code(exc) == ErrorCode.MANIFEST_STATE_MISMATCH.value


def test_last_event_is_taken_in_canonical_order_not_file_order(tmp_path: Path) -> None:
    """Spec lifecycle §5.4: consumers re-sort by (timestamp, event_id). A
    withdraw written first in the file but timestamped last is still last."""
    _write(
        tmp_path,
        [_entry(CLAIM_A, INST_A1, BODY_A, state="active")],
        [_follow(2, CLAIM_A, "withdraw", 1, INST_A1), _create(1, CLAIM_A, INST_A1)],
        {f"claims/{CLAIM_A}.md": BODY_A},
    )
    with pytest.raises(AphelionError) as exc:
        verify(tmp_path)
    assert _code(exc) == ErrorCode.MANIFEST_STATE_MISMATCH.value


# ---------- ERR-SEM-005: duplicate claim_instance_id ----------


def test_duplicate_claim_instance_id_in_manifest(tmp_path: Path) -> None:
    _write(
        tmp_path,
        [_entry(CLAIM_A, INST_A1, BODY_A), _entry(CLAIM_B, INST_A1, BODY_B)],
        [_create(1, CLAIM_A, INST_A1), _create(2, CLAIM_B, INST_A1)],
        {f"claims/{CLAIM_A}.md": BODY_A, f"claims/{CLAIM_B}.md": BODY_B},
    )
    with pytest.raises(AphelionError) as exc:
        verify(tmp_path)
    assert _code(exc) == ErrorCode.DUPLICATE_CLAIM_INSTANCE_ID.value


def test_revise_reusing_an_instance_id_is_a_duplicate(tmp_path: Path) -> None:
    """Identity I-2 / provenance P-3: a revise emits an instance id never used
    before in the package."""
    _write(
        tmp_path,
        [_entry(CLAIM_A, INST_A1, BODY_A)],
        [
            _create(1, CLAIM_A, INST_A1),
            _follow(2, CLAIM_A, "revise", 1, INST_A1, claim_instance_id=INST_A1),
        ],
        {f"claims/{CLAIM_A}.md": BODY_A},
    )
    with pytest.raises(AphelionError) as exc:
        verify(tmp_path)
    assert _code(exc) == ErrorCode.DUPLICATE_CLAIM_INSTANCE_ID.value


# ---------- ERR-SEM-006: duplicate event_id ----------


def test_duplicate_event_id_across_claims(tmp_path: Path) -> None:
    create_b = _create(2, CLAIM_B, INST_B1)
    create_b["event_id"] = _ev(1)
    _write(
        tmp_path,
        [_entry(CLAIM_A, INST_A1, BODY_A), _entry(CLAIM_B, INST_B1, BODY_B)],
        [_create(1, CLAIM_A, INST_A1), create_b],
        {f"claims/{CLAIM_A}.md": BODY_A, f"claims/{CLAIM_B}.md": BODY_B},
    )
    with pytest.raises(AphelionError) as exc:
        verify(tmp_path)
    assert _code(exc) == ErrorCode.DUPLICATE_EVENT_ID.value


def test_duplicate_event_id_within_one_claim(tmp_path: Path) -> None:
    reaffirm = _follow(2, CLAIM_A, "reaffirm", 1, INST_A1)
    reaffirm["event_id"] = _ev(1)
    _write(
        tmp_path,
        [_entry(CLAIM_A, INST_A1, BODY_A)],
        [_create(1, CLAIM_A, INST_A1), reaffirm],
        {f"claims/{CLAIM_A}.md": BODY_A},
    )
    with pytest.raises(AphelionError) as exc:
        verify(tmp_path)
    assert _code(exc) == ErrorCode.DUPLICATE_EVENT_ID.value


# ---------- instance ids that were never established ----------


def test_target_instance_never_established(tmp_path: Path) -> None:
    _write(
        tmp_path,
        [_entry(CLAIM_A, INST_A1, BODY_A)],
        [_create(1, CLAIM_A, INST_A1), _follow(2, CLAIM_A, "reaffirm", 1, UNKNOWN_INST)],
        {f"claims/{CLAIM_A}.md": BODY_A},
    )
    with pytest.raises(AphelionError) as exc:
        verify(tmp_path)
    assert _code(exc) == ErrorCode.DANGLING_REFERENCE.value


def test_target_instance_of_another_claim(tmp_path: Path) -> None:
    _write(
        tmp_path,
        [_entry(CLAIM_A, INST_A1, BODY_A), _entry(CLAIM_B, INST_B1, BODY_B)],
        [
            _create(1, CLAIM_A, INST_A1),
            _create(2, CLAIM_B, INST_B1),
            _follow(3, CLAIM_A, "reaffirm", 1, INST_B1),
        ],
        {f"claims/{CLAIM_A}.md": BODY_A, f"claims/{CLAIM_B}.md": BODY_B},
    )
    with pytest.raises(AphelionError) as exc:
        verify(tmp_path)
    assert _code(exc) == ErrorCode.DANGLING_REFERENCE.value


def test_target_instance_no_longer_in_force(tmp_path: Path) -> None:
    """Lifecycle §5.5: the target is the instance in force at the time of the
    event, so after a revise the old instance cannot be reaffirmed."""
    _write(
        tmp_path,
        [_entry(CLAIM_A, INST_A2, BODY_A)],
        [
            _create(1, CLAIM_A, INST_A1),
            _follow(2, CLAIM_A, "revise", 1, INST_A1, claim_instance_id=INST_A2),
            _follow(3, CLAIM_A, "reaffirm", 2, INST_A1),
        ],
        {f"claims/{CLAIM_A}.md": BODY_A},
    )
    with pytest.raises(AphelionError) as exc:
        verify(tmp_path)
    assert _code(exc) == ErrorCode.DANGLING_REFERENCE.value


def test_manifest_instance_never_established(tmp_path: Path) -> None:
    _write(
        tmp_path,
        [_entry(CLAIM_A, UNKNOWN_INST, BODY_A)],
        [_create(1, CLAIM_A, INST_A1)],
        {f"claims/{CLAIM_A}.md": BODY_A},
    )
    with pytest.raises(AphelionError) as exc:
        verify(tmp_path)
    assert _code(exc) == ErrorCode.DANGLING_REFERENCE.value


def test_manifest_claim_without_any_provenance(tmp_path: Path) -> None:
    _write(
        tmp_path,
        [_entry(CLAIM_A, INST_A1, BODY_A), _entry(CLAIM_B, INST_B1, BODY_B)],
        [_create(1, CLAIM_A, INST_A1)],
        {f"claims/{CLAIM_A}.md": BODY_A, f"claims/{CLAIM_B}.md": BODY_B},
    )
    with pytest.raises(AphelionError) as exc:
        verify(tmp_path)
    assert _code(exc) == ErrorCode.DANGLING_REFERENCE.value


# ---------- two claims sharing one file ----------


def test_two_claims_sharing_one_file(tmp_path: Path) -> None:
    shared = f"claims/{CLAIM_A}.md"
    _write(
        tmp_path,
        [
            _entry(CLAIM_A, INST_A1, BODY_A),
            _entry(CLAIM_B, INST_B1, BODY_A, path=shared),
        ],
        [_create(1, CLAIM_A, INST_A1), _create(2, CLAIM_B, INST_B1)],
        {shared: BODY_A},
    )
    with pytest.raises(AphelionError) as exc:
        verify(tmp_path)
    assert _code(exc) == ErrorCode.FILESET_DIVERGENCE.value


def test_claim_path_must_name_its_own_claim_id(tmp_path: Path) -> None:
    """Packaging path rule 4: claims/<uuid>.md, where the UUID is the claim_id."""
    _write(
        tmp_path,
        [_entry(CLAIM_A, INST_A1, BODY_A, path=f"claims/{CLAIM_B}.md")],
        [_create(1, CLAIM_A, INST_A1)],
        {f"claims/{CLAIM_B}.md": BODY_A},
    )
    with pytest.raises(AphelionError) as exc:
        verify(tmp_path)
    assert _code(exc) == ErrorCode.FILESET_DIVERGENCE.value
