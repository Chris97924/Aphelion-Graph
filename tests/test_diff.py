"""Tests for ``aphelion.diff.diff_packages`` and the ``aphelion diff`` CLI."""

from __future__ import annotations

import json
from pathlib import Path

from aphelion.diff import diff_packages, is_empty
from tests.conftest import run_cli


ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "samples"

CLAIM_A = "01930001-0000-7000-8000-00000000aaaa"
INST_A = "01930001-0000-7000-8000-aaaaaaaaaaaa"
HASH_A = "a" * 64
HASH_B = "b" * 64


def _write_pkg(
    base: Path,
    *,
    claims: list[dict],
    events: list[dict],
    package_id: str = "01930000-0000-7000-8000-000000000001",
) -> Path:
    base.mkdir(parents=True, exist_ok=True)
    manifest = {
        "aphelion_spec_version": "0.4.0",
        "claims": claims,
        "created_at": "2026-04-21T00:00:00Z",
        "format_version": "2.0",
        "license": "CC0-1.0",
        "package_id": package_id,
        "producer": "test",
        "provenance_path": "provenance.jsonl",
    }
    (base / "manifest.json").write_text(
        json.dumps(manifest, sort_keys=True), encoding="utf-8", newline=""
    )
    prov_lines = "".join(
        json.dumps(e, sort_keys=True) + "\n" for e in events
    )
    (base / "provenance.jsonl").write_text(prov_lines, encoding="utf-8", newline="")
    return base


def _minimal_claim() -> dict:
    return {
        "claim_id": CLAIM_A,
        "claim_instance_id": INST_A,
        "hash": HASH_A,
        "path": f"claims/{CLAIM_A}.md",
        "state": "active",
    }


def _create_event(event_id: str, ts: str = "2026-04-21T00:00:00Z") -> dict:
    return {
        "actor": "test",
        "claim_id": CLAIM_A,
        "claim_instance_id": INST_A,
        "event_id": event_id,
        "event_type": "create",
        "timestamp": ts,
    }


def _reaffirm_event(event_id: str, prev: str, ts: str) -> dict:
    return {
        "actor": "test",
        "claim_id": CLAIM_A,
        "event_id": event_id,
        "event_type": "reaffirm",
        "prev_event_id": prev,
        "target_claim_instance_id": INST_A,
        "timestamp": ts,
    }


# ---------- (a) identical packages -> empty diff ----------------------------


def test_identical_packages_empty_diff(tmp_path: Path) -> None:
    a = _write_pkg(tmp_path / "a", claims=[_minimal_claim()], events=[_create_event("01930001-0000-7000-8000-eeee00000001")])
    b = _write_pkg(tmp_path / "b", claims=[_minimal_claim()], events=[_create_event("01930001-0000-7000-8000-eeee00000001")])
    diff = diff_packages(a, b)
    assert is_empty(diff), diff
    assert diff["manifest_diff"]["added_fields"] == []
    assert diff["claim_set_diff"]["changed_claim_ids"] == []
    assert diff["per_claim_evidence_diff"] == {}
    assert diff["provenance_timeline_diff"]["added_event_ids"] == []


# ---------- (b) exactly one new event ---------------------------------------


def test_one_extra_event_isolated(tmp_path: Path) -> None:
    first = _create_event("01930001-0000-7000-8000-eeee00000001")
    reaffirm = _reaffirm_event(
        "01930001-0000-7000-8000-eeee00000002",
        prev="01930001-0000-7000-8000-eeee00000001",
        ts="2026-04-21T00:00:01Z",
    )
    a = _write_pkg(tmp_path / "a", claims=[_minimal_claim()], events=[first])
    b = _write_pkg(tmp_path / "b", claims=[_minimal_claim()], events=[first, reaffirm])
    diff = diff_packages(a, b)
    assert diff["provenance_timeline_diff"]["added_event_ids"] == [
        "01930001-0000-7000-8000-eeee00000002"
    ]
    assert diff["provenance_timeline_diff"]["removed_event_ids"] == []
    assert diff["claim_set_diff"]["changed_claim_ids"] == []
    assert diff["per_claim_evidence_diff"] == {}


# ---------- (c) one claim's content_hash differs ----------------------------


def test_claim_hash_change_only(tmp_path: Path) -> None:
    claim_a = _minimal_claim()
    claim_b = {**_minimal_claim(), "hash": HASH_B}
    a = _write_pkg(tmp_path / "a", claims=[claim_a], events=[_create_event("01930001-0000-7000-8000-eeee00000001")])
    b = _write_pkg(tmp_path / "b", claims=[claim_b], events=[_create_event("01930001-0000-7000-8000-eeee00000001")])
    diff = diff_packages(a, b)
    assert diff["claim_set_diff"]["changed_claim_ids"] == [CLAIM_A]
    assert CLAIM_A in diff["per_claim_evidence_diff"]
    hash_change = diff["per_claim_evidence_diff"][CLAIM_A]["hash_change"]
    assert hash_change == {"before": HASH_A, "after": HASH_B}
    assert diff["provenance_timeline_diff"]["added_event_ids"] == []


# ---------- JSON validity ---------------------------------------------------


def test_diff_output_validates_against_schema(tmp_path: Path) -> None:
    """Every required top-level key in the diff schema is present."""
    a = _write_pkg(tmp_path / "a", claims=[_minimal_claim()], events=[_create_event("01930001-0000-7000-8000-eeee00000001")])
    b = _write_pkg(tmp_path / "b", claims=[_minimal_claim()], events=[_create_event("01930001-0000-7000-8000-eeee00000001")])
    diff = diff_packages(a, b)
    # Minimal structural check — the schema listing is informational; we
    # enforce the keys directly to avoid a jsonschema runtime dep.
    required = {
        "diff_spec_version",
        "a",
        "b",
        "manifest_diff",
        "claim_set_diff",
        "per_claim_evidence_diff",
        "provenance_timeline_diff",
    }
    assert required <= diff.keys()
    assert diff["diff_spec_version"] == "0.4.0"


# ---------- CLI integration -------------------------------------------------


def test_cli_diff_human_banner(tmp_path: Path) -> None:
    a = _write_pkg(tmp_path / "a", claims=[_minimal_claim()], events=[_create_event("01930001-0000-7000-8000-eeee00000001")])
    b = _write_pkg(tmp_path / "b", claims=[_minimal_claim()], events=[_create_event("01930001-0000-7000-8000-eeee00000001")])
    code, out, _ = run_cli(["diff", str(a), str(b)])
    assert code == 0
    assert "NOTE: Human-readable diff is informational only" in out
    assert "machine contract" in out


def test_cli_diff_json_mode(tmp_path: Path) -> None:
    a = _write_pkg(tmp_path / "a", claims=[_minimal_claim()], events=[_create_event("01930001-0000-7000-8000-eeee00000001")])
    b = _write_pkg(tmp_path / "b", claims=[_minimal_claim()], events=[_create_event("01930001-0000-7000-8000-eeee00000001")])
    code, out, _ = run_cli(["--json", "diff", str(a), str(b)])
    assert code == 0
    payload = json.loads(out.strip().splitlines()[0])
    assert payload["command"] == "diff"
    assert payload["diff_spec_version"] == "0.4.0"


def test_cli_diff_exits_nonzero_on_difference(tmp_path: Path) -> None:
    a = _write_pkg(tmp_path / "a", claims=[_minimal_claim()], events=[_create_event("01930001-0000-7000-8000-eeee00000001")])
    b_claim = {**_minimal_claim(), "hash": HASH_B}
    b = _write_pkg(tmp_path / "b", claims=[b_claim], events=[_create_event("01930001-0000-7000-8000-eeee00000001")])
    code, _, _ = run_cli(["diff", str(a), str(b)])
    assert code == 1
