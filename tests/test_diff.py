"""Tests for ``aphelion.diff.diff_packages`` and the ``aphelion diff`` CLI."""

from __future__ import annotations

import json
from pathlib import Path

from aphelion.diff import diff_packages, is_empty, render_human
from tests.conftest import run_cli


ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "samples"

CLAIM_A = "01930001-0000-7000-8000-00000000aaaa"
CLAIM_B = "01930001-0000-7000-8000-00000000bbbb"
CLAIM_C = "01930001-0000-7000-8000-00000000cccc"
INST_A = "01930001-0000-7000-8000-aaaaaaaaaaaa"
INST_B = "01930001-0000-7000-8000-bbbbbbbbbbbb"
INST_C = "01930001-0000-7000-8000-cccccccccccc"
HASH_A = "a" * 64
HASH_B = "b" * 64


def _write_pkg(
    base: Path,
    *,
    claims: list[dict],
    events: list[dict],
    package_id: str = "01930000-0000-7000-8000-000000000001",
    extra_manifest: dict | None = None,
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
    if extra_manifest:
        manifest.update(extra_manifest)
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


# ---------- (d) per-claim state / tag / label deltas ------------------------


def test_per_claim_state_tag_label_deltas(tmp_path: Path) -> None:
    """A shared claim whose state, tags, and labels all change must surface
    each delta independently in ``per_claim_evidence_diff`` (machine contract
    layer 3). hash is unchanged so ``hash_change`` must be absent."""
    claim_a = {
        **_minimal_claim(),
        "state": "active",
        "tags": ["alpha", "beta"],
        "labels": ["x"],
    }
    claim_b = {
        **_minimal_claim(),
        "state": "retracted",
        "tags": ["beta", "gamma"],
        "labels": ["x", "y"],
    }
    ev = _create_event("01930001-0000-7000-8000-eeee00000001")
    a = _write_pkg(tmp_path / "a", claims=[claim_a], events=[ev])
    b = _write_pkg(tmp_path / "b", claims=[claim_b], events=[ev])

    diff = diff_packages(a, b)
    assert diff["claim_set_diff"]["changed_claim_ids"] == [CLAIM_A]
    delta = diff["per_claim_evidence_diff"][CLAIM_A]

    # state_change branch (diff.py:93)
    assert delta["state_change"] == {"before": "active", "after": "retracted"}
    # tags delta branch (diff.py:100) — symmetric add/remove
    assert delta["tags"] == {"added": ["gamma"], "removed": ["alpha"]}
    # labels delta branch (diff.py:107) — pure add, empty remove
    assert delta["labels"] == {"added": ["y"], "removed": []}
    # hash is identical -> the hash_change key must NOT be emitted
    assert "hash_change" not in delta


# ---------- (e) provenance re-order on the shared intersection --------------


def test_provenance_reorder_detected(tmp_path: Path) -> None:
    """Two packages sharing the same event_ids but emitting them in a
    different wire order must report every shared id under
    ``reordered_event_ids`` and report no add/remove (diff.py:129)."""
    e1 = _create_event("01930001-0000-7000-8000-eeee00000001")
    e2 = _reaffirm_event(
        "01930001-0000-7000-8000-eeee00000002",
        prev="01930001-0000-7000-8000-eeee00000001",
        ts="2026-04-21T00:00:01Z",
    )
    a = _write_pkg(tmp_path / "a", claims=[_minimal_claim()], events=[e1, e2])
    # Same two events, reversed wire order (out of canonical order).
    b = _write_pkg(tmp_path / "b", claims=[_minimal_claim()], events=[e2, e1])

    ptd = diff_packages(a, b)["provenance_timeline_diff"]
    assert ptd["added_event_ids"] == []
    assert ptd["removed_event_ids"] == []
    assert ptd["reordered_event_ids"] == sorted(
        [
            "01930001-0000-7000-8000-eeee00000001",
            "01930001-0000-7000-8000-eeee00000002",
        ]
    )


def test_provenance_same_order_not_flagged(tmp_path: Path) -> None:
    """Teeth for diff.py:129 — identical wire order must leave
    ``reordered_event_ids`` empty (guards against a flag-everything bug)."""
    e1 = _create_event("01930001-0000-7000-8000-eeee00000001")
    e2 = _reaffirm_event(
        "01930001-0000-7000-8000-eeee00000002",
        prev="01930001-0000-7000-8000-eeee00000001",
        ts="2026-04-21T00:00:01Z",
    )
    a = _write_pkg(tmp_path / "a", claims=[_minimal_claim()], events=[e1, e2])
    b = _write_pkg(tmp_path / "b", claims=[_minimal_claim()], events=[e1, e2])
    ptd = diff_packages(a, b)["provenance_timeline_diff"]
    assert ptd["reordered_event_ids"] == []


# ---------- (f) human render of a full multi-layer diff ---------------------


def test_render_human_multi_layer(tmp_path: Path) -> None:
    """A diff touching all four layers must render each labelled section of
    the human report (diff.py:186-218): Manifest, Claim set, Per-claim
    evidence, and Provenance timeline."""
    # --- claims: X changed (state/tags/labels), Y removed, Z added ---------
    claim_x_a = {
        **_minimal_claim(),
        "state": "active",
        "tags": ["t1"],
        "labels": ["l1"],
    }
    claim_x_b = {
        **_minimal_claim(),
        "state": "retracted",
        "tags": ["t2"],
        "labels": ["l1", "l2"],
    }
    claim_y = {
        "claim_id": CLAIM_B,
        "claim_instance_id": INST_B,
        "hash": HASH_B,
        "path": f"claims/{CLAIM_B}.md",
        "state": "active",
    }
    claim_z = {
        "claim_id": CLAIM_C,
        "claim_instance_id": INST_C,
        "hash": HASH_A,
        "path": f"claims/{CLAIM_C}.md",
        "state": "active",
    }

    # --- events: E1/E2 shared but reordered, plus one removed + one added ---
    e1 = _create_event("01930001-0000-7000-8000-eeee00000001")
    e2 = _reaffirm_event(
        "01930001-0000-7000-8000-eeee00000002",
        prev="01930001-0000-7000-8000-eeee00000001",
        ts="2026-04-21T00:00:01Z",
    )
    e_removed = _create_event("01930001-0000-7000-8000-eeee00000009")
    e_added = _create_event("01930001-0000-7000-8000-eeee0000000a")

    a = _write_pkg(
        tmp_path / "a",
        claims=[claim_x_a, claim_y],
        events=[e1, e2, e_removed],
        extra_manifest={"producer": "alice", "only_in_a": "1"},
    )
    b = _write_pkg(
        tmp_path / "b",
        claims=[claim_x_b, claim_z],
        events=[e2, e1, e_added],
        extra_manifest={"producer": "bob", "only_in_b": "2"},
    )

    diff = diff_packages(a, b)
    assert not is_empty(diff)
    text = render_human(diff)

    # The mandatory banner is always present.
    assert "machine contract" in text

    # All four labelled sections render for a multi-layer diff.
    assert "Manifest:" in text
    assert "Claim set:" in text
    assert "Per-claim evidence:" in text
    assert "Provenance timeline:" in text

    # Manifest layer: added / removed / changed field lines (diff.py:188-193).
    assert "+ only_in_b" in text
    assert "- only_in_a" in text
    assert "~ producer" in text

    # Claim-set layer: added (diff.py:199) and removed (diff.py:201) claims.
    assert f"+ claim {CLAIM_C}" in text
    assert f"- claim {CLAIM_B}" in text
    assert f"~ claim {CLAIM_A}" in text

    # Provenance layer: added / removed / reordered events (diff.py:213-218).
    assert "+ event 01930001-0000-7000-8000-eeee0000000a" in text
    assert "- event 01930001-0000-7000-8000-eeee00000009" in text
    assert "reordered: 2 event(s)" in text
