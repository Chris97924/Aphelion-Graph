"""Layered ``aphelion diff`` (v0.3.0).

Produces a four-layer diff between two on-disk Aphelion packages:

1. ``manifest_diff`` — top-level manifest field additions / removals /
   changes (excluding volatile fields such as ``created_at``).
2. ``claim_set_diff`` — which claim_ids were added, removed, or changed.
3. ``per_claim_evidence_diff`` — for each changed claim: hash change,
   state change, tag/label add/remove.
4. ``provenance_timeline_diff`` — event_ids added / removed. Re-ordering
   between two canonically-sorted timelines is represented by
   ``reordered_event_ids`` (empty when both streams already sort
   canonically, as producers must).

The JSON form is the machine contract. The human formatter in
``render_human`` prepends the banner required by the v0.3.0 PRD.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from aphelion.canonical_json import loads


_HUMAN_BANNER = (
    "NOTE: Human-readable diff is informational only; the JSON form "
    "(--json) is the machine contract"
)

# Manifest fields intentionally excluded from the diff because they vary
# with packaging time / author identity but not with claim semantics.
_MANIFEST_EXCLUDE: frozenset[str] = frozenset({"created_at"})


def _read_package(path: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    manifest = loads((path / "manifest.json").read_bytes())
    events: list[dict[str, Any]] = []
    prov = path / "provenance.jsonl"
    if prov.exists():
        for line in prov.read_bytes().splitlines():
            if line.strip():
                events.append(loads(line))
    return manifest, events


def _manifest_diff(a: dict[str, Any], b: dict[str, Any]) -> dict[str, Any]:
    keys_a = set(a) - _MANIFEST_EXCLUDE
    keys_b = set(b) - _MANIFEST_EXCLUDE
    added = sorted(keys_b - keys_a)
    removed = sorted(keys_a - keys_b)
    changed: dict[str, dict[str, Any]] = {}
    for key in sorted(keys_a & keys_b):
        if key == "claims":
            continue
        if a[key] != b[key]:
            changed[key] = {"before": a[key], "after": b[key]}
    return {"added_fields": added, "removed_fields": removed, "changed_fields": changed}


def _index_claims(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {entry["claim_id"]: entry for entry in manifest.get("claims", [])}


def _claim_set_diff(
    a_claims: dict[str, dict[str, Any]], b_claims: dict[str, dict[str, Any]]
) -> dict[str, list[str]]:
    added = sorted(set(b_claims) - set(a_claims))
    removed = sorted(set(a_claims) - set(b_claims))
    changed = sorted(
        cid for cid in set(a_claims) & set(b_claims) if a_claims[cid] != b_claims[cid]
    )
    return {
        "added_claim_ids": added,
        "removed_claim_ids": removed,
        "changed_claim_ids": changed,
    }


def _per_claim_evidence_diff(
    a_claims: dict[str, dict[str, Any]], b_claims: dict[str, dict[str, Any]]
) -> dict[str, dict[str, Any]]:
    shared = set(a_claims) & set(b_claims)
    out: dict[str, dict[str, Any]] = {}
    for cid in sorted(shared):
        ca, cb = a_claims[cid], b_claims[cid]
        claim_delta: dict[str, Any] = {}
        if ca.get("hash") != cb.get("hash"):
            claim_delta["hash_change"] = {"before": ca.get("hash"), "after": cb.get("hash")}
        if ca.get("state") != cb.get("state"):
            claim_delta["state_change"] = {
                "before": ca.get("state"),
                "after": cb.get("state"),
            }
        tag_a = set(ca.get("tags", []) or [])
        tag_b = set(cb.get("tags", []) or [])
        if tag_a != tag_b:
            claim_delta["tags"] = {
                "added": sorted(tag_b - tag_a),
                "removed": sorted(tag_a - tag_b),
            }
        lab_a = set(ca.get("labels", []) or [])
        lab_b = set(cb.get("labels", []) or [])
        if lab_a != lab_b:
            claim_delta["labels"] = {
                "added": sorted(lab_b - lab_a),
                "removed": sorted(lab_a - lab_b),
            }
        if claim_delta:
            out[cid] = claim_delta
    return out


def _provenance_timeline_diff(
    events_a: list[dict[str, Any]], events_b: list[dict[str, Any]]
) -> dict[str, list[str]]:
    ids_a = {e["event_id"] for e in events_a}
    ids_b = {e["event_id"] for e in events_b}
    added = sorted(ids_b - ids_a)
    removed = sorted(ids_a - ids_b)
    # Detect wire-order drift relative to canonical order on the intersection.
    shared = ids_a & ids_b
    order_a_wire = [e["event_id"] for e in events_a if e["event_id"] in shared]
    order_b_wire = [e["event_id"] for e in events_b if e["event_id"] in shared]
    reordered: list[str] = []
    if order_a_wire != order_b_wire:
        reordered = sorted(shared)
    return {
        "added_event_ids": added,
        "removed_event_ids": removed,
        "reordered_event_ids": reordered,
    }


def diff_packages(a_path: Path | str, b_path: Path | str) -> dict[str, Any]:
    """Compute the canonical four-layer diff between packages ``a`` and ``b``."""
    a_path = Path(a_path)
    b_path = Path(b_path)
    manifest_a, events_a = _read_package(a_path)
    manifest_b, events_b = _read_package(b_path)
    claims_a = _index_claims(manifest_a)
    claims_b = _index_claims(manifest_b)
    return {
        "diff_spec_version": "0.4.0",
        "a": str(a_path),
        "b": str(b_path),
        "manifest_diff": _manifest_diff(manifest_a, manifest_b),
        "claim_set_diff": _claim_set_diff(claims_a, claims_b),
        "per_claim_evidence_diff": _per_claim_evidence_diff(claims_a, claims_b),
        "provenance_timeline_diff": _provenance_timeline_diff(events_a, events_b),
    }


def is_empty(diff: dict[str, Any]) -> bool:
    """Return True iff the diff reports no changes across all four layers."""
    m = diff["manifest_diff"]
    c = diff["claim_set_diff"]
    p = diff["provenance_timeline_diff"]
    return (
        not m["added_fields"]
        and not m["removed_fields"]
        and not m["changed_fields"]
        and not c["added_claim_ids"]
        and not c["removed_claim_ids"]
        and not c["changed_claim_ids"]
        and not diff["per_claim_evidence_diff"]
        and not p["added_event_ids"]
        and not p["removed_event_ids"]
        and not p["reordered_event_ids"]
    )


def render_human(diff: dict[str, Any]) -> str:
    """Human-readable summary with the mandatory informational banner."""
    lines = [_HUMAN_BANNER, ""]
    lines.append(f"A: {diff['a']}")
    lines.append(f"B: {diff['b']}")
    if is_empty(diff):
        lines.append("No differences.")
        return "\n".join(lines) + "\n"

    m = diff["manifest_diff"]
    if m["added_fields"] or m["removed_fields"] or m["changed_fields"]:
        lines.append("")
        lines.append("Manifest:")
        for f in m["added_fields"]:
            lines.append(f"  + {f}")
        for f in m["removed_fields"]:
            lines.append(f"  - {f}")
        for f in sorted(m["changed_fields"]):
            lines.append(f"  ~ {f}")
    c = diff["claim_set_diff"]
    if c["added_claim_ids"] or c["removed_claim_ids"] or c["changed_claim_ids"]:
        lines.append("")
        lines.append("Claim set:")
        for cid in c["added_claim_ids"]:
            lines.append(f"  + claim {cid}")
        for cid in c["removed_claim_ids"]:
            lines.append(f"  - claim {cid}")
        for cid in c["changed_claim_ids"]:
            lines.append(f"  ~ claim {cid}")
    if diff["per_claim_evidence_diff"]:
        lines.append("")
        lines.append("Per-claim evidence:")
        for cid, delta in sorted(diff["per_claim_evidence_diff"].items()):
            lines.append(f"  {cid}: {json.dumps(delta, sort_keys=True)}")
    p = diff["provenance_timeline_diff"]
    if p["added_event_ids"] or p["removed_event_ids"] or p["reordered_event_ids"]:
        lines.append("")
        lines.append("Provenance timeline:")
        for eid in p["added_event_ids"]:
            lines.append(f"  + event {eid}")
        for eid in p["removed_event_ids"]:
            lines.append(f"  - event {eid}")
        if p["reordered_event_ids"]:
            lines.append(f"  ~ reordered: {len(p['reordered_event_ids'])} event(s)")
    return "\n".join(lines) + "\n"
