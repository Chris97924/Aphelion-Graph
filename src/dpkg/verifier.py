"""Semantic verifier: post-unpack cross-reference checks.

Raises :class:`dpkg.errors.SemanticError` / :class:`VerificationError` with
codes drawn from :class:`dpkg.error_codes.ErrorCode` (5NN band).
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from dpkg.canonical_json import loads
from dpkg.error_codes import ErrorCode
from dpkg.errors import SemanticError, VerificationError
from dpkg.validator import validate_package


def _load_events(path: Path) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    raw = path.read_bytes()
    for line in raw.splitlines():
        if not line.strip():
            continue
        out.append(loads(line))
    return out


def verify(unpacked_dir: Path | str) -> None:
    """Run the 4 semantic checks on an unpacked DPKG tree.

    1. manifest hash ↔ actual claim file bytes (HASH_MISMATCH)
    2. archive file set ↔ manifest.claims paths (FILESET_DIVERGENCE)
    3. provenance chain continuity per claim (CHAIN_BROKEN)
    4. provenance events reference known claims (DANGLING_REFERENCE)
    """
    root = Path(unpacked_dir)
    manifest = loads((root / "manifest.json").read_bytes())
    events = _load_events(root / "provenance.jsonl")
    validate_package(manifest, events)

    _check_hashes(manifest, root)
    _check_fileset(manifest, root)
    _check_provenance_chain(events)
    _check_provenance_refs(manifest, events)


def _check_hashes(manifest: dict[str, Any], root: Path) -> None:
    for entry in manifest["claims"]:
        claim_path = root / entry["path"]
        if not claim_path.exists():
            raise SemanticError(
                code=ErrorCode.FILESET_DIVERGENCE,
                msg=f"claim file missing: {entry['path']}",
                path=entry["path"],
            )
        actual = hashlib.sha256(claim_path.read_bytes()).hexdigest()
        if actual != entry["hash"]:
            raise VerificationError(
                code=ErrorCode.HASH_MISMATCH,
                msg=(
                    f"hash mismatch for {entry['path']}: manifest={entry['hash']} "
                    f"actual={actual}"
                ),
                path=entry["path"],
            )


def _check_fileset(manifest: dict[str, Any], root: Path) -> None:
    declared = {entry["path"] for entry in manifest["claims"]}
    claims_dir = root / "claims"
    actual: set[str] = set()
    if claims_dir.exists():
        for p in claims_dir.rglob("*"):
            if p.is_file():
                rel = p.relative_to(root).as_posix()
                actual.add(rel)
    extra = actual - declared
    missing = declared - actual
    if extra or missing:
        raise SemanticError(
            code=ErrorCode.FILESET_DIVERGENCE,
            msg=(
                f"archive fileset diverges from manifest: "
                f"extra={sorted(extra)!r} missing={sorted(missing)!r}"
            ),
        )


def _check_provenance_chain(events: list[dict[str, Any]]) -> None:
    """Each claim's events must form a valid chain: create first, then each
    non-create event's prev_event_id must link to a prior event_id for the
    same claim_id. Forks (two children sharing a prev_event_id) are rejected.
    """
    by_claim: dict[str, list[dict[str, Any]]] = {}
    for ev in events:
        by_claim.setdefault(ev["claim_id"], []).append(ev)

    for claim_id, chain in by_claim.items():
        if not chain:
            continue
        creates = [e for e in chain if e["event_type"] == "create"]
        if len(creates) != 1:
            raise SemanticError(
                code=ErrorCode.CHAIN_BROKEN,
                msg=(
                    f"claim {claim_id} must have exactly one create event; "
                    f"found {len(creates)}"
                ),
                path=claim_id,
            )
        seen_event_ids: set[str] = {creates[0]["event_id"]}
        child_of: dict[str, str] = {}
        for ev in chain:
            if ev["event_type"] == "create":
                continue
            prev = ev.get("prev_event_id")
            if prev is None or prev not in seen_event_ids:
                raise SemanticError(
                    code=ErrorCode.CHAIN_BROKEN,
                    msg=(
                        f"claim {claim_id}: event {ev['event_id']} has dangling "
                        f"prev_event_id={prev}"
                    ),
                    path=claim_id,
                )
            if prev in child_of:
                raise SemanticError(
                    code=ErrorCode.CHAIN_BROKEN,
                    msg=(
                        f"claim {claim_id}: fork detected - {prev} has two "
                        f"children ({child_of[prev]} and {ev['event_id']})"
                    ),
                    path=claim_id,
                )
            child_of[prev] = ev["event_id"]
            seen_event_ids.add(ev["event_id"])


def _check_provenance_refs(
    manifest: dict[str, Any], events: list[dict[str, Any]]
) -> None:
    """Every event's claim_id must be present in the manifest."""
    known = {entry["claim_id"] for entry in manifest["claims"]}
    for ev in events:
        if ev["claim_id"] not in known:
            raise SemanticError(
                code=ErrorCode.DANGLING_REFERENCE,
                msg=(
                    f"event {ev['event_id']} references unknown "
                    f"claim_id {ev['claim_id']!r}"
                ),
                path=ev["event_id"],
            )
