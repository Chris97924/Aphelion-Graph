"""Semantic verifier: post-unpack cross-reference checks plus v0.5 signature verification.

v0.4 checks (§S1–§S3, plus the ERR-SEM rules of spec/validator.md):
  Raises :class:`aphelion.errors.SemanticError` / :class:`VerificationError` with
  codes drawn from :class:`aphelion.error_codes.ErrorCode` (5NN band).

v0.5 extension:
  ``verify_package(tar_path, *, require_signed=False, require_notary=False)``
  runs v0.4 checks first, then validates signatures per spec §5.
  Returns :class:`VerifyResult` (frozen dataclass) with ``envelopes`` and
  ``attestations`` fields.

Backward-compat: ``require_signed=False, require_notary=False`` preserves v0.4
behavior. Presence of ``signatures.jsonl`` always invokes §5 — the
``require_signed`` flag only controls whether ABSENCE of signatures is an error.
"""

from __future__ import annotations

import hashlib
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from aphelion.canonical_json import loads
from aphelion.error_codes import ErrorCode
from aphelion.errors import SemanticError, VerificationError
from aphelion.lifecycle import timestamp_to_ms
from aphelion.validator import validate_package


def _load_events(path: Path) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    raw = path.read_bytes()
    for line in raw.splitlines():
        if not line.strip():
            continue
        out.append(loads(line))
    return out


def verify(unpacked_dir: Path | str) -> None:
    """Run the semantic checks on an unpacked Aphelion tree.

    1. unique claim_instance_id / event_id (DUPLICATE_CLAIM_INSTANCE_ID,
       DUPLICATE_EVENT_ID; ERR-SEM-005 / 006)
    2. each claim has its own file, claims/<claim_id>.md (FILESET_DIVERGENCE)
    3. manifest hash ↔ actual claim file bytes (HASH_MISMATCH)
    4. archive file set ↔ manifest.claims paths (FILESET_DIVERGENCE)
    5. provenance chain continuity per claim (CHAIN_BROKEN)
    6. provenance events reference known claims (DANGLING_REFERENCE)
    7. instance ids referenced by events and the manifest were established
       by the provenance (DANGLING_REFERENCE)
    8. manifest terminal state ↔ provenance last event (MANIFEST_STATE_MISMATCH;
       ERR-SEM-013)
    """
    root = Path(unpacked_dir)
    manifest = loads((root / "manifest.json").read_bytes())
    events = _load_events(root / "provenance.jsonl")
    validate_package(manifest, events)

    _check_unique_ids(manifest, events)
    _check_claim_paths(manifest)
    _check_hashes(manifest, root)
    _check_fileset(manifest, root)
    _check_provenance_chain(events)
    _check_provenance_refs(manifest, events)
    by_claim = _events_by_claim(events)
    _check_instance_refs(manifest, by_claim)
    _check_manifest_states(manifest, by_claim)


def _check_unique_ids(manifest: dict[str, Any], events: list[dict[str, Any]]) -> None:
    """ERR-SEM-005 / identity I-2 and ERR-SEM-006 / identity I-3.

    A claim_instance_id names one snapshot: no two manifest entries and no two
    instance-emitting events (create / revise / supersede) may share one.
    """
    seen_instances: set[str] = set()
    for idx, entry in enumerate(manifest["claims"]):
        instance = entry["claim_instance_id"]
        if instance in seen_instances:
            raise SemanticError(
                code=ErrorCode.DUPLICATE_CLAIM_INSTANCE_ID,
                msg=f"duplicate claim_instance_id in manifest: {instance}",
                path=f"manifest.json:claims[{idx}]",
            )
        seen_instances.add(instance)

    seen_events: set[str] = set()
    emitted: set[str] = set()
    for idx, ev in enumerate(events):
        where = f"provenance.jsonl:{idx + 1}"
        if ev["event_id"] in seen_events:
            raise SemanticError(
                code=ErrorCode.DUPLICATE_EVENT_ID,
                msg=f"duplicate event_id in provenance.jsonl: {ev['event_id']}",
                path=where,
            )
        seen_events.add(ev["event_id"])
        instance = ev.get("claim_instance_id")
        if instance is None:
            continue
        if instance in emitted:
            raise SemanticError(
                code=ErrorCode.DUPLICATE_CLAIM_INSTANCE_ID,
                msg=(
                    f"claim_instance_id {instance} is emitted by more than one "
                    "provenance event"
                ),
                path=where,
            )
        emitted.add(instance)


def _check_claim_paths(manifest: dict[str, Any]) -> None:
    """Packaging path rule 4: a claim lives at claims/<claim_id>.md.

    Without this two manifest entries can point at one file, and the hash and
    fileset checks pass for both because they compare against the same bytes.
    """
    owner: dict[str, str] = {}
    for entry in manifest["claims"]:
        path = entry["path"]
        if path in owner:
            raise SemanticError(
                code=ErrorCode.FILESET_DIVERGENCE,
                msg=(
                    f"claims {owner[path]} and {entry['claim_id']} share one "
                    f"claim file: {path}"
                ),
                path=path,
            )
        owner[path] = entry["claim_id"]
        expected = f"claims/{entry['claim_id']}.md"
        if path != expected:
            raise SemanticError(
                code=ErrorCode.FILESET_DIVERGENCE,
                msg=(
                    f"claim {entry['claim_id']} has path {path!r}; its file must "
                    f"be {expected!r}"
                ),
                path=path,
            )


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
            continue  # pragma: no cover - by_claim values are never empty by construction
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


def _events_by_claim(events: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """Group events per claim_id in canonical order (lifecycle §5.4)."""
    by_claim: dict[str, list[dict[str, Any]]] = {}
    for ev in events:
        by_claim.setdefault(ev["claim_id"], []).append(ev)
    for chain in by_claim.values():
        chain.sort(key=lambda ev: (timestamp_to_ms(ev["timestamp"]), ev["event_id"]))
    return by_claim


def _check_instance_refs(
    manifest: dict[str, Any], by_claim: dict[str, list[dict[str, Any]]]
) -> None:
    """Instance ids must have been established by the claim's own provenance.

    * ``target_claim_instance_id`` names the instance in force at the time of
      the event (lifecycle §5.5): the one most recently emitted by a create /
      revise / supersede of the same claim.
    * a manifest entry's ``claim_instance_id`` was emitted by one of its
      claim's events (provenance is the authoritative history of every claim,
      so a claim without provenance has no established instance).
    """
    established: dict[str, set[str]] = {}
    for claim_id, chain in by_claim.items():
        emitted = established.setdefault(claim_id, set())
        in_force: str | None = None
        for ev in chain:
            target = ev.get("target_claim_instance_id")
            if target is not None and target != in_force:
                reason = (
                    "was never established for this claim"
                    if target not in emitted
                    else f"is not the instance in force ({in_force})"
                )
                raise SemanticError(
                    code=ErrorCode.DANGLING_REFERENCE,
                    msg=(
                        f"event {ev['event_id']} targets claim_instance_id "
                        f"{target}, which {reason}"
                    ),
                    path=ev["event_id"],
                )
            instance = ev.get("claim_instance_id")
            if instance is not None:
                emitted.add(instance)
                in_force = instance

    for entry in manifest["claims"]:
        instance = entry["claim_instance_id"]
        if instance not in established.get(entry["claim_id"], set()):
            raise SemanticError(
                code=ErrorCode.DANGLING_REFERENCE,
                msg=(
                    f"manifest claim {entry['claim_id']} declares "
                    f"claim_instance_id {instance}, which its provenance never "
                    "established"
                ),
                path=entry["path"],
            )


_TERMINAL_STATE_BY_EVENT = {"supersede": "superseded", "withdraw": "withdrawn"}
_TERMINAL_STATES = frozenset(_TERMINAL_STATE_BY_EVENT.values())


def _check_manifest_states(
    manifest: dict[str, Any], by_claim: dict[str, list[dict[str, Any]]]
) -> None:
    """ERR-SEM-013: manifest terminal state must agree with the last event.

    A chain ending in supersede / withdraw requires that terminal state in the
    manifest, and a terminal manifest state requires a chain ending in the
    matching event. draft vs active is not compared: a create may leave the
    claim in either (lifecycle §4).
    """
    for entry in manifest["claims"]:
        chain = by_claim.get(entry["claim_id"])
        if not chain:
            continue  # pragma: no cover - _check_instance_refs rejects this first
        last = chain[-1]["event_type"]
        expected = _TERMINAL_STATE_BY_EVENT.get(last)
        state = entry["state"]
        if (expected is not None and state != expected) or (
            expected is None and state in _TERMINAL_STATES
        ):
            raise SemanticError(
                code=ErrorCode.MANIFEST_STATE_MISMATCH,
                msg=(
                    f"manifest state {state!r} for claim {entry['claim_id']} "
                    f"disagrees with its last provenance event {last!r} "
                    f"({chain[-1]['event_id']})"
                ),
                path=entry["path"],
            )


# ---------------------------------------------------------------------------
# v0.5 extension: VerifyResult + verify_package()
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class VerifyResult:
    """Result of ``verify_package()``.

    ``envelopes``: tuple of verified ``SignatureEnvelope`` objects (empty for unsigned).
    ``attestations``: tuple of ``NotaryAttestation`` strings, one per envelope.
    """

    envelopes: tuple[Any, ...]
    attestations: tuple[Any, ...]


def verify_package(
    tar_path: Path | str,
    *,
    require_signed: bool = False,
    require_notary: bool = False,
) -> VerifyResult:
    """Verify a .aphelion.tar end-to-end (v0.4 rules + v0.5 signature rules).

    Spec §5 verification order:
    1. Unpack tar, run v0.4 semantic checks (hash, fileset, chain, refs).
       Failure here uses v0.4 error codes; signatures are NOT checked.
    2. Run §5 signature validation, reusing the parsed signer manifests it
       already extracted (no per-envelope tar re-read).
    3. If ``require_signed=True`` and envelopes is empty: raise E_SIGNER_REQUIRED.
    4. For each envelope, resolve notary. If ``require_notary=True`` and any
       attestation is ``"verified-locally"`` only: raise E_SIGNER_NOTARY_REQUIRED.

    Backward-compat: defaults (require_signed=False, require_notary=False) preserve
    v0.4 behavior — unsigned packages pass, signed packages are §5-verified.
    """
    from aphelion.signer import SignerVerificationError
    from aphelion.trust import resolve_notary, attestation_is_acceptable
    from aphelion.validator import _validate_signatures_full

    tar_path = Path(tar_path)

    # Step 1: v0.4 checks via unpack + verify
    with tempfile.TemporaryDirectory() as tmp_dir:
        from aphelion.unpacker import unpack
        unpacked = unpack(tar_path, tmp_dir)
        verify(unpacked)

    # Step 2: v0.5 signature validation. This extracts and parses each signer
    # manifest exactly once (with typed-error guards); reuse the parsed
    # SignerManifest objects below instead of re-reading the whole tar and
    # re-parsing per envelope.
    envelopes, signer_manifests_by_id = _validate_signatures_full(tar_path)

    # Step 3: require_signed check
    if require_signed and len(envelopes) == 0:
        raise SignerVerificationError(
            "E_SIGNER_REQUIRED",
            "package has no signatures but caller requires --require-signed",
        )

    # Step 4: notary resolution
    attestations: list[Any] = []
    for envelope in envelopes:
        sm = signer_manifests_by_id[envelope.signer_id]
        attestation = resolve_notary(sm)
        attestations.append(attestation)

        if require_notary and not attestation_is_acceptable(attestation, require_notary=True):
            raise SignerVerificationError(
                "E_SIGNER_NOTARY_REQUIRED",
                f"signer {envelope.signer_id!r} attestation is {attestation!r} "
                "but caller requires --require-notary",
            )

    return VerifyResult(
        envelopes=tuple(envelopes),
        attestations=tuple(attestations),
    )
