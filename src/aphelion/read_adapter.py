"""Aphelion v0.3-r1r4 read-side conflict detection.

Implements the normative R4 detection algorithm (spec §6.3 steps 0-3)
plus the non-normative reference residual-set policy (spec §6.3b) as
the default tiebreak. Implementations may substitute their own policy
that satisfies the §6.3a contract.

The adapter is **stateless** — callers pass the candidate claims plus a
``query_time``; the adapter returns a :class:`QueryResult` with the
derived ``conflict_class``, the active set after supersession, and any
warnings raised during processing.

Spec ground truth: ``spec/v0.3-claim-semantics.md`` §6.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from aphelion.error_codes import WarningCode
from aphelion.v03_validator import validate_subject_required_for_r4


class ConflictClass(str, Enum):
    """Closed enum returned by R4 detection (spec §1.2 + §6.3a)."""

    NOT_FOUND = "not_found"
    NONE = "none"
    SUPERSESSION = "supersession"
    CONTRADICTION = "contradiction"
    AMBIGUITY = "ambiguity"


@dataclass(frozen=True)
class Warning_:
    """Non-fatal signal emitted during read processing.

    ``code`` is a :class:`aphelion.error_codes.WarningCode` value.
    ``data`` carries observability fields suitable for Prometheus labels
    (e.g. ``package_id``, ``target_id``).
    """

    code: WarningCode
    msg: str
    data: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class QueryResult:
    """Outcome of :func:`AphelionReadAdapter.query`.

    ``primary`` and ``surfaced`` are claim mappings (the same shape as
    inputs). ``superseded`` is the list of claim_ids dropped during R4
    step 3. ``used_query_time`` is the truncated-to-second value that
    R2-active filtering ran against (spec §6.4 D1.4).
    """

    conflict_class: ConflictClass
    primary: Mapping[str, Any] | None
    surfaced: tuple[Mapping[str, Any], ...]
    superseded: tuple[str, ...]
    used_query_time: str
    warnings: tuple[Warning_, ...]


def _polarity(claim: Mapping[str, Any]) -> str:
    """Return effective polarity: explicit value or default ``affirm`` (spec §5)."""
    p = claim.get("polarity", "affirm")
    return p if isinstance(p, str) else "affirm"


def _r2_active(claim: Mapping[str, Any], used_query_time: str) -> bool:
    """Spec §4.1: ``valid_from <= query_time <= valid_until`` with both bounds optional."""
    vf = claim.get("valid_from")
    vu = claim.get("valid_until")
    if isinstance(vf, str) and used_query_time < vf:
        return False
    if isinstance(vu, str) and used_query_time > vu:
        return False
    return True


def _truncate_to_second(when: datetime) -> datetime:
    """Drop microseconds — uniform with caller-supplied values (spec §6.4)."""
    return when.replace(microsecond=0)


def _format_iso_z(when: datetime) -> str:
    """Emit the 20-char ``YYYY-MM-DDTHH:MM:SSZ`` form expected by R2 + the audit row."""
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return when.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _resolve_query_time(query_time: datetime | None) -> str:
    """Spec §6.4 D1.4: default = ``datetime.now(UTC)``; truncate to seconds; emit Z."""
    raw = query_time if query_time is not None else datetime.now(timezone.utc)
    return _format_iso_z(_truncate_to_second(raw))


class AphelionReadAdapter:
    """Stateless reader; one method ``query``.

    Constructed in-process by the caller (no external dependencies);
    instantiation does NOT require a ``.aphelion`` package on disk —
    callers pass already-parsed claim frontmatters.

    The adapter is intentionally minimal at MVP: it does NOT load
    packages, walk filesystems, or open archives. Those are the
    caller's job (the existing :mod:`aphelion.unpacker` /
    :mod:`aphelion.validator` chain). This keeps R4 detection
    side-effect-free and easy to test.
    """

    def query(
        self,
        *,
        subject: str,
        candidate_claims: Iterable[Mapping[str, Any]],
        query_time: datetime | None = None,
    ) -> QueryResult:
        """Run R4 detection against ``candidate_claims`` for ``subject``.

        Args:
            subject: subject the caller is querying about. Only claims
                whose frontmatter ``subject`` matches survive step 1.
            candidate_claims: iterable of frontmatter mappings. The
                caller is responsible for having validated each via
                :func:`aphelion.v03_validator.validate_v03_fields`
                first; this adapter does NOT re-run schema validation.
                Step 0 (subject-required-when-R4) is re-checked here as
                defence-in-depth so a caller that skipped validation
                still surfaces the issue.
            query_time: defaults to ``datetime.now(UTC)``.

        Returns:
            :class:`QueryResult` with ``conflict_class``, ``primary``,
            ``surfaced``, ``superseded``, ``used_query_time``, and
            ``warnings``.

        Raises:
            SchemaError: if step 0 detects R4-trigger field on any claim
                without a ``subject``.
        """
        used = _resolve_query_time(query_time)
        warnings: list[Warning_] = []

        # ---- step 0: defence-in-depth subject-required-when-R4 -----------
        all_candidates = list(candidate_claims)
        for claim in all_candidates:
            validate_subject_required_for_r4(claim)

        # ---- step 1: subject + R2-active filter --------------------------
        active = [
            c
            for c in all_candidates
            if c.get("subject") == subject and _r2_active(c, used)
        ]

        # ---- step 2: size predicates -------------------------------------
        if not active:
            return QueryResult(
                conflict_class=ConflictClass.NOT_FOUND,
                primary=None,
                surfaced=(),
                superseded=(),
                used_query_time=used,
                warnings=tuple(warnings),
            )
        if len(active) == 1:
            return QueryResult(
                conflict_class=ConflictClass.NONE,
                primary=active[0],
                surfaced=tuple(active),
                superseded=(),
                used_query_time=used,
                warnings=tuple(warnings),
            )

        # ---- step 3: explicit supersession (lenient cross-pkg) -----------
        active_after_super, superseded_ids, super_warns = _apply_supersession(
            active, all_candidates
        )
        warnings.extend(super_warns)
        if len(active_after_super) == 1:
            return QueryResult(
                conflict_class=ConflictClass.SUPERSESSION,
                primary=active_after_super[0],
                surfaced=tuple(active_after_super),
                superseded=tuple(superseded_ids),
                used_query_time=used,
                warnings=tuple(warnings),
            )

        # ---- §6.3b reference policy (default residual-set tiebreak) -----
        return _residual_default_policy(
            active_after_super,
            superseded_ids=superseded_ids,
            used_query_time=used,
            warnings=warnings,
        )


def _apply_supersession(
    active: list[Mapping[str, Any]],
    all_candidates: list[Mapping[str, Any]],
) -> tuple[list[Mapping[str, Any]], list[str], list[Warning_]]:
    """Spec §6.3 step 3 — lenient cross-package supersession.

    Returns ``(remaining_active, dropped_claim_ids, warnings)``.
    Targets that are not present in the loaded candidate set emit
    :data:`WarningCode.CLAIM_SUPERSEDES_DANGLING` and are skipped
    rather than dropped — the supersession in question is silently
    omitted from this query, but the claim itself stays valid.
    """
    loaded_ids = {
        c.get("claim_id")
        for c in all_candidates
        if isinstance(c.get("claim_id"), str)
    }
    # Only claims that are in the active set can actually be dropped by
    # step 3.  ``superseded`` must reflect IDs removed from *active*, not
    # every claim that happens to exist in the loaded corpus.
    active_ids = {
        c.get("claim_id")
        for c in active
        if isinstance(c.get("claim_id"), str)
    }
    dropped: list[str] = []
    warnings: list[Warning_] = []
    # Iterate copy because we mutate ``active`` indirectly through the
    # returned remaining list.
    for c in list(active):
        targets = c.get("supersedes")
        if not isinstance(targets, list):
            continue
        for target_id in targets:
            if not isinstance(target_id, str):
                continue
            if target_id not in loaded_ids:
                # Lenient cross-pkg per D1.2 (spec §6.2)
                warnings.append(
                    Warning_(
                        code=WarningCode.CLAIM_SUPERSEDES_DANGLING,
                        msg=(
                            f"supersedes target {target_id!r} not present in "
                            "loaded packages; supersession entry skipped"
                        ),
                        data={
                            "claim_id_with_supersedes": str(c.get("claim_id", "")),
                            "dangling_target_id": target_id,
                            "package_id": str(c.get("package_id", "")),
                        },
                    )
                )
                continue
            if target_id not in active_ids:
                # Target exists in the loaded corpus but was not in the
                # active set (different subject or outside R2 window);
                # dropping it would misreport QueryResult.superseded.
                continue
            if target_id in dropped:
                continue
            dropped.append(target_id)
    if not dropped:
        return list(active), dropped, warnings
    remaining = [c for c in active if c.get("claim_id") not in dropped]
    return remaining, dropped, warnings


def _residual_default_policy(
    active: list[Mapping[str, Any]],
    *,
    superseded_ids: list[str],
    used_query_time: str,
    warnings: list[Warning_],
) -> QueryResult:
    """Default residual-set tiebreak per spec §6.3b reference sketch.

    Polarity divergence → contradiction (spec §6.3a binding).
    Mixed unknown vs definite → ambiguity.
    Otherwise recency tiebreak → supersession on primary, others surfaced.

    Implementations MAY substitute their own policy that satisfies the
    §6.3a contract (return one of {contradiction, ambiguity, supersession};
    deterministic; polarity divergence → contradiction).
    """
    polarities = {_polarity(c) for c in active}
    definite = polarities & {"affirm", "negate"}
    if len(definite) >= 2:
        return QueryResult(
            conflict_class=ConflictClass.CONTRADICTION,
            primary=None,
            surfaced=tuple(active),
            superseded=tuple(superseded_ids),
            used_query_time=used_query_time,
            warnings=tuple(warnings),
        )
    if "unknown" in polarities and definite:
        primary = next(c for c in active if _polarity(c) in {"affirm", "negate"})
        return QueryResult(
            conflict_class=ConflictClass.AMBIGUITY,
            primary=primary,
            surfaced=tuple(active),
            superseded=tuple(superseded_ids),
            used_query_time=used_query_time,
            warnings=tuple(warnings),
        )

    # Guard: supersession cycle (A→B and B→A) can empty the residual set.
    # Return SUPERSESSION with no primary rather than crashing on index 0.
    if not active:
        return QueryResult(
            conflict_class=ConflictClass.SUPERSESSION,
            primary=None,
            surfaced=(),
            superseded=tuple(superseded_ids),
            used_query_time=used_query_time,
            warnings=tuple(warnings),
        )

    # Recency tiebreak — newest created_at wins; ties broken by claim_id ascending
    sorted_recent = sorted(
        active,
        key=lambda c: (c.get("created_at", ""), c.get("claim_id", "")),
        reverse=True,
    )
    return QueryResult(
        conflict_class=ConflictClass.SUPERSESSION,
        primary=sorted_recent[0],
        surfaced=tuple(sorted_recent),
        superseded=tuple(superseded_ids),
        used_query_time=used_query_time,
        warnings=tuple(warnings),
    )
