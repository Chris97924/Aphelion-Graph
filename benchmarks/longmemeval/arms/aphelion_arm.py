"""Arm C — the full aphelion claim-semantics store.

This is the arm under test. It exercises exactly the three mechanisms the G2
kill-gate is meant to judge (design doc §2.3):

* **content_hash coalescing** — RFC 8785 (JCS) canonicalisation of the identity
  projection → SHA-256, via :func:`aphelion.content_hash.compute_content_hash`.
  Two claims coalesce **iff** they share the same ``claim_id`` (same lineage)
  **and** their 64-hex ``content_hash`` is byte-equal. Never by textual
  proximity, embedding similarity, or any near-duplicate heuristic.
* **event state machine** — ``superseded`` and ``withdrawn`` claims are
  suppressed from retrieval surfacing.
* **R4 conflict classification** — the surviving active set is subject-grouped
  and resolved through :class:`aphelion.read_adapter.AphelionReadAdapter`.

**Why the ``claim_id`` gate is load-bearing.** The ``content_hash`` identity
projection (``spec/content-hash.md`` §3–§4) is a whitelist over ``subject`` /
``predicate`` / ``object`` / ``state`` and the other content fields; it excludes
``claim_id`` outright and drops every R4 field — ``supersedes``, ``valid_from``,
``valid_until``, ``polarity``, ``conflict_class`` — by omission. Two claims can
therefore be byte-equal in ``content_hash`` while differing in R4, e.g. opposite
``polarity``: a live **contradiction**. Coalescing on ``content_hash`` alone
would merge such a different-``claim_id`` pair *before* R4 runs, silently erasing
the conflict — inflating M2 with a false duplicate and poisoning M3 by hiding the
stale value. Gating on ``claim_id`` keeps coalescing lineage-scoped so
cross-lineage collisions reach R4 intact.

Same ``claim_id`` with a *differing* ``content_hash`` is not a coalesce either:
``spec/lifecycle-state-machine.md`` §5.1 makes it a hard
``ERR-SEM-DUPLICATE-HASH-COLLISION`` failure with no automatic reconciliation.

Claim frontmatter travels in :attr:`Claim.metadata`; ``claim_id`` is required
because without a lineage there is no legal way to coalesce.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Iterable, Mapping

from aphelion.content_hash import compute_content_hash
from aphelion.error_codes import ErrorCode
from aphelion.errors import SemanticError
from aphelion.read_adapter import AphelionReadAdapter, ConflictClass, QueryResult

from benchmarks.longmemeval.pipeline import (
    Claim,
    Extractor,
    Retriever,
    Session,
    default_extractor,
)

# States the event state machine makes read-only; they never reach surfacing.
SUPPRESSED_STATES: frozenset[str] = frozenset({"superseded", "withdrawn"})

# Verdicts that surface exactly the R4 primary. ``ambiguity`` and
# ``contradiction`` are handled separately: both surface more than one claim.
_PRIMARY_ONLY_VERDICTS: frozenset[ConflictClass] = frozenset(
    {ConflictClass.NONE, ConflictClass.SUPERSESSION}
)


def frontmatter(claim: Claim) -> dict[str, Any]:
    """The aphelion claim frontmatter carried in ``claim.metadata``."""
    return dict(claim.metadata)


def lineage_id(claim: Claim) -> str:
    """The claim's ``claim_id`` — its lineage. Required by Arm C.

    Arm C's coalescing rule is lineage-gated, so a claim with no ``claim_id``
    cannot be placed on either side of the rule. Failing here is deliberate:
    silently treating it as its own lineage would let un-lineaged claims
    accumulate and quietly change M2.
    """
    value = claim.metadata.get("claim_id")
    if not isinstance(value, str) or not value:
        raise ValueError(
            f"Arm C requires a non-empty 'claim_id' in claim metadata; "
            f"claim {claim.id!r} has {value!r}. Arm C coalescing is "
            "lineage-gated (design doc §2.3) and cannot run without one."
        )
    return value


def content_hash_of(claim: Claim) -> str:
    """The 64-hex ``content_hash`` of a claim's identity projection.

    Delegates to the reference implementation, so the R4 fields and ``claim_id``
    are excluded by the package's own projection rather than by a local copy of
    the rule.
    """
    return compute_content_hash(frontmatter(claim))


def coalescing_key(claim: Claim) -> tuple[str, str]:
    """The lineage-gated coalescing key: ``(claim_id, content_hash)``.

    Both halves must match for two claims to merge. Equality on the hash alone
    is *not* sufficient — that is the cross-lineage case R4 must still see.
    """
    return (lineage_id(claim), content_hash_of(claim))


class AphelionStore:
    """Arm C — content_hash coalescing + event SM suppression + R4 resolution."""

    def __init__(
        self,
        retriever: Retriever,
        *,
        extractor: Extractor = default_extractor,
        adapter: AphelionReadAdapter | None = None,
        query_time: datetime | None = None,
    ) -> None:
        self._retriever = retriever
        self._extractor = extractor
        self._adapter = adapter if adapter is not None else AphelionReadAdapter()
        # Pinned query time keeps R2 valid-time filtering — and therefore the
        # whole run — reproducible; the adapter would otherwise default to now().
        self._query_time = query_time
        self._claims: list[Claim] = []
        # (claim_id, content_hash) -> ids of every claim coalesced into it.
        self._members: dict[tuple[str, str], list[str]] = {}
        # claim_id -> content_hash, to detect §5.1 collisions across lineages.
        self._hash_by_lineage: dict[str, str] = {}

    @property
    def claims(self) -> list[Claim]:
        """The retained claims, in insertion order (read-only copy)."""
        return list(self._claims)

    @property
    def clusters(self) -> list[list[str]]:
        """M2 merge clusters — one per retained claim, listing every id it absorbed."""
        return [list(members) for members in self._members.values()]

    def add_claims(self, claims: list[Claim]) -> None:
        """Coalesce iff same ``claim_id`` AND byte-equal ``content_hash``.

        Raises :class:`aphelion.errors.SemanticError` with
        ``DUPLICATE_HASH_COLLISION`` when one lineage carries two different
        content hashes (``spec/lifecycle-state-machine.md`` §5.1: MUST fail, no
        automatic reconciliation).
        """
        for claim in claims:
            claim_id, chash = coalescing_key(claim)

            prior = self._hash_by_lineage.get(claim_id)
            if prior is not None and prior != chash:
                raise SemanticError(
                    code=ErrorCode.DUPLICATE_HASH_COLLISION,
                    msg=(
                        f"claim_id {claim_id!r} carries two different content "
                        f"hashes ({prior} vs {chash}); spec/lifecycle-state-"
                        "machine.md §5.1 forbids automatic reconciliation"
                    ),
                    path=claim.id,
                )
            self._hash_by_lineage[claim_id] = chash

            existing = self._members.get((claim_id, chash))
            if existing is not None:
                existing.append(claim.id)
                continue
            self._members[(claim_id, chash)] = [claim.id]
            self._claims.append(claim)

    def ingest(self, sessions: list[Session]) -> None:
        for session in sessions:
            self.add_claims(self._extractor(session))

    def retrieve(self, question: str) -> list[Claim]:
        """Rank, suppress read-only states, then resolve R4 per subject group.

        The retriever and the candidate set are the ones Arms A and B see; the
        R4 pass is a *post-filter* over that same set, so the memory layer stays
        the only independent variable. Results keep retriever rank order.
        """
        ranked = self._retriever.rank(question, self._claims)
        active = [claim for claim in ranked if not self.is_suppressed(claim)]
        surfaced = self._r4_surfaced_ids(active)
        return [claim for claim in active if lineage_id(claim) in surfaced]

    @staticmethod
    def is_suppressed(claim: Claim) -> bool:
        """True for ``superseded`` / ``withdrawn`` — the read-only states."""
        return claim.metadata.get("state") in SUPPRESSED_STATES

    def resolve_subject(self, subject: str, claims: Iterable[Claim]) -> QueryResult:
        """R4-resolve one subject group; returns the adapter's ``QueryResult``."""
        return self._adapter.query(
            subject=subject,
            candidate_claims=[frontmatter(claim) for claim in claims],
            query_time=self._query_time,
        )

    def _r4_surfaced_ids(self, active: list[Claim]) -> set[str]:
        """The ``claim_id``s R4 surfaces, across every subject group.

        Claims with no ``subject`` carry no R4 machinery (R4 is subject-scoped by
        spec), so they surface unchanged rather than being silently dropped.
        """
        surfaced: set[str] = set()
        groups: dict[str, list[Claim]] = {}
        for claim in active:
            subject = claim.metadata.get("subject")
            if not isinstance(subject, str) or not subject:
                surfaced.add(lineage_id(claim))
                continue
            groups.setdefault(subject, []).append(claim)

        for subject, group in groups.items():
            surfaced.update(_surfaced_lineages(self.resolve_subject(subject, group)))
        return surfaced


def _surfaced_lineages(result: QueryResult) -> set[str]:
    """Map one R4 ``QueryResult`` onto the lineages Arm C surfaces.

    Per design doc §2.3 the verdict governs surfacing:

    * ``none`` / ``supersession`` — a single ``primary``;
    * ``ambiguity`` — the ``primary`` (the definite claim) **plus** the others;
    * ``contradiction`` — **no** ``primary``; every conflicting claim is
      surfaced. Collapsing a contradiction to one claim would hide a live
      conflict and is an Arm C implementation bug, not a result (design doc
      §2.3 "Harness note").
    * ``not_found`` — nothing survives R2 valid-time filtering.
    """
    if result.conflict_class in _PRIMARY_ONLY_VERDICTS:
        if result.primary is None:
            return set()
        return {result.primary["claim_id"]}
    if result.conflict_class in (
        ConflictClass.AMBIGUITY,
        ConflictClass.CONTRADICTION,
    ):
        return {claim["claim_id"] for claim in result.surfaced}
    return set()


def claim_from_frontmatter(
    fields: Mapping[str, Any],
    text: str = "",
    *,
    record_id: str | None = None,
) -> Claim:
    """Build a harness :class:`Claim` carrying aphelion frontmatter.

    The harness claim id defaults to the ``claim_id``, so a single-lineage claim
    needs no separate identifier; pass ``record_id`` to distinguish two harness
    records that share one lineage — the coalescing case.
    """
    meta = dict(fields)
    return Claim(id=str(record_id or meta["claim_id"]), text=text, metadata=meta)
