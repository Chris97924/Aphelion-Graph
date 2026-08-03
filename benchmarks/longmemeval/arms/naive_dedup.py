"""Arm B — a claim store that collapses whitespace-identical duplicates.

Two claims are treated as the same iff their bodies are byte-equal after
leading/trailing whitespace is stripped and every internal run of whitespace is
collapsed to a single space (:func:`normalize_body`). Nothing smarter: no
case-folding, Unicode normalisation, punctuation stripping, or semantic
hashing — so ``"5K PB is 22:00"`` and ``"my 5K personal best is 22:00"`` stay
two distinct claims. The first occurrence of each normalised body is kept; later
collisions are dropped. Retrieval is the shared BM25 retriever.
"""

from __future__ import annotations

from benchmarks.longmemeval.pipeline import (
    Claim,
    Extractor,
    Retriever,
    Session,
    default_extractor,
)


def normalize_body(text: str) -> str:
    """Strip the ends and collapse internal whitespace runs to single spaces.

    ``str.split()`` with no separator splits on runs of any whitespace and drops
    empty pieces, so ``" ".join(text.split())`` is exactly a leading/trailing
    strip plus internal-run collapse — and nothing else.
    """
    return " ".join(text.split())


class NaiveDedupStore:
    """Whitespace-collapsing claim store — Arm B. First writer wins."""

    def __init__(
        self,
        retriever: Retriever,
        *,
        extractor: Extractor = default_extractor,
    ) -> None:
        self._retriever = retriever
        self._extractor = extractor
        self._claims: list[Claim] = []
        # Normalised body -> the ids of every claim that collapsed into it, in
        # arrival order. Keyed insertion order matches ``_claims`` order, so the
        # two stay aligned without a second index.
        self._members: dict[str, list[str]] = {}

    @property
    def claims(self) -> list[Claim]:
        """The retained claims, in insertion order (read-only copy)."""
        return list(self._claims)

    @property
    def clusters(self) -> list[list[str]]:
        """M2 merge clusters — one per retained claim, listing every id it absorbed."""
        return [list(members) for members in self._members.values()]

    def add_claims(self, claims: list[Claim]) -> None:
        """Keep the first claim per normalised body; drop later collisions."""
        for claim in claims:
            key = normalize_body(claim.text)
            existing = self._members.get(key)
            if existing is not None:
                existing.append(claim.id)
                continue
            self._members[key] = [claim.id]
            self._claims.append(claim)

    def ingest(self, sessions: list[Session]) -> None:
        for session in sessions:
            self.add_claims(self._extractor(session))

    def retrieve(self, question: str) -> list[Claim]:
        return self._retriever.rank(question, self._claims)
