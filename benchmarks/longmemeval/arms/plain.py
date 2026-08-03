"""Arm A — a flat claim store that keeps every claim (duplicates included).

This is the no-memory-management baseline: whatever the extractor emits is
appended verbatim, so exact duplicates and near-duplicates all accumulate. Only
the retention policy distinguishes it from the other arms; retrieval is the
shared BM25 retriever.
"""

from __future__ import annotations

from benchmarks.longmemeval.pipeline import (
    Claim,
    Extractor,
    Retriever,
    Session,
    default_extractor,
)


class PlainStore:
    """Append-only claim store — Arm A. Duplicates are kept."""

    def __init__(
        self,
        retriever: Retriever,
        *,
        extractor: Extractor = default_extractor,
    ) -> None:
        self._retriever = retriever
        self._extractor = extractor
        self._claims: list[Claim] = []

    @property
    def retriever(self) -> Retriever:
        """The ranking engine this store retrieves with — the run records it."""
        return self._retriever

    @property
    def claims(self) -> list[Claim]:
        """The stored claims, in insertion order (read-only copy)."""
        return list(self._claims)

    @property
    def clusters(self) -> list[list[str]]:
        """M2 merge clusters — all singletons: Arm A never merges anything.

        Arm A therefore predicts *no* duplicate pairs, which is the floor M2's
        ``C.F1 > A.F1 + 0.10`` arm is measured against.
        """
        return [[claim.id] for claim in self._claims]

    def add_claims(self, claims: list[Claim]) -> None:
        """Store every claim verbatim — Arm A keeps all duplicates."""
        self._claims.extend(claims)

    def ingest(self, sessions: list[Session]) -> None:
        for session in sessions:
            self.add_claims(self._extractor(session))

    def retrieve(self, question: str) -> list[Claim]:
        return self._retriever.rank(question, self._claims)
