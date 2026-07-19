"""Arm-agnostic LongMemEval pipeline scaffold.

This module defines the shared vocabulary and control flow of the 3-arm
LongMemEval benchmark. The design invariant is that the *only* independent
variable across arms is the memory layer (the :class:`MemoryStore`); every
other stage — tokenisation/ranking (:mod:`benchmarks.longmemeval.retriever`),
claim extraction, answer synthesis, and judging — is identical for every arm.

Because only the memory layer differs:

* :class:`Session` and :class:`Claim` are the shared data records.
* :class:`MemoryStore` is the structural contract each arm implements
  (see ``benchmarks.longmemeval.arms.plain`` / ``.naive_dedup``).
* :func:`run_arm` is the arm-agnostic evaluation loop.

The extractor / answerer / judge stages are wired in by the S5 smoke story
(next wave). Their signatures are fixed here and the default implementations
raise :class:`NotImplementedError` — these are the *only* not-yet-implemented
paths in this package; the stores and retriever are fully implemented.

Pure stdlib.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Protocol, Sequence, runtime_checkable


# ---------------------------------------------------------------------------
# Shared records
# ---------------------------------------------------------------------------


@dataclass
class Session:
    """One ingested conversation/document unit fed to a store.

    ``text`` is the raw body an extractor turns into claims; ``metadata``
    carries opaque provenance (session/user/turn ids, ...) that arms may keep
    but must never branch retrieval on.
    """

    id: str
    text: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class Claim:
    """An atomic memory record — the unit a store keeps and retrieves.

    ``text`` is the body BM25 ranks and Arm B deduplicates on; ``id`` is the
    stable, deterministic tiebreak key used when scores are equal.
    """

    id: str
    text: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class QAItem:
    """A benchmark question paired with its gold answer."""

    question: str
    gold: str
    metadata: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Structural contracts
# ---------------------------------------------------------------------------


class Retriever(Protocol):
    """Ranks claims against a query. One shared instance serves every arm."""

    def rank(self, query: str, claims: Sequence[Claim]) -> list[Claim]: ...


@runtime_checkable
class MemoryStore(Protocol):
    """The one component that varies across arms.

    ``ingest`` turns sessions into stored claims (applying the arm's retention
    policy); ``retrieve`` returns the arm's claims ranked for a question.
    """

    def ingest(self, sessions: list[Session]) -> None: ...

    def retrieve(self, question: str) -> list[Claim]: ...


# ---------------------------------------------------------------------------
# Deferred pipeline hooks (wired in by the S5 smoke story)
# ---------------------------------------------------------------------------

# An extractor turns one raw session into zero or more atomic claims. It is a
# store dependency (``ingest`` applies it); injecting a real one is deferred.
Extractor = Callable[[Session], list[Claim]]

# An answerer synthesises an answer string from the retrieved claims.
Answerer = Callable[[str, Sequence[Claim]], str]

# A judge decides whether a predicted answer matches the gold answer.
Judge = Callable[[str, str], bool]


def default_extractor(session: Session) -> list[Claim]:
    """Placeholder extractor — replaced by the S5 smoke story.

    Inject a concrete :data:`Extractor` when constructing a store to ingest
    real sessions; the stores themselves are fully implemented.
    """
    raise NotImplementedError(
        "claim extraction is wired in by the S5 smoke story; "
        "inject an Extractor to ingest real sessions"
    )


def default_answerer(question: str, claims: Sequence[Claim]) -> str:
    """Placeholder answerer — replaced by the S5 smoke story."""
    raise NotImplementedError("answer synthesis is wired in by the S5 smoke story")


def default_judge(predicted: str, gold: str) -> bool:
    """Placeholder judge — replaced by the S5 smoke story."""
    raise NotImplementedError("judging is wired in by the S5 smoke story")


# ---------------------------------------------------------------------------
# Arm-agnostic run scaffold
# ---------------------------------------------------------------------------


@dataclass
class ArmResult:
    """Outcome of running one arm over a question set."""

    predictions: list[str]
    correct: list[bool]
    retriever_params: dict[str, Any] = field(default_factory=dict)

    @property
    def num_questions(self) -> int:
        return len(self.correct)

    @property
    def accuracy(self) -> float:
        return sum(self.correct) / len(self.correct) if self.correct else 0.0


def run_arm(
    store: MemoryStore,
    retriever: Retriever,
    sessions: Sequence[Session],
    questions: Sequence[QAItem],
    *,
    answerer: Answerer = default_answerer,
    judge: Judge = default_judge,
    top_k: int = 10,
) -> ArmResult:
    """Run one arm end-to-end; the memory layer is the only thing that varies.

    ``store`` is ingested, then every question is answered from its top-``k``
    retrieved claims and scored. ``retriever`` is the shared ranking engine the
    store was built with; it is passed explicitly so its parameters are recorded
    on the result (documenting that one instance serves every arm) and so a
    future re-ranking stage can reuse it.

    ``answerer`` and ``judge`` default to the deferred hooks and therefore raise
    :class:`NotImplementedError`; the S5 smoke story supplies real ones. The
    ingest + retrieval plumbing exercised here is fully implemented.
    """
    store.ingest(list(sessions))
    predictions: list[str] = []
    correct: list[bool] = []
    for item in questions:
        retrieved = store.retrieve(item.question)[:top_k]
        predicted = answerer(item.question, retrieved)
        predictions.append(predicted)
        correct.append(judge(predicted, item.gold))
    return ArmResult(
        predictions=predictions,
        correct=correct,
        retriever_params=dict(getattr(retriever, "params", {})),
    )
