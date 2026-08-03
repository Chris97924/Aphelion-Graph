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

The extractor / answerer / judge stages are the three model-backed stages. They
are supplied through the :class:`PipelineConfig` injection surface below rather
than implemented here: *which* model serves each stage is a maintainer decision
pinned in ``preregister.json`` (design doc §5.2), so this module deliberately
carries no model name, endpoint, or threshold of its own. A stage that runs
without its pin raises :class:`UnpinnedStageError` naming exactly what to set.

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
# Model-backed stages: pins + injection
# ---------------------------------------------------------------------------

# An extractor turns one raw session into zero or more atomic claims. It is a
# store dependency (``ingest`` applies it).
Extractor = Callable[[Session], list[Claim]]

# An answerer synthesises an answer string from the retrieved claims.
Answerer = Callable[[str, Sequence[Claim]], str]

# A judge decides whether a predicted answer matches the gold answer.
Judge = Callable[[str, str], bool]

# The three model-backed stage names, in pipeline order.
STAGE_NAMES: tuple[str, ...] = ("extractor", "answering", "judge")


class UnpinnedStageError(NotImplementedError):
    """A model-backed stage was run without its pinned model.

    Subclasses :class:`NotImplementedError` because an unpinned stage genuinely
    has no implementation to run: the benchmark refuses to invent a model
    identity, so the stage stays unimplemented until a maintainer pins one.
    """


@dataclass(frozen=True)
class ModelPin:
    """Identity and decoding knobs of one pinned model.

    Every field is required — there is deliberately no default anywhere in this
    module. The pinned values live in ``preregister.json`` (design doc §5.2) and
    are a maintainer decision; the harness only records and enforces them.
    """

    model: str
    endpoint: str
    temperature: float
    seed: int

    def __post_init__(self) -> None:
        if not self.model.strip():
            raise ValueError("ModelPin.model must be a non-empty model identifier")
        if not self.endpoint.strip():
            raise ValueError("ModelPin.endpoint must be a non-empty endpoint")

    def as_record(self) -> dict[str, Any]:
        """The pin as a results-row fragment, for the run's audit trail."""
        return {
            "model": self.model,
            "endpoint": self.endpoint,
            "temperature": self.temperature,
            "seed": self.seed,
        }


@dataclass(frozen=True)
class StageBinding:
    """A pinned model plus the callable that actually invokes it.

    ``pin`` is the recorded identity (what ran); ``call`` is the operator-supplied
    implementation (how to reach it). Splitting the two keeps every model name and
    endpoint out of this repository while still forcing each run to record which
    model produced its numbers.
    """

    pin: ModelPin
    call: Callable[..., Any]

    def __post_init__(self) -> None:
        if not callable(self.call):
            raise TypeError("StageBinding.call must be callable")


@dataclass(frozen=True)
class PipelineConfig:
    """The three model-backed stage bindings. Unset stages fail loud when run.

    An empty config is the honest default: nothing is pinned, so every
    model-backed stage raises :class:`UnpinnedStageError` rather than silently
    running against some invented model.
    """

    extractor: StageBinding | None = None
    answering: StageBinding | None = None
    judge: StageBinding | None = None

    def binding(self, stage: str) -> StageBinding | None:
        if stage not in STAGE_NAMES:
            raise ValueError(f"unknown stage {stage!r}; expected one of {STAGE_NAMES}")
        return getattr(self, stage)

    def pins_record(self) -> dict[str, Any]:
        """Recorded pins for every bound stage — the run's model audit trail."""
        return {
            stage: binding.pin.as_record()
            for stage in STAGE_NAMES
            if (binding := self.binding(stage)) is not None
        }


def require_binding(config: PipelineConfig, stage: str) -> StageBinding:
    """Return the binding for ``stage``, or raise an actionable error.

    The message names the stage, the attribute to set, and where the pinned value
    is decided — but never what the value is: model choice is a maintainer
    decision (design doc §5.2), not something this harness may default.
    """
    binding = config.binding(stage)
    if binding is None:
        raise UnpinnedStageError(
            f"the {stage!r} stage has no pinned model, so it cannot run. "
            f"Set PipelineConfig.{stage} to a StageBinding(pin=ModelPin(...), "
            "call=<your client>). The pinned model identifier, endpoint, "
            "temperature and seed are recorded in "
            "benchmarks/longmemeval/preregister.json (design doc §5.2) and are a "
            "maintainer decision — this harness will not default them."
        )
    return binding


def build_extractor(config: PipelineConfig) -> Extractor:
    """Bind the pinned extractor model into an :data:`Extractor`.

    Raises :class:`UnpinnedStageError` immediately (at build time, not at first
    session) when the extractor stage is unpinned.
    """
    binding = require_binding(config, "extractor")

    def extract(session: Session) -> list[Claim]:
        return list(binding.call(session, pin=binding.pin))

    return extract


def build_answerer(config: PipelineConfig) -> Answerer:
    """Bind the pinned answering model into an :data:`Answerer`."""
    binding = require_binding(config, "answering")

    def answer(question: str, claims: Sequence[Claim]) -> str:
        return str(binding.call(question, claims, pin=binding.pin))

    return answer


def build_judge(config: PipelineConfig) -> Judge:
    """Bind the pinned judge model into a :data:`Judge`.

    Per design doc §6.1 (blind scoring) the judge sees only
    ``(question-answer, gold)`` — no arm label ever reaches it.
    """
    binding = require_binding(config, "judge")

    def judge(predicted: str, gold: str) -> bool:
        return bool(binding.call(predicted, gold, pin=binding.pin))

    return judge


# The unpinned config: every model-backed stage below resolves through it, so the
# default behaviour of the pipeline is to fail loud rather than to guess a model.
UNPINNED = PipelineConfig()


def default_extractor(session: Session) -> list[Claim]:
    """Resolve the extractor from the unpinned config — always fails loud.

    Inject a concrete :data:`Extractor` (or a pinned :class:`PipelineConfig` via
    :func:`build_extractor`) when constructing a store; the stores themselves are
    fully implemented.
    """
    return build_extractor(UNPINNED)(session)


def default_answerer(question: str, claims: Sequence[Claim]) -> str:
    """Resolve the answerer from the unpinned config — always fails loud."""
    return build_answerer(UNPINNED)(question, claims)


def default_judge(predicted: str, gold: str) -> bool:
    """Resolve the judge from the unpinned config — always fails loud."""
    return build_judge(UNPINNED)(predicted, gold)


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

    ``answerer`` and ``judge`` default to the unpinned resolvers and therefore
    raise :class:`UnpinnedStageError`; pass ones built from a pinned
    :class:`PipelineConfig` (:func:`build_answerer` / :func:`build_judge`), or
    deterministic offline stages for a smoke run. The ingest + retrieval
    plumbing exercised here is fully implemented.
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
