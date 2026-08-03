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
* :func:`run_arm` is the arm-agnostic *answer-production* loop, and
  :func:`score_blind` is the separate scoring phase that judges every arm at
  once. Evaluation is split in two because design doc §6.1 guard 1 requires the
  judge to see one shuffled, de-identified batch: judging inline, arm by arm,
  hands it three arm-correlated runs and lets the arm leak through ordering.

The extractor / answerer / judge stages are the three model-backed stages. They
are supplied through the :class:`PipelineConfig` injection surface below rather
than implemented here: *which* model serves each stage is a maintainer decision
pinned in ``preregister.json`` (design doc §5.2), so this module deliberately
carries no model name, endpoint, or threshold of its own. A stage that runs
without its pin raises :class:`UnpinnedStageError` naming exactly what to set.

Pure stdlib.
"""

from __future__ import annotations

import json
import random
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol, Sequence, runtime_checkable


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


class Judge(Protocol):
    """Decides whether a candidate answer matches the gold answer.

    Per design doc §6.1 (blind scoring) a judge receives
    ``(question, gold, candidate_answer)`` and never an arm label. The question
    is mandatory, not decorative: a short or context-dependent gold ("22:00",
    "yes") cannot be scored without knowing what was asked.
    """

    def __call__(self, question: str, gold: str, candidate_answer: str) -> bool: ...


# The three model-backed stage names, in pipeline order.
STAGE_NAMES: tuple[str, ...] = ("extractor", "answering", "judge")

# The pre-registration sits next to this module. Pinned knobs are read from it at
# call time rather than copied into this source, so the frozen value and the code
# that consumes it cannot drift apart (design doc §5.2, §6.1 guard 2).
PREREGISTER_PATH = Path(__file__).resolve().parent / "preregister.json"


def preregistered(key: str, path: Path = PREREGISTER_PATH) -> Any:
    """Return one pinned value from ``preregister.json``.

    Raises :class:`KeyError` rather than defaulting: a knob the pre-registration
    does not carry is a maintainer decision this harness may not invent.
    """
    record = json.loads(path.read_text(encoding="utf-8"))
    if key not in record:
        raise KeyError(
            f"{path} carries no pinned {key!r}. The pre-registration is the only "
            "source for it and this harness will not default it."
        )
    return record[key]


def pinned_seed(path: Path = PREREGISTER_PATH) -> int:
    """The pre-registered seed — the only seed this harness may draw from.

    Design doc §6.1 guard 2 pins one seed for the whole benchmark; the blind
    scoring shuffle uses it so the batch order is reproducible and auditable
    against the pre-registration instead of against a constant in this file.
    """
    seed = preregistered("seed", path)
    if isinstance(seed, bool) or not isinstance(seed, int):
        raise TypeError(
            f"the pinned seed must be an int; {path} carries "
            f"{type(seed).__name__} ({seed!r})"
        )
    return seed


class JudgeVerdictError(TypeError):
    """A judge binding returned something that is not a ``bool``.

    Subclasses :class:`TypeError` because the binding violated its declared
    return type. The harness deliberately refuses to coerce or parse the value:
    ``bool("false")``, ``bool("incorrect")`` and ``bool("error: rate limited")``
    are all ``True``, so coercion would silently inflate M1. Turning a text
    verdict into a boolean is the pinned judge prompt's job (design doc §6.1),
    not this module's.
    """


class UnpinnedStageError(NotImplementedError):
    """A model-backed stage was run without its pinned model.

    Subclasses :class:`NotImplementedError` because an unpinned stage genuinely
    has no implementation to run: the benchmark refuses to invent a model
    identity, so the stage stays unimplemented until a maintainer pins one.
    """


class UnrecordedPinsError(ValueError):
    """A run would have produced results carrying no model pin record.

    Two evaluations against different model snapshots, endpoints, temperatures
    or seeds are otherwise indistinguishable once they are numbers in a results
    file, and neither can be audited against ``preregister.json``. The harness
    therefore refuses to start such a run rather than emit unattributable rows.
    """


class PinMismatchError(ValueError):
    """Two arms were produced under different model pins.

    ``preregister.json``'s ``model_fairness_constraint`` requires the answering
    model, the extractor model and the retriever to be identical across arms
    A/B/C — the memory layer is the only independent variable. Arms that ran
    against different pins are not a measurement of the memory layer, so scoring
    them against each other is refused instead of silently reported.
    """


class UnscoredArmError(ValueError):
    """An arm's accuracy was read before the blind scoring phase ran.

    Returning ``0.0`` would read as "got every question wrong" rather than "was
    never judged", so the unscored state is an error, not a value.
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
    """Bind the pinned judge model into a :class:`Judge`.

    Per design doc §6.1 (blind scoring) the judge receives
    ``(question, gold, candidate_answer)`` — no arm label ever reaches it.

    The verdict must be a real ``bool``; anything else raises
    :class:`JudgeVerdictError` instead of being coerced.
    """
    binding = require_binding(config, "judge")

    def judge(question: str, gold: str, candidate_answer: str) -> bool:
        verdict = binding.call(question, gold, candidate_answer, pin=binding.pin)
        if not isinstance(verdict, bool):
            raise JudgeVerdictError(
                f"the judge binding returned {type(verdict).__name__} "
                f"({verdict!r}); the judge stage must return a bool. Make "
                "PipelineConfig.judge.call return True/False — this harness will "
                "not coerce or parse the value, because a truthy 'false' or error "
                "string would silently inflate M1. Verdict parsing belongs to the "
                "pinned judge prompt (design doc §6.1)."
            )
        return verdict

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


def default_judge(question: str, gold: str, candidate_answer: str) -> bool:
    """Resolve the judge from the unpinned config — always fails loud."""
    return build_judge(UNPINNED)(question, gold, candidate_answer)


# ---------------------------------------------------------------------------
# Arm-agnostic run scaffold
# ---------------------------------------------------------------------------


@dataclass
class ArmResult:
    """One arm's answers, plus the verdicts once the blind phase has scored them.

    ``correct`` is ``None`` until :func:`score_blind` runs. Answer production and
    scoring are deliberately separate phases: a judge that sees one arm's answers
    as a contiguous batch can read the arm off the ordering alone, which design
    doc §6.1 guard 1 forbids.

    ``pins`` is the :meth:`PipelineConfig.pins_record` the answers were produced
    under — which models, at which endpoints, temperatures and seeds. Without it
    two runs against different model snapshots yield indistinguishable results
    and nothing can be audited against ``preregister.json``.
    """

    predictions: list[str]
    pins: dict[str, Any]
    correct: list[bool] | None = None
    retriever_params: dict[str, Any] = field(default_factory=dict)

    @property
    def scored(self) -> bool:
        """True once the blind scoring phase has attached verdicts."""
        return self.correct is not None

    @property
    def num_questions(self) -> int:
        return len(self.predictions)

    @property
    def verdicts(self) -> list[bool]:
        """The per-question verdicts; raises while the arm is still unscored."""
        if self.correct is None:
            raise UnscoredArmError(
                "this arm has not been judged yet. Answers are produced by "
                "run_arm and scored afterwards by score_blind, which judges every "
                "arm in one shuffled batch (design doc §6.1)."
            )
        return self.correct

    @property
    def accuracy(self) -> float:
        marks = self.verdicts
        return sum(marks) / len(marks) if marks else 0.0


def run_arm(
    store: MemoryStore,
    retriever: Retriever,
    sessions: Sequence[Session],
    questions: Sequence[QAItem],
    *,
    config: PipelineConfig,
    answerer: Answerer | None = None,
    top_k: int = 10,
) -> ArmResult:
    """Produce one arm's answers; the memory layer is the only thing that varies.

    ``store`` is ingested, then every question is answered from its top-``k``
    retrieved claims. ``retriever`` is the shared ranking engine the store was
    built with; it is passed explicitly so its parameters are recorded on the
    result (documenting that one instance serves every arm) and so a future
    re-ranking stage can reuse it.

    This function deliberately does **not** judge. Scoring every arm is a single
    later phase (:func:`score_blind`) so the judge receives one shuffled,
    de-identified batch rather than three arm-correlated ones.

    ``config`` supplies both the answering stage and the pin record stamped onto
    the result, and a config that pins nothing raises
    :class:`UnrecordedPinsError` before the run starts. ``answerer`` overrides
    only the *callable*, for a deterministic offline stage; the record still
    describes ``config``, so overriding it with a different model would make the
    result claim a model it did not run.
    """
    pins = config.pins_record()
    if not pins:
        raise UnrecordedPinsError(
            "this run would record no model pins, so its results could not be "
            "attributed to any model or audited against "
            "benchmarks/longmemeval/preregister.json. Pass a PipelineConfig with "
            "at least one StageBinding(pin=ModelPin(...), call=<your client>)."
        )

    answer = answerer if answerer is not None else build_answerer(config)
    store.ingest(list(sessions))
    predictions = [
        answer(item.question, store.retrieve(item.question)[:top_k])
        for item in questions
    ]
    return ArmResult(
        predictions=predictions,
        pins=pins,
        retriever_params=dict(getattr(retriever, "params", {})),
    )


# ---------------------------------------------------------------------------
# Blind scoring — one shuffled, de-identified batch across every arm
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BlindSlot:
    """One candidate answer's place in the blind batch.

    The slot is the harness's *private* bookkeeping: it names the arm so verdicts
    can be routed home afterwards, and it never travels to the judge, which only
    ever sees ``(question, gold, candidate_answer)``.
    """

    arm: str
    question_index: int


def blind_batch_order(
    arms: Sequence[str], num_questions: int, *, seed: int
) -> list[BlindSlot]:
    """Every ``(arm, question)`` candidate, shuffled under the pinned ``seed``.

    Design doc §6.1 guard 1 requires candidates from A/B/C to be shuffled before
    scoring: an arm leaks through position even when no label is attached, so a
    judge fed all of A, then all of B, then all of C could favour "the fancy one"
    from ordering alone.

    The pre-shuffle order is built from ``sorted(arms)``, so the result is a pure
    function of the arm *set*, the question count and the seed — it cannot drift
    with a caller's mapping iteration order.
    """
    slots = [
        BlindSlot(arm=arm, question_index=index)
        for arm in sorted(arms)
        for index in range(num_questions)
    ]
    random.Random(seed).shuffle(slots)
    return slots


def score_blind(
    results: Mapping[str, ArmResult],
    questions: Sequence[QAItem],
    *,
    config: PipelineConfig,
    judge: Judge | None = None,
    seed: int | None = None,
) -> dict[str, ArmResult]:
    """Score every arm's answers in ONE pinned-shuffled, de-identified batch.

    This is the second half of the two-phase protocol design doc §6.1 guard 1
    mandates. Every arm's answers are collected first (:func:`run_arm`), then
    pooled and shuffled with :func:`blind_batch_order` before a single pass over
    the judge; verdicts are routed back to their own arm afterwards. The judge
    payload stays ``(question, gold, candidate_answer)`` — the arm is carried
    only by the harness-side :class:`BlindSlot`.

    Two fairness preconditions are enforced rather than assumed, because a breach
    means the run is not measuring the memory layer:

    * every arm must carry a pin record (:class:`UnrecordedPinsError`);
    * it must be the *same* record the judge is pinned to
      (:class:`PinMismatchError`), per ``preregister.json``'s
      ``model_fairness_constraint``.

    ``seed`` defaults to the pre-registered seed read from ``preregister.json``.
    Returns new :class:`ArmResult`\\ s; the inputs are left unscored.
    """
    if not results:
        raise ValueError("score_blind needs at least one arm's results to score")

    expected_pins = config.pins_record()
    if not expected_pins:
        raise UnrecordedPinsError(
            "the scoring config pins no model, so the verdicts could not be "
            "attributed to a judge. Pass the PipelineConfig the run was produced "
            "under (see benchmarks/longmemeval/preregister.json)."
        )

    for arm, result in sorted(results.items()):
        if not result.pins:
            raise UnrecordedPinsError(
                f"arm {arm!r} carries no model pin record, so its answers cannot "
                "be attributed to any model. Produce arm results through run_arm "
                "with a pinned PipelineConfig."
            )
        if result.pins != expected_pins:
            raise PinMismatchError(
                f"arm {arm!r} was produced under a different model pin record "
                f"({result.pins}) than the one scoring is pinned to "
                f"({expected_pins}). preregister.json's "
                "model_fairness_constraint requires identical models across arms "
                "A/B/C — the memory layer is the only independent variable — so "
                "these arms are not comparable."
            )
        if len(result.predictions) != len(questions):
            raise ValueError(
                f"arm {arm!r} answered {len(result.predictions)} questions but "
                f"{len(questions)} were passed for scoring; every arm must answer "
                "the same question set."
            )

    verdict_of = judge if judge is not None else build_judge(config)
    order = blind_batch_order(
        list(results),
        len(questions),
        seed=pinned_seed() if seed is None else seed,
    )

    # Keyed by question index rather than appended, because the batch is
    # shuffled: a verdict's position in the batch says nothing about which
    # question it answered. Verdicts are stored exactly as the judge returned
    # them — coercing here would undo build_judge's strict-bool guard.
    verdicts: dict[str, dict[int, bool]] = {arm: {} for arm in results}
    for slot in order:
        item = questions[slot.question_index]
        candidate = results[slot.arm].predictions[slot.question_index]
        verdicts[slot.arm][slot.question_index] = verdict_of(
            item.question, item.gold, candidate
        )

    # Indexing every slot back out fails loudly if the batch missed one.
    return {
        arm: replace(
            result,
            correct=[verdicts[arm][index] for index in range(len(questions))],
        )
        for arm, result in results.items()
    }
