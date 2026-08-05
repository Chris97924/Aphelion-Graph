"""Tests for the LongMemEval execution layer: injection, metrics, 3-arm smoke.

Covers the S1 acceptance contract outside Arm C itself (which has its own file):

* **Injection** — the three model-backed stages resolve through
  :class:`~benchmarks.longmemeval.pipeline.PipelineConfig`; running one without a
  pin raises an actionable :class:`UnpinnedStageError`, and no model name,
  endpoint or threshold is hardcoded anywhere in the package.
* **M2 / M3 store bridges** — each metric scores straight from an arm's store.
* **M5** — byte-level round-trip equality, driven through the ``aphelion``
  package's own public API (proven by recording the calls), plus the refusal to
  report the pinned gate as runnable.
* **3-arm smoke** — arms A+B+C and metrics M2+M3+M5 in one offline command, with
  every network entry point monkeypatched to raise.
"""

from __future__ import annotations

import http.client
import itertools
import json
import socket
import urllib.request
from pathlib import Path

import pytest

from benchmarks.longmemeval import corpus
from benchmarks.longmemeval import run as run_mod
from benchmarks.longmemeval.arms import ARM_STORES
from benchmarks.longmemeval.arms.naive_dedup import NaiveDedupStore
from benchmarks.longmemeval.arms.plain import PlainStore
from benchmarks.longmemeval.metrics import m2_dedup, m3_contamination, m5_roundtrip
from benchmarks.longmemeval.pipeline import (
    ArmResult,
    Claim,
    JudgeVerdictError,
    ModelPin,
    PinMismatchError,
    PipelineConfig,
    QAItem,
    RetrieverMismatchError,
    RetrieverProvenanceError,
    Session,
    StageBinding,
    UnpinnedStageError,
    UnrecordedPinsError,
    UnscoredArmError,
    blind_batch_order,
    build_answerer,
    build_extractor,
    build_judge,
    default_answerer,
    default_extractor,
    default_judge,
    pinned_seed,
    run_arm,
    score_blind,
)
from benchmarks.longmemeval.retriever import BM25Retriever

_REPO_ROOT = Path(__file__).resolve().parent.parent
_SAMPLES_ROOT = _REPO_ROOT / "samples"
_BENCH_ROOT = _REPO_ROOT / "benchmarks" / "longmemeval"

_DATA_DIR = corpus.data_dir()
requires_oracle = pytest.mark.skipif(
    not (_DATA_DIR / corpus.ORACLE_FILENAME).is_file(),
    reason=f"LongMemEval oracle not found in {_DATA_DIR}",
)

_PIN = ModelPin(model="stub-model", endpoint="stub://local", temperature=0.0, seed=1)

# A fully pinned config whose stage calls are inert. Tests below inject the
# behaviour they need through ``answerer=`` / ``judge=`` and use the config only
# for the pin record every run is required to carry.
_STUB_CONFIG = PipelineConfig(
    extractor=StageBinding(pin=_PIN, call=lambda session, *, pin: []),
    answering=StageBinding(pin=_PIN, call=lambda question, claims, *, pin: ""),
    judge=StageBinding(pin=_PIN, call=lambda *args, **kwargs: True),
)

# The arms the blind-scoring tests pool into one judge batch.
_ARMS: tuple[str, ...] = ("A", "B", "C")


def _echo_answerer(question: str, claims) -> str:
    return claims[0].text if claims else ""


def _unscored(arm: str, num_questions: int) -> ArmResult:
    """One arm's answers, each naming its own arm so a transcript is attributable."""
    return ArmResult(
        predictions=[f"{arm}{index}" for index in range(num_questions)],
        pins=_STUB_CONFIG.pins_record(),
    )


# --------------------------------------------------------------------------- #
# Injection: unpinned stages fail loud, pinned ones run                        #
# --------------------------------------------------------------------------- #


@pytest.mark.unit
@pytest.mark.parametrize("stage", ["extractor", "answering", "judge"])
def test_unpinned_stage_raises_an_actionable_error(stage: str) -> None:
    """The message must name the attribute to set and where the pin is decided."""
    builder = {
        "extractor": build_extractor,
        "answering": build_answerer,
        "judge": build_judge,
    }[stage]

    with pytest.raises(UnpinnedStageError) as excinfo:
        builder(PipelineConfig())

    message = str(excinfo.value)
    assert f"PipelineConfig.{stage}" in message
    assert "preregister.json" in message


@pytest.mark.unit
def test_default_stages_resolve_through_the_unpinned_config() -> None:
    """The default hooks are the unpinned path, so they fail loud rather than guess."""
    with pytest.raises(UnpinnedStageError):
        default_extractor(Session(id="s", text="x"))
    with pytest.raises(UnpinnedStageError):
        default_answerer("q", [])
    with pytest.raises(UnpinnedStageError):
        default_judge("q", "gold", "candidate")


@pytest.mark.unit
def test_pinned_config_builds_working_stages() -> None:
    """A bound stage invokes the injected callable and receives its own pin."""
    seen: list[ModelPin] = []

    def extract(session: Session, *, pin: ModelPin) -> list[Claim]:
        seen.append(pin)
        return [Claim(id=session.id, text=session.text)]

    def answer(question: str, claims, *, pin: ModelPin) -> str:
        seen.append(pin)
        return claims[0].text if claims else ""

    def judge(
        question: str, gold: str, candidate_answer: str, *, pin: ModelPin
    ) -> bool:
        seen.append(pin)
        return candidate_answer == gold

    config = PipelineConfig(
        extractor=StageBinding(pin=_PIN, call=extract),
        answering=StageBinding(pin=_PIN, call=answer),
        judge=StageBinding(pin=_PIN, call=judge),
    )

    claims = build_extractor(config)(Session(id="s1", text="hello"))
    assert [claim.text for claim in claims] == ["hello"]
    assert build_answerer(config)("q", claims) == "hello"
    assert build_judge(config)("q", "hello", "hello") is True
    assert seen == [_PIN, _PIN, _PIN]


# --------------------------------------------------------------------------- #
# Judge contract: blind scoring gets the question; verdicts must be real bools  #
# --------------------------------------------------------------------------- #


@pytest.mark.unit
def test_judge_receives_the_question_with_the_gold_and_candidate() -> None:
    """Design doc §6.1: the judge sees ``(question, gold, candidate_answer)``.

    Without the question a short or context-dependent gold ("22:00", "yes")
    cannot be scored reliably, so M1 silently mis-scores.
    """
    seen: list[tuple[str, str, str]] = []

    def judge(
        question: str, gold: str, candidate_answer: str, *, pin: ModelPin
    ) -> bool:
        seen.append((question, gold, candidate_answer))
        return True

    bound = build_judge(PipelineConfig(judge=StageBinding(pin=_PIN, call=judge)))
    assert bound("what was my 5K PB?", "22:00", "22:00") is True
    assert seen == [("what was my 5K PB?", "22:00", "22:00")]


@pytest.mark.unit
def test_blind_scoring_forwards_each_question_to_the_judge() -> None:
    """The question reaching the judge must be the item's own question."""
    judged: list[tuple[str, str, str]] = []

    def judge(question: str, gold: str, candidate_answer: str) -> bool:
        judged.append((question, gold, candidate_answer))
        return gold == candidate_answer

    store = PlainStore(
        BM25Retriever(), extractor=lambda s: [Claim(id=s.id, text=s.text)]
    )
    questions = [QAItem(question="what was my 5K PB?", gold="22:00")]
    produced = run_arm(
        store,
        BM25Retriever(),
        [Session(id="s1", text="22:00")],
        questions,
        config=_STUB_CONFIG,
        answerer=_echo_answerer,
    )
    scored = score_blind({"A": produced}, questions, config=_STUB_CONFIG, judge=judge)

    assert judged == [("what was my 5K PB?", "22:00", "22:00")]
    assert scored["A"].correct == [True]


@pytest.mark.unit
@pytest.mark.parametrize(
    "verdict", ["false", "incorrect", "no", "0", "error: rate limited", 1, 0, None, ""]
)
def test_non_boolean_judge_verdict_fails_loud(verdict: object) -> None:
    """``bool(...)`` on a text verdict silently inflates M1 — reject it instead.

    ``"false"`` / ``"incorrect"`` / an error string are all truthy, and ``1`` /
    ``0`` are ints, not verdicts. The harness refuses to guess a parse: parsing
    semantics belong to the pinned judge prompt, so a non-bool is an error.
    """
    bound = build_judge(
        PipelineConfig(judge=StageBinding(pin=_PIN, call=lambda *a, **k: verdict))
    )
    with pytest.raises(JudgeVerdictError) as excinfo:
        bound("q", "gold", "candidate")

    message = str(excinfo.value)
    assert "judge" in message
    assert type(verdict).__name__ in message


@pytest.mark.unit
def test_boolean_judge_verdicts_pass_through_unchanged() -> None:
    """Real bools — and only real bools — are accepted, both ways."""
    for verdict in (True, False):
        bound = build_judge(
            PipelineConfig(judge=StageBinding(pin=_PIN, call=lambda *a, **k: verdict))
        )
        assert bound("q", "gold", "candidate") is verdict


# --------------------------------------------------------------------------- #
# Blind scoring — ONE pinned-shuffled cross-arm batch (design doc §6.1 guard 1) #
# --------------------------------------------------------------------------- #


@pytest.mark.unit
def test_run_arm_produces_answers_and_does_not_judge() -> None:
    """Answer production is separate from scoring.

    Judging inside ``run_arm`` handed the judge one arm's answers as a
    contiguous batch, which leaks the arm through ordering even with no label
    attached (design doc §6.1 guard 1). Scoring therefore happens once, across
    every arm, in :func:`score_blind`.
    """
    store = PlainStore(
        BM25Retriever(), extractor=lambda s: [Claim(id=s.id, text=s.text)]
    )
    result = run_arm(
        store,
        BM25Retriever(),
        [Session(id="s1", text="22:00")],
        [QAItem(question="what was my 5K PB?", gold="22:00")],
        config=_STUB_CONFIG,
        answerer=_echo_answerer,
    )

    assert result.predictions == ["22:00"]
    assert result.correct is None
    assert result.scored is False
    # An unscored arm has no accuracy — returning 0.0 would read as "got them
    # all wrong" rather than "was never judged".
    with pytest.raises(UnscoredArmError):
        _ = result.accuracy


@pytest.mark.unit
def test_the_judge_batch_interleaves_the_arms_and_is_deterministic() -> None:
    """The judge must never see one arm as a contiguous run of candidates.

    Inline per-arm judging produced ``AAAA BBBB CCCC``; position alone would then
    tell the judge which arm it is scoring, which is exactly what guard 1 forbids.
    The replacement order is a shuffle seeded from the pre-registration, so it is
    both non-arm-ordered and reproducible.
    """
    questions = [QAItem(question=f"q{i}", gold=f"g{i}") for i in range(6)]

    def transcript() -> list[str]:
        seen: list[str] = []

        def judge(question: str, gold: str, candidate_answer: str) -> bool:
            seen.append(candidate_answer)
            return True

        score_blind(
            {arm: _unscored(arm, len(questions)) for arm in _ARMS},
            questions,
            config=_STUB_CONFIG,
            judge=judge,
        )
        return seen

    first, second = transcript(), transcript()

    assert first == second, "the pinned seed must make the batch order reproducible"
    assert sorted(first) == sorted(
        f"{arm}{index}" for arm in _ARMS for index in range(len(questions))
    ), "every arm's every answer must be scored exactly once"

    arms_in_order = [candidate[0] for candidate in first]
    # ``sorted`` is precisely the buggy grouping: all of A, then all of B, then C.
    assert arms_in_order != sorted(arms_in_order)
    longest_run = max(len(list(group)) for _, group in itertools.groupby(arms_in_order))
    assert longest_run < len(questions)


@pytest.mark.unit
def test_the_judge_batch_maps_every_verdict_back_to_its_own_arm() -> None:
    """Shuffling must not scramble attribution: each verdict lands on its arm."""
    questions = [QAItem(question=f"q{i}", gold=f"g{i}") for i in range(4)]

    # An arbitrary verdict pattern no ordering could reproduce by accident.
    def judge(question: str, gold: str, candidate_answer: str) -> bool:
        return candidate_answer.startswith("B") or candidate_answer == "C2"

    scored = score_blind(
        {arm: _unscored(arm, len(questions)) for arm in _ARMS},
        questions,
        config=_STUB_CONFIG,
        judge=judge,
    )

    assert scored["A"].correct == [False, False, False, False]
    assert scored["B"].correct == [True, True, True, True]
    assert scored["C"].correct == [False, False, True, False]
    assert scored["B"].accuracy == 1.0
    assert scored["C"].accuracy == 0.25


@pytest.mark.unit
def test_the_judge_never_receives_an_arm_label() -> None:
    """Guard 1's de-identification: the payload is ``(question, gold, candidate)``."""
    questions = [QAItem(question="q0", gold="g0")]
    payloads: list[tuple] = []

    def judge(*args, **kwargs) -> bool:
        payloads.append((args, kwargs))
        return True

    score_blind(
        {arm: _unscored(arm, 1) for arm in _ARMS},
        questions,
        config=_STUB_CONFIG,
        judge=judge,
    )

    assert len(payloads) == len(_ARMS)
    for args, kwargs in payloads:
        assert kwargs == {}
        assert len(args) == 3
        assert args[0] == "q0" and args[1] == "g0"


@pytest.mark.unit
def test_the_batch_order_is_a_pure_function_of_seed_arms_and_length() -> None:
    """Arm iteration order must not change the batch — the base order is sorted."""
    assert blind_batch_order(["C", "A", "B"], 3, seed=7) == blind_batch_order(
        ["A", "B", "C"], 3, seed=7
    )
    assert blind_batch_order(["A", "B"], 4, seed=1) != blind_batch_order(
        ["A", "B"], 4, seed=2
    )


@pytest.mark.unit
def test_the_shuffle_seed_is_read_from_the_preregistration(tmp_path: Path) -> None:
    """The seed is loaded from ``preregister.json`` at run time, never re-hardcoded."""
    recorded = json.loads(
        (_BENCH_ROOT / "preregister.json").read_text(encoding="utf-8")
    )["seed"]
    assert pinned_seed() == recorded

    # Reading a different pre-registration yields its seed — proof the value
    # comes off disk rather than out of a constant in the harness.
    alternate = tmp_path / "preregister.json"
    alternate.write_text(json.dumps({"seed": 1}), encoding="utf-8")
    assert pinned_seed(alternate) == 1


# --------------------------------------------------------------------------- #
# F-5 — every result carries the model pin record it was produced under        #
# --------------------------------------------------------------------------- #


@pytest.mark.unit
def test_run_arm_records_the_pins_it_ran_under() -> None:
    """Two runs under different model snapshots must not be indistinguishable."""
    store = PlainStore(
        BM25Retriever(), extractor=lambda s: [Claim(id=s.id, text=s.text)]
    )
    result = run_arm(
        store,
        BM25Retriever(),
        [Session(id="s1", text="22:00")],
        [QAItem(question="q", gold="22:00")],
        config=_STUB_CONFIG,
        answerer=_echo_answerer,
    )

    assert result.pins == _STUB_CONFIG.pins_record()
    assert result.pins["answering"] == {
        "model": "stub-model",
        "endpoint": "stub://local",
        "temperature": 0.0,
        "seed": 1,
    }


@pytest.mark.unit
def test_run_arm_refuses_a_run_with_no_recorded_pins() -> None:
    """An unpinned result cannot be audited against ``preregister.json``."""
    store = PlainStore(
        BM25Retriever(), extractor=lambda s: [Claim(id=s.id, text=s.text)]
    )
    with pytest.raises(UnrecordedPinsError) as excinfo:
        run_arm(
            store,
            BM25Retriever(),
            [Session(id="s1", text="22:00")],
            [QAItem(question="q", gold="22:00")],
            config=PipelineConfig(),
            answerer=_echo_answerer,
        )
    assert "preregister.json" in str(excinfo.value)


@pytest.mark.unit
def test_scoring_refuses_arms_produced_under_different_pins() -> None:
    """``preregister.json`` model_fairness_constraint: identical models across arms.

    An A/B/C comparison whose arms ran against different model snapshots,
    endpoints, temperatures or seeds is not measuring the memory layer.
    """
    other_pin = ModelPin(
        model="stub-model", endpoint="stub://local", temperature=0.7, seed=1
    )
    other = PipelineConfig(
        answering=StageBinding(pin=other_pin, call=lambda q, c, *, pin: "")
    )
    questions = [QAItem(question="q0", gold="g0")]

    results = {arm: _unscored(arm, 1) for arm in _ARMS}
    results["C"] = ArmResult(predictions=["C0"], pins=other.pins_record())

    with pytest.raises(PinMismatchError) as excinfo:
        score_blind(results, questions, config=_STUB_CONFIG, judge=lambda *a: True)
    assert "C" in str(excinfo.value)


@pytest.mark.unit
def test_scoring_refuses_results_with_no_pin_record() -> None:
    questions = [QAItem(question="q0", gold="g0")]
    results = {"A": ArmResult(predictions=["A0"], pins={})}
    with pytest.raises(UnrecordedPinsError):
        score_blind(results, questions, config=_STUB_CONFIG, judge=lambda *a: True)


@pytest.mark.unit
def test_scoring_refuses_an_arm_that_answered_a_different_question_count() -> None:
    questions = [QAItem(question=f"q{i}", gold=f"g{i}") for i in range(3)]
    results = {"A": _unscored("A", 3), "B": _unscored("B", 2)}
    with pytest.raises(ValueError, match="B"):
        score_blind(results, questions, config=_STUB_CONFIG, judge=lambda *a: True)


# --------------------------------------------------------------------------- #
# F-7 / F-8 — the retriever is pinned too, and the record names the real one   #
# --------------------------------------------------------------------------- #


def _answers(arm: str, retriever_params: dict) -> ArmResult:
    """One arm's answers under an explicit retriever record."""
    return ArmResult(
        predictions=[f"{arm}0"],
        pins=_STUB_CONFIG.pins_record(),
        retriever_params=retriever_params,
    )


@pytest.mark.unit
def test_scoring_refuses_arms_retrieved_under_different_retriever_settings() -> None:
    """``preregister.json`` pins the retriever across arms, not just the models.

    Identical pins are not enough: answers produced under different BM25
    parameters differ in what the answering model ever saw, so scoring them
    against each other measures the retriever, not the memory layer.
    """
    shared = BM25Retriever()
    tuned = BM25Retriever(k1=2.0, b=0.5)
    assert shared.params != tuned.params

    results = {
        "A": _answers("A", shared.params),
        "B": _answers("B", shared.params),
        "C": _answers("C", tuned.params),
    }
    # The pins are byte-identical — this is exactly the case the pin check passes.
    assert results["C"].pins == results["A"].pins

    with pytest.raises(RetrieverMismatchError) as excinfo:
        score_blind(
            results,
            [QAItem(question="q0", gold="g0")],
            config=_STUB_CONFIG,
            judge=lambda *a: True,
        )

    message = str(excinfo.value)
    assert "'C'" in message, "the offending arm must be named"
    assert "2.0" in message, "the disagreeing settings must be shown"


@pytest.mark.unit
def test_scoring_accepts_arms_that_share_one_retriever_record() -> None:
    """The guard is scoped to disagreement; the shared-retriever run still scores."""
    shared = BM25Retriever().params
    scored = score_blind(
        {arm: _answers(arm, shared) for arm in _ARMS},
        [QAItem(question="q0", gold="g0")],
        config=_STUB_CONFIG,
        judge=lambda *a: True,
    )
    assert {arm: result.correct for arm, result in scored.items()} == {
        arm: [True] for arm in _ARMS
    }


@pytest.mark.unit
def test_run_arm_records_the_retriever_the_store_ranked_with() -> None:
    """The audit trail describes the retriever that produced the answers."""
    tuned = BM25Retriever(k1=2.0, b=0.5)
    store = PlainStore(tuned, extractor=lambda s: [Claim(id=s.id, text=s.text)])

    result = run_arm(
        store,
        tuned,
        [Session(id="s1", text="22:00")],
        [QAItem(question="q", gold="22:00")],
        config=_STUB_CONFIG,
        answerer=_echo_answerer,
    )

    assert result.retriever_params == tuned.params
    assert result.retriever_params != BM25Retriever().params


@pytest.mark.unit
def test_run_arm_refuses_a_store_built_with_a_different_retriever() -> None:
    """Recording the argument would claim a retriever that ranked nothing.

    The store answers from ``store.retrieve(...)``, so the store's own retriever
    is what produced the predictions. A run that recorded the passed-in one would
    stamp the shared/pinned settings onto answers another retriever generated.
    """
    store = PlainStore(
        BM25Retriever(k1=2.0, b=0.5),
        extractor=lambda s: [Claim(id=s.id, text=s.text)],
    )

    with pytest.raises(RetrieverProvenanceError) as excinfo:
        run_arm(
            store,
            BM25Retriever(),
            [Session(id="s1", text="22:00")],
            [QAItem(question="q", gold="22:00")],
            config=_STUB_CONFIG,
            answerer=_echo_answerer,
        )

    message = str(excinfo.value)
    assert "2.0" in message and "1.5" in message, "both settings must be shown"


@pytest.mark.unit
def test_run_arm_accepts_two_references_to_the_same_retriever_settings() -> None:
    """The invariant is the ranking configuration, not object identity.

    ``BM25Retriever`` is stateless, so two instances carrying the same parameters
    rank identically and the record is unambiguous either way.
    """
    store_retriever = BM25Retriever()
    twin = BM25Retriever()
    assert twin is not store_retriever

    store = PlainStore(
        store_retriever, extractor=lambda s: [Claim(id=s.id, text=s.text)]
    )
    result = run_arm(
        store,
        twin,
        [Session(id="s1", text="22:00")],
        [QAItem(question="q", gold="22:00")],
        config=_STUB_CONFIG,
        answerer=_echo_answerer,
    )
    assert result.retriever_params == store_retriever.params


@pytest.mark.unit
def test_run_arm_refuses_a_store_that_names_no_retriever() -> None:
    """No silent fallback to the argument — that is the whole failure mode.

    A store that will not say which retriever it ranked with cannot have its
    answers attributed, so the run is refused rather than stamped with the
    retriever that merely happened to be passed alongside it.
    """

    class _OpaqueStore:
        def ingest(self, sessions: list[Session]) -> None:
            return None

        def retrieve(self, question: str) -> list[Claim]:
            return []

    with pytest.raises(RetrieverProvenanceError) as excinfo:
        run_arm(
            _OpaqueStore(),
            BM25Retriever(),
            [Session(id="s1", text="22:00")],
            [QAItem(question="q", gold="22:00")],
            config=_STUB_CONFIG,
            answerer=_echo_answerer,
        )
    assert "retriever" in str(excinfo.value)


@pytest.mark.unit
def test_every_arm_store_names_the_retriever_it_ranks_with() -> None:
    """The provenance check is answerable by every arm, so no arm is exempt."""
    for arm, store_cls in ARM_STORES.items():
        retriever = BM25Retriever()
        assert store_cls(retriever).retriever is retriever, arm


@pytest.mark.unit
def test_the_3arm_path_carries_a_real_retriever_record_into_scoring() -> None:
    """The cross-arm retriever check needs something to compare.

    The 3-arm run pools each question's answers into one :class:`ArmResult` per
    arm. Pooling them without their retriever record would leave every arm's
    record empty and equal, so the fairness check would pass vacuously on the one
    path that actually runs three arms against each other.
    """
    retriever = BM25Retriever()
    record = {
        "question_id": "q-fixture",
        "question": "what was my 5K PB?",
        "answer": "22:00",
        "answer_session_ids": ["s1"],
        "haystack_session_ids": ["s1"],
        "haystack_sessions": [[{"role": "user", "content": "my 5K PB is 22:00"}]],
    }

    run = run_mod.run_three_arm_question(record, retriever)

    assert set(run.retriever_params) == set(ARM_STORES)
    for arm, params in run.retriever_params.items():
        assert params, "an empty record makes the cross-arm check vacuous"
        assert params == retriever.params, arm


@pytest.mark.unit
def test_pins_record_is_the_run_audit_trail() -> None:
    config = PipelineConfig(judge=StageBinding(pin=_PIN, call=lambda *a, **k: True))
    assert config.pins_record() == {
        "judge": {
            "model": "stub-model",
            "endpoint": "stub://local",
            "temperature": 0.0,
            "seed": 1,
        }
    }


@pytest.mark.unit
def test_model_pin_rejects_blank_identity() -> None:
    with pytest.raises(ValueError):
        ModelPin(model="  ", endpoint="stub://local", temperature=0.0, seed=1)
    with pytest.raises(ValueError):
        ModelPin(model="m", endpoint="", temperature=0.0, seed=1)


@pytest.mark.unit
def test_unknown_stage_name_is_rejected() -> None:
    with pytest.raises(ValueError, match="unknown stage"):
        PipelineConfig().binding("retriever")


@pytest.mark.unit
def test_no_hardcoded_model_or_endpoint_defaults_in_the_package() -> None:
    """Model choice is a maintainer decision; the harness must not carry one.

    Scans the package's own sources. ``preregister.json`` is where the pinned
    identifiers legitimately live, and it is not Python.
    """
    forbidden = ("gpt-", "claude-", "gemini-", "ollama", "11434", "192.168.")
    offenders: list[str] = []
    for path in sorted(_BENCH_ROOT.rglob("*.py")):
        lowered = path.read_text(encoding="utf-8").lower()
        for token in forbidden:
            if token in lowered:
                offenders.append(f"{path.relative_to(_REPO_ROOT)}: {token}")
    assert offenders == []


@pytest.mark.unit
def test_no_placeholder_raises_remain_in_the_package() -> None:
    """No stage is a bare placeholder any more.

    ``NotImplementedError`` survives only as the base class of
    :class:`UnpinnedStageError` — which carries a pin-specific, actionable
    message — and nothing in the package raises it directly.
    """
    for path in sorted(_BENCH_ROOT.rglob("*.py")):
        source = path.read_text(encoding="utf-8")
        assert "raise NotImplementedError" not in source, path

    pipeline_src = (_BENCH_ROOT / "pipeline.py").read_text(encoding="utf-8")
    assert "class UnpinnedStageError(NotImplementedError)" in pipeline_src
    for name in ("default_extractor", "default_answerer", "default_judge"):
        body = pipeline_src.split(f"def {name}(", 1)[1].split("\ndef ", 1)[0]
        assert "NotImplementedError" not in body


# --------------------------------------------------------------------------- #
# M2 — scoring an arm straight from its store                                  #
# --------------------------------------------------------------------------- #


def _dup_claims() -> list[Claim]:
    return [
        Claim(id="c1", text="I live in Taipei"),
        Claim(id="c2", text="I live in Taipei"),
        Claim(id="c3", text="I moved to Tainan"),
    ]


@pytest.mark.unit
def test_m2_scores_arms_a_and_b_from_their_stores() -> None:
    """Arm A merges nothing (F1 0.0); Arm B catches the exact restatement (1.0)."""
    plain = PlainStore(BM25Retriever())
    dedup = NaiveDedupStore(BM25Retriever())
    for store in (plain, dedup):
        store.add_claims(_dup_claims())

    assert plain.clusters == [["c1"], ["c2"], ["c3"]]
    assert dedup.clusters == [["c1", "c2"], ["c3"]]

    scores = m2_dedup.score_stores([("c1", "c2")], {"A": plain, "B": dedup})
    assert scores["A"].f1 == 0.0
    assert scores["B"].f1 == 1.0


@pytest.mark.unit
def test_m2_labeled_pairs_from_groups_expands_ground_truth() -> None:
    assert m2_dedup.labeled_pairs_from_groups([["a", "b", "c"]]) == {
        frozenset(("a", "b")),
        frozenset(("a", "c")),
        frozenset(("b", "c")),
    }


@pytest.mark.unit
def test_arm_stores_all_expose_clusters() -> None:
    for store_cls in ARM_STORES.values():
        assert isinstance(store_cls(BM25Retriever()), m2_dedup.ClusteringStore)


# --------------------------------------------------------------------------- #
# M3 — contamination from the context an arm actually surfaces                 #
# --------------------------------------------------------------------------- #


@pytest.mark.unit
def test_m3_contexts_come_from_the_store_top_k() -> None:
    store = PlainStore(BM25Retriever())
    store.add_claims(
        [
            Claim(id="c1", text="5K personal best is 22:00"),
            Claim(id="c2", text="5K personal best is 24:30"),
        ]
    )
    contexts = m3_contamination.contexts_from_store(
        store, {"q1": "5K personal best"}, top_k=1
    )
    assert len(contexts["q1"]) == 1


@pytest.mark.unit
def test_m3_separates_the_arms_on_the_pinned_fixture() -> None:
    """Arm C suppresses the superseded value; A and B keep surfacing it."""
    retriever = BM25Retriever()
    _, m3, _ = run_mod.run_fixture_metrics(retriever)

    assert m3["A"].rate == 0.5
    assert m3["B"].rate == 0.5
    assert m3["C"].rate == 0.0
    assert m3["A"].contaminated_ids == ("fx-ku",)
    assert m3["C"].contaminated_ids == ()


# --------------------------------------------------------------------------- #
# M5 — byte-level round trip through the aphelion package API                  #
# --------------------------------------------------------------------------- #


@pytest.mark.unit
def test_m5_byte_equality_over_the_committed_samples() -> None:
    """Every packable sample re-packs to identical bytes; invalid ones are named."""
    result = m5_roundtrip.byte_equality(_SAMPLES_ROOT)

    assert result.mismatches == ()
    assert result.all_identical is True
    assert result.rate == 1.0
    # The two deliberately-invalid fixtures are reported, never silently dropped.
    assert {name for name, _ in result.unpackable} == {
        "duplicate-reaffirm-collision",
        "withdraw-then-illegal-reaffirm",
    }
    assert result.total + len(result.unpackable) == 8


@pytest.mark.unit
def test_m5_reader_path_goes_through_the_aphelion_package_api(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """M5 must drive the installed package, not a benchmark-local re-implementation.

    Recording wrappers are installed on the package's own public entry points; if
    the metric had its own canonicalizer or verifier, they would never fire.
    """
    import aphelion.packer
    import aphelion.unpacker
    import aphelion.verifier

    calls: list[str] = []

    def record(name: str, original):
        def wrapper(*args, **kwargs):
            calls.append(name)
            return original(*args, **kwargs)

        return wrapper

    monkeypatch.setattr(aphelion.packer, "pack", record("pack", aphelion.packer.pack))
    monkeypatch.setattr(
        aphelion.unpacker, "unpack", record("unpack", aphelion.unpacker.unpack)
    )
    monkeypatch.setattr(
        aphelion.verifier,
        "verify_package",
        record("verify_package", aphelion.verifier.verify_package),
    )

    sample = _SAMPLES_ROOT / "architecture-claim"
    assert m5_roundtrip.roundtrip_is_byte_identical(sample, tmp_path / "rt") is True
    assert m5_roundtrip.independent_verdict(sample, tmp_path / "vf") == "valid"

    assert calls.count("pack") == 3  # two for the round trip, one for the verdict
    assert "unpack" in calls
    assert "verify_package" in calls


@pytest.mark.unit
def test_m5_independent_verdict_reports_the_error_code_for_an_invalid_sample() -> None:
    verdict = m5_roundtrip.independent_verdict(
        _SAMPLES_ROOT / "withdraw-then-illegal-reaffirm",
        Path(__import__("tempfile").mkdtemp()),
    )
    assert verdict == "PX_E_5101"


@pytest.mark.unit
def test_m5_pinned_gate_is_reported_as_blocked() -> None:
    """Option (b) numbers must never be published as the pinned option (a) gate."""
    status = m5_roundtrip.gate_status(_SAMPLES_ROOT)
    assert status.runnable is False
    assert "W-M5" in status.blocker
    assert status.verdict_agreement.all_agree is True
    assert status.byte_equality.all_identical is True


# --------------------------------------------------------------------------- #
# 3-arm smoke — one offline command, arms A+B+C and metrics M2+M3+M5           #
# --------------------------------------------------------------------------- #


@pytest.mark.unit
def test_three_arm_registry_is_a_b_c() -> None:
    assert tuple(ARM_STORES) == ("A", "B", "C")
    # The pinned A/B smoke contract is untouched by the 3-arm addition.
    assert tuple(run_mod.SMOKE_ARM_STORES) == ("A", "B")


@requires_oracle
@pytest.mark.integration
def test_3arm_smoke_emits_all_arms_and_a_metrics_row(tmp_path: Path) -> None:
    out = tmp_path / "results-3arm.jsonl"
    rows = run_mod.run_3arm_smoke(out, data_directory=_DATA_DIR)

    on_disk = [
        json.loads(line)
        for line in out.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert on_disk == rows

    arm_rows = [row for row in rows if row["kind"] == "arm_question"]
    assert len(arm_rows) == len(run_mod.SMOKE_KU_QUESTION_IDS) * 3
    assert {row["arm"] for row in arm_rows} == {"A", "B", "C"}

    metrics = rows[-1]
    assert metrics["kind"] == "metrics"
    assert set(metrics["m2_f1"]) == {"A", "B", "C"}
    assert set(metrics["m3_rate"]) == {"A", "B", "C"}
    assert metrics["m5_verdict_total"] == 8
    assert metrics["m5_byte_identical"] == metrics["m5_byte_total"] == 6
    assert metrics["m5_gate_runnable"] is False
    # The smoke's own numbers must carry their caveats.
    assert "not an M2 result" in metrics["m2_caveat"]
    assert "not an M3 result" in metrics["m3_caveat"]


@requires_oracle
@pytest.mark.integration
def test_3arm_smoke_rows_carry_the_pin_record_they_ran_under(tmp_path: Path) -> None:
    """Every emitted result is auditable: which models, at which settings (F-5)."""
    rows = run_mod.run_3arm_smoke(tmp_path / "out.jsonl", data_directory=_DATA_DIR)
    arm_rows = [row for row in rows if row["kind"] == "arm_question"]
    recorded_seed = json.loads(
        (_BENCH_ROOT / "preregister.json").read_text(encoding="utf-8")
    )["seed"]

    assert arm_rows
    for row in arm_rows:
        assert set(row["pins"]) == {"extractor", "answering", "judge"}
        for stage in row["pins"].values():
            assert stage["seed"] == recorded_seed
            assert stage["temperature"] == 0.0

    # Cross-arm fairness: one identical pin record behind all three arms.
    assert len({json.dumps(row["pins"], sort_keys=True) for row in arm_rows}) == 1


@requires_oracle
@pytest.mark.integration
def test_3arm_smoke_judges_one_blind_cross_arm_batch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The smoke binds judging through the blind phase, not per arm (F-4)."""
    seen: list[str] = []
    real_judge = run_mod.stub_judge

    def recording_judge(question: str, gold: str, candidate_answer: str) -> bool:
        seen.append(question)
        return real_judge(question, gold, candidate_answer)

    monkeypatch.setattr(run_mod, "stub_judge", recording_judge)
    run_mod.run_3arm_smoke(tmp_path / "out.jsonl", data_directory=_DATA_DIR)

    records = run_mod.load_pinned_ku_questions(_DATA_DIR)
    order = blind_batch_order(list(ARM_STORES), len(records), seed=pinned_seed())
    expected = [records[slot.question_index]["question"] for slot in order]

    assert len(seen) == len(records) * len(ARM_STORES)
    assert seen == expected, "the smoke must judge through the pinned blind order"

    # That order is not the one inline per-arm judging produced, where a
    # question's three arms arrived back to back.
    inline = [record["question"] for record in records for _ in ARM_STORES]
    assert expected != inline


@requires_oracle
@pytest.mark.integration
def test_3arm_smoke_is_byte_identical_across_runs(tmp_path: Path) -> None:
    first = tmp_path / "first.jsonl"
    second = tmp_path / "second.jsonl"
    run_mod.run_3arm_smoke(first, data_directory=_DATA_DIR)
    run_mod.run_3arm_smoke(second, data_directory=_DATA_DIR)
    assert first.read_bytes() == second.read_bytes()


@requires_oracle
@pytest.mark.integration
def test_3arm_smoke_makes_no_model_or_network_calls(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """All three arms and all three metrics run with every socket path disabled."""

    def _boom(*args, **kwargs):
        raise RuntimeError("network call attempted inside the 3-arm smoke")

    monkeypatch.setattr(socket, "socket", _boom)
    monkeypatch.setattr(socket, "create_connection", _boom)
    monkeypatch.setattr(urllib.request, "urlopen", _boom)
    monkeypatch.setattr(http.client.HTTPConnection, "connect", _boom, raising=False)
    monkeypatch.setattr(http.client.HTTPSConnection, "connect", _boom, raising=False)

    rows = run_mod.run_3arm_smoke(tmp_path / "out.jsonl", data_directory=_DATA_DIR)
    assert {row["arm"] for row in rows if row["kind"] == "arm_question"} == {
        "A",
        "B",
        "C",
    }


@requires_oracle
@pytest.mark.integration
def test_3arm_smoke_cli_runs(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    """The documented command is the one that works."""
    exit_code = run_mod.main(
        [
            "--smoke-3arm",
            "--out",
            str(tmp_path / "cli.jsonl"),
            "--data-dir",
            str(_DATA_DIR),
        ]
    )
    assert exit_code == 0
    assert "3-arm smoke" in capsys.readouterr().out
