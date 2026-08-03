"""LongMemEval 3-arm benchmark orchestrator.

The prep drive ships one runnable entry point: the deterministic, pure-stdlib
**smoke**. It exercises the whole arm-agnostic pipeline
(:func:`benchmarks.longmemeval.pipeline.run_arm`) end-to-end for arms A and B over
five pinned knowledge-update questions, using *stub* extractor / answerer / judge
stages so nothing calls a model or the network:

* **stub extractor** — one claim per evidence-session turn, rendered as a single
  ``"role: text"`` line (:func:`stub_extractor`);
* **stub answerer** — echo the top-1 retrieved claim (:func:`stub_answerer`);
* **stub judge** — exact string match against the gold answer
  (:func:`stub_judge`).

All three are injected as pinned stages (:func:`smoke_config`), so every emitted
row records which stages produced it — stubs here, the ``preregister.json``
models on the real run. Judging is not inline: each arm answers first, then
:func:`~benchmarks.longmemeval.pipeline.score_blind` scores one shuffled,
de-identified batch of every (arm, question) candidate, which is what design doc
§6.1 guard 1 requires of blind scoring.

The five questions are the first five ``knowledge-update`` ``question_id``\\ s in
lexicographic order (:data:`SMOKE_KU_QUESTION_IDS`), pinned here and re-derived
from the corpus at run time so a drift in the frozen corpus fails loudly rather
than silently scoring a different set. Every arm sees the *same* extractor,
answerer, judge, and shared BM25 retriever — the memory layer is the only
independent variable — and the run emits one ``results.jsonl`` row per
(question, arm), deterministic and byte-identical across runs.

A second entry point, ``--smoke-3arm``, extends this to **arms A + B + C** and
**metrics M2 + M3 + M5**, still fully offline. It adds:

* a :class:`SharedLinker` — one arm-independent extract+link stage per question,
  so all three arms see byte-identical claims carrying aphelion frontmatter;
* **M2** micro-averaged over the slice from each arm's own merge clusters;
* **M3** over a pinned synthetic fixture (the corpus ships no old-value labels);
* **M5** verdict agreement plus byte-level pack/unpack/re-pack equality.

Both smokes are deterministic and byte-identical across runs, and neither opens a
socket. M1 (QA accuracy) and M4 (latency) still need the pinned answering and
judge models, so they remain part of the GB10-gated execution run.

Run them with::

    python -m benchmarks.longmemeval.run --smoke
    python -m benchmarks.longmemeval.run --smoke-3arm
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Sequence

from benchmarks.longmemeval import corpus
from benchmarks.longmemeval.arms import ARM_STORES
from benchmarks.longmemeval.arms.aphelion_arm import AphelionStore
from benchmarks.longmemeval.arms.naive_dedup import NaiveDedupStore, normalize_body
from benchmarks.longmemeval.arms.plain import PlainStore
from benchmarks.longmemeval.metrics import m2_dedup, m3_contamination, m5_roundtrip
from benchmarks.longmemeval.pipeline import (
    ArmResult,
    Claim,
    Extractor,
    MemoryStore,
    ModelPin,
    PipelineConfig,
    QAItem,
    Retriever,
    Session,
    StageBinding,
    build_extractor,
    default_extractor,
    pinned_seed,
    preregistered,
    run_arm,
    score_blind,
)
from benchmarks.longmemeval.retriever import BM25Retriever

# The five pinned knowledge-update question_ids: the first five of the KU pool
# sorted lexicographically. The KU pool is taken in full (preregister.json
# knowledge_update_basis="all"), so "first five sorted" is a stable, auditable
# slice. Re-derived and checked against the live corpus in
# :func:`load_pinned_ku_questions` so a corpus drift can never go unnoticed.
SMOKE_KU_QUESTION_IDS: tuple[str, ...] = (
    "01493427",
    "031748ae",
    "031748ae_abs",
    "06db6396",
    "07741c44",
)

# Only arms A (PlainStore) and B (NaiveDedupStore) exist in the prep scope; Arm C
# is an execution-drive deliverable. The store classes share the arm-agnostic
# constructor ``(retriever, *, extractor)``.
SMOKE_ARM_STORES: dict[str, type] = {"A": PlainStore, "B": NaiveDedupStore}

SMOKE_TOP_K = 10

# results.jsonl is written next to this module so the default output path is
# independent of the caller's working directory.
DEFAULT_SMOKE_OUTPUT = Path(__file__).resolve().parent / "results.jsonl"

# The 3-arm smoke writes its own file so it never overwrites the A/B smoke's.
DEFAULT_3ARM_OUTPUT = Path(__file__).resolve().parent / "results-3arm.jsonl"

# benchmarks/longmemeval/run.py -> repo root is two parents up.
SAMPLES_ROOT = Path(__file__).resolve().parents[2] / "samples"


# ---------------------------------------------------------------------------
# Stub pipeline stages (deterministic; NO model or network calls)
# ---------------------------------------------------------------------------


def stub_extractor(session: Session) -> list[Claim]:
    """Mechanical claim extractor for the smoke: one claim per non-blank line.

    :func:`_evidence_sessions` renders every evidence-session turn as a single
    ``"role: text"`` line, so splitting the session body on newlines recovers one
    claim per turn. Claim ids are stable and unique (``"<session id>#L<NNN>"``),
    which keeps the shared BM25 tiebreak a total order across the whole corpus.
    Pure and deterministic — this stands in for the execution drive's real
    model-backed extractor (the one pinned in ``preregister.json``).
    """
    claims: list[Claim] = []
    for line_no, line in enumerate(session.text.split("\n")):
        if not line.strip():
            continue
        claims.append(
            Claim(
                id=f"{session.id}#L{line_no:03d}",
                text=line,
                metadata=dict(session.metadata),
            )
        )
    return claims


def stub_answerer(question: str, claims: Sequence[Claim]) -> str:
    """Echo the top-1 retrieved claim's text (empty string when none retrieved)."""
    return claims[0].text if claims else ""


def stub_judge(question: str, gold: str, candidate_answer: str) -> bool:
    """Exact-match judge: the candidate must equal the gold answer verbatim.

    ``question`` is unused by an exact-match stub but is part of the §6.1 judge
    contract every judge is called under — the pinned model-backed judge needs it
    to score short, context-dependent gold answers.
    """
    return candidate_answer == gold


def _offline_binding(pin: ModelPin, stub: Callable[..., Any]) -> StageBinding:
    """Bind a deterministic offline stub as a pinned pipeline stage.

    The stub reaches no model, so it takes no ``pin`` and the wrapper drops it.
    The pin still travels on the binding, which is what the run records.
    """

    def call(*args: Any, pin: ModelPin, **kwargs: Any) -> Any:
        return stub(*args, **kwargs)

    return StageBinding(pin=pin, call=call)


def smoke_pin() -> ModelPin:
    """The offline stubs' own recorded identity.

    The stubs are not models, so they carry their own name rather than borrowing
    a pinned model's: a smoke row must never be mistakable for a real result. The
    decoding knobs are read from ``preregister.json`` so the recorded settings
    are the pre-registered ones rather than a second set of constants.
    """
    return ModelPin(
        model="offline-stub",
        endpoint="stub://offline",
        temperature=float(preregistered("temperature")),
        seed=pinned_seed(),
    )


def smoke_config(extractor: Extractor = stub_extractor) -> PipelineConfig:
    """The three stub stages under one pin, so every smoke result is attributable.

    ``extractor`` varies across the smokes — the 3-arm path binds a per-question
    :class:`SharedLinker` — but the recorded identity does not, so every config
    this returns yields the same :meth:`PipelineConfig.pins_record` and the
    cross-arm fairness check in :func:`score_blind` sees one pin record.
    """
    pin = smoke_pin()
    return PipelineConfig(
        extractor=_offline_binding(pin, extractor),
        answering=_offline_binding(pin, stub_answerer),
        judge=_offline_binding(pin, stub_judge),
    )


# ---------------------------------------------------------------------------
# Corpus -> pipeline records
# ---------------------------------------------------------------------------


def load_pinned_ku_questions(data_directory: Path | None = None) -> list[dict]:
    """Return the oracle records for the five pinned knowledge-update questions.

    Loads ``longmemeval_oracle.json`` from ``data_directory`` (default:
    :func:`corpus.data_dir`), re-derives the lexicographically sorted
    knowledge-update pool, and asserts its first five ids equal
    :data:`SMOKE_KU_QUESTION_IDS`. A mismatch means the frozen corpus drifted and
    raises :class:`ValueError` rather than silently scoring a different set.
    Records are returned in the pinned (sorted) order.
    """
    directory = data_directory or corpus.data_dir()
    oracle_path = directory / corpus.ORACLE_FILENAME
    oracle = json.loads(oracle_path.read_text(encoding="utf-8"))

    ku_ids = sorted(
        {r["question_id"] for r in oracle if r["question_type"] == corpus.KU_TYPE}
    )
    derived = tuple(ku_ids[: len(SMOKE_KU_QUESTION_IDS)])
    if derived != SMOKE_KU_QUESTION_IDS:
        raise ValueError(
            "pinned knowledge-update question_ids drifted from the corpus: "
            f"first {len(SMOKE_KU_QUESTION_IDS)} sorted KU ids are {derived}, "
            f"expected {SMOKE_KU_QUESTION_IDS}"
        )

    by_id = {r["question_id"]: r for r in oracle}
    return [by_id[qid] for qid in SMOKE_KU_QUESTION_IDS]


def _evidence_sessions(record: dict) -> list[Session]:
    """Build one :class:`Session` per evidence session of a question.

    Only the sessions named in ``answer_session_ids`` (the "oracle evidence
    sessions") are used, visited in sorted id order for determinism. Each turn is
    rendered as a single ``"role: text"`` line with its content whitespace-collapsed
    so newline splitting in :func:`stub_extractor` yields exactly one claim per
    turn; blank turns are dropped.
    """
    qid = record["question_id"]
    evidence_ids = set(record["answer_session_ids"])
    by_session_id = dict(
        zip(record["haystack_session_ids"], record["haystack_sessions"])
    )

    sessions: list[Session] = []
    for sid in sorted(evidence_ids):
        turns = by_session_id.get(sid)
        if turns is None:
            continue
        lines: list[str] = []
        for turn in turns:
            content = " ".join(str(turn.get("content", "")).split())
            if not content:
                continue
            lines.append(f"{turn.get('role', '?')}: {content}")
        sessions.append(
            Session(
                id=f"{qid}::{sid}",
                text="\n".join(lines),
                metadata={"question_id": qid, "session_id": sid},
            )
        )
    return sessions


# ---------------------------------------------------------------------------
# Smoke run
# ---------------------------------------------------------------------------


@dataclass
class ArmAnswers:
    """One arm's answers over the pinned question list, plus its per-question rows.

    The rows are complete except for ``correct``, which only exists after the
    blind cross-arm scoring phase has run.
    """

    result: ArmResult
    rows: list[dict]


def answer_arm_smoke(
    arm: str,
    records: Sequence[dict],
    retriever: Retriever,
    config: PipelineConfig,
) -> ArmAnswers:
    """Produce one arm's answers for every pinned question — no scoring here.

    Each question gets a fresh store, so its memory stays independent of the
    others; the answers are pooled across questions because the judge scores all
    arms in one shuffled batch afterwards (design doc §6.1 guard 1).
    """
    predictions: list[str] = []
    rows: list[dict] = []
    retriever_params: dict = {}

    for record in records:
        store: MemoryStore = SMOKE_ARM_STORES[arm](
            retriever, extractor=build_extractor(config)
        )
        question = QAItem(question=record["question"], gold=record["answer"])
        result = run_arm(
            store,
            retriever,
            _evidence_sessions(record),
            [question],
            config=config,
            top_k=SMOKE_TOP_K,
        )
        predictions.extend(result.predictions)
        retriever_params = result.retriever_params
        # Recompute the retrieved slice the answer came from (retrieval is
        # stateless and deterministic, so this reproduces it exactly).
        rows.append(
            {
                "question_id": record["question_id"],
                "arm": arm,
                "retrieved": len(store.retrieve(question.question)[:SMOKE_TOP_K]),
                "num_claims": len(store.claims),
                "pins": result.pins,
            }
        )

    return ArmAnswers(
        result=ArmResult(
            predictions=predictions,
            pins=config.pins_record(),
            retriever_params=retriever_params,
        ),
        rows=rows,
    )


def run_smoke(
    out_path: Path = DEFAULT_SMOKE_OUTPUT,
    data_directory: Path | None = None,
) -> list[dict]:
    """Run arms A and B over the five pinned questions and write ``results.jsonl``.

    Both arms answer first; the judge then scores one shuffled, de-identified
    batch of every (arm, question) candidate. Returns the emitted rows (one per
    question x arm, questions in pinned order, arms in ``A, B`` order). One shared
    :class:`BM25Retriever` serves every arm, documenting arm-invariance. The
    output is written deterministically so a rerun is byte-identical.
    """
    records = load_pinned_ku_questions(data_directory)
    retriever = BM25Retriever()
    config = smoke_config()
    questions = [QAItem(question=r["question"], gold=r["answer"]) for r in records]

    answers = {
        arm: answer_arm_smoke(arm, records, retriever, config)
        for arm in SMOKE_ARM_STORES
    }
    scored = score_blind(
        {arm: answer.result for arm, answer in answers.items()},
        questions,
        config=config,
    )

    rows: list[dict] = []
    for index in range(len(records)):
        for arm in SMOKE_ARM_STORES:
            rows.append(
                {**answers[arm].rows[index], "correct": scored[arm].verdicts[index]}
            )

    _write_jsonl(out_path, rows)
    return rows


def _write_jsonl(path: Path, rows: Sequence[dict]) -> None:
    """Write ``rows`` as canonical JSON Lines (sorted keys, LF, trailing newline)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    body = "".join(
        json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n" for row in rows
    )
    # write_bytes avoids platform newline translation, so the file is
    # byte-identical across runs and operating systems.
    path.write_bytes(body.encode("utf-8"))


# ---------------------------------------------------------------------------
# 3-arm smoke: arms A + B + C and metrics M2 + M3 + M5, fully offline
# ---------------------------------------------------------------------------

# The pinned seed (``preregister.json`` seed = 20260717) read as its date. Arm C's
# R2 valid-time filtering would otherwise default to ``now()``, which would make
# the run non-reproducible; deriving the instant from the pinned seed keeps the
# knob traceable to the pre-registration instead of inventing a fresh constant.
SMOKE_QUERY_TIME = datetime(
    year=corpus.SEED // 10000,
    month=corpus.SEED // 100 % 100,
    day=corpus.SEED % 100,
    tzinfo=timezone.utc,
)

# Retrieval depth for the 3-arm smoke's M3 contamination contexts.
SMOKE_M3_TOP_K = SMOKE_TOP_K


class SharedLinker:
    """The shared, arm-independent extract + link stage (design doc §7.3).

    One instance serves arms A, B and C for a single question, so all three see
    byte-identical claims — the fairness constraint that makes the memory layer
    the only independent variable.

    Linking is exact-restatement: every distinct normalised body gets one
    lineage (``claim_id``), and a repeated body is re-linked to the lineage it
    already has. This is the deterministic stdlib stand-in for the execution
    drive's real linker; it detects no updates, so it assigns no ``supersedes``
    edges and Arm C's R4 pass finds no conflicts — the "linker recall bounds Arm
    C's ceiling" case the design doc calls out as the central validity risk.
    """

    def __init__(self, question_id: str) -> None:
        self._question_id = question_id
        self._lineage_by_body: dict[str, str] = {}
        self._ids_by_body: dict[str, list[str]] = {}

    def __call__(self, session: Session) -> list[Claim]:
        claims: list[Claim] = []
        for line_no, line in enumerate(session.text.split("\n")):
            if not line.strip():
                continue
            body = normalize_body(line)
            lineage = self._lineage_by_body.get(body)
            if lineage is None:
                lineage = f"{self._question_id}#C{len(self._lineage_by_body):05d}"
                self._lineage_by_body[body] = lineage
                self._ids_by_body[body] = []
            record_id = f"{session.id}#L{line_no:03d}"
            if record_id not in self._ids_by_body[body]:
                self._ids_by_body[body].append(record_id)
            claims.append(
                Claim(
                    id=record_id,
                    text=line,
                    # Aphelion frontmatter. Arms A and B ignore it; Arm C hashes
                    # the identity projection out of it. ``subject`` tracks the
                    # lineage because the stub linker has no subject model.
                    metadata={
                        "claim_id": lineage,
                        "subject": lineage,
                        "predicate": "states",
                        "object": body,
                        "state": "active",
                        "type": "conversation_turn",
                        "question_id": self._question_id,
                    },
                )
            )
        return claims

    def duplicate_groups(self) -> list[list[str]]:
        """Ground-truth exact-restatement groups — M2's labeled duplicate set."""
        return [list(ids) for ids in self._ids_by_body.values()]


# Neither M2 nor M3 is measurable on the 5-question corpus slice, for two
# different and equally load-bearing reasons. Both are therefore scored on a
# pinned synthetic fixture and labelled as plumbing evidence, never as a result.
#
# M2: the slice's evidence sessions contain no exact restatements at all, so the
# labeled duplicate set is empty and every arm scores 0.0 for lack of labels
# rather than for lack of dedup. The emitted ``m2_corpus_labeled_pairs`` count
# makes that visible instead of letting three zeros look like a measurement.
M2_SMOKE_CAVEAT = (
    "synthetic fixture: the 5-question corpus slice contains no exact "
    "restatements (see m2_corpus_labeled_pairs), so M2 is exercised on pinned "
    "fixture claims. Plumbing evidence only, not an M2 result."
)

# M3: LongMemEval ships no old-value (stale) annotations, so a corpus-scored M3
# would likewise be 0.0 everywhere for lack of labels.
M3_SMOKE_CAVEAT = (
    "synthetic fixture: the LongMemEval corpus carries no old-value labels, so "
    "M3 is exercised on pinned fixture claims. Plumbing evidence only, not an M3 "
    "result."
)

# Pinned fixture questions. ``fx-ku`` is a knowledge-update whose old value was
# superseded; ``fx-stable`` never changed.
FIXTURE_QUESTIONS: dict[str, str] = {
    "fx-ku": "What is my 5K personal best?",
    "fx-stable": "Which city do I live in?",
}

# M3 ground truth: the stale value that must not reach the answering model.
FIXTURE_OLD_VALUES: dict[str, list[str]] = {"fx-ku": ["24:30"]}

# M2 ground truth: the one genuine exact-restatement group. The two records are
# the same fact stated twice, so a correct arm merges them.
FIXTURE_DUPLICATE_GROUPS: tuple[tuple[str, ...], ...] = (("fx-city", "fx-city-again"),)

# Pinned fixture claims. Arms A and B keep the stale 5K claim (it is a different
# string, so exact-string dedup cannot drop it); Arm C suppresses it because the
# event state machine marked it ``superseded``. The repeated city claim is one
# lineage stated twice, so Arm B merges it on text and Arm C on
# ``(claim_id, content_hash)`` while Arm A keeps both.
FIXTURE_CLAIMS: tuple[dict[str, object], ...] = (
    {
        "record_id": "fx-ku-old",
        "text": "My 5K personal best is 24:30",
        "claim_id": "fx-ku-lineage-old",
        "subject": "chris/5k-personal-best",
        "predicate": "equals",
        "object": "24:30",
        "state": "superseded",
        "type": "running_record",
    },
    {
        "record_id": "fx-ku-new",
        "text": "My 5K personal best is 22:00",
        "claim_id": "fx-ku-lineage-new",
        "subject": "chris/5k-personal-best",
        "predicate": "equals",
        "object": "22:00",
        "state": "active",
        "type": "running_record",
        "supersedes": ["fx-ku-lineage-old"],
    },
    {
        "record_id": "fx-city",
        "text": "I live in Taipei",
        "claim_id": "fx-city-lineage",
        "subject": "chris/city",
        "predicate": "equals",
        "object": "Taipei",
        "state": "active",
        "type": "residence",
    },
    {
        "record_id": "fx-city-again",
        "text": "I live in Taipei",
        "claim_id": "fx-city-lineage",
        "subject": "chris/city",
        "predicate": "equals",
        "object": "Taipei",
        "state": "active",
        "type": "residence",
    },
)


def _fixture_claims() -> list[Claim]:
    """Materialise the pinned fixture as harness claims."""
    claims: list[Claim] = []
    for spec in FIXTURE_CLAIMS:
        fields = dict(spec)
        record_id = str(fields.pop("record_id"))
        text = str(fields.pop("text"))
        claims.append(Claim(id=record_id, text=text, metadata=fields))
    return claims


def _build_store(
    arm: str,
    retriever: Retriever,
    extractor: object = default_extractor,
) -> MemoryStore:
    """Construct one arm's store, pinning Arm C's query time for reproducibility.

    ``extractor`` defaults to the unpinned resolver, so a store built for a
    direct ``add_claims`` path fails loud if anything tries to ``ingest``
    through it.
    """
    store_cls = ARM_STORES[arm]
    if store_cls is AphelionStore:
        return AphelionStore(
            retriever, extractor=extractor, query_time=SMOKE_QUERY_TIME
        )
    return store_cls(retriever, extractor=extractor)


@dataclass
class QuestionRun:
    """One question's 3-arm answers, plus the M2 inputs it contributed.

    ``rows``, ``predictions`` and ``retriever_params`` are keyed by arm. No
    verdict is attached yet: scoring is a single later pass over every arm's
    answers at once.

    ``retriever_params`` is carried through rather than re-read from the shared
    retriever so the pooled result keeps the record ``run_arm`` verified against
    each store's own retriever — which is what the cross-arm check in
    :func:`~benchmarks.longmemeval.pipeline.score_blind` then compares.
    """

    rows: dict[str, dict]
    predictions: dict[str, str]
    duplicate_groups: list[list[str]]
    clusters: dict[str, list[list[str]]]
    retriever_params: dict[str, dict]


def run_three_arm_question(record: dict, retriever: Retriever) -> QuestionRun:
    """Answer one question with arms A, B and C — scoring happens later, blind.

    A single :class:`SharedLinker` serves all three arms, so the extracted claims
    are byte-identical across them — the design's fairness constraint.
    """
    linker = SharedLinker(record["question_id"])
    config = smoke_config(linker)
    sessions = _evidence_sessions(record)
    question = QAItem(question=record["question"], gold=record["answer"])

    rows: dict[str, dict] = {}
    predictions: dict[str, str] = {}
    clusters: dict[str, list[list[str]]] = {}
    retriever_params: dict[str, dict] = {}
    for arm in ARM_STORES:
        store = _build_store(arm, retriever, build_extractor(config))
        result = run_arm(
            store,
            retriever,
            sessions,
            [question],
            config=config,
            top_k=SMOKE_TOP_K,
        )
        clusters[arm] = store.clusters
        predictions[arm] = result.predictions[0]
        retriever_params[arm] = result.retriever_params
        rows[arm] = {
            "kind": "arm_question",
            "question_id": record["question_id"],
            "arm": arm,
            "retrieved": len(store.retrieve(question.question)[:SMOKE_TOP_K]),
            "num_claims": len(store.claims),
            "pins": result.pins,
        }

    return QuestionRun(
        rows=rows,
        predictions=predictions,
        duplicate_groups=linker.duplicate_groups(),
        clusters=clusters,
        retriever_params=retriever_params,
    )


def run_fixture_metrics(
    retriever: Retriever,
) -> tuple[
    dict[str, m2_dedup.DedupScore],
    dict[str, m3_contamination.ContaminationScore],
]:
    """Score M2 and M3 for all three arms over the pinned fixture.

    One set of stores is ingested and scored twice, so both metrics see the
    identical memory state — the same guarantee the corpus path gets from the
    shared linker.
    """
    stores: dict[str, MemoryStore] = {}
    for arm in ARM_STORES:
        store = _build_store(arm, retriever)
        store.add_claims(_fixture_claims())
        stores[arm] = store

    m2 = m2_dedup.score_stores(FIXTURE_DUPLICATE_GROUPS, stores)
    m3 = m3_contamination.score_stores(
        FIXTURE_QUESTIONS,
        FIXTURE_OLD_VALUES,
        stores,
        top_k=SMOKE_M3_TOP_K,
    )
    return m2, m3


def run_3arm_smoke(
    out_path: Path = DEFAULT_3ARM_OUTPUT,
    data_directory: Path | None = None,
    samples_root: Path = SAMPLES_ROOT,
) -> list[dict]:
    """Run arms A+B+C and metrics M2+M3+M5 end-to-end, offline.

    Emits one ``arm_question`` row per (question, arm) plus one ``metrics``
    summary row carrying the M2 / M3 / M5 outcomes and the caveats that keep the
    smoke's numbers from being read as benchmark results. Deterministic: a rerun
    is byte-identical.

    All three arms answer first; the judge then scores one shuffled,
    de-identified batch of every (arm, question) candidate, per design doc §6.1
    guard 1.
    """
    records = load_pinned_ku_questions(data_directory)
    retriever = BM25Retriever()
    config = smoke_config()
    questions = [QAItem(question=r["question"], gold=r["answer"]) for r in records]

    runs = [run_three_arm_question(record, retriever) for record in records]
    labeled_groups: list[list[str]] = [
        group for run in runs for group in run.duplicate_groups
    ]

    # Every question ran that arm against the same shared retriever, and run_arm
    # checked each store against it, so any question's record is the arm's record.
    scored = score_blind(
        {
            arm: ArmResult(
                predictions=[run.predictions[arm] for run in runs],
                pins=config.pins_record(),
                retriever_params=runs[0].retriever_params[arm],
            )
            for arm in ARM_STORES
        },
        questions,
        config=config,
    )

    rows: list[dict] = []
    for index, run in enumerate(runs):
        for arm in ARM_STORES:
            rows.append({**run.rows[arm], "correct": scored[arm].verdicts[index]})

    # The corpus slice's labeled duplicate set, pooled across questions (claim
    # ids are question-scoped, so pooling cannot create cross-question pairs).
    # Reported as a count because it is empty — see M2_SMOKE_CAVEAT.
    corpus_labeled_pairs = m2_dedup.labeled_pairs_from_groups(labeled_groups)
    m2, m3 = run_fixture_metrics(retriever)
    m5 = m5_roundtrip.gate_status(samples_root)

    rows.append(
        {
            "kind": "metrics",
            "m2_f1": {arm: score.f1 for arm, score in sorted(m2.items())},
            "m2_corpus_labeled_pairs": len(corpus_labeled_pairs),
            "m2_caveat": M2_SMOKE_CAVEAT,
            "m3_rate": {arm: score.rate for arm, score in sorted(m3.items())},
            "m3_caveat": M3_SMOKE_CAVEAT,
            "m5_verdict_agreements": m5.verdict_agreement.agreements,
            "m5_verdict_total": m5.verdict_agreement.total,
            "m5_byte_identical": m5.byte_equality.identical,
            "m5_byte_total": m5.byte_equality.total,
            "m5_gate_runnable": m5.runnable,
            "m5_gate_blocker": m5.blocker,
        }
    )

    _write_jsonl(out_path, rows)
    return rows


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m benchmarks.longmemeval.run",
        description="LongMemEval 3-arm benchmark orchestrator (prep scope: smoke only).",
    )
    parser.add_argument(
        "--smoke",
        action="store_true",
        help="run the deterministic 5-question stub smoke for arms A and B",
    )
    parser.add_argument(
        "--smoke-3arm",
        action="store_true",
        help=(
            "run the deterministic 5-question smoke for arms A, B and C with "
            "metrics M2, M3 and M5 (fully offline; no model or network)"
        ),
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=None,
        help=(
            "results.jsonl output path "
            f"(default: {DEFAULT_SMOKE_OUTPUT} for --smoke, "
            f"{DEFAULT_3ARM_OUTPUT} for --smoke-3arm)"
        ),
    )
    parser.add_argument(
        "--data-dir",
        type=Path,
        default=None,
        help=(
            "LongMemEval corpus directory "
            f"(default: ${corpus.DATA_DIR_ENV} or {corpus.DEFAULT_DATA_DIR})"
        ),
    )
    args = parser.parse_args(argv)

    if args.smoke and args.smoke_3arm:
        parser.error("pass either --smoke or --smoke-3arm, not both")
    if not (args.smoke or args.smoke_3arm):
        parser.error("nothing to do: pass --smoke or --smoke-3arm")

    if args.smoke_3arm:
        out = args.out or DEFAULT_3ARM_OUTPUT
        rows = run_3arm_smoke(out, args.data_dir)
        metrics = rows[-1]
        arm_rows = [row for row in rows if row["kind"] == "arm_question"]
        print(
            f"3-arm smoke: wrote {len(rows)} rows to {out} "
            f"({len(SMOKE_KU_QUESTION_IDS)} questions x {len(ARM_STORES)} arms "
            f"= {len(arm_rows)} arm rows + 1 metrics row)"
        )
        print(f"  M2 F1 (caveated): {metrics['m2_f1']}")
        print(f"  M3 rate (fixture): {metrics['m3_rate']}")
        print(
            f"  M5 verdict {metrics['m5_verdict_agreements']}/"
            f"{metrics['m5_verdict_total']} agree, byte-equal "
            f"{metrics['m5_byte_identical']}/{metrics['m5_byte_total']}; "
            f"pinned gate runnable: {metrics['m5_gate_runnable']}"
        )
        return 0

    out = args.out or DEFAULT_SMOKE_OUTPUT
    rows = run_smoke(out, args.data_dir)
    correct = sum(1 for row in rows if row["correct"])
    print(
        f"smoke: wrote {len(rows)} rows to {out} "
        f"({len(SMOKE_KU_QUESTION_IDS)} questions x {len(SMOKE_ARM_STORES)} arms, "
        f"{correct} exact-match correct)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
