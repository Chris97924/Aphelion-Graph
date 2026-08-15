"""The real-model LongMemEval 3-arm execution run.

``run.py``'s two smokes prove the plumbing offline with stub stages. This module
is the pinned run itself: the full frozen split answered by arms A, B and C
against the models ``preregister.json`` pins, scored by the pinned judge, and
reduced to the §4 metrics.

Four properties shape every design decision below.

**Blind scoring is structural, not procedural.** Design doc §6.1 guard 1 forbids
judging an arm's answers as a contiguous batch. The run therefore has two hard
phases: *every* arm answers *every* question first, and only then does one
shuffled, de-identified batch reach the judge. The shuffle is
:func:`~benchmarks.longmemeval.pipeline.blind_batch_order` under the pinned seed,
so the batch order is a pure function of (arms, question count, seed) — which is
what makes it both auditable and resumable.

**The run will be interrupted.** 220 questions x 3 arms over a local 120B model
and a subscription judge CLI is a multi-hour-to-multi-day job that will meet a
quota wall, a reboot, or a thermal event. Every phase therefore appends durable
JSON Lines rows as it goes and skips work already recorded on restart:
extractions key on session id, answers on ``(question_id, arm)``, verdicts on
``(arm, question_id)``. Nothing is held only in memory, and no phase has to
complete for its work to survive.

**Resuming must not silently mix runs.** Because slicing flags change which
questions exist — and therefore what the blind batch order means — the manifest
records a digest of the exact question list, and a resume against a different one
is refused (:class:`RunManifestMismatchError`) rather than quietly interleaved.

**The claims must be byte-identical across arms.** The extractor is model-backed
here, and a model called three times can answer three ways. Extraction is
therefore memoised per session (durably), and the one
:class:`~benchmarks.longmemeval.linker.SharedLinker` for a question sees the same
bodies on every arm's pass. Without that, the arms would differ by extraction
noise and the run would not be measuring the memory layer at all.

Run it with::

    python -m benchmarks.longmemeval.run --preflight
    python -m benchmarks.longmemeval.run --real --haystack s --split all

Pure stdlib.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator, Mapping, Sequence

from benchmarks.longmemeval import clients, corpus, labeled_pairs
from benchmarks.longmemeval.arms import ARM_STORES
from benchmarks.longmemeval.arms.aphelion_arm import AphelionStore
from benchmarks.longmemeval.linker import LinkerStats, SharedLinker, parse_corpus_instant
from benchmarks.longmemeval.metrics import (
    m1_qa,
    m2_dedup,
    m3_contamination,
    m4_perf,
    m5_roundtrip,
)
from benchmarks.longmemeval.metrics._stats import percentile
from benchmarks.longmemeval.pipeline import (
    PREREGISTER_PATH,
    ArmResult,
    BlindSlot,
    Claim,
    MemoryStore,
    ModelPin,
    PipelineConfig,
    QAItem,
    Retriever,
    Session,
    StageBinding,
    blind_batch_order,
    build_extractor,
    pinned_seed,
    preregistered_metric,
    run_arm,
    score_blind,
)
from benchmarks.longmemeval.retriever import BM25Retriever
from benchmarks.longmemeval.run import _session_order_key

# benchmarks/longmemeval/real_run.py -> repo root is two parents up.
REPO_ROOT = Path(__file__).resolve().parents[2]
SAMPLES_ROOT = REPO_ROOT / "samples"

# Durable output lives beside the harness by default so a run started from any
# working directory writes to the same place a resume will look.
DEFAULT_OUT_DIR = Path(__file__).resolve().parent / "runs" / "real"

# The retrieval depth handed to the answering model, matching the smoke's
# SMOKE_TOP_K. Not a pinned knob — ``preregister.json`` fixes the models, the
# retriever and the seed, not the context window — so it is recorded in the run
# manifest rather than treated as frozen.
DEFAULT_TOP_K = 10

# Corpus roles, design doc §3.4: the oracle supplies gold answers and evidence
# labels; ``S`` supplies the distractor-heavy haystack the extractor ingests.
HAYSTACK_ORACLE = "oracle"
HAYSTACK_S = "s"
HAYSTACK_CHOICES = (HAYSTACK_ORACLE, HAYSTACK_S)

# CLI split names -> the keys ``split_manifest.json`` records them under. The
# manifest's own order is the run's canonical question order.
SPLIT_KEYS: dict[str, str] = {"ku": "ku", "ms": "ms", "adv": "adversarial"}
SPLIT_ALL = "all"
SPLIT_CHOICES = (*SPLIT_KEYS, SPLIT_ALL)

# The instant Arm C resolves valid-time (R2) against. Derived from the pinned
# seed read as a date, exactly as ``run.SMOKE_QUERY_TIME`` is: the adapter would
# otherwise default to ``now()`` and make the run unreproducible. Deriving it
# from the pin rather than from each question's own ``question_date`` is
# deliberate — a per-question query time is a methodological knob the
# pre-registration never fixed, and introducing one during the run would be the
# kind of after-the-fact choice design doc §6.3 exists to prevent. Every corpus
# session predates this instant, so R2 filters nothing on either reading.
PINNED_QUERY_TIME = datetime(
    year=corpus.SEED // 10000,
    month=corpus.SEED // 100 % 100,
    day=corpus.SEED % 100,
    tzinfo=timezone.utc,
)

# Durable artefacts. Each is append-only and independently resumable.
MANIFEST_NAME = "manifest.json"
EXTRACTIONS_NAME = "extractions.jsonl"
CLAIMS_NAME = "claims.jsonl"
ANSWERS_NAME = "answers.jsonl"
VERDICTS_NAME = "verdicts.jsonl"
METRICS_NAME = "metrics.json"


class RunManifestMismatchError(ValueError):
    """A resume was attempted against a run of a different shape.

    The blind batch order is a function of the question count, and every resume
    key is a function of the question set, so continuing a 78-question run inside
    a 220-question output directory would silently interleave two different
    experiments. Refused rather than merged.
    """


class MissingAnswerError(ValueError):
    """The judging phase reached a candidate no arm had answered.

    Only possible when the answers file was truncated or hand-edited; it means
    the blind batch is incomplete, so scoring it would report an arm on a subset
    of its own questions.
    """


class VerdictReplayError(ValueError):
    """A durable verdict did not match the candidate it was replayed against.

    The final scoring pass re-drives :func:`score_blind` over the recorded
    verdicts to inherit its cross-arm fairness checks. This error means the
    recorded verdict stream and the canonical blind order disagree — the verdicts
    would be routed to the wrong arms — so the run stops instead of reporting
    them.
    """


# ---------------------------------------------------------------------------
# Durable JSON Lines
# ---------------------------------------------------------------------------


def read_jsonl(path: Path) -> list[dict]:
    """Read durable rows, tolerating one torn row at the end of the file.

    A run killed mid-``write`` can leave a partial final line. Dropping *only* a
    trailing unparseable line is safe — that work is simply redone, because every
    phase re-derives what is missing — while an unparseable line anywhere else is
    corruption that must not be silently skipped.
    """
    if not path.is_file():
        return []
    rows: list[dict] = []
    lines = path.read_text(encoding="utf-8").split("\n")
    for index, line in enumerate(lines):
        if not line.strip():
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            remaining = [rest for rest in lines[index + 1 :] if rest.strip()]
            if remaining:
                raise
            break
    return rows


class JsonlWriter:
    """Append-only writer that makes each row durable before returning.

    ``flush`` plus ``fsync`` per row: the row counts are in the hundreds to low
    tens of thousands against model calls measured in seconds, so the cost is
    noise, and the property bought — an interrupted run never loses completed
    model work — is the entire reason this run is resumable.
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, row: Mapping[str, Any]) -> None:
        line = json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n"
        with self.path.open("ab") as handle:
            handle.write(line.encode("utf-8"))
            handle.flush()
            os.fsync(handle.fileno())


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def payload_digest(question: str, gold: str, candidate: str) -> str:
    """Digest of exactly what the judge was shown — its whole payload, in order.

    Recorded on every verdict row so the replay pass can prove a stored verdict
    belongs to the candidate it is about to be attributed to.
    """
    return _sha256_text(
        json.dumps([question, gold, candidate], ensure_ascii=False, sort_keys=False)
    )


# ---------------------------------------------------------------------------
# Corpus loading
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class QuestionSpec:
    """One question of the run: its split, its gold answer, its haystack."""

    question_id: str
    split: str
    question: str
    gold: str
    sessions: tuple[Session, ...]


def load_split(path: Path = corpus.MANIFEST_PATH) -> dict:
    """Read the frozen split manifest."""
    return json.loads(path.read_text(encoding="utf-8"))


def selected_question_ids(
    split_manifest: Mapping[str, Any], split: str, limit: int | None
) -> list[tuple[str, str]]:
    """The run's ``(question_id, split)`` list, in canonical order.

    Splits are visited in the manifest's own order and each split's ids are
    already sorted there, so the sequence is a pure function of the frozen
    manifest and the two slicing flags. ``--limit`` truncates that sequence, so a
    limited run is always a prefix of the full one — which is what lets a driver
    smoke a slice and then extend it without changing what the earlier questions
    were.
    """
    if split not in SPLIT_CHOICES:
        raise ValueError(f"unknown split {split!r}; expected one of {SPLIT_CHOICES}")
    keys = list(SPLIT_KEYS.values()) if split == SPLIT_ALL else [SPLIT_KEYS[split]]

    ids: list[tuple[str, str]] = []
    question_ids = split_manifest["question_ids"]
    for key in keys:
        ids.extend((qid, key) for qid in question_ids[key])
    return ids[:limit] if limit is not None else ids


def load_records(
    directory: Path, filename: str, question_ids: Iterable[str]
) -> dict[str, dict]:
    """Load only the wanted question records out of a corpus file.

    The ``S`` haystack is a 264 MiB array of 500 records; the whole file is
    parsed (the stdlib has no streaming JSON reader) but only the run's own
    records are retained, so the process does not carry 280 questions it will
    never answer through a multi-hour run.
    """
    wanted = set(question_ids)
    with (directory / filename).open(encoding="utf-8") as handle:
        records = json.load(handle)
    return {r["question_id"]: r for r in records if r["question_id"] in wanted}


def build_sessions(record: Mapping[str, Any], *, evidence_only: bool) -> list[Session]:
    """Build one :class:`Session` per haystack session of a question.

    ``evidence_only`` selects between the two corpus roles design doc §3.4 fixes:
    the oracle's evidence sessions (what the smoke uses) or the full
    distractor-heavy haystack (the real retrieval challenge).

    Sessions are visited in **occurrence order** using the same total order
    ``run.py`` derives — imported rather than restated, because getting it wrong
    is a correctness bug, not a cosmetic one: the linker builds its ``supersedes``
    chain in ingestion order, so an out-of-order pass would mark a newer claim as
    superseded by an older one and invert Arm C on exactly the knowledge-update
    questions M1 and M3 ride on.
    """
    session_ids = list(record["haystack_session_ids"])
    if evidence_only:
        evidence = set(record["answer_session_ids"])
        session_ids = [sid for sid in session_ids if sid in evidence]

    qid = record["question_id"]
    by_session_id = dict(zip(record["haystack_session_ids"], record["haystack_sessions"]))
    dates = dict(zip(record["haystack_session_ids"], record.get("haystack_dates", [])))
    instants = {sid: parse_corpus_instant(dates.get(sid)) for sid in session_ids}

    sessions: list[Session] = []
    for sid in sorted(session_ids, key=lambda s: _session_order_key(s, instants[s])):
        turns = by_session_id.get(sid)
        if turns is None:
            continue
        lines = []
        for turn in turns:
            content = " ".join(str(turn.get("content", "")).split())
            if content:
                lines.append(f"{turn.get('role', '?')}: {content}")
        if not lines:
            continue
        metadata: dict[str, Any] = {"question_id": qid, "session_id": sid}
        if instants[sid] is not None:
            metadata["occurred_at"] = instants[sid]
        sessions.append(
            Session(id=f"{qid}::{sid}", text="\n".join(lines), metadata=metadata)
        )
    return sessions


def load_questions(
    *,
    split: str,
    limit: int | None,
    haystack: str,
    data_directory: Path,
    split_manifest: Mapping[str, Any],
) -> list[QuestionSpec]:
    """Assemble the run's questions: gold from the oracle, haystack per §3.4."""
    if haystack not in HAYSTACK_CHOICES:
        raise ValueError(
            f"unknown haystack {haystack!r}; expected one of {HAYSTACK_CHOICES}"
        )

    pairs = selected_question_ids(split_manifest, split, limit)
    ids = [qid for qid, _ in pairs]
    oracle = load_records(data_directory, corpus.ORACLE_FILENAME, ids)

    if haystack == HAYSTACK_S:
        haystacks = load_records(data_directory, corpus.S_CLEANED_FILENAME, ids)
    else:
        haystacks = oracle

    specs: list[QuestionSpec] = []
    for qid, split_key in pairs:
        record = oracle[qid]
        specs.append(
            QuestionSpec(
                question_id=qid,
                split=split_key,
                question=record["question"],
                gold=record["answer"],
                sessions=tuple(
                    build_sessions(
                        haystacks[qid], evidence_only=haystack == HAYSTACK_ORACLE
                    )
                ),
            )
        )
    return specs


# ---------------------------------------------------------------------------
# The model-backed extractor: memoised, then linked
# ---------------------------------------------------------------------------


class ExtractionCache:
    """Durable session -> claim bodies memo for the pinned extractor model.

    This is a correctness mechanism before it is an economy. Every arm ingests
    the same sessions, so the extractor runs once per arm; a model asked three
    times can answer three ways, and three arms holding different claims are no
    longer a measurement of the memory layer (design doc §7.3). Memoising makes
    the extraction a fixed input to all three arms — and, because the memo is on
    disk, keeps it fixed across a restart too.
    """

    def __init__(self, path: Path) -> None:
        self._writer = JsonlWriter(path)
        self._bodies: dict[str, list[str]] = {
            row["session_id"]: list(row["bodies"]) for row in read_jsonl(path)
        }

    def __len__(self) -> int:
        return len(self._bodies)

    def get(self, session_id: str) -> list[str] | None:
        bodies = self._bodies.get(session_id)
        return list(bodies) if bodies is not None else None

    def put(self, session_id: str, bodies: Sequence[str]) -> None:
        self._bodies[session_id] = list(bodies)
        self._writer.append({"session_id": session_id, "bodies": list(bodies)})


@dataclass
class RealExtractor:
    """The pinned extractor model, memoised, feeding the shared linker.

    The model turns one session into atomic claim bodies; the linker turns those
    bodies into lineages and update edges. Composing them this way — rather than
    letting the linker read the raw session — is what puts the *pinned* extractor
    in the extractor's place while leaving the linker's arm-independence
    untouched: it still receives one text, splits it on newlines, and mints one
    claim per line, exactly as the smoke exercises it.
    """

    client: Any
    linker: SharedLinker
    cache: ExtractionCache
    calls: int = 0

    def __call__(self, session: Session, *, pin: ModelPin) -> list[Claim]:
        bodies = self.cache.get(session.id)
        if bodies is None:
            completion = self.client.chat(clients.extract_messages(session.text))
            bodies = clients.extracted_lines(completion)
            self.cache.put(session.id, bodies)
            self.calls += 1
        return self.linker(
            Session(id=session.id, text="\n".join(bodies), metadata=dict(session.metadata))
        )


def build_config(
    *,
    extractor_call: Callable[..., list[Claim]],
    answering_pin: ModelPin,
    extractor_pin: ModelPin,
    judge_pin: ModelPin,
    answer_client: Any,
) -> PipelineConfig:
    """The three real stage bindings under their pinned identities.

    The judge is bound even though the judging phase calls its client directly:
    :func:`score_blind` compares each arm's recorded pins against the scoring
    config's, so a config missing the judge would either fail that check or
    record answers that cannot say who judged them.
    """

    def answer(question: str, claims: Sequence[Claim], *, pin: ModelPin) -> str:
        return answer_client.chat(clients.answer_messages(question, claims))

    return PipelineConfig(
        extractor=StageBinding(pin=extractor_pin, call=extractor_call),
        answering=StageBinding(pin=answering_pin, call=answer),
        judge=StageBinding(pin=judge_pin, call=_unreachable_judge),
    )


def _unreachable_judge(*args: Any, **kwargs: Any) -> bool:
    """The judge binding's call slot, which nothing may reach.

    Judging runs as its own durable phase (:func:`judge_blind`), so the binding
    exists purely to carry the judge's pin onto every results row and into
    :func:`score_blind`'s cross-arm pin check. Raising rather than delegating
    keeps a future caller from quietly reintroducing inline, unresumable judging.
    """
    raise AssertionError(
        "the judge stage is driven by judge_blind, not through PipelineConfig; "
        "this binding only carries the judge pin onto the results rows."
    )


def pins_config(pins: Mapping[str, ModelPin]) -> PipelineConfig:
    """A config that carries the three pins and runs nothing.

    :func:`score_blind` reads ``pins_record()`` off the config it is given to
    check every arm was produced under the same models. The scoring pass has its
    verdicts already, so it needs the record and none of the callables — and a
    config whose stages *cannot* run is the honest way to say so.
    """
    return build_config(
        extractor_call=_unreachable_extractor,
        answering_pin=pins["answering"],
        extractor_pin=pins["extractor"],
        judge_pin=pins["judge"],
        answer_client=None,
    )


def _unreachable_extractor(*args: Any, **kwargs: Any) -> list[Claim]:
    """The extractor slot of a pins-only config; reaching it is a bug."""
    raise AssertionError(
        "this PipelineConfig carries pins for scoring only; extraction runs "
        "through RealExtractor during the answering phase."
    )


def build_store(arm: str, retriever: Retriever, extractor: Any) -> MemoryStore:
    """Construct one arm's store, pinning Arm C's query time for reproducibility."""
    store_cls = ARM_STORES[arm]
    if store_cls is AphelionStore:
        return AphelionStore(retriever, extractor=extractor, query_time=PINNED_QUERY_TIME)
    return store_cls(retriever, extractor=extractor)


# ---------------------------------------------------------------------------
# Run configuration and manifest
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RealRunConfig:
    """Everything a run needs that is not pinned by the pre-registration."""

    out_dir: Path = DEFAULT_OUT_DIR
    split: str = SPLIT_ALL
    limit: int | None = None
    haystack: str = HAYSTACK_ORACLE
    data_dir: Path | None = None
    top_k: int = DEFAULT_TOP_K
    samples_root: Path = SAMPLES_ROOT
    m3_labels: Path | None = None
    resamples: int = m1_qa.BOOTSTRAP_RESAMPLES
    # Which form the judge CLI is handed its prompt. Exposed as a run setting
    # because which form the installed build accepts is an operational fact about
    # that machine, and discovering it must not require editing the harness in
    # the middle of a run.
    judge_prompt_via: str = clients.PROMPT_VIA_STDIN
    split_manifest_path: Path = corpus.MANIFEST_PATH
    preregister_path: Path = PREREGISTER_PATH

    def directory(self) -> Path:
        return self.data_dir or corpus.data_dir()


def git_provenance(root: Path = REPO_ROOT) -> dict[str, Any]:
    """The commit a run was produced from, or why that could not be read.

    Recorded rather than required: a missing git binary is not a reason to
    abandon hours of model work, but a results file that cannot name its own
    code revision has to say so out loud.
    """
    try:
        sha = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            capture_output=True,
            check=False,
            timeout=30,
        )
        dirty = subprocess.run(
            ["git", "-C", str(root), "status", "--porcelain"],
            capture_output=True,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return {"sha": None, "dirty": None, "error": str(exc)}
    if sha.returncode != 0:
        return {"sha": None, "dirty": None, "error": _loose_decode(sha.stderr)}
    return {
        "sha": _loose_decode(sha.stdout),
        "dirty": bool(_loose_decode(dirty.stdout)),
        "error": None,
    }


def _loose_decode(raw: bytes) -> str:
    """Decode provenance output, degrading to a repr instead of failing.

    The strict-UTF-8 rule that governs model and judge output
    (:func:`clients.decode_stream`) is about not corrupting *measurements*. A
    commit sha is neither a measurement nor UTF-8-guaranteed on this platform, so
    an undecodable byte here should annotate the manifest, not abort a run that
    has hours of model work behind it.
    """
    try:
        return raw.decode("utf-8").strip()
    except UnicodeDecodeError:
        return repr(raw[:120])


def build_manifest(
    cfg: RealRunConfig,
    specs: Sequence[QuestionSpec],
    pins: Mapping[str, Any],
    *,
    judge_fallback: str | None,
    retriever_params: Mapping[str, Any],
    split_manifest: Mapping[str, Any],
) -> dict[str, Any]:
    """The run's provenance record: what ran, against what, under which pins."""
    preregister = json.loads(cfg.preregister_path.read_text(encoding="utf-8"))
    return {
        "benchmark": preregister.get("benchmark"),
        "mode": "real",
        "arms": sorted(ARM_STORES),
        "pins": dict(pins),
        "judge_fallback_model": judge_fallback,
        "design_doc_sha256": preregister.get("design_doc_sha256"),
        "preregister_sha256": _sha256_text(
            cfg.preregister_path.read_text(encoding="utf-8")
        ),
        "split_manifest_sha256": _sha256_text(
            cfg.split_manifest_path.read_text(encoding="utf-8")
        ),
        "corpus_source_sha256": split_manifest.get("source_sha256", {}),
        "corpus_data_dir": str(cfg.directory()),
        "haystack": cfg.haystack,
        "split": cfg.split,
        "limit": cfg.limit,
        "top_k": cfg.top_k,
        "seed": pinned_seed(cfg.preregister_path),
        "query_time": PINNED_QUERY_TIME.isoformat(),
        "retriever_params": dict(retriever_params),
        "question_count": len(specs),
        "questions_sha256": _sha256_text(
            "\n".join(spec.question_id for spec in specs)
        ),
        "git": git_provenance(),
    }


# The manifest fields that define what a run *is*. A resume whose shape differs
# on any of them is a different experiment sharing an output directory.
_IDENTITY_FIELDS = (
    "arms",
    "pins",
    "haystack",
    "split",
    "limit",
    "top_k",
    "seed",
    "question_count",
    "questions_sha256",
)


def reconcile_manifest(path: Path, fresh: Mapping[str, Any]) -> dict[str, Any]:
    """Write the manifest, or check a resume against the one already there."""
    if not path.is_file():
        record = dict(fresh)
        record["started_at"] = datetime.now(timezone.utc).isoformat()
        record["completed_at"] = None
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(
            (json.dumps(record, indent=2, sort_keys=True, ensure_ascii=False) + "\n")
            .encode("utf-8")
        )
        return record

    existing = json.loads(path.read_text(encoding="utf-8"))
    differences = [
        f"{field_name}: existing {existing.get(field_name)!r} != requested "
        f"{fresh.get(field_name)!r}"
        for field_name in _IDENTITY_FIELDS
        if existing.get(field_name) != fresh.get(field_name)
    ]
    if differences:
        raise RunManifestMismatchError(
            f"{path} records a different run than the one requested, so resuming "
            "would interleave two experiments in one output directory. Use a new "
            "--out-dir, or re-run with the recorded settings. Differences:\n  "
            + "\n  ".join(differences)
        )
    return existing


def finalize_manifest(path: Path, record: Mapping[str, Any]) -> None:
    """Stamp the completion time onto an existing manifest."""
    updated = dict(record)
    updated["completed_at"] = datetime.now(timezone.utc).isoformat()
    path.write_bytes(
        (json.dumps(updated, indent=2, sort_keys=True, ensure_ascii=False) + "\n")
        .encode("utf-8")
    )


# ---------------------------------------------------------------------------
# Phase 1 — every arm answers every question
# ---------------------------------------------------------------------------


@dataclass
class AnswerPhase:
    """Answers for every (question, arm), produced once and reread thereafter."""

    rows: dict[tuple[str, str], dict] = field(default_factory=dict)
    claim_question_ids: set[str] = field(default_factory=set)
    model_calls: int = 0

    def answered(self, question_id: str, arm: str) -> bool:
        return (question_id, arm) in self.rows


def load_answer_phase(out_dir: Path) -> AnswerPhase:
    """Rebuild the answering phase's completed work from its durable rows."""
    phase = AnswerPhase()
    for row in read_jsonl(out_dir / ANSWERS_NAME):
        phase.rows[(row["question_id"], row["arm"])] = row
    phase.claim_question_ids = {
        row["question_id"] for row in read_jsonl(out_dir / CLAIMS_NAME)
    }
    return phase


def answer_questions(
    specs: Sequence[QuestionSpec],
    cfg: RealRunConfig,
    *,
    retriever: Retriever,
    client_factory: Callable[[ModelPin], Any],
    pins: Mapping[str, ModelPin],
    phase: AnswerPhase,
    progress: Callable[[str], None] = lambda _message: None,
) -> AnswerPhase:
    """Produce every arm's answers, skipping ``(question, arm)`` pairs on file.

    No judging happens here, by construction: design doc §6.1 guard 1 requires
    the judge to see one shuffled batch of every arm's answers, which is only
    possible once every arm has answered.
    """
    answers = JsonlWriter(cfg.out_dir / ANSWERS_NAME)
    claims_out = JsonlWriter(cfg.out_dir / CLAIMS_NAME)
    cache = ExtractionCache(cfg.out_dir / EXTRACTIONS_NAME)
    extract_client = client_factory(pins["extractor"])
    answer_client = client_factory(pins["answering"])

    for position, spec in enumerate(specs, 1):
        pending = [arm for arm in ARM_STORES if not phase.answered(spec.question_id, arm)]
        if not pending and spec.question_id in phase.claim_question_ids:
            continue

        # One linker per question, shared by every arm — including on a resume
        # that only has to finish one arm, because the linker is deterministic
        # over the same sessions and the extraction memo makes those sessions'
        # claim bodies fixed.
        linker = SharedLinker(spec.question_id)
        extractor = RealExtractor(client=extract_client, linker=linker, cache=cache)
        config = build_config(
            extractor_call=extractor,
            answering_pin=pins["answering"],
            extractor_pin=pins["extractor"],
            judge_pin=pins["judge"],
            answer_client=answer_client,
        )
        item = QAItem(question=spec.question, gold=spec.gold)

        for arm in ARM_STORES:
            store = build_store(arm, retriever, build_extractor(config))
            if phase.answered(spec.question_id, arm):
                # Re-ingest anyway: this arm's answer is on file, but the shared
                # linker still has to see the question's sessions so the arms
                # that remain are linked against the same lineage state the
                # finished ones were.
                store.ingest(list(spec.sessions))
                continue

            result = run_arm(
                store,
                retriever,
                spec.sessions,
                [item],
                config=config,
                top_k=cfg.top_k,
            )
            # Retrieval is stateless and deterministic, so re-running it
            # reproduces exactly the context the answer came from — and times it.
            # M4 measures ``retrieve(...)[:top_k]``, the same span m4_perf times.
            started = time.perf_counter()
            retrieved = list(store.retrieve(spec.question))[: cfg.top_k]
            retrieve_ms = (time.perf_counter() - started) * 1000.0

            stored = list(store.claims)
            row = {
                "kind": "arm_question",
                "question_id": spec.question_id,
                "split": spec.split,
                "arm": arm,
                "prediction": result.predictions[0],
                "retrieved_ids": [claim.id for claim in retrieved],
                "retrieved_texts": [claim.text for claim in retrieved],
                "clusters": store.clusters,
                "num_claims": len(stored),
                "storage_bytes": sum(
                    m4_perf.canonical_claim_bytes(claim) for claim in stored
                ),
                "retrieve_ms": retrieve_ms,
                "pins": result.pins,
                "retriever_params": result.retriever_params,
                "answered_at": datetime.now(timezone.utc).isoformat(),
            }
            answers.append(row)
            phase.rows[(spec.question_id, arm)] = row

        if spec.question_id not in phase.claim_question_ids:
            claims_out.append(
                {
                    "kind": "claims",
                    "question_id": spec.question_id,
                    "linker": linker.stats.as_record(),
                    "claims": [
                        {
                            "id": claim.id,
                            "text": claim.text,
                            "metadata": claim.metadata,
                        }
                        for claim in linker.claims
                    ],
                }
            )
            phase.claim_question_ids.add(spec.question_id)

        phase.model_calls += extractor.calls
        progress(
            f"  [{position}/{len(specs)}] {spec.question_id} ({spec.split}): "
            f"{len(spec.sessions)} sessions, {len(linker.claims)} claims, "
            f"{extractor.calls} extraction call(s)"
        )

    return phase


# ---------------------------------------------------------------------------
# Phase 2 — one shuffled, de-identified judge batch
# ---------------------------------------------------------------------------


def blind_slots(specs: Sequence[QuestionSpec], seed: int) -> list[BlindSlot]:
    """The pinned blind batch order over this run's arms and questions."""
    return blind_batch_order(sorted(ARM_STORES), len(specs), seed=seed)


def judge_blind(
    specs: Sequence[QuestionSpec],
    cfg: RealRunConfig,
    *,
    phase: AnswerPhase,
    judge_client: Any,
    seed: int,
    progress: Callable[[str], None] = lambda _message: None,
) -> dict[tuple[str, str], dict]:
    """Score every candidate in one shuffled batch, resuming where it left off.

    The judge sees ``(question, gold, candidate_answer)`` and nothing else — the
    arm lives only in the harness-side slot. Because the order is a pure function
    of (arms, question count, pinned seed), a resumed batch continues in exactly
    the position the pinned shuffle put it, so an interruption cannot change what
    the judge saw next.
    """
    verdicts_out = JsonlWriter(cfg.out_dir / VERDICTS_NAME)
    recorded: dict[tuple[str, str], dict] = {
        (row["arm"], row["question_id"]): row
        for row in read_jsonl(cfg.out_dir / VERDICTS_NAME)
    }

    order = blind_slots(specs, seed)
    for position, slot in enumerate(order):
        spec = specs[slot.question_index]
        key = (slot.arm, spec.question_id)
        if key in recorded:
            continue

        answer_row = phase.rows.get((spec.question_id, slot.arm))
        if answer_row is None:
            raise MissingAnswerError(
                f"no answer on file for question {spec.question_id!r} arm "
                f"{slot.arm!r}, so the blind batch is incomplete. Every arm must "
                "answer every question before any of them is judged (design doc "
                "§6.1 guard 1); re-run the answering phase first."
            )

        candidate = answer_row["prediction"]
        verdict = judge_client.verdict(spec.question, spec.gold, candidate)
        row = {
            "kind": "verdict",
            "arm": slot.arm,
            "question_id": spec.question_id,
            "question_index": slot.question_index,
            "batch_position": position,
            "verdict": bool(verdict),
            "payload_sha256": payload_digest(spec.question, spec.gold, candidate),
            "judged_at": datetime.now(timezone.utc).isoformat(),
        }
        verdicts_out.append(row)
        recorded[key] = row
        progress(f"  [{position + 1}/{len(order)}] judged {spec.question_id}")

    return recorded


def replay_judge(
    specs: Sequence[QuestionSpec],
    recorded: Mapping[tuple[str, str], dict],
    seed: int,
) -> Callable[[str, str, str], bool]:
    """A judge that returns the durable verdicts, in the canonical blind order.

    The final scoring pass runs through :func:`score_blind` rather than assembling
    verdict lists directly, so the run inherits its cross-arm fairness
    preconditions — identical pins and identical retriever settings across A/B/C.
    That means feeding it a judge, and the honest judge to feed it is the one
    that replays what the real judge already said.

    The ordering assumption this rests on — that ``score_blind`` walks the same
    :func:`blind_batch_order` — is *checked*, not trusted: every replayed verdict
    must match the digest of the payload it was recorded against, so a drift
    between the recorded stream and the canonical order raises
    :class:`VerdictReplayError` instead of silently routing verdicts to the wrong
    arms.
    """
    slots: Iterator[BlindSlot] = iter(blind_slots(specs, seed))

    def judge(question: str, gold: str, candidate_answer: str) -> bool:
        try:
            slot = next(slots)
        except StopIteration as exc:  # pragma: no cover - defensive
            raise VerdictReplayError(
                "score_blind asked for more verdicts than the pinned blind batch "
                "contains."
            ) from exc

        spec = specs[slot.question_index]
        row = recorded.get((slot.arm, spec.question_id))
        if row is None:
            raise VerdictReplayError(
                f"no recorded verdict for arm {slot.arm!r} question "
                f"{spec.question_id!r}."
            )
        digest = payload_digest(question, gold, candidate_answer)
        if digest != row["payload_sha256"]:
            raise VerdictReplayError(
                f"the recorded verdict for arm {slot.arm!r} question "
                f"{spec.question_id!r} was made against a different payload "
                f"({row['payload_sha256']}) than the one being scored ({digest}). "
                "The verdict stream and the pinned blind order disagree; scoring "
                "would attribute verdicts to the wrong answers."
            )
        return bool(row["verdict"])

    return judge


# ---------------------------------------------------------------------------
# Phase 3 — metrics
# ---------------------------------------------------------------------------


def sign_test_p(b: int, c: int) -> float:
    """Exact two-sided sign test on ``b`` / ``c`` discordances.

    ``p = min(1, 2 * P(X <= min(b, c)))`` for ``X ~ Binomial(b + c, 1/2)``,
    the statistic ``preregister.json`` pins for M3's INCONCLUSIVE rule. Computed
    exactly with integer binomials rather than a normal approximation, because at
    the handful of discordances this corpus can produce the approximation is
    exactly where it is worst.
    """
    n = b + c
    if n == 0:
        return 1.0
    k = min(b, c)
    tail = sum(math.comb(n, i) for i in range(k + 1))
    return min(1.0, 2.0 * tail / (2**n))


def m3_readability(
    contaminated: Mapping[str, set[str]], question_ids: Sequence[str], path: Path
) -> dict[str, Any]:
    """M3's pinned INCONCLUSIVE test over the paired A-only / C-only discordances."""
    record = preregistered_metric("M3", path)
    test = record.get("inconclusive_test", {})
    alpha = float(test.get("alpha", 0.05))

    a_only = sorted(
        qid
        for qid in question_ids
        if qid in contaminated.get("A", set()) and qid not in contaminated.get("C", set())
    )
    c_only = sorted(
        qid
        for qid in question_ids
        if qid in contaminated.get("C", set()) and qid not in contaminated.get("A", set())
    )
    p_value = sign_test_p(len(a_only), len(c_only))
    return {
        "b_a_only": len(a_only),
        "c_c_only": len(c_only),
        "n": len(a_only) + len(c_only),
        "p_value": p_value,
        "alpha": alpha,
        "inconclusive": p_value >= alpha,
        "a_only_question_ids": a_only,
        "c_only_question_ids": c_only,
        "method": test.get("method"),
    }


def adversarial_diagnostic(
    verdicts: Mapping[str, Sequence[bool]],
    indices: Sequence[int],
    question_ids: Sequence[str],
    path: Path,
) -> dict[str, Any]:
    """The AG bias-guard tripwire and the response tier its breach mandates.

    Every discordant question is enumerated unconditionally. The pinned Tier 1
    response requires exactly that enumeration — a net advantage does not imply a
    single differing question — and at N = 20 producing it costs nothing, so the
    results carry the evidence whether or not the tripwire fired.
    """
    record = preregistered_metric("AG", path)
    response = record.get("breach_response", {})
    tier1 = float(response.get("tier1_pp", 5.0))
    tier2 = float(response.get("tier2_pp", 10.0))

    treatment = [verdicts["C"][index] for index in indices]
    control = [verdicts["B"][index] for index in indices]
    n = len(indices)
    delta_pp = 100.0 * (sum(treatment) - sum(control)) / n if n else 0.0

    discordant = [
        {
            "question_id": question_ids[index],
            "winner": "C" if verdicts["C"][index] else "B",
        }
        for index in indices
        if verdicts["C"][index] != verdicts["B"][index]
    ]

    if delta_pp >= tier2:
        tier = "tier2"
    elif delta_pp >= tier1:
        tier = "tier1"
    else:
        tier = "none"

    return {
        "gate": record.get("gate"),
        "gating": record.get("gating"),
        "n": n,
        "correct": {"B": sum(control), "C": sum(treatment)},
        "delta_pp": delta_pp,
        "tier1_pp": tier1,
        "tier2_pp": tier2,
        "response_tier": tier,
        "discordant": discordant,
    }


def _pool_arm_perf(rows: Iterable[Mapping[str, Any]], arm: str) -> m4_perf.ArmPerf:
    """One arm's real p50/p95 and bytes/claim, pooled over every question.

    Unlike the smoke, the clock here is :func:`time.perf_counter` — the latencies
    are wall time on the machine that ran the benchmark, which is what M4 is for
    and why its numbers are (correctly) not reproducible byte-for-byte.
    """
    own = [row for row in rows if row["arm"] == arm]
    latencies = [float(row["retrieve_ms"]) for row in own]
    claims = sum(int(row["num_claims"]) for row in own)
    storage = sum(int(row["storage_bytes"]) for row in own)
    return m4_perf.ArmPerf(
        arm=arm,
        p50_ms=percentile(latencies, 0.50) if latencies else 0.0,
        p95_ms=percentile(latencies, 0.95) if latencies else 0.0,
        num_queries=len(latencies),
        num_claims=claims,
        storage_bytes=storage,
        bytes_per_claim=storage / claims if claims else 0.0,
    )


def load_m3_labels(path: Path | None) -> dict[str, list[str]]:
    """Read an external stale-value label file, or return no labels.

    M3 needs, per knowledge-update question, the *old* value that must not reach
    the answering model. LongMemEval ships no such annotation, and the harness
    deliberately does not synthesise one: the obvious derivation — reading the old
    value off the shared linker's own ``supersedes`` edges — would label M3 with
    exactly the edges Arm C acts on, making the metric close to tautological.
    Choosing a label source is a pre-registration-level decision (design doc §6.3)
    for the maintainer, so it arrives as data or not at all.
    """
    if path is None:
        return {}
    return {
        str(qid): [str(value) for value in values]
        for qid, values in json.loads(path.read_text(encoding="utf-8")).items()
    }


def compute_metrics(
    specs: Sequence[QuestionSpec],
    cfg: RealRunConfig,
    *,
    scored: Mapping[str, ArmResult],
    phase: AnswerPhase,
    claim_rows: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Reduce the run's durable rows to the §4 metrics.

    Every metric that can be computed from what actually ran is computed; every
    metric that cannot says why in the same record, so a reader never has to
    infer whether a missing number means "zero" or "never measured".
    """
    path = cfg.preregister_path
    answer_rows = list(phase.rows.values())
    verdicts = {arm: result.verdicts for arm, result in scored.items()}
    question_ids = [spec.question_id for spec in specs]
    by_split: dict[str, list[int]] = {}
    for index, spec in enumerate(specs):
        by_split.setdefault(spec.split, []).append(index)

    metrics: dict[str, Any] = {
        "kind": "metrics",
        "counts": {name: len(indices) for name, indices in sorted(by_split.items())},
        "arms": sorted(scored),
    }

    # -- M1 ---------------------------------------------------------------
    ku_indices = by_split.get(SPLIT_KEYS["ku"], [])
    if ku_indices:
        report = m1_qa.score_m1(
            scored, subset=ku_indices, resamples=cfg.resamples, path=path
        )
        metrics["m1"] = report.as_record()
    else:
        metrics["m1"] = None
        metrics["m1_reason"] = (
            "no knowledge-update questions in this slice; M1's pinned denominator "
            "is the knowledge-update pool (design doc §3.3)."
        )

    # -- M2 ---------------------------------------------------------------
    # Labeled pairs are derived from the shared linker's claims pooled across
    # questions, which is what surfaces the cross-lineage restatements M2's
    # 2026-07-19 annotation makes the §8 diagnosis check first.
    linked = [
        Claim(id=claim["id"], text=claim["text"], metadata=claim["metadata"])
        for row in claim_rows
        for claim in row["claims"]
    ]
    labeled = labeled_pairs.labeled_pairs_from_claims(linked)
    arm_clusters: dict[str, list[list[str]]] = {arm: [] for arm in ARM_STORES}
    for row in answer_rows:
        arm_clusters[row["arm"]].extend(row["clusters"])
    m2_scores = {
        arm: m2_dedup.score_arm(labeled.pairs, clusters)
        for arm, clusters in sorted(arm_clusters.items())
    }
    metrics["m2"] = {
        "f1": {arm: score.f1 for arm, score in m2_scores.items()},
        "precision": {arm: score.precision for arm, score in m2_scores.items()},
        "recall": {arm: score.recall for arm, score in m2_scores.items()},
        "labeled_pairs": labeled.as_record(),
        "labeled_pairs_derivation": labeled.derivation,
    }

    # -- M3 ---------------------------------------------------------------
    labels = load_m3_labels(cfg.m3_labels)
    if labels:
        contexts: dict[str, dict[str, list[str]]] = {arm: {} for arm in ARM_STORES}
        for row in answer_rows:
            if row["question_id"] in labels:
                contexts[row["arm"]][row["question_id"]] = row["retrieved_texts"]
        scores = {
            arm: m3_contamination.contamination_rate(per_arm, labels)
            for arm, per_arm in sorted(contexts.items())
        }
        contaminated = {arm: set(score.contaminated_ids) for arm, score in scores.items()}
        labelled_ids = sorted(set(labels) & set(question_ids))
        metrics["m3"] = {
            "rate": {arm: score.rate for arm, score in scores.items()},
            "contaminated": {arm: score.contaminated for arm, score in scores.items()},
            "total": {arm: score.total for arm, score in scores.items()},
            "readability": m3_readability(contaminated, labelled_ids, path),
            "labels_source": str(cfg.m3_labels),
        }
    else:
        metrics["m3"] = None
        metrics["m3_reason"] = (
            "no stale-value labels supplied (--m3-labels). The corpus ships no "
            "old-value annotation and this harness will not derive one from the "
            "shared linker's supersedes edges, because those are the very edges "
            "Arm C acts on: M3 would then score Arm C against its own mechanism. "
            "Choosing a label source is a maintainer decision under design doc "
            "§6.3."
        )

    # -- M4 ---------------------------------------------------------------
    m4 = m4_perf.M4Report(
        tripwire=m4_perf.pinned_tripwire(path),
        arms={arm: _pool_arm_perf(answer_rows, arm) for arm in sorted(ARM_STORES)},
    )
    metrics["m4"] = m4.as_record()
    metrics["m4_clock"] = "time.perf_counter (real wall time)"

    # -- M5 ---------------------------------------------------------------
    m5 = m5_roundtrip.gate_status(cfg.samples_root)
    metrics["m5"] = {
        "verdict_agreements": m5.verdict_agreement.agreements,
        "verdict_total": m5.verdict_agreement.total,
        "byte_identical": m5.byte_equality.identical,
        "byte_total": m5.byte_equality.total,
        "cross_implementation": {
            "identical": m5.cross_implementation.identical,
            "total": m5.cross_implementation.total,
        },
        "gate_runnable": m5.runnable,
        "gate_blocker": m5.blocker,
        "gate_verdict": m5.passed,
        "gate_verdict_reason": m5.verdict_reason,
    }

    # -- AG ---------------------------------------------------------------
    adv_indices = by_split.get(SPLIT_KEYS["adv"], [])
    if adv_indices and {"B", "C"} <= set(verdicts):
        metrics["ag"] = adversarial_diagnostic(
            verdicts, adv_indices, question_ids, path
        )
    else:
        metrics["ag"] = None
        metrics["ag_reason"] = (
            "no adversarial questions in this slice; the AG tripwire is defined "
            "over the 20-question adversarial set (design doc §6 guard 4)."
        )

    # -- linker recall ----------------------------------------------------
    metrics["linker"] = LinkerStats.total(
        LinkerStats(**row["linker"]) for row in claim_rows
    ).as_record()

    return metrics


# ---------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------


def default_client_factory(pin: ModelPin) -> clients.LocalChatClient:
    return clients.LocalChatClient(pin=pin)


def preflight(
    *,
    client_factory: Callable[[ModelPin], Any] = default_client_factory,
    judge_client: Any | None = None,
    path: Path = PREREGISTER_PATH,
) -> dict[str, Any]:
    """Check every pinned stage is reachable — generating nothing.

    Connectivity only, deliberately. The first real generation from a pinned arm
    is procedurally significant: it closes design doc §6.3's pre-registration
    amendment window, so a preflight that "just tried one question" would spend
    that event on a connectivity check.
    """
    answering = clients.answering_pin(path)
    extractor = clients.extractor_pin(path)
    cli_pin = clients.judge_pin(path)
    judge = judge_client or clients.JudgeClient(cli_pin=cli_pin)

    report: dict[str, Any] = {"answering": None, "extractor": None, "judge": None}
    errors: list[str] = []
    for name, pin in (("answering", answering), ("extractor", extractor)):
        try:
            report[name] = client_factory(pin).preflight()
        except Exception as exc:  # noqa: BLE001 - a preflight reports, never raises
            report[name] = {"model": pin.model, "endpoint": pin.endpoint, "error": str(exc)}
            errors.append(f"{name}: {exc}")
    try:
        report["judge"] = judge.preflight()
    except Exception as exc:  # noqa: BLE001 - same contract as above
        report["judge"] = {"model": cli_pin.pin.model, "error": str(exc)}
        errors.append(f"judge: {exc}")

    ready = (
        bool(report["answering"] and report["answering"].get("model_present"))
        and bool(report["extractor"] and report["extractor"].get("model_present"))
        and bool(report["judge"] and report["judge"].get("runs"))
    )
    report["ready"] = ready and not errors
    report["errors"] = errors
    return report


def execute(
    cfg: RealRunConfig,
    *,
    client_factory: Callable[[ModelPin], Any] = default_client_factory,
    judge_client: Any | None = None,
    progress: Callable[[str], None] = lambda _message: None,
) -> dict[str, Any]:
    """Run the pinned benchmark end to end, resuming whatever is already done."""
    cfg.out_dir.mkdir(parents=True, exist_ok=True)
    seed = pinned_seed(cfg.preregister_path)
    split_manifest = load_split(cfg.split_manifest_path)

    specs = load_questions(
        split=cfg.split,
        limit=cfg.limit,
        haystack=cfg.haystack,
        data_directory=cfg.directory(),
        split_manifest=split_manifest,
    )
    if not specs:
        raise ValueError(
            f"the {cfg.split!r} split with limit {cfg.limit!r} selects no questions"
        )

    pins = {
        "answering": clients.answering_pin(cfg.preregister_path),
        "extractor": clients.extractor_pin(cfg.preregister_path),
        "judge": clients.judge_pin(cfg.preregister_path).pin,
    }
    cli_pin = clients.judge_pin(cfg.preregister_path)
    judge = judge_client or clients.JudgeClient(
        cli_pin=cli_pin, prompt_via=cfg.judge_prompt_via
    )
    retriever = BM25Retriever()

    config = pins_config(pins)
    manifest_path = cfg.out_dir / MANIFEST_NAME
    manifest = reconcile_manifest(
        manifest_path,
        build_manifest(
            cfg,
            specs,
            config.pins_record(),
            judge_fallback=cli_pin.fallback_model,
            retriever_params=retriever.params,
            split_manifest=split_manifest,
        ),
    )

    progress(f"answering {len(specs)} questions x {len(ARM_STORES)} arms")
    phase = load_answer_phase(cfg.out_dir)
    phase = answer_questions(
        specs,
        cfg,
        retriever=retriever,
        client_factory=client_factory,
        pins=pins,
        phase=phase,
        progress=progress,
    )

    missing = [
        f"{spec.question_id}/{arm}"
        for spec in specs
        for arm in ARM_STORES
        if not phase.answered(spec.question_id, arm)
    ]
    if missing:
        raise MissingAnswerError(
            f"{len(missing)} (question, arm) pairs have no answer on file, so the "
            "blind batch would be incomplete: every arm answers every question "
            "before any of them is judged (design doc §6.1 guard 1). First few: "
            f"{missing[:5]}"
        )

    progress(f"blind-scoring {len(specs) * len(ARM_STORES)} candidates")
    recorded = judge_blind(
        specs,
        cfg,
        phase=phase,
        judge_client=judge,
        seed=seed,
        progress=progress,
    )

    # Assemble each arm's answers and re-drive score_blind over the recorded
    # verdicts, so the cross-arm pin and retriever fairness checks run on the
    # real results rather than being assumed.
    questions = [QAItem(question=spec.question, gold=spec.gold) for spec in specs]
    results = {}
    for arm in ARM_STORES:
        rows = [phase.rows[(spec.question_id, arm)] for spec in specs]
        results[arm] = ArmResult(
            predictions=[row["prediction"] for row in rows],
            pins=rows[0]["pins"],
            retriever_params=rows[0]["retriever_params"],
        )
    scored = score_blind(
        results,
        questions,
        config=config,
        judge=replay_judge(specs, recorded, seed),
        seed=seed,
    )

    metrics = compute_metrics(
        specs,
        cfg,
        scored=scored,
        phase=phase,
        claim_rows=read_jsonl(cfg.out_dir / CLAIMS_NAME),
    )
    metrics["manifest"] = {
        key: manifest.get(key) for key in ("pins", "haystack", "split", "git")
    }
    (cfg.out_dir / METRICS_NAME).write_bytes(
        (json.dumps(metrics, indent=2, sort_keys=True, ensure_ascii=False) + "\n")
        .encode("utf-8")
    )
    finalize_manifest(manifest_path, manifest)
    return metrics
