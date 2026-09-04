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
import re
import signal
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator, Mapping, Sequence

from benchmarks.longmemeval import clients, corpus, labeled_pairs
from benchmarks.longmemeval.arms import ARM_STORES
from benchmarks.longmemeval.arms.aphelion_arm import AphelionStore
from benchmarks.longmemeval import linker as linker_mod
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
    GatePinError,
    JudgeVerdictError,
    MemoryStore,
    MissingArmError,
    ModelPin,
    PipelineConfig,
    QAItem,
    Retriever,
    Session,
    StageBinding,
    UnrecordedPinsError,
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

# The extraction-only pass records its provenance under its OWN name rather than
# sharing manifest.json. The graded run's manifest is keyed on things an
# extraction pass has no opinion about — which judge ran, which M3 label set was
# scored — so writing this pass's record into that file would make the very
# ``--real`` resume the pass exists to prepare fail its identity check.
EXTRACT_MANIFEST_NAME = "extract-manifest.json"

# The extraction cache's own provenance, written beside the cache rather than
# inside either manifest. The two modes validate different manifests — ``--real``
# reads manifest.json, an extraction pass reads extract-manifest.json — but they
# append to ONE extractions.jsonl, whose rows are keyed on nothing but
# ``(question_id, session_id)``. A record only one mode consults cannot defend a
# file both of them write, so the cache carries its identity itself and BOTH
# modes check it before reading or appending a row (:func:`extraction_identity`).
EXTRACTION_IDENTITY_NAME = "extractions-identity.json"

# What a manifest's ``mode`` says produced it.
MODE_REAL = "real"
MODE_EXTRACT_ONLY = "extract-only"

# How many QUESTIONS an extraction pass has in flight at once. One by default,
# and deliberately so: the pinned run's shape is the thing being measured, and a
# default that quietly ran it eight questions wide would make every recorded run
# before this one a different pass from every run after it. Raising it is an
# explicit operator choice, recorded in the manifest with the rest of the run's
# shape (:func:`extract_questions` for what it may and may not change).
DEFAULT_EXTRACT_WORKERS = 1


class RunManifestMismatchError(ValueError):
    """A resume was attempted against a run of a different shape.

    The blind batch order is a function of the question count, and every resume
    key is a function of the question set, so continuing a 78-question run inside
    a 220-question output directory would silently interleave two different
    experiments. Refused rather than merged.
    """


class ExtractionIdentityMismatchError(ValueError):
    """The extraction cache on disk was produced under another identity.

    A cache row records what the pinned extractor said about one session's bytes.
    Its key names neither the extractor nor the bytes, so a row extracted under
    one pin, corpus or harness revision is indistinguishable — by key — from the
    row a different configuration would write, and replaying it would have a run
    answer from claims its own extractor never produced. Refused rather than
    merged, in both directions: the mode that would *read* such a row and the
    mode that would *append* beside it are equally wrong.
    """


class CorruptRowError(ValueError):
    """A durable row was terminated but unparseable — corruption, not a tear.

    An interrupted write can only ever damage the *last* row, and only by
    truncating it before its newline. Anything else means the file was damaged
    by something this harness does not model, so it stops rather than skipping
    rows and reporting a run over silently fewer questions.
    """


# The extraction cache's row format. Bumped whenever the PROMPT that produced a
# cached extraction changes, because a replayed claim set is only sound if it
# could have been produced by the prompt this code would send today. Version 2
# adds vocabulary priming: a session's prompt now depends on the subject slugs
# its predecessors minted, so version-1 rows are not replayable.
EXTRACTION_CACHE_FORMAT = 2


class ExtractionCacheVersionError(ValueError):
    """A durable extraction cache was written by a different extraction protocol.

    Refused rather than migrated. The claims themselves are still valid text, but
    they were produced by prompts this harness no longer sends; replaying them
    beside newly-primed sessions would mix two protocols inside one question, and
    the resulting linkage would belong to neither.
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


def _complete_rows(raw: bytes) -> tuple[list[dict], int]:
    """Parse whole rows out of ``raw``; return them and the byte offset they end at.

    Bytes, not text, all the way through. A process killed mid-``write`` can tear
    the file in the middle of a UTF-8 sequence, and decoding the whole file first
    would raise :class:`UnicodeDecodeError` before any tolerance for a torn row
    could apply — turning a recoverable tear into an unreadable run.

    The returned offset is the end of the last row that parsed, which is where an
    append may safely resume from. Anything after it is residue.
    """
    rows: list[dict] = []
    offset = 0
    position = 0
    for chunk in raw.split(b"\n"):
        position += len(chunk) + 1
        if not chunk.strip():
            # A blank line carries no row, but it is still complete input: an
            # append may resume after it.
            if position <= len(raw):
                offset = min(position, len(raw))
            continue
        if position > len(raw):
            # The final chunk had no terminating newline, so the writer did not
            # finish it. Torn, by definition.
            break
        try:
            rows.append(json.loads(chunk.decode("utf-8")))
        except (json.JSONDecodeError, UnicodeDecodeError):
            # A row that is terminated but unparseable is corruption in the
            # middle of the file, not an interrupted write. Surfaced by the
            # callers below rather than skipped.
            raise CorruptRowError(
                f"row ending at byte {position} is terminated but does not parse; "
                f"first bytes: {chunk[:80]!r}. A complete-but-unparseable row is "
                "corruption, not an interrupted write, and is never skipped."
            ) from None
        offset = position
    return rows, offset


def read_jsonl(path: Path) -> list[dict]:
    """Read durable rows, tolerating one torn row at the end of the file.

    Dropping *only* an unterminated final row is safe — that work is simply
    redone, because every phase re-derives what is missing — while a terminated
    row that does not parse is corruption that must not be silently skipped.
    """
    if not path.is_file():
        return []
    return _complete_rows(path.read_bytes())[0]


def repair_jsonl(path: Path) -> int:
    """Truncate any torn trailing row, returning the number of bytes dropped.

    Reading tolerantly is not enough on its own: the writer appends with ``ab``,
    so a torn row left in place would have the next row concatenated onto it and
    become a *permanently* unparseable row in the middle of the file — at which
    point the tolerance above correctly refuses to read it and the run is stuck.
    The residue therefore has to go before anything appends, which is why this
    runs once per durable file at the start of every run.
    """
    if not path.is_file():
        return 0
    raw = path.read_bytes()
    _, offset = _complete_rows(raw)
    dropped = len(raw) - offset
    if dropped:
        with path.open("r+b") as handle:
            handle.truncate(offset)
            handle.flush()
            os.fsync(handle.fileno())
    return dropped


class JsonlWriter:
    """Append-only writer that makes each row durable before returning.

    ``flush`` plus ``fsync`` per row: the row counts are in the hundreds to low
    tens of thousands against model calls measured in seconds, so the cost is
    noise, and the property bought — an interrupted run never loses completed
    model work — is the entire reason this run is resumable.

    The file is repaired on construction, so an append can never land on top of a
    torn row (see :func:`repair_jsonl`).

    **One row, one write, one thread at a time.** The extraction scheduler runs
    questions concurrently against a single cache file, so appends arrive from
    many threads. The row is serialised to bytes *before* the lock and handed to
    one ``write`` call inside it, which makes the failure this guards against
    impossible rather than unlikely: two interleaved appends do not produce a
    *torn* row — the tolerance above is for those, and they are only ever at the
    end of a file — they produce a spliced row in the MIDDLE of one, which
    :func:`read_jsonl` refuses permanently and correctly, leaving the run
    unresumable with its model work already paid for.

    The lock belongs to the *instance*, which is the whole of what is claimed.
    Two writers over one path hold two different locks and do not serialise
    against each other, so a phase that opens its own writer must not overlap
    another that has one — as things stand none do: a graded run's pre-extraction
    finishes before the answering phase opens the cache again. Two *processes*
    were never supported either; what stops those is the manifest and
    extraction-identity gates, which refuse a second run over another pass's rows
    before a byte is written.
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self.repaired_bytes = repair_jsonl(path)

    def append(self, row: Mapping[str, Any]) -> None:
        # Encoded outside the lock: it is pure CPU on a private row, and holding
        # the lock across it would serialise formatting as well as writing.
        payload = (json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n").encode(
            "utf-8"
        )
        with self._lock:
            with self.path.open("ab") as handle:
                handle.write(payload)
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

    Shared by every question the extraction scheduler has in flight, so the
    in-memory index and the durable row behind it are updated under one lock. The
    two halves must not be observable out of step: a row on disk the index does
    not know about is a session re-extracted and paid for twice, and an index
    entry with no row behind it is a session that silently disappears on the next
    resume. Under the lock they are one operation, so a key is in both or neither.
    """

    def __init__(self, path: Path) -> None:
        self._writer = JsonlWriter(path)
        self._records: dict[tuple[str, str], list[dict]] = {}
        self._lock = threading.Lock()
        for row in read_jsonl(path):
            if row.get("format") != EXTRACTION_CACHE_FORMAT:
                raise ExtractionCacheVersionError(
                    f"{path} holds extraction rows in format "
                    f"{row.get('format')!r}, but this harness writes and reads "
                    f"format {EXTRACTION_CACHE_FORMAT}. Rows written before "
                    "vocabulary priming were produced by UNPRIMED prompts: the "
                    "same session now receives a prompt carrying the subject "
                    "slugs its predecessors minted, so replaying the old claims "
                    "would mix two extraction protocols inside one question. "
                    "Discard this cache (delete the file, or start a new "
                    "--out-dir) and let the sessions be re-extracted."
                )
            self._records[(row["question_id"], row["session_id"])] = list(row["claims"])

    def __len__(self) -> int:
        with self._lock:
            return len(self._records)

    def get(self, question_id: str, session_id: str) -> list[dict] | None:
        with self._lock:
            records = self._records.get((question_id, session_id))
            return (
                [dict(record) for record in records] if records is not None else None
            )

    def put(
        self,
        question_id: str,
        session_id: str,
        records: Sequence[Mapping[str, str]],
        *,
        instrumentation: Mapping[str, Any] | None = None,
    ) -> None:
        """Memoise one session's claims, optionally annotated with call costs.

        ``instrumentation`` rides *beside* the four fields that define the row,
        never inside them: a reader replaying this cache takes ``claims`` and
        ignores the rest, so an annotated row and a bare one are the same input
        to every arm. The pinned ``--real`` path passes nothing, which keeps its
        rows byte-identical to the ones it has always written.
        """
        stored = [dict(record) for record in records]
        row: dict[str, Any] = {
            "format": EXTRACTION_CACHE_FORMAT,
            "question_id": question_id,
            "session_id": session_id,
            "claims": stored,
        }
        for key, value in sorted(dict(instrumentation or {}).items()):
            # Never allowed to shadow the fields the replay reads.
            if key not in row:
                row[key] = value
        # Index and row together — see the class docstring. The append is inside
        # the lock rather than after it because "durable, then visible" is the
        # order a resume depends on: a caller that saw the memo entry has to be
        # able to assume the bytes behind it survive the process.
        with self._lock:
            self._records[(question_id, session_id)] = stored
            self._writer.append(row)


def _call_instrumentation(
    wall_ms: float, usage: Mapping[str, int] | None
) -> dict[str, Any]:
    """What one extraction call cost, in the fields a cache row carries.

    ``wall_ms`` is always present — it is measured here, so it cannot be
    missing. The token counts are prefixed ``usage_`` and appear only when the
    endpoint reported them: a served model that says nothing about tokens must
    leave the fields absent rather than record a zero that reads as a
    measurement.
    """
    record: dict[str, Any] = {"wall_ms": wall_ms}
    for name, value in sorted(dict(usage or {}).items()):
        record[f"usage_{name}"] = value
    return record


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
    question_id: str
    calls: int = 0
    # When set, every FRESH extraction annotates its cache row with what the call
    # cost — wall time here, tokens as the endpoint reported them. Off for the
    # pinned run, whose cache rows are an input to three arms and are therefore
    # kept to the fields a replay reads.
    instrument: bool = False
    # Session ids in first-seen (pinned occurrence) order, and their claims. The
    # priming vocabulary for a session is derived from these rather than
    # accumulated as the run goes, so it is a pure function of the pinned order
    # and not of how many arm passes have happened to reach this point.
    _order: list[str] = field(default_factory=list)
    _claims_by_session: dict[str, list[dict]] = field(default_factory=dict)

    def vocabulary_before(self, session_id: str) -> list[tuple[str, str]]:
        """Subject slugs minted by this question's EARLIER sessions, with values.

        Ordered by when each slug was first minted, carrying the most recent
        value seen for it. Derived from the sessions preceding ``session_id`` in
        pinned order — never from "everything seen so far" — because every arm
        replays the same sessions through this one shared extractor, and a
        vocabulary that grew with the replays would prime a session differently
        on the second pass than on the first.
        """
        vocabulary: dict[str, str] = {}
        for earlier in self._order:
            if earlier == session_id:
                break
            for record in self._claims_by_session.get(earlier, ()):
                vocabulary[record["subject"]] = record["value"]
        return list(vocabulary.items())

    def __call__(self, session: Session, *, pin: ModelPin) -> list[Claim]:
        if session.id not in self._order:
            self._order.append(session.id)

        records = self.cache.get(self.question_id, session.id)
        if records is None:
            started = time.perf_counter()
            result = clients.chat_result(
                self.client,
                clients.extract_structured_messages(
                    session.text, self.vocabulary_before(session.id)
                ),
            )
            wall_ms = (time.perf_counter() - started) * 1000.0
            records = [
                {"text": claim.text, "subject": claim.subject, "value": claim.value}
                for claim in clients.extracted_claims(result.text)
            ]
            self.cache.put(
                self.question_id,
                session.id,
                records,
                instrumentation=(
                    _call_instrumentation(wall_ms, result.usage)
                    if self.instrument
                    else None
                ),
            )
            self.calls += 1

        # Recorded whether the claims came from the model or from the memo: the
        # vocabulary a later session is primed with has to be identical either
        # way, which is what makes a resumed run send the prompts the original
        # run sent.
        self._claims_by_session[session.id] = records

        # The claim sentences are what retrieval and answering see, exactly as
        # before; the subject/value pair travels beside them so the shared linker
        # can key lineages on the FACT rather than on its phrasing. Free-text
        # phrasing varies between sessions, which is why the 2026-08-15 probe
        # found 243 records resolving to 243 lineages and zero update edges.
        metadata = dict(session.metadata)
        metadata[linker_mod.STRUCTURED_KEY] = {
            record["text"]: {
                "subject": record["subject"],
                "value": record["value"],
            }
            for record in records
        }
        return self.linker(
            Session(
                id=session.id,
                text="\n".join(record["text"] for record in records),
                metadata=metadata,
            )
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
    # Set only to score M3 from a labels file that is not the pre-registered one.
    # Mirrors judge_deviation_ack: the deviation is allowed, but never implicit.
    m3_labels_deviation_ack: bool = False
    resamples: int = m1_qa.BOOTSTRAP_RESAMPLES
    # Which form the judge CLI is handed its prompt. Exposed as a run setting
    # because which form the installed build accepts is an operational fact about
    # that machine, and discovering it must not require editing the harness in
    # the middle of a run.
    judge_prompt_via: str = clients.PROMPT_VIA_STDIN
    # Set only to run with a judge the pre-registration does not name. The design
    # doc sanctions a manual fallback judge, so this exists to make that an
    # explicit act rather than something a run can drift into unnoticed.
    judge_deviation_ack: bool = False
    split_manifest_path: Path = corpus.MANIFEST_PATH
    preregister_path: Path = PREREGISTER_PATH
    # How many questions the extraction stage has in flight at once. A scheduling
    # setting and nothing more: it cannot change which rows are produced or what
    # is in them, only how long the pass takes (:func:`extract_questions`).
    extract_workers: int = DEFAULT_EXTRACT_WORKERS

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
            # Untracked files are excluded deliberately: a run writes its own
            # durable output under the repo by default, so counting untracked
            # files would report every run as dirty and say nothing about the
            # code. Uncommitted edits to code that matters are caught precisely
            # by :func:`harness_digest`.
            ["git", "-C", str(root), "status", "--porcelain", "--untracked-files=no"],
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
    judge_standing: Mapping[str, Any],
    label_source: M3LabelSource | None,
    model_config: Mapping[str, Any],
    mode: str = MODE_REAL,
) -> dict[str, Any]:
    """The run's provenance record: what ran, against what, under which pins.

    ``mode`` names which pass produced the record. It is deliberately *not* one
    of :data:`_IDENTITY_FIELDS`: the two modes write to different manifest files
    (see :data:`EXTRACT_MANIFEST_NAME`), so it is a label for a reader rather
    than a resume key.
    """
    preregister = json.loads(cfg.preregister_path.read_text(encoding="utf-8"))
    git = git_provenance()
    record: dict[str, Any] = {
        **dict(judge_standing),
        "benchmark": preregister.get("benchmark"),
        "mode": mode,
        "arms": sorted(ARM_STORES),
        "pins": dict(pins),
        # Beyond the four fields pipeline.py's fairness checks compare: the chat
        # dialect, the upstream weights a served name resolves to, and the
        # template switches without which the server answers differently.
        "model_config": dict(model_config),
        "judge_fallback_model": judge_fallback,
        "design_doc_sha256": preregister.get("design_doc_sha256"),
        "preregister_sha256": _sha256_text(
            cfg.preregister_path.read_text(encoding="utf-8")
        ),
        "split_manifest_sha256": _sha256_text(
            cfg.split_manifest_path.read_text(encoding="utf-8")
        ),
        "corpus_source_sha256": split_manifest.get("source_sha256", {}),
        "corpus_loaded_sha256": corpus_digests(cfg),
        "corpus_data_dir": str(cfg.directory()),
        **(
            label_source.as_record()
            if label_source is not None
            else {
                "m3_labels_path": None,
                "m3_labels_sha256": None,
                "m3_labels_match_preregistered": None,
                "m3_labels_pinned_file": None,
                "m3_labels_deviation_acknowledged": False,
            }
        ),
        # Resolved, so the manifest names where the bytes were actually read
        # from. A symlinked samples root is a legitimate operator arrangement and
        # the digest covers its target correctly — M5's own package discovery
        # follows it identically — but a manifest that recorded the link rather
        # than its destination would describe a corpus that is not the one
        # measured.
        "samples_root": str(Path(cfg.samples_root).resolve()),
        "samples_sha256": samples_digest(cfg.samples_root),
        "haystack": cfg.haystack,
        "split": cfg.split,
        "limit": cfg.limit,
        "top_k": cfg.top_k,
        # How wide the extraction stage ran. Recorded because it is part of how
        # the run was performed and an operator reading the record months later
        # should not have to guess — and deliberately NOT part of
        # :data:`_IDENTITY_FIELDS` or :func:`extraction_identity`, because it
        # cannot change a row. A pass that extracted eight questions at a time
        # produces rows a one-at-a-time pass would produce, so refusing to resume
        # across a change of width would throw away paid work for a scheduling
        # decision.
        "extract_workers": cfg.extract_workers,
        "seed": pinned_seed(cfg.preregister_path),
        "query_time": PINNED_QUERY_TIME.isoformat(),
        "retriever_params": dict(retriever_params),
        "question_count": len(specs),
        "questions_sha256": questions_digest(specs),
        "harness_sha256": harness_digest(),
        # Narrower on purpose, and recorded beside the wide one so a reader can
        # see both: this is the digest the extraction cache is keyed on.
        "extraction_harness_sha256": harness_digest(_EXTRACTION_HARNESS_ROOTS),
        "git_sha": git.get("sha"),
        "git_dirty": git.get("dirty"),
        "git": git,
    }
    # Recorded in both manifests, and identical to the record written beside the
    # cache: a reader holding one file can see what the other agreed to without
    # having to know which fields the projection selects.
    record["extraction_identity"] = extraction_identity(record)
    return record


class JudgeDeviationError(ValueError):
    """The configured judge is not the pre-registered one, and nobody said so.

    The design doc sanctions a *manual* fallback judge (§5.2 names one), so this
    is not a prohibition — it is a requirement that the deviation be an explicit
    operator act rather than something a run drifts into. A run that quietly
    judged with another model would publish M1 and AG under the pre-registered
    judge's name, and nothing in the results would say otherwise.
    """


def judge_standing(
    judge_client: Any, preregistered: ModelPin
) -> dict[str, Any]:
    """Compare the judge that will actually run against the pre-registered pin.

    Returns the fields a run records about *which* judge produced its verdicts.
    The comparison is on the full pin record — model, endpoint, temperature and
    seed — because reaching the same model a different way is also a change the
    results have to be able to state.
    """
    pin = getattr(judge_client, "pin", None)
    if not isinstance(pin, ModelPin):
        raise UnrecordedPinsError(
            f"{type(judge_client).__name__} exposes no ModelPin, so the run could "
            "not record which judge produced its verdicts."
        )
    matches = pin.as_record() == preregistered.as_record()
    return {
        "judge_pin": pin.as_record(),
        "judge_model": pin.model,
        "preregistered_judge_model": preregistered.model,
        "judge_matches_preregistered_pin": matches,
    }


def require_judge_acknowledged(standing: Mapping[str, Any], acknowledged: bool) -> None:
    """Refuse an unacknowledged deviation from the pre-registered judge."""
    if standing["judge_matches_preregistered_pin"] or acknowledged:
        return
    raise JudgeDeviationError(
        f"the configured judge is {standing['judge_model']!r} but "
        f"benchmarks/longmemeval/preregister.json pins "
        f"{standing['preregistered_judge_model']!r} (design doc §5.2). Running "
        "the pinned benchmark with a different judge is allowed — the design doc "
        "names a fallback — but it has to be deliberate: pass "
        "--judge-deviation-ack to record the deviation in the run manifest. "
        "Without it the results would carry M1 and AG numbers produced by a judge "
        "the pre-registration does not name."
    )


def file_digest(path: Path | None) -> str | None:
    """Hex SHA-256 of a file's bytes, or ``None`` when there is no file."""
    if path is None or not Path(path).is_file():
        return None
    return corpus.sha256_file(Path(path))


def corpus_digests(cfg: RealRunConfig) -> dict[str, str | None]:
    """Digest every corpus file this run actually reads.

    ``split_manifest.json``'s own ``source_sha256`` records what the *split* was
    frozen over, which is not the same claim: a run can point ``--data-dir`` at a
    different directory whose files carry the same question ids. Hashing what was
    loaded is what ties the results to the bytes they came from.
    """
    directory = cfg.directory()
    names = [corpus.ORACLE_FILENAME]
    if cfg.haystack == HAYSTACK_S:
        names.append(corpus.S_CLEANED_FILENAME)
    return {name: file_digest(directory / name) for name in names}


def questions_digest(specs: Sequence[QuestionSpec]) -> str:
    """Digest the run's questions by content, not just by id.

    Ids alone would let a corpus swap that preserved question ids resume onto
    rows answered against different text. The session ids are folded in too, so a
    haystack that changed underneath a resume is caught even where the question
    and gold answer did not move.
    """
    return _sha256_text(
        "\n".join(
            "\t".join(
                [
                    spec.question_id,
                    spec.split,
                    spec.question,
                    spec.gold,
                    ",".join(session.id for session in spec.sessions),
                ]
            )
            for spec in specs
        )
    )


# The sources whose contents decide what a run produces: the harness itself, the
# aphelion package Arm C's machinery lives in, and the independent reader M5's
# gate is measured against. The reader is named as a single file because it sits
# outside every package tree — it is deliberately import-free of ``aphelion``,
# which is the whole reason M5 can use it as a second implementation — and
# because nothing else in ``scripts/`` affects a run.
_HARNESS_ROOTS = (
    Path(__file__).resolve().parent,
    REPO_ROOT / "src" / "aphelion",
    REPO_ROOT / "scripts" / "external_reader.py",
)

# The subset of the above that can change one extraction ROW: the prompt is built
# here, the sessions are ordered here, and the priming vocabulary is minted here.
# The other two roots are read by consumers of the cache — Arm C's store ingests
# the claims a row already holds, M5's reader is measured against the run's
# output — so digesting them into the cache's identity would throw away paid
# extraction work every time the shipped package moved, for a resume that cannot
# be unsafe. The run's own identity keeps the wide digest (:data:`_IDENTITY_FIELDS`).
_EXTRACTION_HARNESS_ROOTS = (Path(__file__).resolve().parent,)


def _framed(digest: "hashlib._Hash", *parts: bytes) -> None:
    """Feed length-prefixed parts, so no two different inputs can collide.

    Concatenating a path and its bytes straight into the hash is ambiguous: a
    tree whose file content ends with the next file's path produces the same
    byte stream as a tree where that text is genuinely a separate file, and the
    two get the same digest without SHA-256 being broken at all. Prefixing each
    part with its length makes the stream self-delimiting, so a digest identifies
    exactly one (path, bytes) sequence.
    """
    for part in parts:
        digest.update(str(len(part)).encode("ascii"))
        digest.update(b":")
        digest.update(part)


def harness_digest(roots: Sequence[Path] = _HARNESS_ROOTS) -> str:
    """Digest the code that decides what the arms — and M5 — do.

    A git sha alone is not code identity: uncommitted edits move behaviour
    without moving the sha, and an untracked new module is invisible to it, so
    the resume check hashes the actual source that produces the results. This is
    the precise form of the guard — an edit to an unrelated file elsewhere in the
    repo does not block a resume, and an edit to an arm or to the independent
    reader does.

    Both directories and single files are accepted, and a *missing* named file
    still contributes to the digest, so its disappearance is a change rather than
    a silent no-op.
    """
    digest = hashlib.sha256()
    for root in roots:
        target = Path(root)
        paths = (
            [target]
            if target.suffix == ".py" and not target.is_dir()
            else sorted(target.rglob("*.py"))
        )
        for path in paths:
            if "__pycache__" in path.parts:
                continue
            _framed(
                digest,
                path.name.encode("utf-8"),
                path.read_bytes() if path.is_file() else b"<absent>",
            )
    return digest.hexdigest()


class SamplesTreeError(ValueError):
    """A symlink was found inside the sample corpus.

    :func:`~benchmarks.longmemeval.metrics.m5_roundtrip._package_dirs` decides
    what a package is with ``candidate.is_dir()``, which *follows* symlinks, so a
    symlinked directory is a package M5 reads. The digest must therefore cover it
    too, or a resume could accept a corpus whose content moved.

    Refusing is chosen over following. Following reaches arbitrary locations
    outside the tree — whose content can change with nothing in the repository
    changing — and admits symlink cycles, so the digest would have to defend
    against unbounded traversal to describe a corpus that is, by construction, a
    fixed set of package directories. Refusing keeps the guarantee exact: what is
    hashed is everything M5 can reach. Copy the target in instead.
    """


def _sample_files(base: Path) -> list[Path]:
    """Every regular file under ``base``, refusing symlinks anywhere inside.

    Walked explicitly rather than through ``rglob``: on this Python ``rglob`` does
    not recurse into symlinked directories, while M5's own package discovery
    follows them, and a digest that sees less than the metric it protects is
    worse than none.
    """
    found: list[Path] = []
    stack = [base]
    while stack:
        for entry in sorted(stack.pop().iterdir()):
            if entry.is_symlink():
                raise SamplesTreeError(
                    f"{entry} is a symlink. M5 follows symlinked directories when "
                    "it enumerates packages, so a digest that skipped this could "
                    "accept a resume after the target changed; and following it "
                    "would reach outside the corpus. Replace the link with a copy."
                )
            if entry.is_dir():
                stack.append(entry)
            elif entry.is_file():
                found.append(entry)
    return found


def samples_digest(root: Path) -> str:
    """Digest the sample corpus M5's gate is measured over.

    M5's denominator and verdict are functions of what is in ``samples/``: adding
    a package changes the gate's ``n``, and editing one changes whether the two
    implementations agree. Those files are frequently untracked while being
    worked on, so neither the git sha nor :func:`harness_digest` sees them — which
    is exactly how a resumed run could report an M5 measured over a different
    corpus than the one it started with.

    Relative paths are hashed alongside the bytes so a rename is a change, both
    are length-framed so no two trees can collide (:func:`_framed`), and the walk
    is sorted so the digest does not depend on directory iteration order.
    """
    base = Path(root)
    if not base.is_dir():
        return _sha256_text(f"<absent:{base.name}>")
    digest = hashlib.sha256()
    for path in sorted(
        _sample_files(base), key=lambda p: p.relative_to(base).as_posix()
    ):
        _framed(
            digest,
            path.relative_to(base).as_posix().encode("utf-8"),
            path.read_bytes(),
        )
    return digest.hexdigest()


# The manifest fields that define what a run *is*. A resume whose shape differs
# on any of them is a different experiment sharing an output directory: the rows
# already on disk were produced under one set of these, and rows appended after a
# change would be produced under another, with nothing in the results to say so.
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
    # Content identity: the frozen inputs and the code that consumes them.
    "harness_sha256",
    "git_sha",
    "git_dirty",
    "preregister_sha256",
    "split_manifest_sha256",
    "corpus_loaded_sha256",
    "corpus_data_dir",
    "model_config",
    "m3_labels_sha256",
    # Whether M3 was scored from the pre-registered sample. A resume that swapped
    # a deviant label set in halfway would otherwise report one M3 over two.
    "m3_labels_match_preregistered",
    # M5's inputs: its gate is a function of the sample corpus, which is often
    # untracked and therefore invisible to both git and the harness digest.
    "samples_sha256",
    # The judge that actually ran — not the pinned one — so a fallback judge
    # cannot be swapped in halfway through one blind batch.
    "judge_model",
    "judge_matches_preregistered_pin",
)


def manifest_identity(record: Mapping[str, Any]) -> dict[str, Any]:
    """The projection of a manifest that defines what the whole run *is*."""
    return {field_name: record.get(field_name) for field_name in _IDENTITY_FIELDS}


def extraction_identity(record: Mapping[str, Any]) -> dict[str, Any]:
    """The projection of a manifest that decides one extraction ROW.

    Every field here changes what the pinned extractor would say about a session:
    which model answers and how it is served, which corpus bytes it is shown,
    which sessions a question even has, and the code that builds the prompt.
    Nothing else is admitted, and the omissions are the point —
    :data:`_IDENTITY_FIELDS` is the *run's* identity and covers scoring too, so
    keying the cache on it would refuse resumes that cannot be unsafe: a changed
    ``top_k`` re-ranks retrieval and cannot move a claim; the arm list, the M5
    sample corpus, the M3 labels and the judge all read the cache's output and
    never its input. ``limit`` is left out for the same reason — a narrower pass
    writes a strict subset of the rows a wider one would, each produced exactly
    as the wider pass would produce it — which is what lets a small pilot
    extraction be topped up rather than thrown away.

    ``split`` is kept even though it, too, only selects questions: an extraction
    pass exists to pre-pay a *named* graded run, and quietly serving a different
    split's rows out of one directory is the confusion this record exists to make
    impossible.

    The code is identified by ``extraction_harness_sha256`` — the digest over
    ``benchmarks/longmemeval/`` alone (:data:`_EXTRACTION_HARNESS_ROOTS`) — and
    not by ``git_sha``, which moves with every unrelated edit in the repository,
    nor by the run-wide ``harness_sha256``, which also spans ``src/aphelion/``
    and ``scripts/external_reader.py``. Those two are read by *consumers* of a
    row and cannot change one, so admitting them would re-import the same
    over-coupling this projection drops ``top_k`` and ``arms`` to avoid: a
    one-line edit to the shipped package would discard hours of paid extraction.
    ``harness_sha256`` stays in the *run's* identity, where those files do decide
    the result (:data:`_IDENTITY_FIELDS`).
    """
    pins = record.get("pins") or {}
    model_config = record.get("model_config") or {}
    return {
        "extraction_cache_format": EXTRACTION_CACHE_FORMAT,
        "extractor_pin": pins.get("extractor"),
        "extractor_model_config": model_config.get("extractor"),
        "haystack": record.get("haystack"),
        "split": record.get("split"),
        "corpus_data_dir": record.get("corpus_data_dir"),
        "corpus_loaded_sha256": record.get("corpus_loaded_sha256"),
        "split_manifest_sha256": record.get("split_manifest_sha256"),
        "extraction_harness_sha256": record.get("extraction_harness_sha256"),
    }


def _identity_differences(
    existing: Mapping[str, Any], fresh: Mapping[str, Any]
) -> list[str]:
    """Field-by-field disagreement between two identity projections.

    Reported in the fresh projection's own order, with any field only the
    existing record carries listed after it, so a record written by an older
    revision is described rather than silently ignored.
    """
    names = list(fresh) + [name for name in existing if name not in fresh]
    return [
        f"{name}: existing {existing.get(name)!r} != requested {fresh.get(name)!r}"
        for name in names
        if existing.get(name) != fresh.get(name)
    ]


def check_manifest(
    path: Path,
    fresh: Mapping[str, Any],
    *,
    identity: Callable[[Mapping[str, Any]], Mapping[str, Any]] = manifest_identity,
) -> dict[str, Any] | None:
    """The manifest already at ``path``, checked against ``fresh``.

    ``None`` when there is none to check. Checking is separated from writing
    (:func:`write_manifest`) because a run has more than one gate to pass, and a
    manifest minted before the others have spoken would describe an experiment
    that never happened — one the *next* attempt would then have to reconcile
    against, having done nothing wrong.

    ``identity`` names which projection has to agree. It is a parameter because
    the two modes guard different things: a graded resume must match the whole
    run (:func:`manifest_identity`), while an extraction pass may require only
    what an extraction row depends on (:func:`extraction_identity`).
    """
    if not path.is_file():
        return None

    existing = json.loads(path.read_text(encoding="utf-8"))
    differences = _identity_differences(identity(existing), identity(fresh))
    if differences:
        raise RunManifestMismatchError(
            f"{path} records a different run than the one requested, so resuming "
            "would interleave two experiments in one output directory. Use a new "
            "--out-dir, or re-run with the recorded settings. Differences:\n  "
            + "\n  ".join(differences)
        )
    return existing


def write_manifest(path: Path, fresh: Mapping[str, Any]) -> dict[str, Any]:
    """Write a first manifest for this output directory, stamped as started."""
    record = dict(fresh)
    record["started_at"] = datetime.now(timezone.utc).isoformat()
    record["completed_at"] = None
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(
        (json.dumps(record, indent=2, sort_keys=True, ensure_ascii=False) + "\n")
        .encode("utf-8")
    )
    return record


def reconcile_extraction_identity(
    path: Path, fresh: Mapping[str, Any], *, cache_path: Path
) -> dict[str, Any]:
    """Write the extraction cache's identity, or check it against the one there.

    Called by both modes before either reads or appends a row. What decides the
    outcome is whether there are ROWS to misattribute — the record exists to
    vouch for bytes, so with no bytes it has nothing to say:

    * No identity record and no rows — this pass owns the cache; the record is
      written and it is now attributable.
    * A record that agrees — the rows on disk were produced by this exact
      extraction, and replaying or extending them is what resume means.
    * A record that disagrees **over rows on disk** — refused: replaying them
      would answer from claims this configuration's extractor never made.
    * A record that disagrees over an absent or empty cache — replaced. Both
      modes write the sidecar *before* extracting, so a pass that died at its
      first model call leaves one behind with nothing beneath it; enforcing that
      would pin an output directory to an identity that never produced a byte.
    * Rows with no record at all — refused, and this is not the benign case it
      looks like: rows whose provenance is missing are precisely the rows nothing
      can vouch for, and writing this pass's identity over them would mint an
      attestation for bytes it never produced.
    """
    # Checked before anything is read or written, and deliberately on size rather
    # than on parsed rows: a torn trailing row is still a row somebody paid for.
    rows_on_disk = cache_path.is_file() and bool(cache_path.stat().st_size)

    if path.is_file():
        existing = json.loads(path.read_text(encoding="utf-8"))
        differences = _identity_differences(existing, fresh)
        if not differences:
            return existing
        if rows_on_disk:
            raise ExtractionIdentityMismatchError(
                f"{cache_path} holds extractions produced under a different "
                "identity, so replaying them would answer from claims this "
                "configuration's extractor never made. Use a new --out-dir, or "
                "re-run with the recorded settings. Differences:\n  "
                + "\n  ".join(differences)
            )
    elif rows_on_disk:
        raise ExtractionIdentityMismatchError(
            f"{cache_path} holds extraction rows but {path.name} is missing, so "
            "nothing says which extractor, corpus or harness revision produced "
            f"them. Refused rather than adopted: delete {cache_path.name} (or "
            "start a new --out-dir) to re-extract, and only restore the identity "
            "record if you know what wrote those rows."
        )

    record = dict(fresh)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(
        (json.dumps(record, indent=2, sort_keys=True, ensure_ascii=False) + "\n")
        .encode("utf-8")
    )
    return record


def finalize_manifest(
    path: Path, record: Mapping[str, Any], *, resume: Mapping[str, Any] | None = None
) -> None:
    """Stamp the completion time onto an existing manifest.

    ``resume`` appends one entry to a ``resumes`` list, stamped with the same
    instant. It exists because an extraction manifest is reconciled on the
    *extraction* projection, which deliberately admits neither ``limit`` nor
    ``question_count``: a wider pass may legitimately resume a narrow pilot's
    directory, and what the record's own header then describes is the pass that
    FIRST wrote it. Re-stamping ``completed_at`` alone would leave the file
    reporting a slice that is no longer what the directory holds, with nothing on
    it to say otherwise. The header is not rewritten — that pass really did do
    what it says — so the ledger is how each later pass gets to speak for itself.
    """
    updated = dict(record)
    finished_at = datetime.now(timezone.utc).isoformat()
    updated["completed_at"] = finished_at
    if resume is not None:
        updated["resumes"] = [
            *(updated.get("resumes") or []),
            {**dict(resume), "finished_at": finished_at},
        ]
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
    client_factory: Callable[[Any], Any],
    pins: Mapping[str, ModelPin],
    chat_pins: Mapping[str, Any],
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
    extract_client = client_factory(chat_pins["extractor"])
    answer_client = client_factory(chat_pins["answering"])

    for position, spec in enumerate(specs, 1):
        pending = [arm for arm in ARM_STORES if not phase.answered(spec.question_id, arm)]
        if not pending and spec.question_id in phase.claim_question_ids:
            continue

        # One linker per question, shared by every arm — including on a resume
        # that only has to finish one arm, because the linker is deterministic
        # over the same sessions and the extraction memo makes those sessions'
        # claim bodies fixed.
        linker = SharedLinker(spec.question_id)
        extractor = RealExtractor(
            client=extract_client,
            linker=linker,
            cache=cache,
            question_id=spec.question_id,
        )
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
    order = blind_slots(specs, seed)
    verdicts_out = JsonlWriter(cfg.out_dir / VERDICTS_NAME)
    rows = read_jsonl(cfg.out_dir / VERDICTS_NAME)
    verify_verdict_prefix(rows, order, specs)
    judge_record = judge_identity(judge_client)
    for row in rows:
        verify_verdict_judge(row, judge_record)
    verify_verdict_prompts(rows, specs, phase, judge_client)
    recorded: dict[tuple[str, str], dict] = {
        (row["arm"], row["question_id"]): row for row in rows
    }

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
        # The prompt comes back from the call that sent it, so the digest
        # recorded is of what was actually asked rather than of a second
        # rendering that could have drifted from it.
        verdict, prompt = judge_client.verdict_with_prompt(
            spec.question, spec.gold, candidate
        )
        row = {
            "kind": "verdict",
            "arm": slot.arm,
            "question_id": spec.question_id,
            "question_index": slot.question_index,
            "batch_position": position,
            "verdict": strict_verdict(verdict, arm=slot.arm, question_id=spec.question_id),
            "payload_sha256": payload_digest(spec.question, spec.gold, candidate),
            "prompt_sha256": _sha256_text(prompt),
            "judged_at": datetime.now(timezone.utc).isoformat(),
            **judge_record,
        }
        verdicts_out.append(row)
        recorded[key] = row
        progress(f"  [{position + 1}/{len(order)}] judged {spec.question_id}")

    return recorded


def strict_verdict(verdict: Any, *, arm: str, question_id: str) -> bool:
    """Accept a judge result only if it is genuinely ``True`` or ``False``.

    ``bool(verdict)`` is not a safe read here and never was: a judge adapter that
    returned the *string* ``"INCORRECT"`` would coerce to ``True`` and be recorded
    as a correct answer, while ``None`` would coerce to ``False`` and be recorded
    as a wrong one. Both then travel into M1's gate and the AG tripwire as
    measurements. ``pipeline.build_judge`` refuses the same coercion for exactly
    this reason; the durable judging phase does not go through it, so it has to
    make the check itself.
    """
    if verdict is True or verdict is False:
        return verdict
    raise JudgeVerdictError(
        f"the judge returned {type(verdict).__name__} ({verdict!r}) for arm "
        f"{arm!r} question {question_id!r}; a verdict must be a bool. This is not "
        "coerced: a truthy 'INCORRECT' would be recorded as a correct answer and "
        "a None as a wrong one, and both would enter M1 as measurements."
    )


def judge_identity(judge_client: Any) -> dict[str, Any]:
    """The judge fields stamped onto every verdict row.

    A verdict row carrying only a payload digest and a boolean can be replayed by
    *any* judge that saw the same payload — including a different model, or the
    pinned model reached a different way — and the results would still attribute
    it to the pinned judge. Recording the identity next to the verdict is what
    makes that attributable.

    A client that cannot name its model raises rather than stamping ``null``:
    nulls would compare equal to each other on resume, so the check would pass
    while attributing the verdicts to nothing at all — the failure this record
    exists to prevent, wearing the shape of a green check.
    """
    pin = getattr(judge_client, "pin", None)
    model = getattr(pin, "model", None)
    if not isinstance(model, str) or not model.strip():
        raise UnrecordedPinsError(
            f"{type(judge_client).__name__} exposes no judge pin, so its verdicts "
            "could not record which model produced them. Give the judge client a "
            "'pin' (a ModelPin) — every verdict has to be attributable to a model "
            "for the results to be auditable against preregister.json."
        )
    return {
        "judge_model": model,
        "judge_endpoint": getattr(pin, "endpoint", None),
        "judge_prompt_via": getattr(judge_client, "prompt_via", None),
    }


def verify_verdict_judge(row: Mapping[str, Any], expected: Mapping[str, Any]) -> None:
    """Refuse verdicts produced by a judge other than the one now configured."""
    actual = {key: row.get(key) for key in expected}
    if actual != dict(expected):
        raise VerdictReplayError(
            f"the recorded verdict for arm {row.get('arm')!r} question "
            f"{row.get('question_id')!r} was produced by {actual}, but this run is "
            f"configured with {dict(expected)}. Verdicts from two judges in one "
            "blind batch would be reported under a single judge pin; start a new "
            "--out-dir, or restore the judge the batch was begun with."
        )


def verify_verdict_prompts(
    rows: Sequence[Mapping[str, Any]],
    specs: Sequence[QuestionSpec],
    phase: AnswerPhase,
    judge_client: Any,
) -> None:
    """Refuse recorded verdicts whose prompt is not the one this judge would send.

    The judge identity fields say *which model* answered; this says *what it was
    asked*. They are different guarantees: the same model handed a different
    rubric — a wrapper that prepends an instruction, a rubric edited between
    sessions — produces verdicts that are not comparable with the ones already on
    disk, while every model/endpoint field still matches.

    The expected digest is re-derived through the client's own
    ``render_prompt``, which is the same method
    :meth:`clients.JudgeClient.verdict_with_prompt` sends, so this compares the
    recorded ask against the ask this run would make rather than against a copy
    of the template kept here.
    """
    by_question = {spec.question_id: spec for spec in specs}
    for row in rows:
        recorded = row.get("prompt_sha256")
        spec = by_question.get(row.get("question_id"))
        answer = phase.rows.get((row.get("question_id"), row.get("arm")))
        if spec is None or answer is None:
            # Absent answers are the blind-batch completeness problem, reported
            # by MissingAnswerError with a better message than this check could.
            continue
        expected = _sha256_text(
            judge_client.render_prompt(spec.question, spec.gold, answer["prediction"])
        )
        if recorded != expected:
            raise VerdictReplayError(
                f"the verdict recorded for arm {row.get('arm')!r} question "
                f"{row.get('question_id')!r} was made against prompt "
                f"{recorded} but this run would send {expected}. The judge is "
                "being asked a different question than the one already scored, so "
                "the two halves of the batch are not comparable; start a new "
                "--out-dir, or restore the prompt the batch was begun with."
            )


def verify_verdict_prefix(
    rows: Sequence[Mapping[str, Any]],
    order: Sequence[BlindSlot],
    specs: Sequence[QuestionSpec],
) -> None:
    """Require the recorded verdicts to be exactly positions 0..k-1 of the shuffle.

    Keying resume on ``(arm, question_id)`` alone would let a file with a *hole* —
    a missing middle verdict, however it arose — resume by judging that one slot
    last, out of its pinned position. The replay pass would then still accept the
    stream, because every payload digest matches its own row. Requiring the
    recorded rows to be a strict prefix of the recomputed order is what makes the
    blind batch's ordering a checked property of the durable file rather than of
    the process that happened to write it.
    """
    if not rows:
        return
    positions = [row.get("batch_position") for row in rows]
    expected = list(range(len(rows)))
    if sorted(position for position in positions if isinstance(position, int)) != expected:
        missing = sorted(set(expected) - {p for p in positions if isinstance(p, int)})
        raise VerdictReplayError(
            f"the recorded verdicts are not a prefix of the pinned blind batch: "
            f"{len(rows)} rows should occupy positions 0..{len(rows) - 1} but "
            f"{missing or 'duplicate/absent positions'} are missing. Resuming would "
            "judge the gap out of its pinned position, so the batch order would no "
            "longer be the one the seed fixes (design doc §6.1 guard 1)."
        )

    by_position = {row["batch_position"]: row for row in rows}
    for position in expected:
        row = by_position[position]
        slot = order[position]
        spec = specs[slot.question_index]
        if (row.get("arm"), row.get("question_id")) != (slot.arm, spec.question_id):
            raise VerdictReplayError(
                f"the verdict recorded at batch position {position} is arm "
                f"{row.get('arm')!r} question {row.get('question_id')!r}, but the "
                f"pinned shuffle puts arm {slot.arm!r} question "
                f"{spec.question_id!r} there. The durable stream and the canonical "
                "order disagree."
            )


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
        return strict_verdict(
            row["verdict"], arm=slot.arm, question_id=spec.question_id
        )

    return judge


# ---------------------------------------------------------------------------
# Phase 3 — metrics
# ---------------------------------------------------------------------------


def _gate_number(text: str, pattern: str, metric: str, path: Path) -> float:
    """Pull one frozen number out of a pinned gate string.

    The §4 thresholds are prose in ``preregister.json`` and are parsed there
    rather than re-declared in Python, exactly as the metric modules do, so a
    pinned value and the code enforcing it cannot drift apart. A parse failure
    raises :class:`GatePinError` rather than falling back to a constant: scoring
    a run against a gate the pre-registration does not carry is worse than
    stopping (design doc §6.1 guard 3).
    """
    match = re.search(pattern, text)
    if match is None:
        raise GatePinError(
            f"{path}: pinned {metric} gate {text!r} does not carry a number "
            f"matching {pattern!r}. This harness enforces the pinned shape and "
            "will not guess a threshold; re-read the pin (design doc §4) and "
            "update the parser deliberately."
        )
    return float(match.group(1))


def _pinned_number(
    record: Mapping[str, Any], key: str, metric: str, path: Path
) -> float:
    """Read one required numeric knob out of a pinned metric record.

    Sibling of :func:`_gate_number` and for the same reason: a knob the
    pre-registration does not carry may not be defaulted in code. ``alpha`` and
    the AG tier thresholds are pinned decision boundaries — silently substituting
    an in-code constant would score the run against a rule the pre-registration
    never froze, which is precisely what design doc §6.1 guard 3 forbids.
    """
    value = record.get(key)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise GatePinError(
            f"{path}: pinned {metric} {key!r} must be a number, got "
            f"{type(value).__name__} ({value!r}). This harness will not default a "
            "pinned threshold."
        )
    # ``json.loads`` accepts the JavaScript literals NaN / Infinity, and a
    # non-finite threshold silently inverts the rule it encodes rather than
    # failing: every comparison against NaN is False, so an ``alpha`` of NaN
    # makes ``p_value >= alpha`` false for every input and M3 reads as *always*
    # readable — the opposite of the pre-registered INCONCLUSIVE guard.
    if not math.isfinite(value):
        raise GatePinError(
            f"{path}: pinned {metric} {key!r} is {value!r}, which is not a finite "
            "number. Every comparison against a NaN is false, so a non-finite "
            "threshold does not merely misread — it silently inverts the rule it "
            "is supposed to enforce."
        )
    return float(value)


def _pinned_int(
    record: Mapping[str, Any], key: str, metric: str, path: Path
) -> int:
    """Read one required integer knob (a denominator) out of a pinned record.

    ``bool`` is rejected explicitly because ``isinstance(True, int)`` is true in
    Python, so a pin carrying ``true`` where a denominator belongs would
    otherwise be read as the number 1.
    """
    value = record.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        raise GatePinError(
            f"{path}: pinned {metric} {key!r} must be an int, got "
            f"{type(value).__name__} ({value!r})."
        )
    return value


def m2_gate_verdict(
    f1: Mapping[str, float], path: Path = PREREGISTER_PATH
) -> dict[str, Any]:
    """The pinned M2 gate: ``C.F1 > A.F1 + 0.10 AND C.F1 >= B.F1 - epsilon``.

    Both arms of the conjunction are reported separately, because §8's M2-fail
    row diagnoses them differently: failing the first means dedup is not working
    at all, while failing the second means the naive control beats the machinery
    and points at the identity projection.
    """
    record = preregistered_metric("M2", path)
    gate = str(record.get("gate", ""))
    margin = _gate_number(gate, r"A\.F1\s*\+\s*([\d.]+)", "M2", path)
    epsilon = _pinned_number(record, "epsilon", "M2", path)

    missing = sorted({"A", "B", "C"} - set(f1))
    if missing:
        raise MissingArmError(
            f"M2's pinned gate names arms A, B and C; {missing} are absent from "
            f"{sorted(f1)}. Every §4 gate is a comparison."
        )

    clears_floor = f1["C"] > f1["A"] + margin
    holds_control = f1["C"] >= f1["B"] - float(epsilon)
    return {
        "gate": gate,
        "margin": margin,
        "epsilon": float(epsilon),
        "clears_a_plus_margin": clears_floor,
        "not_below_b_minus_epsilon": holds_control,
        "verdict": clears_floor and holds_control,
    }


def m3_gate_verdict(
    rate: Mapping[str, float],
    readability: Mapping[str, Any],
    n_scored: int,
    path: Path = PREREGISTER_PATH,
) -> dict[str, Any]:
    """The pinned M3 gate ``C <= 0.5 * A``, read only when the sign test allows.

    The pre-registration is explicit that the ratio is scale-free and therefore
    says nothing about whether a verdict is *readable*: at ``p >= alpha`` over the
    paired A-only / C-only discordances, M3 is **INCONCLUSIVE — neither pass nor
    fail** — and must neither fire §8's state-machine demotion nor count toward
    §8's All-pass row. That is a pre-registered rule, so it is enforced here
    rather than left to whoever reads the numbers.
    """
    record = preregistered_metric("M3", path)
    gate = str(record.get("gate", ""))
    ratio = _gate_number(gate, r"C\s*<=\s*([\d.]+)\s*\*\s*A", "M3", path)
    pinned_n = _pinned_int(record, "N", "M3", path)

    missing = sorted({"A", "C"} - set(rate))
    if missing:
        raise MissingArmError(
            f"M3's pinned gate names arms A and C; {missing} are absent from "
            f"{sorted(rate)}."
        )

    inconclusive = bool(readability.get("inconclusive"))
    n_matches_pin = n_scored == pinned_n
    if inconclusive:
        status, verdict = "INCONCLUSIVE", None
    elif not n_matches_pin:
        status, verdict = "UNDERPOWERED", None
    else:
        verdict = rate["C"] <= ratio * rate["A"]
        status = "PASS" if verdict else "FAIL"

    return {
        "gate": gate,
        "ratio": ratio,
        "n": n_scored,
        "pinned_n": pinned_n,
        "n_matches_pin": n_matches_pin,
        "status": status,
        "verdict": verdict,
        "fires_s8_demotion": status == "FAIL",
        "counts_toward_all_pass": status == "PASS",
    }


@dataclass(frozen=True)
class M3Denominator:
    """M3's two question sets, which are deliberately not the same set.

    ``label_ids`` is the **structural** knowledge-update pool minus its
    abstention variants — the keyset the labels file must cover exactly, so that
    a question carrying no old value is visible as an empty list rather than
    absent. ``scored_ids`` is the **pinned denominator**: those same questions
    minus the ones the labeling pass found carry no old→new update at all.

    Keeping them apart is the point. Validating the label file against the wider
    set keeps the exclusion auditable in the data; scoring against the narrower
    one keeps 6 structurally uncontaminable questions from deflating both arms
    equally and biasing the pinned ``C <= 0.5 * A`` ratio toward FAIL.
    """

    label_ids: tuple[str, ...]
    no_update_ids: tuple[str, ...]
    scored_ids: tuple[str, ...]
    pinned_n: int

    @property
    def matches_pin(self) -> bool:
        """True when the derivation lands on the pre-registered denominator."""
        return len(self.scored_ids) == self.pinned_n


def m3_denominator(
    split_manifest: Mapping[str, Any], path: Path = PREREGISTER_PATH
) -> M3Denominator:
    """Derive M3's label keyset and its pinned scoring denominator.

    The ``_abs`` exclusion is derived **structurally** from the rule the pin
    states ("the 6 KU ``_abs`` variants ... encode no old→new update"), never by
    transcribing ids, because a transcribed list would silently rot if the split
    moved. The no-update exclusion cannot be derived that way — it is an
    empirical finding about six specific transcripts — so it is *read* from the
    pre-registration's own ``no_update_exclusions`` list and never hardcoded
    here.
    """
    # The pin is read FIRST and strictly. Deriving the ids first would let a
    # label-set mismatch raise before an unreadable ``N`` was ever noticed, so
    # the louder error would mask the one that says the pre-registration itself
    # cannot be read.
    record = preregistered_metric("M3", path)
    pinned_n = _pinned_int(record, "N", "M3", path)
    excluded = record.get("no_update_exclusions")
    if not isinstance(excluded, list) or not all(
        isinstance(qid, str) for qid in excluded
    ):
        raise GatePinError(
            f"{path}: pinned M3 'no_update_exclusions' must be a list of question "
            f"ids, got {excluded!r}. The questions carrying no old->new update are "
            "an empirical finding recorded in the pre-registration; this harness "
            "will not re-derive or default them."
        )

    ku = [str(qid) for qid in split_manifest.get("question_ids", {}).get("ku", [])]
    label_ids = tuple(sorted(qid for qid in ku if not qid.endswith("_abs")))
    no_update = tuple(sorted(excluded))
    return M3Denominator(
        label_ids=label_ids,
        no_update_ids=no_update,
        scored_ids=tuple(qid for qid in label_ids if qid not in set(no_update)),
        pinned_n=pinned_n,
    )


class M3LabelError(ValueError):
    """The supplied stale-value labels are not the pinned M3 sample.

    The label file's keys *are* M3's denominator, so an unchecked file silently
    redefines the metric: a cherry-picked subset would report an official-looking
    contamination rate over whichever questions the labeller found convenient,
    and an over-broad one would score questions the pin excludes. Neither is
    detectable from the resulting number.
    """


def validate_m3_labels(
    labels: Mapping[str, Sequence[str]], expected_ids: Sequence[str]
) -> None:
    """Require the label keyset to be exactly M3's pinned denominator."""
    extra = sorted(set(labels) - set(expected_ids))
    missing = sorted(set(expected_ids) - set(labels))
    if extra or missing:
        raise M3LabelError(
            "the --m3-labels keyset is not M3's pinned denominator "
            f"({len(expected_ids)} non-abstention knowledge-update questions). "
            f"Missing {len(missing)}: {missing[:8]}. Unexpected {len(extra)}: "
            f"{extra[:8]}. The label file's keys define what M3 measures, so a "
            "partial or over-broad file would report a rate over a sample the "
            "pre-registration does not carry."
        )


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
    test = record.get("inconclusive_test")
    if not isinstance(test, dict):
        raise GatePinError(
            f"{path}: pinned M3 carries no 'inconclusive_test' record, so the "
            "readability rule that decides whether the ratio may be read at all "
            "cannot be applied. This harness will not substitute one."
        )
    alpha = _pinned_number(test, "alpha", "M3.inconclusive_test", path)

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
    answers: Mapping[tuple[str, str], Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """The AG bias-guard tripwire and the response tier its breach mandates.

    Every discordant question is enumerated unconditionally. The pinned Tier 1
    response requires exactly that enumeration — a net advantage does not imply a
    single differing question — and at N = 20 producing it costs nothing, so the
    results carry the evidence whether or not the tripwire fired.
    """
    answers = answers or {}
    record = preregistered_metric("AG", path)
    response = record.get("breach_response")
    if not isinstance(response, dict):
        raise GatePinError(
            f"{path}: pinned AG carries no 'breach_response' record, so the tiered "
            "response the tripwire mandates cannot be read."
        )
    # The tier boundaries decide whether M1/M3 may be trusted, so they are read
    # strictly for the same reason the gates are: an in-code default would let a
    # run answer a question the pre-registration never froze.
    tier1 = _pinned_number(response, "tier1_pp", "AG.breach_response", path)
    tier2 = _pinned_number(response, "tier2_pp", "AG.breach_response", path)
    tripwire_pp = _gate_number(
        str(record.get("gate", "")), r"([+-]?\d+(?:\.\d+)?)\s*pp", "AG", path
    )

    treatment = [verdicts["C"][index] for index in indices]
    control = [verdicts["B"][index] for index in indices]
    n = len(indices)
    delta_pp = 100.0 * (sum(treatment) - sum(control)) / n if n else 0.0

    discordant = [
        {
            "question_id": question_ids[index],
            "winner": "C" if verdicts["C"][index] else "B",
            **context_diff(question_ids[index], answers),
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
        "tripwire_pp": tripwire_pp,
        "tripwire_breached": delta_pp > tripwire_pp,
        "n": n,
        "correct": {"B": sum(control), "C": sum(treatment)},
        "delta_pp": delta_pp,
        "tier1_pp": tier1,
        "tier2_pp": tier2,
        "response_tier": tier,
        "discordant": discordant,
        "mandated_response": response.get(tier) if tier != "none" else None,
    }


def context_diff(
    question_id: str, answers: Mapping[tuple[str, str], Mapping[str, Any]]
) -> dict[str, Any]:
    """Arm B's retrieved context against Arm C's, for one discordant question.

    The pinned Tier 1 response is not "list the discordant questions" — it is to
    *diff each one's Arm B vs Arm C retrieved context and record all findings in
    the results*. That diff is what could show arm identity leaking into the
    pipeline, so the ids and the bodies both travel: ids alone cannot be read
    without re-deriving the claims, and by then the run is over.
    """
    b_row = answers.get((question_id, "B"), {})
    c_row = answers.get((question_id, "C"), {})
    b_ids = list(b_row.get("retrieved_ids", []))
    c_ids = list(c_row.get("retrieved_ids", []))
    b_text = dict(zip(b_ids, b_row.get("retrieved_texts", [])))
    c_text = dict(zip(c_ids, c_row.get("retrieved_texts", [])))

    b_only = [claim_id for claim_id in b_ids if claim_id not in set(c_ids)]
    c_only = [claim_id for claim_id in c_ids if claim_id not in set(b_ids)]
    return {
        "prediction": {"B": b_row.get("prediction"), "C": c_row.get("prediction")},
        "retrieved_ids": {"B": b_ids, "C": c_ids},
        "context_only_in_b": [
            {"id": claim_id, "text": b_text.get(claim_id)} for claim_id in b_only
        ],
        "context_only_in_c": [
            {"id": claim_id, "text": c_text.get(claim_id)} for claim_id in c_only
        ],
        "context_identical": b_ids == c_ids,
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


def digest_bytes(raw: bytes) -> str:
    """Hex SHA-256 of ``raw`` with CRLF normalized to LF.

    The convention the pre-registration's own ``design_doc_sha256`` and
    ``labels_sha256`` use, so a pin holds on a Windows CRLF working tree and a
    Linux LF checkout of the same committed content alike. Raw-byte hashing would
    make the pinned digest fail on exactly one of the two platforms.

    Takes bytes rather than a path so a caller can hash *the same read* it will
    use — see :func:`resolve_m3_labels`.
    """
    return hashlib.sha256(raw.replace(b"\r\n", b"\n")).hexdigest()


def normalized_digest(path: Path) -> str:
    """Hex SHA-256 of a file, CRLF-normalized. Convenience over :func:`digest_bytes`."""
    return digest_bytes(path.read_bytes())


def parse_m3_labels(raw: bytes, source: Path) -> dict[str, list[str]]:
    """Parse a labels payload, raising :class:`M3LabelError` on anything unusable.

    Parsed from bytes already in hand rather than from a path, so the labels a run
    scores are provably the ones whose digest it verified.
    """
    try:
        record = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise M3LabelError(f"{source}: labels are not valid UTF-8 JSON ({exc})") from exc
    if not isinstance(record, dict):
        raise M3LabelError(
            f"{source}: labels must be a JSON object mapping question_id -> "
            f"[old value, ...], got {type(record).__name__}"
        )
    labels: dict[str, list[str]] = {}
    for qid, values in record.items():
        if not isinstance(values, list) or not all(
            isinstance(value, str) for value in values
        ):
            raise M3LabelError(
                f"{source}: labels for {qid!r} must be a list of strings, got "
                f"{values!r}"
            )
        labels[str(qid)] = list(values)
    return labels


@dataclass(frozen=True)
class M3LabelSource:
    """The labels a run will score M3 from — as a verified **snapshot**.

    ``labels`` is parsed from the very bytes that were hashed, and is the only
    thing scoring ever reads. The path is never re-opened after verification,
    which closes the window where a file modified, repointed or deleted between
    the check and the scoring pass would let a run score one label set while its
    manifest attested another.

    ``matches_preregistered`` is decided by **digest**, not by whether an override
    path was passed: pointing ``--m3-labels`` at the pinned file itself is not a
    deviation, and pointing it anywhere else is one even if the keys line up.
    """

    path: Path
    sha256: str
    labels: dict[str, list[str]]
    matches_preregistered: bool
    pinned_file: str | None
    pinned_sha256: str | None
    deviation_acknowledged: bool

    def as_record(self) -> dict[str, Any]:
        """The label-provenance fields a run records."""
        return {
            "m3_labels_path": str(self.path),
            "m3_labels_sha256": self.sha256,
            "m3_labels_match_preregistered": self.matches_preregistered,
            "m3_labels_pinned_file": self.pinned_file,
            "m3_labels_deviation_acknowledged": self.deviation_acknowledged,
        }


def resolve_m3_labels(
    cfg: RealRunConfig, path: Path = PREREGISTER_PATH
) -> M3LabelSource | None:
    """Resolve, and *enforce*, the label source M3 will be scored from.

    With a label pin in the pre-registration this is no longer an operator
    choice. The labels file **is** M3's sample — its keys are the denominator and
    its values are what "contaminated" means — so a run that scored some other
    JSON, or quietly scored nothing because a flag was omitted, would publish an
    M3 the pre-registration does not describe. Both were possible before this
    check existed.

    The pinned file is resolved repo-relative and its digest verified *before*
    any scoring. A missing file or a digest mismatch is a stop
    (:class:`M3LabelError`), never a downgrade to "no M3".

    An operator file is still reachable, on the same terms the judge deviation
    uses: it must be acknowledged explicitly, and the run records the deviant
    path, its digest and ``m3_labels_match_preregistered: false`` in both the
    manifest and the metrics, so a deviant run can never read as the pinned one.

    Returns ``None`` only when the pre-registration carries no label pin *and* no
    override was supplied — the pre-pin configuration, where M3 genuinely cannot
    be scored.
    """
    record = preregistered_metric("M3", path)
    pinned_file, pinned_sha = _read_label_pin(record, path)

    if pinned_file is None:
        # The legacy, pre-pin configuration: no label pin at all.
        if cfg.m3_labels is None:
            return None
        return _snapshot_labels(
            Path(cfg.m3_labels),
            matches_preregistered=False,
            pinned_file=None,
            pinned_sha256=None,
            acknowledged=cfg.m3_labels_deviation_ack,
        )

    if cfg.m3_labels is not None:
        # The operator override may point anywhere: naming a file outside the
        # repository is its entire purpose, and it is already gated by the
        # deviation acknowledgement below.
        resolved = Path(cfg.m3_labels)
    else:
        resolved = _resolve_pinned_labels(pinned_file, path)

    if not resolved.is_file():
        raise M3LabelError(
            f"the pinned M3 labels file {pinned_file!r} was not found at "
            f"{resolved}. M3's sample is pinned in preregister.json "
            "(metrics.M3.labels_file / labels_sha256); a run cannot score M3 "
            "without it, and will not silently report no M3 instead."
        )

    source = _snapshot_labels(
        resolved,
        matches_preregistered=False,
        pinned_file=pinned_file,
        pinned_sha256=pinned_sha,
        acknowledged=cfg.m3_labels_deviation_ack,
    )
    matches = source.sha256 == pinned_sha
    if not matches and not cfg.m3_labels_deviation_ack:
        raise M3LabelError(
            f"the M3 labels at {resolved} do not match the pre-registered "
            f"labels file.\n  expected sha256 = {pinned_sha}\n  actual   sha256 = "
            f"{source.sha256}\nThe labels file IS M3's sample - its keys are the "
            "denominator and its values define contamination - so scoring a "
            "different one would publish an M3 the pre-registration does not "
            "describe. Restore the pinned file, or pass "
            "--m3-labels-deviation-ack to record the deviation in the results."
        )
    return replace(source, matches_preregistered=matches)


def _resolve_pinned_labels(pinned_file: str, path: Path) -> Path:
    """Resolve the pinned labels path, requiring it to stay inside the repository.

    ``labels_file`` is documented and recorded as repo-relative, so a value that
    escapes the repository is a garbled pin. Checking it here is pin hygiene of
    the same kind applied to the judge command and the endpoint scheme: it puts
    the error on the pre-registration, where the defect is, instead of letting the
    run open some unrelated file and then report a confusing digest mismatch
    against it.

    This is not a sandbox and does not pretend to be one — ``preregister.json`` is
    git-tracked source, so anyone able to write it can write this module — but a
    pin that says "repo-relative" should mean it.
    """
    root = REPO_ROOT.resolve()
    candidate = (root / pinned_file).resolve()
    if candidate != root and root not in candidate.parents:
        raise M3LabelError(
            f"{path}: pinned M3 'labels_file' {pinned_file!r} resolves to "
            f"{candidate}, which is outside the repository. The label pin is "
            "recorded as a repo-relative path; a value that escapes the "
            "repository is a malformed pin, not a location."
        )
    return candidate


def _snapshot_labels(
    path: Path,
    *,
    matches_preregistered: bool,
    pinned_file: str | None,
    pinned_sha256: str | None,
    acknowledged: bool,
) -> M3LabelSource:
    """Read the labels file ONCE, then hash and parse that same read.

    One read is the whole point. Hashing the path and later re-opening it to
    parse leaves a window in which the file can change between the two, so the
    run would score bytes it never verified while its manifest attested the
    digest of bytes it no longer holds.
    """
    raw = path.read_bytes()
    return M3LabelSource(
        path=path,
        sha256=digest_bytes(raw),
        labels=parse_m3_labels(raw, path),
        matches_preregistered=matches_preregistered,
        pinned_file=pinned_file,
        pinned_sha256=pinned_sha256,
        deviation_acknowledged=acknowledged,
    )


def _read_label_pin(
    record: Mapping[str, Any], path: Path
) -> tuple[str | None, str | None]:
    """Read the label pin, failing CLOSED on anything partial or malformed.

    The legacy no-pin path is legal only when ``labels_file`` and
    ``labels_sha256`` are *both entirely absent* — the genuine pre-pin
    configuration. A half-written or mistyped pin is not a configuration without
    a pin, and treating it as one would silently reopen exactly the hole the pin
    was added to close: M3 skipped for a missing flag, or an override accepted
    with no acknowledgement.
    """
    has_file = "labels_file" in record
    has_sha = "labels_sha256" in record
    if not has_file and not has_sha:
        return None, None

    if not has_file or not has_sha:
        missing = "labels_file" if not has_file else "labels_sha256"
        present = "labels_sha256" if not has_file else "labels_file"
        raise GatePinError(
            f"{path}: pinned M3 carries {present!r} but not {missing!r}. A label "
            "pin is both fields or neither; half a pin cannot be verified, and "
            "this harness will not fall back to the unpinned path to make it "
            "usable."
        )

    pinned_file = record["labels_file"]
    pinned_sha = record["labels_sha256"]
    if not isinstance(pinned_file, str) or not pinned_file.strip():
        raise GatePinError(
            f"{path}: pinned M3 'labels_file' must be a non-empty string, got "
            f"{pinned_file!r}."
        )
    if (
        not isinstance(pinned_sha, str)
        or len(pinned_sha) != 64
        or pinned_sha != pinned_sha.lower()
        or any(character not in "0123456789abcdef" for character in pinned_sha)
    ):
        raise GatePinError(
            f"{path}: pinned M3 'labels_sha256' must be 64 lowercase hex "
            f"characters, got {pinned_sha!r}. Reported as a malformed pin rather "
            "than left to surface later as a digest mismatch, which would blame "
            "the labels file for a defect in the pre-registration."
        )
    return pinned_file, pinned_sha


def compute_metrics(
    specs: Sequence[QuestionSpec],
    cfg: RealRunConfig,
    *,
    scored: Mapping[str, ArmResult],
    phase: AnswerPhase,
    claim_rows: Sequence[Mapping[str, Any]],
    split_manifest: Mapping[str, Any],
    label_source: M3LabelSource | None,
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
    # Ground truth and predictions must live in the SAME universe. Each arm's
    # store is per-question, so a labeled pair whose two claims come from
    # different questions is unreachable for every arm by construction: pooling
    # the ground truth across questions and scoring it against per-question
    # clusters would charge all three arms an identical mass of false negatives
    # that measures the harness's own scoping, not the memory layer. M2 is
    # therefore scored on within-question pairs, and the cross-question pairs are
    # reported alongside rather than dropped — they are exactly the linker
    # lineage-fragmentation signal design doc §8's M2-fail row must inspect
    # before blaming the identity projection.
    claims_by_question = {
        row["question_id"]: [
            Claim(id=claim["id"], text=claim["text"], metadata=claim["metadata"])
            for claim in row["claims"]
        ]
        for row in claim_rows
    }
    per_question = [
        labeled_pairs.labeled_pairs_from_claims(claims)
        for claims in claims_by_question.values()
    ]
    scored_pairs: set[frozenset] = set()
    within_lineage: set[frozenset] = set()
    for labeled_set in per_question:
        scored_pairs |= set(labeled_set.pairs)
        within_lineage |= set(labeled_set.within_lineage)

    pooled = labeled_pairs.labeled_pairs_from_claims(
        claim for claims in claims_by_question.values() for claim in claims
    )
    cross_question = set(pooled.pairs) - scored_pairs

    arm_clusters: dict[str, list[list[str]]] = {arm: [] for arm in ARM_STORES}
    for row in answer_rows:
        arm_clusters[row["arm"]].extend(row["clusters"])
    m2_scores = {
        arm: m2_dedup.score_arm(scored_pairs, clusters)
        for arm, clusters in sorted(arm_clusters.items())
    }
    f1 = {arm: score.f1 for arm, score in m2_scores.items()}
    metrics["m2"] = {
        "f1": f1,
        "precision": {arm: score.precision for arm, score in m2_scores.items()},
        "recall": {arm: score.recall for arm, score in m2_scores.items()},
        "scored_pairs": len(scored_pairs),
        "scored_within_lineage": len(within_lineage),
        "scored_cross_lineage": len(scored_pairs) - len(within_lineage),
        "cross_question_pairs_excluded": len(cross_question),
        "pooled_labeled_pairs": pooled.as_record(),
        "labeled_pairs_derivation": pooled.derivation,
        "scoring_universe": (
            "within-question exact restatements only: each arm's store is "
            "per-question, so a cross-question pair is unreachable for every arm "
            "and scoring it would add an arm-independent false-negative mass. The "
            "excluded count is reported for the §8 M2-fail lineage-fragmentation "
            "check."
        ),
        "gate": m2_gate_verdict(f1, path),
    }

    # -- M3 ---------------------------------------------------------------
    # The verified snapshot, never a re-read of the path: between verification
    # and here the file may have been modified, repointed or deleted, and a run
    # that scored those bytes while its manifest attested the earlier digest
    # would be unattributable.
    labels = label_source.labels if label_source else {}
    if label_source and labels:
        denominator = m3_denominator(split_manifest, path)
        validate_m3_labels(labels, denominator.label_ids)
        # Scored over the pinned denominator, NOT over every labeled key: the
        # 6 no-update questions carry no stale value any arm could surface, so
        # including them would add the same uncontaminable mass to every arm and
        # push the C <= 0.5 * A ratio toward 1.
        scored_ids = set(denominator.scored_ids)
        contexts: dict[str, dict[str, list[str]]] = {arm: {} for arm in ARM_STORES}
        for row in answer_rows:
            if row["question_id"] in scored_ids:
                contexts[row["arm"]][row["question_id"]] = row["retrieved_texts"]
        scores = {
            arm: m3_contamination.contamination_rate(per_arm, labels)
            for arm, per_arm in sorted(contexts.items())
        }
        contaminated = {arm: set(score.contaminated_ids) for arm, score in scores.items()}
        scored_here = sorted(scored_ids & set(question_ids))
        readability = m3_readability(contaminated, scored_here, path)
        rate = {arm: score.rate for arm, score in scores.items()}
        metrics["m3"] = {
            "rate": rate,
            "contaminated": {arm: score.contaminated for arm, score in scores.items()},
            "total": {arm: score.total for arm, score in scores.items()},
            "readability": readability,
            "gate": m3_gate_verdict(rate, readability, len(scored_here), path),
            "label_keyset_ids": len(denominator.label_ids),
            "denominator_ids": len(denominator.scored_ids),
            "denominator_matches_pin": denominator.matches_pin,
            "no_update_excluded": list(denominator.no_update_ids),
            "matching": preregistered_metric("M3", path).get("matching"),
            "labels_source": str(label_source.path),
            "labels_sha256": label_source.sha256,
            "labels_match_preregistered": label_source.matches_preregistered,
            "labels_deviation_acknowledged": label_source.deviation_acknowledged,
        }
    elif label_source:
        # A resolved-but-empty label file. Not reachable with the pinned file
        # (66 of its 72 keys carry values), so this means an operator file that
        # labels nothing — reported as a stop rather than as a zero rate.
        metrics["m3"] = None
        metrics["m3_reason"] = (
            f"the labels file at {label_source.path} carries no values, so there "
            "is nothing for M3 to detect. A rate of 0.0 from an empty label set "
            "would read as 'no arm surfaced a stale value' rather than 'nothing "
            "was looked for'."
        )
    else:
        metrics["m3"] = None
        metrics["m3_reason"] = (
            "this pre-registration carries no M3 label pin "
            "(metrics.M3.labels_file / labels_sha256), and no override was "
            "supplied. The corpus ships no old-value annotation and this harness "
            "will not derive one from the shared linker's supersedes edges, "
            "because those are the very edges Arm C acts on: M3 would then score "
            "Arm C against its own mechanism. Choosing a label source is a "
            "maintainer decision under design doc §6.3."
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
            verdicts, adv_indices, question_ids, path, answers=phase.rows
        )
    else:
        metrics["ag"] = None
        metrics["ag_reason"] = (
            "no adversarial questions in this slice; the AG tripwire is defined "
            "over the 20-question adversarial set (design doc §6 guard 4)."
        )

    # -- M1/M3 trust standing ---------------------------------------------
    # Design doc §6 guard 4 makes the Tier 2 leakage investigation a
    # *precondition* on trusting M1 and M3, not a note to read afterwards. A run
    # that finished cleanly and printed its M1 number would be read as a result,
    # so the blocked state is recorded as a machine-readable flag next to the
    # numbers it blocks rather than left to the reader to remember.
    ag = metrics["ag"]
    if ag and ag["response_tier"] == "tier2":
        metrics["m1_m3_trust"] = "blocked_pending_ag_investigation"
        metrics["m1_m3_trust_reason"] = (
            f"AG C-B is {ag['delta_pp']}pp, at or above the pinned Tier 2 "
            f"threshold of {ag['tier2_pp']}pp. Design doc §6 guard 4 requires the "
            "full leakage investigation to be COMPLETED before M1 and M3 are "
            "trusted: at N=20 an adversarial gain this large means the machinery "
            "is winning where it structurally cannot help, which points at arm "
            "identity leaking into the pipeline. The M1/M3 numbers below are "
            "reported but must not be read as results until that investigation "
            "closes. Every discordant question's Arm B vs Arm C retrieved context "
            "is enumerated in metrics.ag.discordant."
        )
    else:
        metrics["m1_m3_trust"] = "ok"

    # -- linker recall ----------------------------------------------------
    metrics["linker"] = LinkerStats.total(
        LinkerStats(**row["linker"]) for row in claim_rows
    ).as_record()

    return metrics


# ---------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------


def default_client_factory(chat_pin: clients.ChatPin) -> Any:
    """Build the client the pinned endpoint's dialect calls for."""
    return clients.client_for(chat_pin)


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
            report[name] = {
                "model": pin.pin.model,
                "endpoint": pin.pin.endpoint,
                "error": str(exc),
            }
            errors.append(f"{name}: {exc}")
    try:
        report["judge"] = judge.preflight()
        # Whether the judge is the pre-registered one is exactly the thing a
        # preflight should surface before hours of judging, not after.
        report["judge"].update(
            {
                key: value
                for key, value in judge_standing(judge, cli_pin.pin).items()
                if key != "judge_pin"
            }
        )
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


# ---------------------------------------------------------------------------
# The extraction scheduler: questions concurrently, sessions never
# ---------------------------------------------------------------------------


class QuestionExtractionError(RuntimeError):
    """One or more questions failed to extract; the rest of the pass completed.

    Raised once, after the pass has drained, rather than at the moment of
    failure. A question already running when another one fails is allowed to
    finish: its rows are durable the moment they are written, so cutting it short
    would not un-spend the calls it had already made — it would only throw away
    the ones it had not yet recorded. What stops immediately is *submission*, so
    a dead endpoint costs one round of in-flight questions rather than the whole
    split.

    At the default one worker nothing is ever in flight beside the failing
    question, so this is precisely the old behaviour — the pass stops at the
    first failure, having attempted nothing after it — carrying a name that says
    which question it was.

    ``not_started`` names the questions that stop bought: the ones a re-run still
    has to get through, read off each outcome's ``started`` flag rather than
    asserted in the message beside them.
    """

    def __init__(
        self,
        failures: Mapping[str, BaseException],
        *,
        not_started: Sequence[str] = (),
    ) -> None:
        self.failures = dict(failures)
        # Which questions those were, not merely that there were some: it is the
        # list the re-run still has to get through, and it is read off the
        # outcomes' own ``started`` flag rather than asserted in this sentence.
        self.not_started = list(not_started)
        detail = "; ".join(
            f"{question_id}: {error!r}" for question_id, error in self.failures.items()
        )
        super().__init__(
            f"{len(self.failures)} question(s) failed to extract and "
            f"{len(self.not_started)} question(s) were never started, because "
            "submission stops at the first failure while every question already "
            "running is allowed to finish — so what they wrote is durable, "
            f"re-run to resume from it. Failures: {detail}. Never started: "
            f"{', '.join(self.not_started) or 'none'}"
        )


@dataclass
class QuestionExtraction:
    """What one question's extraction did, or why it did nothing."""

    question_id: str
    sessions_processed: int = 0
    sessions_extracted: int = 0
    calls: int = 0
    # Every session was already memoised, so the question was not walked at all.
    skipped: bool = False
    # False when the pass had already stopped — a failure elsewhere, or the
    # operator's Ctrl-C — and this question was therefore never begun. Not an
    # error of its own, and not work either. Read by :func:`extract_questions`,
    # which turns the false ones into the list a stopped pass reports
    # (:class:`QuestionExtractionError.not_started`): the questions a re-run
    # still has to get through.
    started: bool = True
    error: BaseException | None = None
    message: str = ""


def _extract_question(
    spec: QuestionSpec,
    *,
    position: int,
    total: int,
    cache: ExtractionCache,
    client: Any,
    pin: ModelPin,
    instrument: bool,
) -> QuestionExtraction:
    """Walk one question's sessions in pinned occurrence order, strictly serially.

    The unit of work the scheduler hands to a worker — and the reason the
    concurrency is *across* questions only. Vocabulary priming makes session k's
    prompt a function of the sessions before it in the same question, so two
    sessions of one question can never be in flight together; two different
    questions share nothing but the cache, whose lock is what makes that sharing
    safe.

    A question is skipped only when EVERY one of its sessions is memoised. A
    partially-extracted question is replayed from its first session, because the
    priming vocabulary for a pending session is derived from the ones before it —
    resuming into the middle would prime it from nothing and send a prompt the
    original run never sent.
    """
    label = f"  [{position}/{total}] {spec.question_id} ({spec.split}): "
    if all(
        cache.get(spec.question_id, session.id) is not None
        for session in spec.sessions
    ):
        return QuestionExtraction(
            question_id=spec.question_id,
            skipped=True,
            message=f"{label}{len(spec.sessions)} session(s) already cached, skipped",
        )

    extractor = RealExtractor(
        client=client,
        linker=SharedLinker(spec.question_id),
        cache=cache,
        question_id=spec.question_id,
        instrument=instrument,
    )
    outcome = QuestionExtraction(question_id=spec.question_id)
    for session in spec.sessions:
        # Counted from what the extractor actually did rather than from a miss
        # set computed before the question ran: `pending` is the miss set as it
        # looked then, and a session this pass has just memoised is no longer a
        # session it has to pay for.
        before = extractor.calls
        extractor(session, pin=pin)
        outcome.sessions_processed += 1
        if extractor.calls != before:
            outcome.sessions_extracted += 1
    outcome.calls = extractor.calls
    outcome.message = (
        f"{label}{len(spec.sessions)} sessions, {extractor.calls} extraction call(s)"
    )
    return outcome


@contextmanager
def _interrupt_at_question_boundary(
    halt: threading.Event, interrupted: threading.Event
) -> Iterator[None]:
    """Hold a Ctrl-C until the question in flight has been walked to its end.

    The wide path gets this for free and the default one did not, which is the
    asymmetry this closes. At more than one worker the interrupt lands in the
    main thread while it drains the pool: the queued questions are dropped, the
    running ones are allowed to finish, and only then does the exception leave.
    At one worker there is no pool and no such boundary — the question is being
    walked on this very thread, so the interrupt lands *inside* it and abandons
    it part-extracted, the one shape :class:`QuestionExtractionError` says never
    happens ("either walked to its end or not started").

    Abandoning it costs nothing already written — rows are durable the moment
    they are appended — but it costs the rest of the question, and a
    part-extracted question is replayed from its first session on the next pass
    (:func:`_extract_question`), so those sessions are walked again to prime the
    ones that were dropped. Stopping one question later leaves strictly more of
    the run done and strictly less of it to redo.

    So SIGINT sets the same ``halt`` a failure sets — submission stops at once —
    and the exception is raised by the caller after the drain. The **second**
    Ctrl-C is handed to :func:`signal.default_int_handler`, because an operator
    pressing it twice is no longer asking to stop tidily. Deliberately the
    interpreter's own handler rather than whichever one was in force on the way
    in: holding the first press is the point, and holding the second would be
    worse than never deferring at all — a parent that set ``SIG_IGN``, or a
    supervisor whose handler records and returns, would leave the operator
    waiting out the question in flight with nothing on the keyboard to cut it
    short. Restoring what was there before is the block's exit, below, and is a
    separate job.

    Outside the main thread there is nothing to install: CPython delivers SIGINT
    to the main thread only, so a pass being driven from a worker thread cannot
    receive one and the block is a no-op.
    """
    try:
        previous = signal.getsignal(signal.SIGINT)
    except (AttributeError, ValueError):  # pragma: no cover - no SIGINT at all
        previous = None
    # ``getsignal`` answers None when the handler was installed from C, and there
    # is then nothing this could put back afterwards. Leaving it alone is the
    # conservative reading: better to keep the old, blunt Ctrl-C than to take
    # over a handler belonging to something that never agreed to give it up.
    installed = previous is not None

    if installed:

        def _stop(_signum: int, _frame: Any) -> None:
            # The interpreter's own handler, NOT whatever was here before.
            # Putting `previous` back is the exit's job and is still done there;
            # doing it here as well conflated two things and got the second press
            # wrong wherever the previous handler does not raise. A parent that
            # set SIG_IGN, or a supervisor whose handler records and returns,
            # would have swallowed it — leaving the operator waiting out the
            # question in flight with nothing on the keyboard to cut it short.
            signal.signal(signal.SIGINT, signal.default_int_handler)
            interrupted.set()
            halt.set()

        try:
            signal.signal(signal.SIGINT, _stop)
        except ValueError:
            # Not the main thread. Nothing to defer, and nothing to restore.
            installed = False

    try:
        yield
    finally:
        if installed:
            signal.signal(signal.SIGINT, previous)


def extract_questions(
    specs: Sequence[QuestionSpec],
    *,
    cache: ExtractionCache,
    client: Any,
    pin: ModelPin,
    instrument: bool = False,
    workers: int = DEFAULT_EXTRACT_WORKERS,
    progress: Callable[[str], None] = lambda _message: None,
) -> list[QuestionExtraction]:
    """Extract every question, up to ``workers`` of them at a time.

    What ``workers`` buys is the only concurrency this harness has any business
    taking: extraction is one model call per session, the calls are seconds long,
    and the endpoint serves several at once. What it must not buy is a different
    *measurement*, so the invariant is drawn tightly:

    * **Serial within a question, concurrent across questions.** Enforced by the
      unit of work (:func:`_extract_question`), not by the scheduler — there is
      no arrangement of workers that can put two sessions of one question in
      flight together, because one call site walks them in a plain loop.
    * **The output is a function of the questions, not of the workers.** Results
      and progress lines are merged back in the order ``specs`` gives, so what a
      reader sees is the pinned question order at any ``workers``. The rows the
      cache holds afterwards are the same SET for any ``workers``; only the order
      they happen to land in the file, and the wall clock, differ.
    * **Content is untouched.** ``instrument`` is the caller's, not the
      scheduler's: a pass records what its calls cost, or does not, for the same
      reason at one worker as at eight.

    ``workers == 1`` builds no pool at all. The questions run inline on the
    calling thread, which is the pinned run's default and is the pass this module
    has always performed, down to the interleaving of progress lines with calls.

    Failures are recorded per question and re-raised together as
    :class:`QuestionExtractionError`; see its docstring for why the pass drains
    rather than aborting.
    """
    if workers < 1:
        raise ValueError(
            f"extract workers must be at least 1, got {workers}: the setting "
            "chooses how many QUESTIONS are extracted at once, and a pass that "
            "extracts none of them is not a slower pass, it is no pass at all"
        )

    total = len(specs)
    failures: dict[str, BaseException] = {}
    # Set by the first failing question, or by a Ctrl-C; read by every question
    # before it starts.
    halt = threading.Event()
    # Set only by a Ctrl-C, so the pass can tell the operator's stop from a
    # failure once it has drained.
    interrupted = threading.Event()

    def run(numbered: tuple[int, QuestionSpec]) -> QuestionExtraction:
        position, spec = numbered
        if halt.is_set():
            return QuestionExtraction(question_id=spec.question_id, started=False)
        try:
            return _extract_question(
                spec,
                position=position,
                total=total,
                cache=cache,
                client=client,
                pin=pin,
                instrument=instrument,
            )
        except Exception as error:  # noqa: BLE001 - re-raised aggregated below
            # Exception, not BaseException: a transport wall or a refused
            # completion is this pass's business to report, while a
            # KeyboardInterrupt is the operator's instruction to stop now and
            # must not be turned into a summary line.
            halt.set()
            return QuestionExtraction(
                question_id=spec.question_id,
                error=error,
                message=(
                    f"  [{position}/{total}] {spec.question_id} "
                    f"({spec.split}): FAILED, {error!r}"
                ),
            )

    def drain(results: Iterable[QuestionExtraction]) -> list[QuestionExtraction]:
        """Report and collect in pinned question order, as results arrive."""
        collected: list[QuestionExtraction] = []
        for outcome in results:
            if outcome.error is not None:
                failures[outcome.question_id] = outcome.error
            if outcome.message:
                progress(outcome.message)
            collected.append(outcome)
        return collected

    numbered = list(enumerate(specs, 1))
    if workers == 1:
        # A generator, so a question runs, reports, and only then does the next
        # one begin — the pinned pass's own rhythm, on the caller's thread. The
        # interrupt is deferred around it rather than inside it, because the
        # boundary being protected is between questions, not inside one.
        with _interrupt_at_question_boundary(halt, interrupted):
            outcomes = drain(run(item) for item in numbered)
    else:
        with ThreadPoolExecutor(
            max_workers=workers, thread_name_prefix="extract"
        ) as pool:
            # ``map`` yields in submission order, which is pinned question order,
            # so the merge is the iteration and no sorting is needed.
            outcomes = drain(pool.map(run, numbered))

    not_started = [outcome.question_id for outcome in outcomes if not outcome.started]
    if interrupted.is_set():
        # Ahead of the failures: the operator asked for this one, and a Ctrl-C
        # reported as a question failure would send them looking for a fault.
        # What they failed at is named in the message all the same.
        progress(
            f"interrupted: stopped at a question boundary, {len(not_started)} "
            "question(s) not started"
        )
        raise KeyboardInterrupt(
            "extraction was interrupted and stopped at a question boundary. The "
            "question in flight was walked to its end, "
            f"{len(not_started)} question(s) were never started and "
            f"{len(failures)} failed. Everything already extracted is durable — "
            "re-run to resume from it."
        )
    if failures:
        raise QuestionExtractionError(
            failures, not_started=not_started
        ) from next(iter(failures.values()))
    return outcomes


def extract_only(
    cfg: RealRunConfig,
    *,
    client_factory: Callable[[Any], Any] = default_client_factory,
    progress: Callable[[str], None] = lambda _message: None,
) -> dict[str, Any]:
    """Run the shared extraction stage alone, and write nothing else.

    This is the answering phase's first pass with the arms taken away. Every
    question's sessions go through one :class:`RealExtractor` in pinned
    occurrence order, strictly serially, so each session is primed by exactly the
    vocabulary its predecessors minted — the same prompts, in the same order, as
    the pass ``--real`` would perform. What lands in ``extractions.jsonl`` is
    therefore the cache a later ``--real`` run resumes from rather than a
    lookalike of it.

    Nothing is answered, scored or judged here, and no answer, verdict, claim or
    metrics file is created: the extraction is the *shared* input to all three
    arms, and separating it lets its cost be measured — and paid — before the
    graded run starts. The pinned run's own manifest is left untouched for the
    same reason (:data:`EXTRACT_MANIFEST_NAME`).
    """
    cfg.out_dir.mkdir(parents=True, exist_ok=True)
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

    chat_pin = clients.extractor_pin(cfg.preregister_path)
    manifest_path = cfg.out_dir / EXTRACT_MANIFEST_NAME
    fresh = build_manifest(
        cfg,
        specs,
        {"extractor": chat_pin.pin.as_record()},
        # No judge and no M3 labels take part in an extraction pass: nothing
        # here is scored, so requiring either would be a gate on a stage that
        # cannot reach them.
        judge_fallback=None,
        retriever_params={},
        split_manifest=split_manifest,
        judge_standing={},
        label_source=None,
        model_config={"extractor": chat_pin.as_record()},
        mode=MODE_EXTRACT_ONLY,
    )
    # Both gates before either record: this pass's own manifest says what it
    # intends to do, and the cache's identity says whether it may. A pass that
    # may not touch these rows must be refused without first writing a manifest
    # claiming it did.
    #
    # The manifest is reconciled on the EXTRACTION projection rather than the
    # whole run's identity. It records a great deal this pass has an opinion
    # about — how many questions it walked, which slice, which M5 sample corpus
    # was on disk — but none of that reaches an extraction row, and requiring it
    # to match made a changed --top-k, a re-pointed samples root or a narrower
    # --limit refuse a resume that could not be unsafe. What the record then
    # describes is the pass that FIRST wrote it, and what has to agree is what
    # decides a row; every later pass appends its own slice to `resumes` at the
    # end, so the file still says what the directory actually holds.
    existing = check_manifest(manifest_path, fresh, identity=extraction_identity)
    reconcile_extraction_identity(
        cfg.out_dir / EXTRACTION_IDENTITY_NAME,
        extraction_identity(fresh),
        cache_path=cfg.out_dir / EXTRACTIONS_NAME,
    )
    manifest = existing if existing is not None else write_manifest(manifest_path, fresh)

    # Repaired only now, once the cache is known to be this pass's to append to.
    # A truncate-and-fsync is a write, and a pass that has just been refused must
    # leave the directory exactly as it found it — including a torn trailing row,
    # which is evidence about the interrupted run that owns these bytes, not
    # litter for the next caller to sweep up. Only the extraction cache is
    # repaired at all, because it is the only file this pass appends to;
    # repairing the graded run's artefacts here would be this mode reaching into
    # a run it does not participate in.
    dropped = repair_jsonl(cfg.out_dir / EXTRACTIONS_NAME)
    if dropped:
        progress(f"repaired {EXTRACTIONS_NAME}: dropped {dropped} torn byte(s)")

    cache = ExtractionCache(cfg.out_dir / EXTRACTIONS_NAME)
    client = client_factory(chat_pin)

    outcomes = extract_questions(
        specs,
        cache=cache,
        client=client,
        pin=chat_pin.pin,
        # This mode exists to measure what extraction costs, so its rows carry
        # what each call cost — beside the four fields a replay reads, never
        # inside them.
        instrument=True,
        workers=cfg.extract_workers,
        progress=progress,
    )

    calls = sum(outcome.calls for outcome in outcomes)
    # Two different numbers, because a partly-cached question replays sessions it
    # does not re-extract: the replay is what keeps the priming vocabulary right,
    # and counting it as extraction would report a cost the run never paid.
    sessions_processed = sum(outcome.sessions_processed for outcome in outcomes)
    sessions_extracted = sum(outcome.sessions_extracted for outcome in outcomes)
    questions_skipped = sum(1 for outcome in outcomes if outcome.skipped)

    # This pass's own slice, appended rather than stamped over the header: the
    # header belongs to whichever pass minted the record (see the note above the
    # check_manifest call), and this is the only place a later pass is described.
    finalize_manifest(
        manifest_path,
        manifest,
        resume={"limit": cfg.limit, "question_count": len(specs)},
    )
    summary = {
        "mode": MODE_EXTRACT_ONLY,
        "questions": len(specs),
        "questions_skipped": questions_skipped,
        # Sessions the model was actually asked about, and sessions walked at all.
        "sessions_extracted": sessions_extracted,
        "sessions_processed": sessions_processed,
        "extraction_calls": calls,
        "cache_rows": len(cache),
        "extractions_path": str(cfg.out_dir / EXTRACTIONS_NAME),
        "manifest_path": str(manifest_path),
    }
    progress(
        f"extract-only: {calls} model call(s) for {sessions_extracted} newly "
        f"extracted session(s), {sessions_processed} session(s) replayed; "
        f"{questions_skipped} question(s) already cached"
    )
    return summary


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

    # Repair before anything reads or appends. A row torn by an interrupted write
    # has to be truncated rather than merely tolerated: the writers append, so
    # residue left in place would have the next row concatenated onto it and
    # become permanently unparseable in the middle of the file.
    #
    # The extraction cache is deliberately NOT in this list. It is the one
    # durable file this run may be *refused* over — it can carry rows another
    # extraction pass produced — and a refused run may not write into the
    # directory at all, truncate-and-fsync included. It is repaired below, once
    # its identity record has said these rows are ours.
    for name in (CLAIMS_NAME, ANSWERS_NAME, VERDICTS_NAME):
        dropped = repair_jsonl(cfg.out_dir / name)
        if dropped:
            progress(f"repaired {name}: dropped {dropped} torn byte(s)")

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

    cli_pin = clients.judge_pin(cfg.preregister_path)
    judge = judge_client or clients.JudgeClient(
        cli_pin=cli_pin, prompt_via=cfg.judge_prompt_via
    )
    # The judge recorded is the one that will actually run, never a blind copy of
    # the pinned one: a manual fallback is a sanctioned path, and results that
    # named the pinned judge while another model produced them would be worse
    # than results that name the deviation.
    standing = judge_standing(judge, cli_pin.pin)
    require_judge_acknowledged(standing, cfg.judge_deviation_ack)
    standing["judge_deviation_acknowledged"] = cfg.judge_deviation_ack

    # Resolved and digest-verified here, before a single model call: M3's sample
    # is pinned, so a missing or altered labels file must stop the run rather
    # than surface hours later as a metric nobody can attribute.
    label_source = resolve_m3_labels(cfg, cfg.preregister_path)

    chat_pins = {
        "answering": clients.answering_pin(cfg.preregister_path),
        "extractor": clients.extractor_pin(cfg.preregister_path),
    }
    pins = {
        "answering": chat_pins["answering"].pin,
        "extractor": chat_pins["extractor"].pin,
        "judge": judge.pin,
    }
    retriever = BM25Retriever()

    config = pins_config(pins)
    manifest_path = cfg.out_dir / MANIFEST_NAME
    fresh = build_manifest(
        cfg,
        specs,
        config.pins_record(),
        judge_fallback=cli_pin.fallback_model,
        retriever_params=retriever.params,
        split_manifest=split_manifest,
        judge_standing=standing,
        label_source=label_source,
        model_config={
            stage: chat_pin.as_record()
            for stage, chat_pin in sorted(chat_pins.items())
        },
    )
    # This run's own manifest first — it is the richer record, and where a resume
    # of a *graded* run belongs. Then the extraction cache, separately, because
    # an extraction pass may have filled it and its identity record is the only
    # thing saying under which extractor, corpus and harness: replaying those
    # rows without agreeing would score claims these pins never produced, and
    # manifest.json, which that pass never wrote, cannot say so. Only once both
    # have passed is a manifest written for a directory that had none.
    existing = check_manifest(manifest_path, fresh)
    reconcile_extraction_identity(
        cfg.out_dir / EXTRACTION_IDENTITY_NAME,
        extraction_identity(fresh),
        cache_path=cfg.out_dir / EXTRACTIONS_NAME,
    )
    manifest = existing if existing is not None else write_manifest(manifest_path, fresh)

    # Now that the cache is ours to append to (see the repair loop above).
    dropped = repair_jsonl(cfg.out_dir / EXTRACTIONS_NAME)
    if dropped:
        progress(f"repaired {EXTRACTIONS_NAME}: dropped {dropped} torn byte(s)")

    if cfg.extract_workers > 1:
        # Extraction is the one stage of a graded run that can be widened, and
        # the answering phase below cannot be the place to widen it: it walks a
        # question's arms through ONE shared linker whose lineage state is built
        # in ingestion order, so its questions are not independent of each other
        # in the way extraction's are. So the cache is warmed first, up to
        # `extract_workers` questions at a time, and the pass below then finds
        # every session memoised and makes no extraction call at all — replaying
        # from the memo exactly as a resumed run always has.
        #
        # Only above 1. At the default this branch does not run, and the graded
        # run is the interleaved, strictly serial pass it has always been, down
        # to the order its extraction calls are made in.
        #
        # `instrument` stays off, as it is in the answering phase: these rows are
        # a shared input to three arms, so they carry the four fields a replay
        # reads and nothing else, and are byte-identical to the ones the serial
        # path writes.
        progress(
            f"pre-extracting {len(specs)} questions, "
            f"{cfg.extract_workers} at a time"
        )
        extract_questions(
            specs,
            cache=ExtractionCache(cfg.out_dir / EXTRACTIONS_NAME),
            client=client_factory(chat_pins["extractor"]),
            pin=pins["extractor"],
            instrument=False,
            workers=cfg.extract_workers,
            progress=progress,
        )

    progress(f"answering {len(specs)} questions x {len(ARM_STORES)} arms")
    phase = load_answer_phase(cfg.out_dir)
    phase = answer_questions(
        specs,
        cfg,
        retriever=retriever,
        client_factory=client_factory,
        pins=pins,
        chat_pins=chat_pins,
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
        split_manifest=split_manifest,
        label_source=label_source,
    )
    metrics["manifest"] = {
        key: manifest.get(key)
        for key in (
            "pins",
            "haystack",
            "split",
            "git",
            "judge_model",
            "preregistered_judge_model",
            "judge_matches_preregistered_pin",
            "judge_deviation_acknowledged",
            "samples_sha256",
            "m3_labels_path",
            "m3_labels_sha256",
            "m3_labels_match_preregistered",
        )
    }
    # Surfaced at the top level too: whether the judge was the pre-registered one
    # is a property of the M1 and AG numbers themselves, and a reader should not
    # have to open the manifest to find out.
    metrics["judge_matches_preregistered_pin"] = manifest.get(
        "judge_matches_preregistered_pin"
    )
    metrics["judge_model"] = manifest.get("judge_model")
    (cfg.out_dir / METRICS_NAME).write_bytes(
        (json.dumps(metrics, indent=2, sort_keys=True, ensure_ascii=False) + "\n")
        .encode("utf-8")
    )
    finalize_manifest(manifest_path, manifest)
    return metrics
