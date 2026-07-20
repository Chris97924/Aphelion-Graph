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

The five questions are the first five ``knowledge-update`` ``question_id``\\ s in
lexicographic order (:data:`SMOKE_KU_QUESTION_IDS`), pinned here and re-derived
from the corpus at run time so a drift in the frozen corpus fails loudly rather
than silently scoring a different set. Every arm sees the *same* extractor,
answerer, judge, and shared BM25 retriever — the memory layer is the only
independent variable — and the run emits one ``results.jsonl`` row per
(question, arm), deterministic and byte-identical across runs.

The full 3-arm evaluation (Arm C, real gpt-oss extractor/answerer, the Opus
judge, and metrics M1/M4) belongs to the GB10-gated execution drive; only the
smoke lives here.

Run it with::

    python -m benchmarks.longmemeval.run --smoke
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Sequence

from benchmarks.longmemeval import corpus
from benchmarks.longmemeval.arms.naive_dedup import NaiveDedupStore
from benchmarks.longmemeval.arms.plain import PlainStore
from benchmarks.longmemeval.pipeline import (
    Claim,
    MemoryStore,
    QAItem,
    Retriever,
    Session,
    run_arm,
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
    gpt-oss extractor.
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


def stub_judge(predicted: str, gold: str) -> bool:
    """Exact-match judge: the prediction must equal the gold answer verbatim."""
    return predicted == gold


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


def run_arm_smoke(
    arm: str,
    record: dict,
    retriever: Retriever,
) -> dict:
    """Run one arm over one question end-to-end and return its result row.

    Ingests the question's evidence sessions through the arm's store (with the
    stub extractor), answers from the top-``SMOKE_TOP_K`` retrieved claims via the
    stub answerer, and scores with the exact-match judge. The returned row carries
    the fields the results file is contracted to expose plus a couple of
    deterministic diagnostics.
    """
    store: MemoryStore = SMOKE_ARM_STORES[arm](retriever, extractor=stub_extractor)
    sessions = _evidence_sessions(record)
    question = QAItem(question=record["question"], gold=record["answer"])

    result = run_arm(
        store,
        retriever,
        sessions,
        [question],
        answerer=stub_answerer,
        judge=stub_judge,
        top_k=SMOKE_TOP_K,
    )
    # Recompute the retrieved slice run_arm answered from (retrieval is stateless
    # and deterministic, so this reproduces exactly what was scored).
    retrieved = store.retrieve(question.question)[:SMOKE_TOP_K]

    return {
        "question_id": record["question_id"],
        "arm": arm,
        "retrieved": len(retrieved),
        "num_claims": len(store.claims),
        "correct": result.correct[0],
    }


def run_smoke(
    out_path: Path = DEFAULT_SMOKE_OUTPUT,
    data_directory: Path | None = None,
) -> list[dict]:
    """Run arms A and B over the five pinned questions and write ``results.jsonl``.

    Returns the emitted rows (one per question x arm, questions in pinned order,
    arms in ``A, B`` order). One shared :class:`BM25Retriever` serves every arm,
    documenting arm-invariance. The output is written deterministically so a rerun
    is byte-identical.
    """
    records = load_pinned_ku_questions(data_directory)
    retriever = BM25Retriever()

    rows: list[dict] = []
    for record in records:
        for arm in SMOKE_ARM_STORES:
            rows.append(run_arm_smoke(arm, record, retriever))

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
        "--out",
        type=Path,
        default=DEFAULT_SMOKE_OUTPUT,
        help=f"results.jsonl output path (default: {DEFAULT_SMOKE_OUTPUT})",
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

    if not args.smoke:
        parser.error("nothing to do: pass --smoke (the only prep-scope entry point)")

    rows = run_smoke(args.out, args.data_dir)
    correct = sum(1 for row in rows if row["correct"])
    print(
        f"smoke: wrote {len(rows)} rows to {args.out} "
        f"({len(SMOKE_KU_QUESTION_IDS)} questions x {len(SMOKE_ARM_STORES)} arms, "
        f"{correct} exact-match correct)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
