"""Tests for the LongMemEval benchmark arms, retriever, and run scaffold.

Covers the S3 acceptance contract:

* Arm A (:class:`PlainStore`) keeps exact duplicates.
* Arm B (:class:`NaiveDedupStore`) collapses whitespace variants but nothing
  smarter (case and semantics are preserved).
* The shared BM25 retriever ranks deterministically with a stable ``id``
  tiebreak on equal scores.
* The arm-agnostic run scaffold's deferred hooks are clean seams (they raise
  :class:`NotImplementedError`), yet the plumbing runs end-to-end once trivial
  hooks are supplied.
"""

from __future__ import annotations

import pytest

from benchmarks.longmemeval.arms.naive_dedup import NaiveDedupStore, normalize_body
from benchmarks.longmemeval.arms.plain import PlainStore
from benchmarks.longmemeval.pipeline import (
    ArmResult,
    Claim,
    MemoryStore,
    QAItem,
    Session,
    default_answerer,
    default_extractor,
    default_judge,
    run_arm,
)
from benchmarks.longmemeval.retriever import BM25Retriever, tokenize


def _claim(cid: str, text: str) -> Claim:
    return Claim(id=cid, text=text)


# ---------------------------------------------------------------------------
# Arm A — duplicates kept
# ---------------------------------------------------------------------------


def test_arm_a_keeps_exact_duplicates() -> None:
    store = PlainStore(BM25Retriever())
    store.add_claims(
        [
            _claim("c1", "5K PB is 22:00"),
            _claim("c2", "5K PB is 22:00"),
            _claim("c3", "5K PB is 22:00"),
        ]
    )
    assert [c.text for c in store.claims] == ["5K PB is 22:00"] * 3
    assert len(store.claims) == 3


def test_arm_a_keeps_whitespace_variants() -> None:
    store = PlainStore(BM25Retriever())
    store.add_claims(
        [
            _claim("c1", "5K PB is 22:00"),
            _claim("c2", "  5K PB   is 22:00  "),
        ]
    )
    assert len(store.claims) == 2


# ---------------------------------------------------------------------------
# Arm B — whitespace collapse, nothing smarter
# ---------------------------------------------------------------------------


def test_arm_b_collapses_whitespace_variants() -> None:
    store = NaiveDedupStore(BM25Retriever())
    store.add_claims(
        [
            _claim("c1", "5K PB is 22:00"),
            _claim("c2", "  5K PB is 22:00  "),  # leading/trailing strip
            _claim("c3", "5K   PB\tis\n22:00"),  # internal run collapse
        ]
    )
    assert len(store.claims) == 1
    # First writer wins — the original claim is retained verbatim.
    assert store.claims[0].id == "c1"
    assert store.claims[0].text == "5K PB is 22:00"


def test_arm_b_keeps_semantically_equal_but_not_byte_equal() -> None:
    store = NaiveDedupStore(BM25Retriever())
    store.add_claims(
        [
            _claim("c1", "5K PB is 22:00"),
            _claim("c2", "my 5K personal best is 22:00"),
        ]
    )
    assert len(store.claims) == 2


def test_arm_b_is_case_sensitive() -> None:
    # "Nothing smarter": no case-folding, so case variants stay distinct.
    store = NaiveDedupStore(BM25Retriever())
    store.add_claims([_claim("c1", "Hello World"), _claim("c2", "hello world")])
    assert len(store.claims) == 2


def test_normalize_body_rules() -> None:
    assert normalize_body("  a   b\tc\n d  ") == "a b c d"
    assert normalize_body("a b") == "a b"
    assert normalize_body("   ") == ""
    # Differs by a word boundary, not just whitespace.
    assert normalize_body("5K PB is 22:00") != normalize_body(
        "my 5K personal best is 22:00"
    )


# ---------------------------------------------------------------------------
# Shared BM25 retriever — determinism + stable tiebreak
# ---------------------------------------------------------------------------


def test_tokenize_is_lowercase_word_runs() -> None:
    assert tokenize("Hello, WORLD! 5K_PB") == ["hello", "world", "5k_pb"]


def test_bm25_ranks_relevant_claim_first() -> None:
    retriever = BM25Retriever()
    claims = [
        _claim("a", "the marathon route passes the harbour"),
        _claim("b", "my 5K personal best is 22 minutes"),
        _claim("c", "i had pasta for dinner"),
    ]
    ranked = retriever.rank("what is my 5K personal best", claims)
    assert ranked[0].id == "b"


def test_bm25_deterministic_across_runs() -> None:
    retriever = BM25Retriever()
    claims = [
        _claim("a", "alpha beta gamma"),
        _claim("b", "beta gamma delta"),
        _claim("c", "gamma delta epsilon"),
        _claim("d", "alpha beta gamma"),
    ]
    first = [c.id for c in retriever.rank("beta gamma", claims)]
    second = [c.id for c in retriever.rank("beta gamma", claims)]
    assert first == second


def test_bm25_stable_tiebreak_on_equal_scores() -> None:
    retriever = BM25Retriever()
    # Byte-identical bodies => identical scores; ids force a total order.
    claims = [
        _claim("z", "identical body text"),
        _claim("a", "identical body text"),
        _claim("m", "identical body text"),
    ]
    assert [c.id for c in retriever.rank("identical body", claims)] == ["a", "m", "z"]
    # Insertion order must not affect the tiebreak.
    reshuffled = retriever.rank("identical body", list(reversed(claims)))
    assert [c.id for c in reshuffled] == ["a", "m", "z"]


def test_bm25_scores_equal_for_equal_bodies() -> None:
    retriever = BM25Retriever()
    claims = [_claim("z", "same words here"), _claim("a", "same words here")]
    scored = retriever.rank_with_scores("same words", claims)
    assert scored[0][1] == scored[1][1]  # equal scores
    assert [c.id for c, _ in scored] == ["a", "z"]  # id tiebreak


def test_bm25_empty_corpus_returns_empty() -> None:
    assert BM25Retriever().rank("anything", []) == []


def test_bm25_all_empty_documents_do_not_crash() -> None:
    retriever = BM25Retriever()
    claims = [_claim("b", ""), _claim("a", "   ")]
    ranked = retriever.rank("query terms", claims)
    assert [c.id for c in ranked] == ["a", "b"]  # all score 0, id-ordered


# ---------------------------------------------------------------------------
# Arm-agnostic run scaffold + deferred seams
# ---------------------------------------------------------------------------


def test_deferred_hooks_raise_not_implemented() -> None:
    with pytest.raises(NotImplementedError):
        default_extractor(Session(id="s", text="x"))
    with pytest.raises(NotImplementedError):
        default_answerer("q", [])
    with pytest.raises(NotImplementedError):
        default_judge("a", "b")


def test_stores_satisfy_memory_store_protocol() -> None:
    assert isinstance(PlainStore(BM25Retriever()), MemoryStore)
    assert isinstance(NaiveDedupStore(BM25Retriever()), MemoryStore)


def test_run_arm_is_arm_agnostic_and_deterministic() -> None:
    retriever = BM25Retriever()

    # Trivial deterministic hooks standing in for the S5 stages.
    def extractor(session: Session) -> list[Claim]:
        return [Claim(id=session.id, text=session.text)]

    def answerer(question: str, claims: list[Claim]) -> str:
        return claims[0].text if claims else ""

    def judge(predicted: str, gold: str) -> bool:
        return predicted == gold

    sessions = [
        Session(id="s1", text="my 5K personal best is 22 minutes"),
        Session(id="s2", text="my 5K personal best is 22 minutes"),  # dup body
        Session(id="s3", text="i moved to Taipei in 2021"),
    ]
    questions = [
        QAItem(
            question="what is my 5K personal best",
            gold="my 5K personal best is 22 minutes",
        )
    ]

    plain = PlainStore(retriever, extractor=extractor)
    dedup = NaiveDedupStore(retriever, extractor=extractor)

    plain_result = run_arm(
        plain, retriever, sessions, questions, answerer=answerer, judge=judge
    )
    dedup_result = run_arm(
        dedup, retriever, sessions, questions, answerer=answerer, judge=judge
    )

    # Same shared retriever/params recorded for both arms.
    assert plain_result.retriever_params == dedup_result.retriever_params
    assert plain_result.retriever_params["algorithm"] == "BM25Okapi"

    # Both arms answer correctly; the memory layer is the only difference —
    # Arm A stored the duplicate, Arm B collapsed it.
    assert plain_result.correct == [True]
    assert dedup_result.correct == [True]
    assert len(plain.claims) == 3
    assert len(dedup.claims) == 2
    assert isinstance(plain_result, ArmResult)


def test_run_arm_with_default_hooks_hits_the_deferred_seam() -> None:
    # The default (deferred) extractor makes ingest itself raise — proving the
    # seam is intentional, not a silently swallowed no-op.
    retriever = BM25Retriever()
    store = PlainStore(retriever)
    with pytest.raises(NotImplementedError):
        run_arm(store, retriever, [Session(id="s", text="x")], [])
