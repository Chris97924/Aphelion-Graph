"""Tests for the LongMemEval prep-scope metrics and the 5-question stub smoke.

Covers the S5 acceptance contract:

* **M2** (:mod:`benchmarks.longmemeval.metrics.m2_dedup`) — pairwise dedup
  precision/recall/F1, checked against a hand-computed fixture.
* **M3** (:mod:`benchmarks.longmemeval.metrics.m3_contamination`) — the
  old-value contamination rate, checked against a hand-computed fixture.
* **M5** (:mod:`benchmarks.longmemeval.metrics.m5_roundtrip`) — verdict-level
  agreement between the independent ``scripts/external_reader.py`` and the
  committed ``samples/`` expectations.
* the **smoke** (:mod:`benchmarks.longmemeval.run`) — arms A and B run
  end-to-end over the five pinned knowledge-update questions with stub stages,
  emitting a deterministic ``results.jsonl`` and touching no model or network.

The metric fixture tests are pure and always run. The smoke tests need the
LongMemEval corpus and skip cleanly when it is absent (as in CI), mirroring
``tests/test_benchmarks_corpus.py``.
"""

from __future__ import annotations

import http.client
import json
import socket
import urllib.request
from pathlib import Path

import pytest

from benchmarks.longmemeval import corpus
from benchmarks.longmemeval import run as run_mod
from benchmarks.longmemeval.metrics.m2_dedup import DedupScore, dedup_prf, score_arm
from benchmarks.longmemeval.metrics.m3_contamination import (
    ContaminationScore,
    contamination_rate,
    context_is_contaminated,
)
from benchmarks.longmemeval.metrics.m5_roundtrip import (
    roundtrip_agreement,
    verdict_agrees,
)

_REPO_ROOT = Path(__file__).resolve().parent.parent
_SAMPLES_ROOT = _REPO_ROOT / "samples"

# The five pinned knowledge-update question_ids, hard-recorded here per the S5
# story: the first five ids of the knowledge-update pool sorted lexicographically
# (the KU pool is taken in full). The smoke must score exactly these.
PINNED_KU_QUESTION_IDS = (
    "01493427",
    "031748ae",
    "031748ae_abs",
    "06db6396",
    "07741c44",
)


# --------------------------------------------------------------------------- #
# M2 — dedup precision / recall / F1 (hand-computed fixture)                   #
# --------------------------------------------------------------------------- #


@pytest.mark.unit
def test_m2_score_arm_hand_computed_f1() -> None:
    """Score one arm against a hand-worked pairwise-dedup fixture.

    Ground truth: c1, c2, c3 are the *same* fact, so the true duplicate pairs are
    the three intra-triangle pairs::

        T = { {c1,c2}, {c1,c3}, {c2,c3} }          |T| = 3

    The arm merged only {c1,c2} and (wrongly) {c4,c5}, leaving c3 on its own::

        clusters = [ {c1,c2}, {c4,c5}, {c3} ]
        P = { {c1,c2}, {c4,c5} }                    |P| = 2

    So, by hand::

        tp = |T ∩ P| = |{ {c1,c2} }|            = 1
        fp = |P − T| = |{ {c4,c5} }|            = 1
        fn = |T − P| = |{ {c1,c3}, {c2,c3} }|   = 2

        precision = tp / (tp + fp) = 1 / 2       = 0.5
        recall    = tp / (tp + fn) = 1 / 3       ≈ 0.3333
        F1 = 2·P·R / (P + R) = (1/3) / (5/6) = 2/5 = 0.4
    """
    labeled_pairs = [("c1", "c2"), ("c1", "c3"), ("c2", "c3")]
    arm_clusters = [["c1", "c2"], ["c4", "c5"], ["c3"]]

    score = score_arm(labeled_pairs, arm_clusters)

    assert isinstance(score, DedupScore)
    assert (score.true_positives, score.false_positives, score.false_negatives) == (
        1,
        1,
        2,
    )
    assert score.precision == 0.5
    assert score.recall == pytest.approx(1 / 3)
    assert score.f1 == pytest.approx(0.4)


@pytest.mark.unit
def test_m2_dedup_prf_boundary_conventions() -> None:
    # No pairs predicted → precision 0, recall 0, F1 0 (an arm that dedups
    # nothing must not score as perfect).
    empty = dedup_prf([("a", "b")], [])
    assert (empty.precision, empty.recall, empty.f1) == (0.0, 0.0, 0.0)
    assert (empty.true_positives, empty.false_positives, empty.false_negatives) == (
        0,
        0,
        1,
    )

    # Every predicted pair correct → precision/recall/F1 all 1.0.
    perfect = dedup_prf([("a", "b"), ("c", "d")], [("b", "a"), ("d", "c")])
    assert (perfect.precision, perfect.recall, perfect.f1) == (1.0, 1.0, 1.0)


@pytest.mark.unit
def test_m2_rejects_self_pairs() -> None:
    with pytest.raises(ValueError):
        dedup_prf([("a", "a")], [])


# --------------------------------------------------------------------------- #
# M3 — old-value contamination rate (hand-computed fixture)                   #
# --------------------------------------------------------------------------- #


@pytest.mark.unit
def test_m3_contamination_rate_hand_computed() -> None:
    """Contamination rate over four questions, worked by hand.

    A question is contaminated iff any retrieved context contains any of its
    labeled old values (case-sensitive substring):

    * ``q1`` — context "…Bonn was the old capital" contains old "Bonn"  → HIT
    * ``q2`` — no old-value label at all                                → clean
    * ``q3`` — olds {"$20", "$25"}, context shows "$30"                 → clean
    * ``q4`` — context "Old price $20 was replaced" contains old "$20"  → HIT

    denominator = |retrieved_contexts| = 4, contaminated = {q1, q4} = 2::

        rate = 2 / 4 = 0.5
    """
    retrieved_contexts = {
        "q1": ["The capital is Berlin now", "Bonn was the old capital"],
        "q2": ["The current CEO is Alice"],
        "q3": ["The price is $30"],
        "q4": ["Old price $20 was replaced by the new tariff"],
    }
    old_value_labels = {
        "q1": ["Bonn"],
        "q3": ["$20", "$25"],
        "q4": ["$20"],
        # q2 is deliberately absent — a question with no label can never leak.
    }

    score = contamination_rate(retrieved_contexts, old_value_labels)

    assert isinstance(score, ContaminationScore)
    assert score.total == 4
    assert score.contaminated == 2
    assert score.rate == 0.5
    assert score.contaminated_ids == ("q1", "q4")


@pytest.mark.unit
def test_m3_contamination_edge_cases() -> None:
    # Empty old-value strings are ignored (a blank label must not mark everything).
    assert context_is_contaminated(["anything at all"], [""]) is False
    # Case-sensitive: "bonn" does not match old "Bonn".
    assert context_is_contaminated(["bonn was the capital"], ["Bonn"]) is False
    assert context_is_contaminated(["Bonn was the capital"], ["Bonn"]) is True
    # Empty corpus of questions → rate 0.0, not a ZeroDivisionError.
    empty = contamination_rate({}, {})
    assert empty.total == 0 and empty.rate == 0.0


# --------------------------------------------------------------------------- #
# M5 — verdict-level round-trip agreement against samples/                     #
# --------------------------------------------------------------------------- #


@pytest.mark.unit
def test_m5_roundtrip_agrees_on_all_samples() -> None:
    """The independent reader's verdict must match every committed sample."""
    agreement = roundtrip_agreement(_SAMPLES_ROOT)

    # All eight committed samples carry an expected-normalized.json.
    assert agreement.total == 8
    assert agreement.disagreements == ()
    assert agreement.agreements == 8
    assert agreement.all_agree is True
    assert agreement.rate == 1.0


@pytest.mark.unit
def test_m5_verdict_agrees_per_sample_including_collision() -> None:
    # A plainly valid single package.
    assert verdict_agrees(_SAMPLES_ROOT / "architecture-claim") is True
    # An invalid lifecycle stream.
    assert verdict_agrees(_SAMPLES_ROOT / "withdraw-then-illegal-reaffirm") is True
    # The collision fixture: expected verdict is "invalid" (merge-time), but the
    # minimal reader reports each sub-package as individually valid — agreement
    # means "every sub-package is valid".
    assert verdict_agrees(_SAMPLES_ROOT / "duplicate-reaffirm-collision") is True


# --------------------------------------------------------------------------- #
# Smoke — needs the corpus; skips cleanly when it is absent                    #
# --------------------------------------------------------------------------- #

_DATA_DIR = corpus.data_dir()
_HAS_ORACLE = (_DATA_DIR / corpus.ORACLE_FILENAME).is_file()
requires_oracle = pytest.mark.skipif(
    not _HAS_ORACLE,
    reason=f"LongMemEval oracle not found in {_DATA_DIR}",
)


def test_smoke_pins_the_recorded_question_ids() -> None:
    """The orchestrator's pinned ids equal the ones hard-recorded in this test."""
    assert run_mod.SMOKE_KU_QUESTION_IDS == PINNED_KU_QUESTION_IDS
    assert tuple(run_mod.SMOKE_ARM_STORES) == ("A", "B")


@requires_oracle
@pytest.mark.integration
def test_smoke_pinned_ids_are_first_five_sorted_ku() -> None:
    """The pins are exactly the first five lexicographically sorted KU ids."""
    with (_DATA_DIR / corpus.ORACLE_FILENAME).open(encoding="utf-8") as handle:
        oracle = json.load(handle)
    ku_sorted = sorted(
        {r["question_id"] for r in oracle if r["question_type"] == corpus.KU_TYPE}
    )
    assert tuple(ku_sorted[:5]) == PINNED_KU_QUESTION_IDS


@requires_oracle
@pytest.mark.integration
def test_smoke_emits_exactly_ten_wellformed_rows(tmp_path: Path) -> None:
    """5 pinned questions x arms {A, B} → exactly 10 rows, 2 per question."""
    out = tmp_path / "results.jsonl"
    rows = run_mod.run_smoke(out, data_directory=_DATA_DIR)

    # Return value and the file agree, and the file is well-formed JSON Lines.
    on_disk = [
        line for line in out.read_text(encoding="utf-8").splitlines() if line.strip()
    ]
    assert len(on_disk) == 10
    assert len(rows) == 10

    per_qid: dict[str, list[str]] = {}
    for row in rows:
        # Every row carries the contracted fields.
        assert set(row) >= {"question_id", "arm", "retrieved"}
        assert row["arm"] in {"A", "B"}
        assert isinstance(row["retrieved"], int) and row["retrieved"] >= 0
        per_qid.setdefault(row["question_id"], []).append(row["arm"])

    # Exactly the five pinned unique question_ids, each with exactly arms A and B.
    assert set(per_qid) == set(PINNED_KU_QUESTION_IDS)
    for arms in per_qid.values():
        assert sorted(arms) == ["A", "B"]


@requires_oracle
@pytest.mark.integration
def test_smoke_is_byte_identical_across_runs(tmp_path: Path) -> None:
    first = tmp_path / "first.jsonl"
    second = tmp_path / "second.jsonl"
    run_mod.run_smoke(first, data_directory=_DATA_DIR)
    run_mod.run_smoke(second, data_directory=_DATA_DIR)
    assert first.read_bytes() == second.read_bytes()


@requires_oracle
@pytest.mark.integration
def test_smoke_makes_no_model_or_network_calls(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The smoke path must not open a socket or an HTTP/urllib connection.

    Every network entry point is monkeypatched to raise; the smoke must still run
    to completion and emit its 10 rows, proving the extractor/answerer/judge
    stages are pure stubs with no model or network dependency.
    """

    def _boom(*args: object, **kwargs: object) -> object:
        raise RuntimeError("network call attempted inside the no-model smoke path")

    monkeypatch.setattr(socket, "socket", _boom)
    monkeypatch.setattr(socket, "create_connection", _boom)
    monkeypatch.setattr(urllib.request, "urlopen", _boom)
    monkeypatch.setattr(http.client.HTTPConnection, "connect", _boom, raising=False)

    out = tmp_path / "results.jsonl"
    rows = run_mod.run_smoke(out, data_directory=_DATA_DIR)
    assert len(rows) == 10
    assert all(row["arm"] in {"A", "B"} for row in rows)
