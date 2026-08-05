"""Tests for the remaining LongMemEval harness legs.

Covers the four modules this drive adds plus the frozen split they run over:

* **linker** (:mod:`benchmarks.longmemeval.linker`) — the shared, arm-independent
  extract + link stage that assigns ``claim_id`` lineages and ``supersedes``
  edges. Design doc §7.3 fixes it as a shared stage whose *recall bounds Arm C's
  ceiling*, so the tests pin both the mechanism and the honest reporting of that
  recall.
* **labeled pairs** (:mod:`benchmarks.longmemeval.labeled_pairs`) — M2's
  exact-duplicate ground truth, partitioned by lineage so the §8 M2-fail
  diagnosis mandated by the 2026-07-19 annotation can actually be run.
* **M1** (:mod:`benchmarks.longmemeval.metrics.m1_qa`) — QA accuracy, the
  ``C − B`` contrast, and the bootstrapped CI, with the threshold read from
  ``preregister.json`` and the judge reached only through the injection surface.
* **M4** (:mod:`benchmarks.longmemeval.metrics.m4_perf`) — the sanity-only perf
  metric and its non-gating 10× tripwire.
* **split_manifest.json** — the persisted deterministic split, checked against
  the pre-registration and against a byte-identical regeneration.

Pure-fixture tests always run; the ones that need the LongMemEval corpus skip
cleanly when it is absent (as in CI), mirroring ``tests/test_benchmarks_corpus.py``.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from benchmarks.longmemeval import corpus, labeled_pairs, linker
from benchmarks.longmemeval import run as run_mod
from benchmarks.longmemeval.arms.aphelion_arm import AphelionStore
from benchmarks.longmemeval.arms.naive_dedup import NaiveDedupStore
from benchmarks.longmemeval.arms.plain import PlainStore
from benchmarks.longmemeval.metrics import m1_qa, m4_perf
from benchmarks.longmemeval.pipeline import (
    ArmResult,
    Claim,
    ModelPin,
    PipelineConfig,
    QAItem,
    Session,
    StageBinding,
    UnpinnedStageError,
)
from benchmarks.longmemeval.retriever import BM25Retriever

_REPO_ROOT = Path(__file__).resolve().parent.parent
_BENCH_ROOT = _REPO_ROOT / "benchmarks" / "longmemeval"
_MANIFEST_PATH = _BENCH_ROOT / "split_manifest.json"
_PREREGISTER_PATH = _BENCH_ROOT / "preregister.json"

_DATA_DIR = corpus.data_dir()
requires_oracle = pytest.mark.skipif(
    not (_DATA_DIR / corpus.ORACLE_FILENAME).is_file(),
    reason=f"LongMemEval oracle not found in {_DATA_DIR}",
)

# split_manifest.json is a build artifact of `python -m benchmarks.longmemeval.corpus`
# and is intended to be committed, but building it needs the 264 MiB haystack. These
# checks therefore assert hard on the manifest wherever one exists — locally and in any
# checkout that carries it — and skip where it does not, mirroring ``requires_oracle``.
requires_manifest = pytest.mark.skipif(
    not _MANIFEST_PATH.is_file(),
    reason=f"split_manifest.json not present at {_MANIFEST_PATH}",
)

_PIN = ModelPin(model="stub-model", endpoint="stub://local", temperature=0.0, seed=1)
_STUB_CONFIG = PipelineConfig(
    extractor=StageBinding(pin=_PIN, call=lambda session, *, pin: []),
    answering=StageBinding(pin=_PIN, call=lambda question, claims, *, pin: ""),
    judge=StageBinding(pin=_PIN, call=lambda *args, **kwargs: True),
)


def _preregistered_metric(name: str) -> dict:
    record = json.loads(_PREREGISTER_PATH.read_text(encoding="utf-8"))
    return record["metrics"][name]


def _session(sid: str, lines: list[str], occurred_at: str | None = None) -> Session:
    metadata = {"question_id": "q1", "session_id": sid}
    if occurred_at is not None:
        metadata["occurred_at"] = occurred_at
    return Session(id=sid, text="\n".join(lines), metadata=metadata)


# --------------------------------------------------------------------------- #
# Linker — lineage assignment and update edges                                 #
# --------------------------------------------------------------------------- #


@pytest.mark.unit
def test_linker_gives_one_lineage_per_distinct_value_on_a_subject() -> None:
    """A changed value on a known subject opens a new lineage that supersedes it."""
    link = linker.SharedLinker("q1")
    first = link(_session("s1", ["user: my 5k personal best is 24:30"]))
    second = link(_session("s2", ["user: my 5k personal best is 22:00"]))

    (old,), (new,) = first, second
    assert old.metadata["subject"] == new.metadata["subject"]
    assert old.metadata["claim_id"] != new.metadata["claim_id"]
    assert new.metadata["supersedes"] == [old.metadata["claim_id"]]
    assert "supersedes" not in old.metadata


@pytest.mark.unit
def test_linker_chains_successive_updates_to_the_current_head() -> None:
    """The third value supersedes the second, not the first — a real chain."""
    link = linker.SharedLinker("q1")
    lineages = [
        link(_session(f"s{i}", [f"user: my 5k personal best is 2{i}:00"]))[0]
        for i in range(1, 4)
    ]
    ids = [claim.metadata["claim_id"] for claim in lineages]

    assert len(set(ids)) == 3
    assert lineages[1].metadata["supersedes"] == [ids[0]]
    assert lineages[2].metadata["supersedes"] == [ids[1]]


@pytest.mark.unit
def test_linker_reuses_the_lineage_for_an_exact_restatement() -> None:
    """A repeated body is the same lineage — the coalesce case Arm C merges."""
    link = linker.SharedLinker("q1")
    first = link(_session("s1", ["user: my 5k personal best is 22:00"]))[0]
    again = link(_session("s2", ["user:  my 5k personal best   is 22:00 "]))[0]

    assert first.id != again.id
    assert first.metadata["claim_id"] == again.metadata["claim_id"]


@pytest.mark.unit
def test_linker_emits_byte_identical_metadata_for_a_repeated_body() -> None:
    """Two records of one lineage must not disagree on any R4 field.

    Arm C raises ``CoalesceConflictError`` when they do, because the surviving
    record would otherwise be decided by ingest order
    (``spec/lifecycle-state-machine.md`` §5.3). The linker is what has to keep
    that promise, so it is pinned here.
    """
    link = linker.SharedLinker("q1")
    first = link(_session("s1", ["user: i live in taipei"], "2023-05-01T10:00:00Z"))[0]
    again = link(_session("s2", ["user: i live in taipei"], "2023-06-02T11:00:00Z"))[0]

    assert first.metadata == again.metadata


@pytest.mark.unit
def test_linker_assigns_no_edges_when_no_update_is_detectable() -> None:
    """The conservative default detects nothing in ordinary prose — and says so."""
    link = linker.SharedLinker("q1")
    link(_session("s1", ["user: i had a great day", "assistant: glad to hear it"]))

    assert link.stats.supersedes_edges == 0
    assert link.stats.updated_subjects == 0
    assert link.stats.records == 2


@pytest.mark.unit
def test_linker_stats_report_the_recall_that_bounds_arm_c() -> None:
    """Design doc §7.3: the linker's recall bounds Arm C's ceiling — so report it."""
    link = linker.SharedLinker("q1")
    link(_session("s1", ["user: my 5k personal best is 24:30", "user: hello there"]))
    link(_session("s2", ["user: my 5k personal best is 22:00"]))

    stats = link.stats
    assert stats.records == 3
    assert stats.lineages == 3
    assert stats.supersedes_edges == 1
    assert stats.updated_subjects == 1


@pytest.mark.unit
def test_linking_the_same_session_once_per_arm_does_not_inflate_the_stats() -> None:
    """One linker serves three arms, so it links the same sessions three times.

    A linker that counted each pass would report three times the corpus it saw,
    and that number is published as Arm C's recall ceiling — an inflated
    denominator there quietly understates how badly the linker is doing.
    """
    link = linker.SharedLinker("q1")
    session = _session("s1", ["user: my 5k personal best is 24:30", "user: hi there"])

    first = link(session)
    for _ in range(2):
        assert [
            (claim.id, claim.text, claim.metadata) for claim in link(session)
        ] == [(claim.id, claim.text, claim.metadata) for claim in first]

    assert link.stats.records == 2
    assert link.stats.lineages == 2
    assert link.stats.restatement_groups == 0
    assert link.duplicate_groups() == [["s1#L000"], ["s1#L001"]]
    assert len(link.claims) == 2


@pytest.mark.unit
def test_linker_takes_valid_from_from_the_session_instant() -> None:
    """``valid_from`` rides on the update edge, in the 20-char R2 comparison form."""
    link = linker.SharedLinker("q1")
    link(_session("s1", ["user: my 5k personal best is 24:30"], "2023-05-25T20:21:00Z"))
    new = link(
        _session("s2", ["user: my 5k personal best is 22:00"], "2023-06-01T00:58:00Z")
    )[0]

    assert new.metadata["valid_from"] == "2023-06-01T00:58:00Z"


@pytest.mark.unit
def test_linker_omits_valid_from_when_the_session_carries_no_instant() -> None:
    """No instant is not a licence to invent one: R2 then simply does not bind."""
    link = linker.SharedLinker("q1")
    link(_session("s1", ["user: my 5k personal best is 24:30"]))
    new = link(_session("s2", ["user: my 5k personal best is 22:00"]))[0]

    assert "valid_from" not in new.metadata
    assert new.metadata["supersedes"]


@pytest.mark.unit
def test_linker_is_deterministic() -> None:
    """Same sessions in, byte-identical claims out — twice."""
    sessions = [
        _session("s1", ["user: my 5k personal best is 24:30"], "2023-05-25T20:21:00Z"),
        _session("s2", ["user: my 5k personal best is 22:00"], "2023-06-01T00:58:00Z"),
    ]

    def link_all() -> list[tuple[str, str, dict]]:
        link = linker.SharedLinker("q1")
        return [
            (claim.id, claim.text, claim.metadata)
            for session in sessions
            for claim in link(session)
        ]

    assert link_all() == link_all()


@pytest.mark.unit
def test_linker_subject_policy_is_injectable() -> None:
    """The update-detection policy is the load-bearing choice, so it is a knob."""
    link = linker.SharedLinker("q1", subject_policy=lambda text: "one-subject")
    first = link(_session("s1", ["user: i had a great day"]))[0]
    second = link(_session("s2", ["user: i had a terrible day"]))[0]

    assert first.metadata["subject"] == second.metadata["subject"] == "one-subject"
    assert second.metadata["supersedes"] == [first.metadata["claim_id"]]


@pytest.mark.unit
@pytest.mark.parametrize(
    "text",
    [
        "user: i had a great day",
        "user: my personal best",
        "22:00",
    ],
)
def test_default_subject_policy_declines_without_a_topic_and_a_value(text: str) -> None:
    """No trailing value token, or no topic left over, means no update detection."""
    assert linker.default_subject_policy(text) is None


@pytest.mark.unit
def test_default_subject_policy_strips_only_the_trailing_value() -> None:
    assert (
        linker.default_subject_policy("user: my 5K personal best is 22:00")
        == "user: my 5k personal best is"
    )


@pytest.mark.unit
def test_arm_c_suppresses_the_superseded_value_the_linker_marked() -> None:
    """The M3 mechanism, end to end: A and B surface the stale value, C does not."""
    link = linker.SharedLinker("q1")
    sessions = [
        _session("s1", ["user: my 5k personal best is 24:30"], "2023-05-25T20:21:00Z"),
        _session("s2", ["user: my 5k personal best is 22:00"], "2023-06-01T00:58:00Z"),
    ]
    retriever = BM25Retriever()
    stores = {
        "A": PlainStore(retriever, extractor=link),
        "B": NaiveDedupStore(retriever, extractor=link),
        "C": AphelionStore(
            retriever, extractor=link, query_time=run_mod.SMOKE_QUERY_TIME
        ),
    }
    for store in stores.values():
        store.ingest(list(sessions))

    surfaced = {
        arm: [claim.text for claim in store.retrieve("what is my 5k personal best")]
        for arm, store in stores.items()
    }

    assert any("24:30" in text for text in surfaced["A"])
    assert any("24:30" in text for text in surfaced["B"])
    assert not any("24:30" in text for text in surfaced["C"])
    assert any("22:00" in text for text in surfaced["C"])


# --------------------------------------------------------------------------- #
# Labeled pairs — M2 ground truth, partitioned by lineage                      #
# --------------------------------------------------------------------------- #


def _labeled_claims() -> list[Claim]:
    """Three exact restatements: two in one lineage, one fragmented into another."""
    return [
        Claim(id="r1", text="I live in Taipei", metadata={"claim_id": "L1"}),
        Claim(id="r2", text="I live in  Taipei ", metadata={"claim_id": "L1"}),
        Claim(id="r3", text="I live in Taipei", metadata={"claim_id": "L2"}),
        Claim(id="r4", text="I moved to Tainan", metadata={"claim_id": "L3"}),
    ]


@pytest.mark.unit
def test_labeled_pairs_are_the_exact_duplicate_pairs() -> None:
    """Ground truth is every pair of byte-equal bodies after whitespace collapse."""
    labeled = labeled_pairs.labeled_pairs_from_claims(_labeled_claims())

    assert labeled.pairs == {
        frozenset(("r1", "r2")),
        frozenset(("r1", "r3")),
        frozenset(("r2", "r3")),
    }


@pytest.mark.unit
def test_labeled_pairs_partition_on_lineage() -> None:
    """The 2026-07-19 annotation needs the within/cross-lineage split to exist."""
    labeled = labeled_pairs.labeled_pairs_from_claims(_labeled_claims())

    assert labeled.within_lineage == {frozenset(("r1", "r2"))}
    assert labeled.cross_lineage == {
        frozenset(("r1", "r3")),
        frozenset(("r2", "r3")),
    }
    assert labeled.within_lineage | labeled.cross_lineage == labeled.pairs


@pytest.mark.unit
def test_labeled_pairs_records_its_derivation() -> None:
    """The derivation is a documented choice, carried with the data, not folklore."""
    labeled = labeled_pairs.labeled_pairs_from_claims(_labeled_claims())
    assert labeled.derivation == labeled_pairs.DERIVATION


@pytest.mark.unit
def test_labeled_pairs_rejects_a_claim_with_no_lineage() -> None:
    with pytest.raises(ValueError, match="claim_id"):
        labeled_pairs.labeled_pairs_from_claims([Claim(id="r1", text="x")])


@pytest.mark.unit
def test_attribution_excuses_a_deficit_made_only_of_cross_lineage_pairs() -> None:
    """§8: a fragmentation artifact is not a projection bug — the check that says so."""
    labeled = labeled_pairs.labeled_pairs_from_claims(_labeled_claims())
    attribution = labeled_pairs.cross_lineage_attribution(
        labeled,
        control_pairs=labeled.pairs,
        treatment_pairs=labeled.within_lineage,
    )

    assert attribution.missed == labeled.cross_lineage
    assert attribution.within_lineage_missed == set()
    assert attribution.fully_attributable is True


@pytest.mark.unit
def test_attribution_refuses_to_excuse_a_within_lineage_miss() -> None:
    """A missed same-lineage duplicate is exactly the projection bug §8 hunts."""
    labeled = labeled_pairs.labeled_pairs_from_claims(_labeled_claims())
    attribution = labeled_pairs.cross_lineage_attribution(
        labeled,
        control_pairs=labeled.pairs,
        treatment_pairs=set(),
    )

    assert attribution.within_lineage_missed == labeled.within_lineage
    assert attribution.fully_attributable is False


@pytest.mark.unit
def test_attribution_of_no_deficit_is_not_attributable_to_fragmentation() -> None:
    """Nothing missed means nothing to excuse; the flag must not read as 'excused'."""
    labeled = labeled_pairs.labeled_pairs_from_claims(_labeled_claims())
    attribution = labeled_pairs.cross_lineage_attribution(
        labeled,
        control_pairs=labeled.pairs,
        treatment_pairs=labeled.pairs,
    )

    assert attribution.missed == set()
    assert attribution.fully_attributable is False


# --------------------------------------------------------------------------- #
# M1 — QA accuracy, the C-B contrast, and the bootstrapped CI                  #
# --------------------------------------------------------------------------- #


@pytest.mark.unit
def test_m1_gate_comes_from_the_preregistration() -> None:
    """The pinned +3pp, the arms, and N=78 are read, never re-hardcoded."""
    gate = m1_qa.pinned_gate()
    pinned = _preregistered_metric("M1")

    assert gate.treatment_arm == "C"
    assert gate.control_arm == "B"
    assert gate.threshold_pp == pytest.approx(3.0)
    assert gate.n == pinned["N"] == 78
    assert gate.secondary_control_arm == "A"


@pytest.mark.unit
def test_m1_gate_parse_refuses_a_drifted_pin(tmp_path: Path) -> None:
    """A pin this parser cannot read is a stop, not a guess."""
    drifted = tmp_path / "preregister.json"
    drifted.write_text(
        json.dumps({"metrics": {"M1": {"gate": "C wins", "N": 78, "reporting": ""}}}),
        encoding="utf-8",
    )

    with pytest.raises(m1_qa.GatePinError, match="M1"):
        m1_qa.pinned_gate(drifted)


@pytest.mark.unit
def test_m1_accuracy_and_delta_are_percentage_points() -> None:
    report = m1_qa.score_m1(_scored({"A": "1100", "B": "1000", "C": "1110"}))

    assert report.accuracies["C"].accuracy == pytest.approx(0.75)
    assert report.accuracies["B"].accuracy == pytest.approx(0.25)
    assert report.primary.delta_pp == pytest.approx(50.0)
    assert report.secondary is not None
    assert report.secondary.delta_pp == pytest.approx(25.0)


@pytest.mark.unit
def test_m1_secondary_contrast_is_c_minus_a() -> None:
    report = m1_qa.score_m1(_scored({"A": "1100", "B": "1000", "C": "1110"}))

    assert report.secondary is not None
    assert (report.secondary.treatment_arm, report.secondary.control_arm) == ("C", "A")


@pytest.mark.unit
def test_m1_bootstrap_ci_is_deterministic_under_the_pinned_seed() -> None:
    scored = _scored({"A": "1100", "B": "1000", "C": "1110"})
    first = m1_qa.score_m1(scored, resamples=200)
    second = m1_qa.score_m1(scored, resamples=200)

    assert first.primary.ci == second.primary.ci
    assert first.primary.ci.resamples == 200


@pytest.mark.unit
def test_m1_bootstrap_ci_brackets_the_point_estimate() -> None:
    report = m1_qa.score_m1(_scored({"A": "1010", "B": "1000", "C": "1110"}))

    assert report.primary.ci.low <= report.primary.delta_pp <= report.primary.ci.high
    assert report.primary.ci.level == pytest.approx(m1_qa.CI_LEVEL)


@pytest.mark.unit
def test_m1_refuses_a_gate_verdict_at_the_wrong_n() -> None:
    """Four questions cannot answer a gate pinned at N=78; saying so is the point."""
    report = m1_qa.score_m1(_scored({"A": "1100", "B": "1000", "C": "1110"}))

    assert report.n_matches_pin is False
    with pytest.raises(m1_qa.UnderpoweredSampleError, match="78"):
        report.gate_verdict()


@pytest.mark.unit
def test_m1_gate_verdict_at_the_pinned_n() -> None:
    """At N=78 the verdict is arithmetic: C-B in pp against the pinned +3."""
    control = "1" * 39 + "0" * 39
    passing = "1" * 42 + "0" * 36
    report = m1_qa.score_m1(
        _scored({"A": control, "B": control, "C": passing}),
    )

    assert report.n_matches_pin is True
    assert report.primary.delta_pp == pytest.approx(300 / 78)
    assert report.gate_verdict() is True


@pytest.mark.unit
def test_m1_gate_verdict_fails_below_the_pinned_threshold() -> None:
    control = "1" * 39 + "0" * 39
    barely = "1" * 41 + "0" * 37
    report = m1_qa.score_m1(_scored({"A": control, "B": control, "C": barely}))

    assert report.primary.delta_pp == pytest.approx(200 / 78)
    assert report.gate_verdict() is False


@pytest.mark.unit
def test_m1_restricts_to_the_knowledge_update_subset() -> None:
    """M1's denominator is the KU subset, not whatever was answered."""
    report = m1_qa.score_m1(
        _scored({"A": "0000", "B": "0011", "C": "1111"}), subset=[0, 1]
    )

    assert report.n == 2
    assert report.accuracies["B"].accuracy == pytest.approx(0.0)
    assert report.primary.delta_pp == pytest.approx(100.0)


@pytest.mark.unit
def test_m1_refuses_results_missing_a_gate_arm() -> None:
    with pytest.raises(m1_qa.MissingArmError, match="'C'"):
        m1_qa.score_m1(_scored({"A": "10", "B": "10"}))


@pytest.mark.unit
def test_m1_run_raises_when_the_judge_is_unpinned() -> None:
    """M1 never runs a model itself; an unpinned judge is a typed refusal."""
    config = PipelineConfig(
        extractor=StageBinding(pin=_PIN, call=lambda session, *, pin: []),
        answering=StageBinding(pin=_PIN, call=lambda question, claims, *, pin: ""),
    )
    questions = [QAItem(question="q", gold="g")]
    results = {
        arm: ArmResult(predictions=["g"], pins=config.pins_record())
        for arm in ("A", "B", "C")
    }

    with pytest.raises(UnpinnedStageError, match="judge"):
        m1_qa.run_m1(results, questions, config=config)


@pytest.mark.unit
def test_m1_run_scores_through_an_injected_judge() -> None:
    """The offline path: a fake judge, no model, a full report."""
    questions = [QAItem(question="q", gold="yes"), QAItem(question="q2", gold="no")]
    pins = _STUB_CONFIG.pins_record()
    results = {
        "A": ArmResult(predictions=["no", "no"], pins=pins),
        "B": ArmResult(predictions=["no", "no"], pins=pins),
        "C": ArmResult(predictions=["yes", "no"], pins=pins),
    }

    report = m1_qa.run_m1(
        results,
        questions,
        config=_STUB_CONFIG,
        judge=lambda question, gold, candidate: candidate == gold,
        resamples=100,
    )

    assert report.accuracies["C"].accuracy == pytest.approx(1.0)
    assert report.accuracies["B"].accuracy == pytest.approx(0.5)
    assert report.primary.delta_pp == pytest.approx(50.0)


@pytest.mark.unit
def test_m1_report_record_is_json_serialisable() -> None:
    report = m1_qa.score_m1(_scored({"A": "1100", "B": "1000", "C": "1110"}))
    record = report.as_record()

    assert json.loads(json.dumps(record, sort_keys=True)) == record
    assert record["n"] == 4
    assert record["gate_verdict"] is None, "an underpowered run reports no verdict"


def _scored(marks: dict[str, str]) -> dict[str, ArmResult]:
    """Build already-judged arm results from ``{arm: "1010"}`` verdict strings."""
    pins = _STUB_CONFIG.pins_record()
    return {
        arm: ArmResult(
            predictions=["" for _ in row],
            pins=pins,
            correct=[char == "1" for char in row],
        )
        for arm, row in marks.items()
    }


# --------------------------------------------------------------------------- #
# M4 — sanity-only perf, with a non-gating 10x tripwire                        #
# --------------------------------------------------------------------------- #


@pytest.mark.unit
def test_m4_tripwire_comes_from_the_preregistration() -> None:
    tripwire = m4_perf.pinned_tripwire()
    pinned = _preregistered_metric("M4")

    assert tripwire.factor == pytest.approx(10.0)
    assert tripwire.reference_arm == "A"
    assert "10x" in pinned["tripwire"]


@pytest.mark.unit
def test_m4_asserts_the_pin_still_declares_no_gate(tmp_path: Path) -> None:
    """If M4 ever acquires a real gate, this harness must stop, not shrug."""
    assert m4_perf.pinned_tripwire().gating is False

    drifted = {"metrics": {"M4": {"gate": "C <= 2x A", "tripwire": "10x Arm A"}}}
    with pytest.raises(m4_perf.GatePinError, match="M4"):
        m4_perf.pinned_tripwire(_written(tmp_path, drifted))


@pytest.mark.unit
def test_m4_tripwire_parse_refuses_a_drifted_pin(tmp_path: Path) -> None:
    drifted = {"metrics": {"M4": {"gate": "none (sanity-only)", "tripwire": "soon"}}}
    with pytest.raises(m4_perf.GatePinError, match="tripwire"):
        m4_perf.pinned_tripwire(_written(tmp_path, drifted))


@pytest.mark.unit
@pytest.mark.parametrize(
    ("values", "q", "expected"),
    [
        ([1.0], 0.5, 1.0),
        ([1.0, 2.0, 3.0, 4.0], 0.5, 2.5),
        ([1.0, 2.0, 3.0, 4.0], 0.0, 1.0),
        ([1.0, 2.0, 3.0, 4.0], 1.0, 4.0),
    ],
)
def test_m4_percentile(values: list[float], q: float, expected: float) -> None:
    assert m4_perf.percentile(values, q) == pytest.approx(expected)


@pytest.mark.unit
def test_m4_percentile_rejects_an_empty_sample() -> None:
    with pytest.raises(ValueError, match="empty"):
        m4_perf.percentile([], 0.5)


@pytest.mark.unit
def test_m4_measures_latency_off_an_injected_clock() -> None:
    """Wall time is not reproducible, so the clock is a knob — that is the pattern."""
    retriever = BM25Retriever()
    store = PlainStore(retriever)
    store.add_claims([Claim(id="c1", text="taipei", metadata={"claim_id": "L1"})])

    perf = m4_perf.measure_arm(
        "A",
        store,
        {"q1": "taipei", "q2": "taipei"},
        top_k=10,
        clock=m4_perf.CountingClock(step_seconds=0.25),
    )

    assert perf.arm == "A"
    assert perf.num_queries == 2
    assert perf.p50_ms == pytest.approx(250.0)
    assert perf.p95_ms == pytest.approx(250.0)


@pytest.mark.unit
def test_m4_reports_storage_bytes_per_claim() -> None:
    retriever = BM25Retriever()
    store = PlainStore(retriever)
    claims = [
        Claim(id="c1", text="taipei", metadata={"claim_id": "L1"}),
        Claim(id="c2", text="tainan", metadata={"claim_id": "L2"}),
    ]
    store.add_claims(claims)

    perf = m4_perf.measure_arm(
        "A", store, {"q1": "taipei"}, top_k=10, clock=m4_perf.CountingClock()
    )

    expected = sum(m4_perf.canonical_claim_bytes(claim) for claim in claims)
    assert perf.num_claims == 2
    assert perf.storage_bytes == expected
    assert perf.bytes_per_claim == pytest.approx(expected / 2)


@pytest.mark.unit
def test_m4_flags_a_ten_times_regression_without_gating() -> None:
    """The tripwire reports; it never fails a run. M4 is sanity-only by pin."""
    report = m4_perf.M4Report(
        tripwire=m4_perf.pinned_tripwire(),
        arms={
            "A": _perf("A", p95_ms=1.0, bytes_per_claim=100.0),
            "B": _perf("B", p95_ms=2.0, bytes_per_claim=150.0),
            "C": _perf("C", p95_ms=40.0, bytes_per_claim=120.0),
        },
    )

    flagged = {(flag.arm, flag.measure) for flag in report.flags}
    assert flagged == {("C", "p95_ms")}
    assert report.tripwire.gating is False
    assert report.as_record()["tripwire_flags"] == [
        {
            "arm": "C",
            "measure": "p95_ms",
            "value": 40.0,
            "reference_value": 1.0,
            "factor": 10.0,
        }
    ]


@pytest.mark.unit
def test_m4_flags_a_storage_regression_too() -> None:
    report = m4_perf.M4Report(
        tripwire=m4_perf.pinned_tripwire(),
        arms={
            "A": _perf("A", p95_ms=1.0, bytes_per_claim=100.0),
            "C": _perf("C", p95_ms=1.0, bytes_per_claim=2000.0),
        },
    )

    assert {(flag.arm, flag.measure) for flag in report.flags} == {
        ("C", "bytes_per_claim")
    }


@pytest.mark.unit
def test_m4_reference_arm_never_flags_itself() -> None:
    report = m4_perf.M4Report(
        tripwire=m4_perf.pinned_tripwire(),
        arms={"A": _perf("A", p95_ms=1.0, bytes_per_claim=1.0)},
    )
    assert report.flags == ()


@pytest.mark.unit
def test_m4_refuses_a_report_without_its_reference_arm() -> None:
    with pytest.raises(m4_perf.MissingArmError, match="'A'"):
        m4_perf.M4Report(
            tripwire=m4_perf.pinned_tripwire(),
            arms={"C": _perf("C", p95_ms=1.0, bytes_per_claim=1.0)},
        ).flags


def _perf(arm: str, *, p95_ms: float, bytes_per_claim: float) -> m4_perf.ArmPerf:
    return m4_perf.ArmPerf(
        arm=arm,
        p50_ms=p95_ms,
        p95_ms=p95_ms,
        num_queries=1,
        num_claims=1,
        storage_bytes=int(bytes_per_claim),
        bytes_per_claim=bytes_per_claim,
    )


def _written(tmp_path: Path, record: dict) -> Path:
    path = tmp_path / "preregister.json"
    path.write_text(json.dumps(record), encoding="utf-8")
    return path


# --------------------------------------------------------------------------- #
# split_manifest.json — the persisted, deterministic split                     #
# --------------------------------------------------------------------------- #


@requires_manifest
@pytest.mark.unit
def test_split_manifest_matches_the_preregistered_split() -> None:
    manifest = json.loads(_MANIFEST_PATH.read_text(encoding="utf-8"))
    pinned = json.loads(_PREREGISTER_PATH.read_text(encoding="utf-8"))

    assert manifest["seed"] == pinned["seed"] == 20260717
    assert manifest["sampling_algorithm"] == pinned["sampling_algorithm"]
    assert manifest["counts"]["ku"] == pinned["split"]["knowledge_update"] == 78
    assert manifest["counts"]["ms"] == pinned["split"]["multi_session"] == 122
    assert manifest["counts"]["adversarial"] == pinned["split"]["adversarial"] == 20
    assert manifest["counts"]["total"] == 220


@requires_manifest
@pytest.mark.unit
def test_split_manifest_ids_are_sorted_unique_and_disjoint() -> None:
    groups = json.loads(_MANIFEST_PATH.read_text(encoding="utf-8"))["question_ids"]

    seen: set[str] = set()
    for name, ids in sorted(groups.items()):
        assert ids == sorted(ids), f"{name} must be canonical (sorted)"
        assert len(ids) == len(set(ids)), f"{name} must not repeat a question_id"
        assert not (seen & set(ids)), f"{name} overlaps an earlier group"
        seen.update(ids)


@requires_manifest
@pytest.mark.unit
def test_split_manifest_is_serialised_canonically() -> None:
    """The on-disk bytes must be exactly what the generator emits.

    Byte-level, not text-level: the pre-existing corpus test compares
    ``read_text`` output, which silently normalises CRLF away and so passed for a
    manifest that had been written with platform newlines.
    """
    manifest = json.loads(_MANIFEST_PATH.read_text(encoding="utf-8"))
    assert _MANIFEST_PATH.read_bytes() == corpus.dumps_manifest(manifest).encode(
        "utf-8"
    )


@requires_manifest
@requires_oracle
@pytest.mark.integration
def test_split_manifest_regenerates_byte_identically() -> None:
    """Rebuild from the corpus and compare bytes — the reproducibility claim."""
    rebuilt = corpus.dumps_manifest(corpus.build_manifest(_DATA_DIR)).encode("utf-8")
    assert rebuilt == _MANIFEST_PATH.read_bytes()


# --------------------------------------------------------------------------- #
# Wiring — the offline smoke exercises M1 and M4                               #
# --------------------------------------------------------------------------- #


@pytest.mark.unit
def test_run_reexports_the_shared_linker_from_its_own_module() -> None:
    assert run_mod.SharedLinker is linker.SharedLinker


@requires_oracle
@pytest.mark.integration
def test_3arm_smoke_emits_m1_and_m4(tmp_path: Path) -> None:
    rows = run_mod.run_3arm_smoke(tmp_path / "out.jsonl", data_directory=_DATA_DIR)
    metrics = rows[-1]

    assert set(metrics["m1"]["accuracy"]) == {"A", "B", "C"}
    assert metrics["m1"]["gate_verdict"] is None, "5 questions cannot answer N=78"
    assert "not an M1 result" in metrics["m1_caveat"]

    assert set(metrics["m4"]["p95_ms"]) == {"A", "B", "C"}
    assert metrics["m4"]["tripwire_factor"] == pytest.approx(10.0)
    assert "not an M4 result" in metrics["m4_caveat"]


@requires_oracle
@pytest.mark.integration
def test_3arm_smoke_reports_the_linker_recall_ceiling(tmp_path: Path) -> None:
    """Arm C's ceiling is the linker's recall, so the smoke must publish it."""
    rows = run_mod.run_3arm_smoke(tmp_path / "out.jsonl", data_directory=_DATA_DIR)
    metrics = rows[-1]

    assert metrics["linker"]["records"] > 0
    assert set(metrics["linker"]) >= {
        "records",
        "lineages",
        "supersedes_edges",
        "updated_subjects",
    }


@requires_oracle
@pytest.mark.integration
def test_3arm_smoke_reports_the_m2_lineage_attribution(tmp_path: Path) -> None:
    """The §8 M2-fail diagnosis needs the within/cross-lineage split in the row."""
    rows = run_mod.run_3arm_smoke(tmp_path / "out.jsonl", data_directory=_DATA_DIR)
    metrics = rows[-1]

    assert set(metrics["m2_labeled_pairs"]) == {"total", "within_lineage", "cross_lineage"}


@pytest.mark.unit
def test_m5_cross_implementation_is_surfaced_when_the_reader_reports_it() -> None:
    """Once the W-M5 second canonical reader lands, its counts reach the row."""
    status = SimpleNamespace(
        cross_implementation=SimpleNamespace(identical=6, total=6),
    )
    assert run_mod._m5_cross_implementation(status) == {"identical": 6, "total": 6}


@pytest.mark.unit
def test_m5_cross_implementation_is_null_before_the_second_reader_lands() -> None:
    """Absent is null, never zero.

    The second canonical reader lands on its own branch, so this tree's
    ``GateStatus`` may carry no ``cross_implementation`` at all. Reporting ``0``
    would claim the two-implementation cross-check ran and matched nothing, which
    is the opposite of "there is no second implementation to check against yet".
    """
    status = SimpleNamespace(runnable=False, blocker="W-M5 not landed")

    assert run_mod._m5_cross_implementation(status) == {
        "identical": None,
        "total": None,
    }


@requires_oracle
@pytest.mark.integration
def test_3arm_smoke_row_carries_the_m5_cross_implementation_surface(
    tmp_path: Path,
) -> None:
    rows = run_mod.run_3arm_smoke(tmp_path / "out.jsonl", data_directory=_DATA_DIR)
    cross = rows[-1]["m5_cross_implementation"]

    assert set(cross) == {"identical", "total"}
    # The pinned gate's standing is reported independently of these counts.
    assert rows[-1]["m5_gate_runnable"] is False


@requires_oracle
@pytest.mark.integration
def test_3arm_smoke_stays_byte_identical_with_the_new_metrics(tmp_path: Path) -> None:
    first = tmp_path / "first.jsonl"
    second = tmp_path / "second.jsonl"
    run_mod.run_3arm_smoke(first, data_directory=_DATA_DIR)
    run_mod.run_3arm_smoke(second, data_directory=_DATA_DIR)
    assert first.read_bytes() == second.read_bytes()
