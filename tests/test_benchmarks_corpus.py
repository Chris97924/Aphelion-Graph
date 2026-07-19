"""Tests for the deterministic LongMemEval corpus split builder.

Unit tests run against small synthetic fixtures. Real-corpus checks are marked
``integration`` and skip cleanly when ``LONGMEMEVAL_DATA_DIR`` has no corpus
(as in CI); they are exercised locally against the real data.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from benchmarks.longmemeval import corpus

# --------------------------------------------------------------------------- #
# Synthetic fixtures                                                          #
# --------------------------------------------------------------------------- #


def _small_type_to_ids() -> dict[str, list[str]]:
    """A tiny type -> ids map with every pool the split touches, plus decoys."""
    return {
        "knowledge-update": [f"ku#{i:02d}" for i in range(5)],
        "multi-session": [f"ms#{i:02d}" for i in range(8)],
        "single-session-preference": [f"pref#{i:02d}" for i in range(3)],
        "single-session-user": [f"user#{i:02d}" for i in range(4)],
        # Decoy pools that must never appear in any group.
        "single-session-assistant": [f"asst#{i:02d}" for i in range(6)],
        "temporal-reasoning": [f"temp#{i:02d}" for i in range(7)],
    }


def _synthetic_corpus() -> tuple[list[dict], dict[str, set[str]]]:
    """Generate a 500-record corpus matching the pinned per-type counts.

    Returns the records plus a per-type map of the ids so tests can assert
    membership without depending on the builder's own indexing.
    """
    records: list[dict] = []
    pools: dict[str, set[str]] = {}
    for qtype, count in corpus.EXPECTED_TYPE_COUNTS.items():
        ids = [f"{qtype}#{i:04d}" for i in range(count)]
        pools[qtype] = set(ids)
        records.extend({"question_id": q, "question_type": qtype} for q in ids)
    return records, pools


# --------------------------------------------------------------------------- #
# build_split — small synthetic fixture (unit)                               #
# --------------------------------------------------------------------------- #


@pytest.mark.unit
def test_build_split_ku_taken_in_full() -> None:
    pools = _small_type_to_ids()
    split = corpus.build_split(pools, ms_sample_size=4, adversarial_sample_size=3)
    assert set(split["ku"]) == set(pools["knowledge-update"])
    assert split["ku"] == sorted(pools["knowledge-update"])  # canonical order
    assert len(split["ku"]) == 5


@pytest.mark.unit
def test_build_split_ms_is_sampled_subset() -> None:
    pools = _small_type_to_ids()
    split = corpus.build_split(pools, ms_sample_size=4, adversarial_sample_size=3)
    ms = split["ms"]
    assert len(ms) == 4
    assert len(set(ms)) == 4  # no duplicates
    assert set(ms) <= set(pools["multi-session"])
    assert ms == sorted(ms)  # canonical order


@pytest.mark.unit
def test_build_split_adversarial_from_union_pool() -> None:
    pools = _small_type_to_ids()
    union = set(pools["single-session-preference"]) | set(pools["single-session-user"])
    split = corpus.build_split(pools, ms_sample_size=4, adversarial_sample_size=3)
    adversarial = split["adversarial"]
    assert len(adversarial) == 3
    assert len(set(adversarial)) == 3
    assert set(adversarial) <= union


@pytest.mark.unit
def test_build_split_groups_pairwise_disjoint_and_exclude_decoys() -> None:
    pools = _small_type_to_ids()
    split = corpus.build_split(pools, ms_sample_size=4, adversarial_sample_size=3)
    ku, ms, adv = set(split["ku"]), set(split["ms"]), set(split["adversarial"])
    assert ku & ms == set()
    assert ku & adv == set()
    assert ms & adv == set()
    decoys = set(pools["single-session-assistant"]) | set(pools["temporal-reasoning"])
    assert (ku | ms | adv) & decoys == set()


@pytest.mark.unit
def test_build_split_is_deterministic() -> None:
    pools = _small_type_to_ids()
    first = corpus.build_split(pools, ms_sample_size=4, adversarial_sample_size=3)
    second = corpus.build_split(pools, ms_sample_size=4, adversarial_sample_size=3)
    assert first == second


@pytest.mark.unit
def test_build_split_different_seed_changes_sample() -> None:
    pools = _small_type_to_ids()
    base = corpus.build_split(pools, ms_sample_size=4, adversarial_sample_size=3)
    other = corpus.build_split(
        pools, ms_sample_size=4, adversarial_sample_size=3, seed=corpus.SEED + 1
    )
    # KU is unsampled so stable; a sampled pool must react to the seed.
    assert base["ku"] == other["ku"]
    assert base["ms"] != other["ms"] or base["adversarial"] != other["adversarial"]


@pytest.mark.unit
def test_index_by_type_sorted_and_unique() -> None:
    records = [
        {"question_id": "b", "question_type": "t1"},
        {"question_id": "a", "question_type": "t1"},
        {"question_id": "a", "question_type": "t1"},  # duplicate collapses
        {"question_id": "c", "question_type": "t2"},
    ]
    indexed = corpus.index_by_type(records)
    assert indexed["t1"] == ["a", "b"]
    assert indexed["t2"] == ["c"]


@pytest.mark.unit
def test_sampling_algorithm_records_the_pinned_rule() -> None:
    text = corpus.SAMPLING_ALGORITHM
    assert "sort question_ids lexicographically" in text
    assert "random.Random(20260717).sample" in text
    assert "KU pool taken in full (no sampling)" in text
    assert "sample 122 of 133" in text
    assert "sample 20 from the union" in text


@pytest.mark.unit
def test_dumps_manifest_is_deterministic_and_utf8_newline_terminated() -> None:
    manifest = {"b": [3, 1, 2], "a": "x", "seed": corpus.SEED}
    first = corpus.dumps_manifest(manifest)
    second = corpus.dumps_manifest(dict(reversed(list(manifest.items()))))
    assert first == second  # key order in input does not matter (sort_keys)
    assert first.endswith("\n")


# --------------------------------------------------------------------------- #
# End-to-end on a full-distribution synthetic corpus (no real data needed)   #
# --------------------------------------------------------------------------- #


def _write_synthetic_corpus(directory: Path) -> None:
    records, _ = _synthetic_corpus()
    for filename in (corpus.ORACLE_FILENAME, corpus.S_CLEANED_FILENAME):
        with (directory / filename).open("w", encoding="utf-8") as handle:
            json.dump(records, handle)


def test_build_manifest_end_to_end_on_synthetic_corpus(tmp_path: Path) -> None:
    _write_synthetic_corpus(tmp_path)
    _, pools = _synthetic_corpus()
    manifest = corpus.build_manifest(tmp_path)

    assert manifest["seed"] == corpus.SEED
    assert manifest["sampling_algorithm"] == corpus.SAMPLING_ALGORITHM
    assert manifest["counts"] == {"ku": 78, "ms": 122, "adversarial": 20, "total": 220}

    qids = manifest["question_ids"]
    assert set(qids["ku"]) == pools["knowledge-update"]
    assert len(qids["ms"]) == 122 and set(qids["ms"]) <= pools["multi-session"]
    union = pools["single-session-preference"] | pools["single-session-user"]
    assert len(qids["adversarial"]) == 20 and set(qids["adversarial"]) <= union

    ku, ms, adv = set(qids["ku"]), set(qids["ms"]), set(qids["adversarial"])
    assert ku & ms == set() and ku & adv == set() and ms & adv == set()

    for digest in manifest["source_sha256"].values():
        assert len(digest) == 64 and digest == digest.lower()
        int(digest, 16)  # raises on any non-hex character


def test_build_manifest_is_byte_identical_across_runs(tmp_path: Path) -> None:
    _write_synthetic_corpus(tmp_path)
    first = corpus.dumps_manifest(corpus.build_manifest(tmp_path))
    second = corpus.dumps_manifest(corpus.build_manifest(tmp_path))
    assert first == second

    out_a = corpus.write_manifest(corpus.build_manifest(tmp_path), tmp_path / "a.json")
    out_b = corpus.write_manifest(corpus.build_manifest(tmp_path), tmp_path / "b.json")
    assert out_a.read_bytes() == out_b.read_bytes()


def test_verify_ground_truth_rejects_wrong_counts(tmp_path: Path) -> None:
    records, _ = _synthetic_corpus()
    short = records[:-1]  # drop one -> 499
    with pytest.raises(ValueError, match="499"):
        corpus.verify_ground_truth(short, short)


# --------------------------------------------------------------------------- #
# Real-corpus integration checks (skip cleanly when the corpus is absent)     #
# --------------------------------------------------------------------------- #

_DATA_DIR = corpus.data_dir()
_HAS_CORPUS = (
    (_DATA_DIR / corpus.ORACLE_FILENAME).is_file()
    and (_DATA_DIR / corpus.S_CLEANED_FILENAME).is_file()
)
requires_corpus = pytest.mark.skipif(
    not _HAS_CORPUS, reason=f"LongMemEval corpus not found in {_DATA_DIR}"
)


@pytest.fixture(scope="module")
def oracle_records() -> list[dict]:
    with (_DATA_DIR / corpus.ORACLE_FILENAME).open(encoding="utf-8") as handle:
        return json.load(handle)


@pytest.fixture(scope="module")
def real_manifest() -> dict:
    return corpus.build_manifest()


def _ids_of_type(records: list[dict], qtype: str) -> set[str]:
    return {r["question_id"] for r in records if r["question_type"] == qtype}


@requires_corpus
@pytest.mark.integration
def test_real_corpus_ground_truth(oracle_records: list[dict]) -> None:
    assert len(oracle_records) == corpus.EXPECTED_QUESTION_COUNT
    from collections import Counter

    counts = dict(Counter(r["question_type"] for r in oracle_records))
    assert counts == corpus.EXPECTED_TYPE_COUNTS


@requires_corpus
@pytest.mark.integration
def test_real_oracle_and_s_cleaned_share_question_ids() -> None:
    with (_DATA_DIR / corpus.S_CLEANED_FILENAME).open(encoding="utf-8") as handle:
        s_cleaned = json.load(handle)
    with (_DATA_DIR / corpus.ORACLE_FILENAME).open(encoding="utf-8") as handle:
        oracle = json.load(handle)
    assert {r["question_id"] for r in oracle} == {r["question_id"] for r in s_cleaned}


@requires_corpus
@pytest.mark.integration
def test_real_ku_is_exact_full_knowledge_update_set(
    real_manifest: dict, oracle_records: list[dict]
) -> None:
    ku = set(real_manifest["question_ids"]["ku"])
    assert ku == _ids_of_type(oracle_records, "knowledge-update")
    assert len(ku) == 78


@requires_corpus
@pytest.mark.integration
def test_real_ms_sample(real_manifest: dict, oracle_records: list[dict]) -> None:
    ms = real_manifest["question_ids"]["ms"]
    assert len(ms) == 122
    assert len(set(ms)) == 122
    assert set(ms) <= _ids_of_type(oracle_records, "multi-session")


@requires_corpus
@pytest.mark.integration
def test_real_adversarial_sample(
    real_manifest: dict, oracle_records: list[dict]
) -> None:
    adversarial = real_manifest["question_ids"]["adversarial"]
    union = _ids_of_type(oracle_records, "single-session-preference") | _ids_of_type(
        oracle_records, "single-session-user"
    )
    assert len(adversarial) == 20
    assert len(set(adversarial)) == 20
    assert set(adversarial) <= union


@requires_corpus
@pytest.mark.integration
def test_real_groups_pairwise_disjoint(real_manifest: dict) -> None:
    qids = real_manifest["question_ids"]
    ku, ms, adv = set(qids["ku"]), set(qids["ms"]), set(qids["adversarial"])
    assert ku & ms == set()
    assert ku & adv == set()
    assert ms & adv == set()


@requires_corpus
@pytest.mark.integration
def test_real_manifest_metadata(real_manifest: dict) -> None:
    assert real_manifest["seed"] == 20260717
    assert real_manifest["sampling_algorithm"] == corpus.SAMPLING_ALGORITHM
    digests = real_manifest["source_sha256"]
    assert set(digests) == {corpus.ORACLE_FILENAME, corpus.S_CLEANED_FILENAME}
    for digest in digests.values():
        assert len(digest) == 64 and digest == digest.lower()
        int(digest, 16)
    # The small oracle digest is cheap to recompute and must match.
    assert digests[corpus.ORACLE_FILENAME] == corpus.sha256_file(
        _DATA_DIR / corpus.ORACLE_FILENAME
    )


@requires_corpus
@pytest.mark.integration
def test_real_build_split_is_deterministic(oracle_records: list[dict]) -> None:
    indexed = corpus.index_by_type(oracle_records)
    assert corpus.build_split(indexed) == corpus.build_split(indexed)


@requires_corpus
@pytest.mark.integration
def test_on_disk_manifest_matches_fresh_build(real_manifest: dict) -> None:
    """A previously built split_manifest.json must reproduce byte-for-byte.

    The manifest is a deterministic build artifact (not committed); when one is
    present on disk it must equal a fresh build, guarding against silent drift.
    """
    if not corpus.MANIFEST_PATH.is_file():
        pytest.skip("split_manifest.json has not been built on disk")
    on_disk = corpus.MANIFEST_PATH.read_text(encoding="utf-8")
    assert on_disk == corpus.dumps_manifest(real_manifest)
