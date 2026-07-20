"""Deterministic LongMemEval corpus split builder.

Builds a frozen, pre-registered question split for the LongMemEval 3-arm
benchmark and writes it to ``split_manifest.json`` next to this module:

* ``ku``          - the full knowledge-update pool (no sampling).
* ``ms``          - a deterministic sample of the multi-session pool.
* ``adversarial`` - a deterministic sample of the union of the
  single-session-preference and single-session-user pools.

The split is reproducible from the seed and the source SHA-256 digests recorded
in the manifest. Before sampling, the corpus is checked against the pinned
ground truth (question count and per-type counts) so a split is never frozen
over an unexpected corpus.

Build the manifest with::

    python -m benchmarks.longmemeval.corpus

The corpus lives in the directory named by ``LONGMEMEVAL_DATA_DIR`` (default
``E:/Workspace/longmemeval/data``) and consists of two top-level JSON arrays of
question records, ``longmemeval_oracle.json`` and ``longmemeval_s_cleaned.json``.
"""

from __future__ import annotations

import hashlib
import json
import os
import random
from collections import Counter
from pathlib import Path

DATA_DIR_ENV = "LONGMEMEVAL_DATA_DIR"
DEFAULT_DATA_DIR = "E:/Workspace/longmemeval/data"
ORACLE_FILENAME = "longmemeval_oracle.json"
S_CLEANED_FILENAME = "longmemeval_s_cleaned.json"

SEED = 20260717
MS_SAMPLE_SIZE = 122
ADVERSARIAL_SAMPLE_SIZE = 20

EXPECTED_QUESTION_COUNT = 500
EXPECTED_TYPE_COUNTS = {
    "knowledge-update": 78,
    "multi-session": 133,
    "single-session-user": 70,
    "single-session-assistant": 56,
    "single-session-preference": 30,
    "temporal-reasoning": 133,
}

KU_TYPE = "knowledge-update"
MS_TYPE = "multi-session"
ADVERSARIAL_TYPES = ("single-session-preference", "single-session-user")

# Recorded verbatim in the manifest so the frozen split documents its own rule.
# MUST stay byte-identical to preregister.json's ``sampling_algorithm`` --
# enforced by tests/test_benchmarks_corpus.py -- since preregister.json is the
# pinned anchor and this constant is required to mirror it exactly, not
# paraphrase it.
#
# In concrete terms this rule means: multi_session samples 122 of the 133
# multi-session question_ids, and adversarial samples 20 from the union pool of
# single-session-preference + single-session-user question_ids (both via the
# lexicographic-sort + random.Random(20260717).sample procedure named below).
SAMPLING_ALGORITHM = (
    "question_ids sorted lexicographically per pool, then "
    "random.Random(20260717).sample; KU pool taken in full (no sampling)"
)

MANIFEST_PATH = Path(__file__).resolve().parent / "split_manifest.json"


def data_dir() -> Path:
    """Return the corpus directory from ``LONGMEMEVAL_DATA_DIR`` or the default."""
    return Path(os.environ.get(DATA_DIR_ENV, DEFAULT_DATA_DIR))


def _load_json_array(path: Path) -> list[dict]:
    """Load a top-level JSON array of records, decoded as UTF-8."""
    with path.open(encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, list):
        raise ValueError(
            f"{path}: expected a top-level JSON array, got {type(data).__name__}"
        )
    return data


def sha256_file(path: Path) -> str:
    """Return the hex SHA-256 of ``path``, read in binary chunks."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def index_by_type(records: list[dict]) -> dict[str, list[str]]:
    """Map each ``question_type`` to its sorted, unique list of ``question_id``."""
    buckets: dict[str, set[str]] = {}
    for record in records:
        buckets.setdefault(record["question_type"], set()).add(record["question_id"])
    return {qtype: sorted(ids) for qtype, ids in buckets.items()}


def verify_ground_truth(oracle: list[dict], s_cleaned: list[dict]) -> None:
    """Assert the corpus matches the pinned pre-registration ground truth.

    Raises ``ValueError`` if the question count, per-type counts, or the shared
    ``question_id`` set do not match, so the build aborts rather than freezing a
    split over an unexpected corpus.
    """
    for name, records in (("oracle", oracle), (S_CLEANED_FILENAME, s_cleaned)):
        if len(records) != EXPECTED_QUESTION_COUNT:
            raise ValueError(
                f"{name}: expected {EXPECTED_QUESTION_COUNT} questions, "
                f"got {len(records)}"
            )

    oracle_ids = {record["question_id"] for record in oracle}
    s_ids = {record["question_id"] for record in s_cleaned}
    if len(oracle_ids) != EXPECTED_QUESTION_COUNT:
        raise ValueError(
            f"oracle: expected {EXPECTED_QUESTION_COUNT} unique question_ids, "
            f"got {len(oracle_ids)}"
        )
    if oracle_ids != s_ids:
        only_oracle = len(oracle_ids - s_ids)
        only_s = len(s_ids - oracle_ids)
        raise ValueError(
            "oracle and s_cleaned question_id sets differ: "
            f"{only_oracle} only in oracle, {only_s} only in s_cleaned"
        )

    counts = dict(Counter(record["question_type"] for record in oracle))
    if counts != EXPECTED_TYPE_COUNTS:
        raise ValueError(
            f"oracle type counts {dict(sorted(counts.items()))} "
            f"!= expected {dict(sorted(EXPECTED_TYPE_COUNTS.items()))}"
        )


def _sample(ids: set[str] | list[str], k: int, seed: int) -> list[str]:
    """Sort ``ids`` lexicographically then draw ``k`` with a fresh RNG at ``seed``."""
    return random.Random(seed).sample(sorted(ids), k)


def build_split(
    type_to_ids: dict[str, list[str]],
    ms_sample_size: int = MS_SAMPLE_SIZE,
    adversarial_sample_size: int = ADVERSARIAL_SAMPLE_SIZE,
    seed: int = SEED,
) -> dict[str, list[str]]:
    """Return the ``ku``/``ms``/``adversarial`` split from a type -> ids map.

    ``ku`` is taken in full; ``ms`` and ``adversarial`` are each sampled with a
    fresh ``random.Random(seed)`` over their lexicographically sorted pool. All
    returned id lists are sorted so the manifest is canonical and diff-stable.
    """
    ku = sorted(type_to_ids.get(KU_TYPE, []))

    ms = _sample(type_to_ids.get(MS_TYPE, []), ms_sample_size, seed)

    adversarial_pool: set[str] = set()
    for qtype in ADVERSARIAL_TYPES:
        adversarial_pool.update(type_to_ids.get(qtype, []))
    adversarial = _sample(adversarial_pool, adversarial_sample_size, seed)

    return {"ku": ku, "ms": sorted(ms), "adversarial": sorted(adversarial)}


def build_manifest(directory: Path | None = None) -> dict:
    """Load the corpus, verify ground truth, and return the split manifest dict."""
    directory = directory or data_dir()
    oracle_path = directory / ORACLE_FILENAME
    s_cleaned_path = directory / S_CLEANED_FILENAME

    oracle = _load_json_array(oracle_path)
    s_cleaned = _load_json_array(s_cleaned_path)
    verify_ground_truth(oracle, s_cleaned)

    groups = build_split(index_by_type(oracle))

    return {
        "seed": SEED,
        "sampling_algorithm": SAMPLING_ALGORITHM,
        "counts": {
            "ku": len(groups["ku"]),
            "ms": len(groups["ms"]),
            "adversarial": len(groups["adversarial"]),
            "total": sum(len(ids) for ids in groups.values()),
        },
        "question_ids": groups,
        "source_sha256": {
            ORACLE_FILENAME: sha256_file(oracle_path),
            S_CLEANED_FILENAME: sha256_file(s_cleaned_path),
        },
    }


def dumps_manifest(manifest: dict) -> str:
    """Serialize the manifest deterministically (sorted keys, trailing newline)."""
    return json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def write_manifest(manifest: dict, path: Path = MANIFEST_PATH) -> Path:
    """Write the manifest to ``path`` as UTF-8 and return the path."""
    path.write_text(dumps_manifest(manifest), encoding="utf-8")
    return path


def main() -> None:
    manifest = build_manifest()
    path = write_manifest(manifest)
    counts = manifest["counts"]
    print(f"wrote {path}")
    print(
        f"  counts ku={counts['ku']} ms={counts['ms']} "
        f"adversarial={counts['adversarial']} total={counts['total']}"
    )
    for name, digest in sorted(manifest["source_sha256"].items()):
        print(f"  sha256 {name} = {digest}")


if __name__ == "__main__":
    main()
