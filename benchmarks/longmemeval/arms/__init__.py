"""The three LongMemEval memory arms — the benchmark's only independent variable.

* :class:`~benchmarks.longmemeval.arms.plain.PlainStore` — **Arm A**, the floor:
  every claim is kept, duplicates included.
* :class:`~benchmarks.longmemeval.arms.naive_dedup.NaiveDedupStore` — **Arm B**,
  the honest middle control: exact-string dedup after whitespace collapse.
* :class:`~benchmarks.longmemeval.arms.aphelion_arm.AphelionStore` — **Arm C**,
  the machinery under test: lineage-gated ``content_hash`` coalescing, event
  state-machine suppression, and R4 conflict resolution.

Every store implements the same ``(retriever, *, extractor)`` constructor and the
:class:`~benchmarks.longmemeval.pipeline.MemoryStore` protocol, and exposes a
``clusters`` property giving its merge groups for M2.
"""

from benchmarks.longmemeval.arms.aphelion_arm import AphelionStore
from benchmarks.longmemeval.arms.naive_dedup import NaiveDedupStore
from benchmarks.longmemeval.arms.plain import PlainStore

# Arm label -> store class. The canonical A/B/C ordering used by the 3-arm run.
ARM_STORES: dict[str, type] = {
    "A": PlainStore,
    "B": NaiveDedupStore,
    "C": AphelionStore,
}

__all__ = ["ARM_STORES", "AphelionStore", "NaiveDedupStore", "PlainStore"]
