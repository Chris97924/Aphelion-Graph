"""Metric skeletons for the LongMemEval 3-arm benchmark (prep scope).

This package carries only the metrics pinned for the *prep* drive:

* :mod:`~benchmarks.longmemeval.metrics.m2_dedup` — deduplication precision /
  recall / F1 from labeled duplicate pairs and an arm's merge clusters.
* :mod:`~benchmarks.longmemeval.metrics.m3_contamination` — the rate at which a
  retrieved context still surfaces a superseded ("old") value.
* :mod:`~benchmarks.longmemeval.metrics.m5_roundtrip` — a verdict-level wrapper
  over the independent Aphelion reader (``scripts/external_reader.py``).

M1 (QA accuracy) and M4 (latency/perf) belong to the GB10-gated execution drive
and are deliberately absent here. Everything in this package is pure stdlib and
makes no model or network calls.
"""
