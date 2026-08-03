"""Offline metrics for the LongMemEval 3-arm benchmark.

The three metrics that can be computed without a model are implemented here,
each with a scorer plus the bridge that feeds it straight from an arm's store:

* :mod:`~benchmarks.longmemeval.metrics.m2_dedup` — deduplication precision /
  recall / F1 from labeled duplicate pairs and an arm's merge clusters
  (``score_stores`` scores every arm against one shared ground truth).
* :mod:`~benchmarks.longmemeval.metrics.m3_contamination` — the rate at which a
  retrieved context still surfaces a superseded ("old") value
  (``score_stores`` retrieves every arm with the same questions and ``top_k``).
* :mod:`~benchmarks.longmemeval.metrics.m5_roundtrip` — round-trip determinism:
  a verdict-level cross-tool check against the independent
  ``scripts/external_reader.py``, plus byte-level pack/unpack/re-pack equality
  through the ``aphelion`` package's public API. The *pinned* M5 gate needs the
  ``W-M5`` second canonical reader and stays blocked until it lands — see that
  module's ``gate_status``.

M1 (QA accuracy) and M4 (latency/perf) need the pinned answering and judge
models, so they belong to the GB10-gated execution run rather than this offline
package. Nothing here makes a model or network call.
"""
