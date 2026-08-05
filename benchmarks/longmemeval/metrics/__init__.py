"""Offline metrics for the LongMemEval 3-arm benchmark.

Every metric is implemented here, each with a scorer plus the bridge that feeds
it straight from an arm's store or from the blind scoring phase:

* :mod:`~benchmarks.longmemeval.metrics.m1_qa` — QA accuracy on
  knowledge-update, the pinned ``C − B`` contrast and its bootstrapped CI. The
  answering and judge models are reached only through the ``PipelineConfig``
  injection surface, so this module runs no model itself: an unpinned judge
  raises ``UnpinnedStageError`` and an injected offline judge makes the whole
  path runnable without a socket.
* :mod:`~benchmarks.longmemeval.metrics.m2_dedup` — deduplication precision /
  recall / F1 from labeled duplicate pairs and an arm's merge clusters
  (``score_stores`` scores every arm against one shared ground truth).
* :mod:`~benchmarks.longmemeval.metrics.m3_contamination` — the rate at which a
  retrieved context still surfaces a superseded ("old") value
  (``score_stores`` retrieves every arm with the same questions and ``top_k``).
* :mod:`~benchmarks.longmemeval.metrics.m4_perf` — sanity-only storage and
  latency, with the advisory 10× tripwire. The clock is injectable for the same
  reason the models are: wall time is not reproducible.
* :mod:`~benchmarks.longmemeval.metrics.m5_roundtrip` — round-trip determinism:
  a verdict-level cross-tool check against the independent
  ``scripts/external_reader.py``, plus byte-level pack/unpack/re-pack equality
  through the ``aphelion`` package's public API. The *pinned* M5 gate needs the
  ``W-M5`` second canonical reader and stays blocked until it lands — see that
  module's ``gate_status``.

Every §4 threshold these modules enforce is parsed out of ``preregister.json``
rather than re-declared in Python, so a frozen gate and the code enforcing it
cannot drift apart. Nothing here makes a model or network call.
"""
