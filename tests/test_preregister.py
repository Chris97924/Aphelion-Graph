"""Locks the LongMemEval 3-arm pre-registration.

The thresholds in ``benchmarks/longmemeval/preregister.json`` were pinned by the
maintainer on 2026-07-19 and are frozen before any benchmark run. This test
asserts the machine-readable pre-registration carries EXACTLY the pinned values
(a full-dict assertion over every key -- deliberately not spot-checks) and that
the recorded design-doc SHA-256 matches the doc bytes on disk, so the frozen
document and its pinned values cannot silently drift apart.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
PREREGISTER = REPO_ROOT / "benchmarks" / "longmemeval" / "preregister.json"
DESIGN_DOC = REPO_ROOT / "docs" / "benchmark" / "longmemeval-3arm-design.md"

# The complete set of pinned values, EXCEPT the dynamic ``design_doc_sha256``
# (verified separately by recomputation). Every key/value here is asserted
# against preregister.json; nothing is left unchecked.
EXPECTED: dict = {
    "benchmark": "longmemeval-3arm",
    "status": "pinned",
    "pinned_date": "2026-07-19",
    "design_doc": "docs/benchmark/longmemeval-3arm-design.md",
    "split": {
        "knowledge_update": 78,
        "knowledge_update_basis": "all",
        "multi_session": 122,
        "multi_session_basis": "seeded sample",
        "adversarial": 20,
        "adversarial_basis": "seeded sample",
    },
    "sampling_algorithm": (
        "question_ids sorted lexicographically per pool, then "
        "random.Random(20260717).sample; KU pool taken in full (no sampling)"
    ),
    "metrics": {
        "M1": {
            "gate": "C-B >= +3pp on knowledge-update",
            "N": 78,
            "reporting": "directional, bootstrapped CI, C-A secondary",
        },
        "M2": {
            "gate": "C.F1 > A.F1 + 0.10 AND C.F1 >= B.F1 - epsilon",
            "epsilon": 0.02,
        },
        "M3": {
            "gate": "C <= 0.5 * A",
            "N": 78,
            "denominator": "knowledge-update",
        },
        "M4": {
            "gate": "none (sanity-only)",
            "tripwire": "10x Arm A",
        },
        "M5": {
            "gate": "100/100 byte-identical canonical form",
            "method": (
                "option (a) W-M5 full canonical independent reader, "
                "true two-implementation byte-equality"
            ),
        },
        "AG": {
            "gate": "C-B <= +3pp on adversarial set",
            "N": 20,
            "gating": "non-gating diagnostic tripwire",
        },
    },
    "answering_model": "gpt-oss:120b @ GB10 ollama 192.168.1.134:11434",
    "extractor_model": "gpt-oss:120b @ GB10 ollama 192.168.1.134:11434",
    "model_fairness_constraint": (
        "answering model, extractor model, and retriever MUST be identical "
        "across arms A/B/C; the memory layer is the only independent variable"
    ),
    "judge_model": (
        "claude-opus-4-8 via claude -p (subscription), fallback gemini-2.5-pro"
    ),
    "retriever": "shared deterministic BM25 (stdlib), identical across arms",
    "temperature": 0,
    "seed": 20260717,
}


def _load_preregister() -> dict:
    return json.loads(PREREGISTER.read_text(encoding="utf-8"))


def test_preregister_and_design_doc_exist() -> None:
    assert PREREGISTER.is_file(), f"pre-registration not found at {PREREGISTER}"
    assert DESIGN_DOC.is_file(), f"design doc not found at {DESIGN_DOC}"


def test_preregister_carries_exactly_the_pinned_values() -> None:
    """Full-dict assertion over every pinned key -- spot-checks are forbidden."""
    actual = _load_preregister()

    recorded_hash = actual.pop("design_doc_sha256", None)
    assert recorded_hash is not None, "preregister.json is missing design_doc_sha256"

    # Iterate the whole expected dict so a mismatch names the offending key...
    for key, value in EXPECTED.items():
        assert key in actual, f"preregister.json is missing pinned key: {key!r}"
        assert actual[key] == value, (
            f"pinned value drift for {key!r}:\n"
            f"  expected = {value!r}\n"
            f"  actual   = {actual[key]!r}"
        )
    # ...then assert deep equality so no extra or missing key escapes the check.
    assert actual == EXPECTED, (
        "preregister.json does not equal the pinned dict exactly "
        "(extra or missing keys once the sha256 is removed):\n"
        f"  expected keys = {sorted(EXPECTED)}\n"
        f"  actual keys   = {sorted(actual)}"
    )


def test_design_doc_sha256_matches_recorded() -> None:
    """Recompute the design-doc SHA-256 and assert it matches the recorded value."""
    recorded_hash = _load_preregister()["design_doc_sha256"]

    assert isinstance(recorded_hash, str) and len(recorded_hash) == 64, (
        f"design_doc_sha256 must be 64 hex chars, got {recorded_hash!r}"
    )
    assert recorded_hash == recorded_hash.lower(), "design_doc_sha256 must be lowercase hex"

    computed = hashlib.sha256(DESIGN_DOC.read_bytes()).hexdigest()
    assert computed == recorded_hash, (
        "design doc SHA-256 mismatch -- was the doc edited after pinning?\n"
        f"  recorded = {recorded_hash}\n"
        f"  computed = {computed}"
    )
