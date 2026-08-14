"""Locks the LongMemEval 3-arm pre-registration.

The thresholds in ``benchmarks/longmemeval/preregister.json`` were pinned by the
maintainer on 2026-07-19 and are frozen before any benchmark run. This test
asserts the machine-readable pre-registration carries EXACTLY the pinned values
(a full-dict assertion over every key -- deliberately not spot-checks) and that
the recorded design-doc SHA-256 matches the doc bytes on disk, so the frozen
document and its pinned values cannot silently drift apart.

Amended 2026-08-14 under the design doc's §6.3 pre-registration window (still
legal: no arm has run). M3's denominator is corrected 78 -> 72 (the 6 abstention
``_abs`` knowledge-update variants carry no old->new update, so no stale-value
label can exist for them), and M1/M3/AG gain the pre-registered interpretation
and breach-response text the pinned table had left to be filled in after results
were seen. No gate ratio or threshold moved; ``split.knowledge_update`` stays 78
and M1 still gates at N=78.
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
    "amendments": [
        {
            "date": "2026-08-14",
            "authority": (
                "design doc S6.3 pre-registration amendment window - legal "
                "because no arm has run"
            ),
            "summary": (
                "closes the four pinned-number defects found by the 2026-08-03 "
                "threshold audit: (1) M3 denominator corrected 78 -> 72; (2) M1 "
                "+3pp recorded as a decision rule, not a significance test; (3) "
                "M3 INCONCLUSIVE floor at 12 contaminated Arm A questions; (4) "
                "AG breach response split into Tier 1 (+5pp) and Tier 2 (>= +10pp)"
            ),
            "gates_moved": (
                "none - M1 +3pp, M2 A+0.10 / epsilon=0.02, M3 C <= 0.5 * A, M4 "
                "no-gate, M5 100/100 and AG +3pp are all unchanged. Defect 1 "
                "corrects a denominator that contradicted its own stated "
                "justification; defects 2-4 add interpretation and response "
                "depth the pinned text left to be filled in after seeing results"
            ),
            "scope_note": (
                "split.knowledge_update stays 78: all 78 KU questions remain in "
                "the split and M1 still gates at N=78. Only M3's scoring "
                "denominator is 72"
            ),
        }
    ],
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
            "interpretation": (
                "decision rule, not a significance test: at N=78 the smallest "
                "paired difference reaching p<0.05 is 6 net discordant questions "
                "(7.7pp), so the bootstrapped CI is reported for honesty and "
                "does not overturn the gate in either direction (amended "
                "2026-08-14, design doc S4 M1 row)"
            ),
        },
        "M2": {
            "gate": "C.F1 > A.F1 + 0.10 AND C.F1 >= B.F1 - epsilon",
            "epsilon": 0.02,
        },
        "M3": {
            "gate": "C <= 0.5 * A",
            "N": 72,
            "denominator": (
                "knowledge-update, excluding the 6 abstention (_abs) variants"
            ),
            "denominator_amendment": (
                "corrected 78 -> 72 on 2026-08-14 (design doc S4 M3 row): the 6 "
                "KU _abs variants (031748ae_abs, 0ddfec37_abs, 2133c1b5_abs, "
                "2698e78f_abs, 6aeb4375_abs, f685340e_abs) encode no old->new "
                "update, so no stale-value label can exist for them. Factual "
                "correction to the denominator; the C <= 0.5 * A ratio is "
                "unchanged"
            ),
            "inconclusive_floor": 12,
            "inconclusive_rule": (
                "if Arm A contaminates fewer than 12 of the 72 questions, M3 is "
                "reported INCONCLUSIVE (neither pass nor fail): even a perfect "
                "halving cannot clear exact-binomial noise below that count, so "
                "M3 does not fire the design doc S8 event-state-machine "
                "demotion branch and does not count toward the S8 All-pass row "
                "(amended 2026-08-14)"
            ),
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
            "breach_response": {
                "tier1_pp": 5.0,
                "tier1": (
                    "one-question breach: log it and diff that single question's "
                    "Arm B vs Arm C retrieved context, recording the finding in "
                    "the results. A bounded check, not an audit"
                ),
                "tier2_pp": 10.0,
                "tier2": (
                    "two-or-more-question breach: the full leakage "
                    "investigation, completed before M1/M3 are trusted (design "
                    "doc S6 guard 4)"
                ),
                "rationale": (
                    "at N=20 one question is 5pp, so the smallest non-zero C-B "
                    "already breaches the +3pp tripwire; under a true null it "
                    "fires ~25-36% of the time. The +3pp tripwire is unchanged - "
                    "only the depth of the mandated response is pinned (amended "
                    "2026-08-14)"
                ),
            },
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
    """Recompute the design-doc SHA-256 and assert it matches the recorded value.

    The doc is hashed after normalizing CRLF -> LF so the pin is checkout-line-ending
    independent: a Windows CRLF working tree and a Linux/CI LF checkout of the same
    committed content must hash identically.
    """
    recorded_hash = _load_preregister()["design_doc_sha256"]

    assert isinstance(recorded_hash, str) and len(recorded_hash) == 64, (
        f"design_doc_sha256 must be 64 hex chars, got {recorded_hash!r}"
    )
    assert recorded_hash == recorded_hash.lower(), "design_doc_sha256 must be lowercase hex"

    normalized = DESIGN_DOC.read_bytes().replace(b"\r\n", b"\n")
    computed = hashlib.sha256(normalized).hexdigest()
    assert computed == recorded_hash, (
        "design doc SHA-256 mismatch -- was the doc edited after pinning?\n"
        f"  recorded = {recorded_hash}\n"
        f"  computed = {computed}"
    )
