"""Tests for aphelion.read_adapter — R4 detection algorithm steps 0-3.

Spec ground truth: spec/v0.3-claim-semantics.md §6.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from aphelion.error_codes import WarningCode
from aphelion.read_adapter import AphelionReadAdapter, ConflictClass

A = "0193e2b1-0001-7000-8000-00000000aaaa"
B = "0193e2b1-0001-7000-8000-00000000bbbb"
C = "0193e2b1-0001-7000-8000-00000000cccc"


def _claim(
    claim_id: str,
    *,
    subject: str = "chris",
    polarity: str = "affirm",
    created_at: str = "2026-05-09T10:00:00Z",
    **extras: object,
) -> dict[str, object]:
    base: dict[str, object] = {
        "claim_id": claim_id,
        "subject": subject,
        "polarity": polarity,
        "created_at": created_at,
    }
    base.update(extras)
    return base


def _at(text: str) -> datetime:
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


@pytest.mark.unit
class TestSizeShortCircuits:
    def test_empty_active_set_returns_not_found(self) -> None:
        adapter = AphelionReadAdapter()
        result = adapter.query(subject="chris", candidate_claims=[])
        assert result.conflict_class == ConflictClass.NOT_FOUND
        assert result.primary is None
        assert result.surfaced == ()

    def test_subject_filter_drops_other_subjects(self) -> None:
        adapter = AphelionReadAdapter()
        result = adapter.query(
            subject="chris",
            candidate_claims=[_claim(A, subject="alice")],
        )
        assert result.conflict_class == ConflictClass.NOT_FOUND

    def test_single_active_claim_returns_none(self) -> None:
        adapter = AphelionReadAdapter()
        result = adapter.query(
            subject="chris", candidate_claims=[_claim(A)]
        )
        assert result.conflict_class == ConflictClass.NONE
        assert result.primary is not None
        assert result.primary["claim_id"] == A


@pytest.mark.unit
class TestR2Window:
    def test_claim_outside_valid_until_filtered(self) -> None:
        adapter = AphelionReadAdapter()
        claim = _claim(A, valid_until="2026-05-08T00:00:00Z")
        result = adapter.query(
            subject="chris",
            candidate_claims=[claim],
            query_time=_at("2026-05-09T00:00:00Z"),
        )
        assert result.conflict_class == ConflictClass.NOT_FOUND

    def test_claim_inside_valid_window_kept(self) -> None:
        adapter = AphelionReadAdapter()
        claim = _claim(
            A,
            valid_from="2026-05-01T00:00:00Z",
            valid_until="2026-05-31T00:00:00Z",
        )
        result = adapter.query(
            subject="chris",
            candidate_claims=[claim],
            query_time=_at("2026-05-09T00:00:00Z"),
        )
        assert result.conflict_class == ConflictClass.NONE


@pytest.mark.unit
class TestSupersession:
    def test_explicit_supersession_drops_target(self) -> None:
        adapter = AphelionReadAdapter()
        claim_a = _claim(A, created_at="2026-05-08T00:00:00Z")
        claim_b = _claim(B, created_at="2026-05-09T10:00:00Z", supersedes=[A])
        result = adapter.query(subject="chris", candidate_claims=[claim_a, claim_b])
        assert result.conflict_class == ConflictClass.SUPERSESSION
        assert result.primary is not None
        assert result.primary["claim_id"] == B
        assert result.superseded == (A,)

    def test_dangling_target_emits_warning_and_skips(self) -> None:
        adapter = AphelionReadAdapter()
        # Two active claims to force step 3 to run.
        claim_a = _claim(A)
        claim_b = _claim(B, supersedes=["0193ffff-ffff-7fff-8fff-ffffffffffff"])
        result = adapter.query(subject="chris", candidate_claims=[claim_a, claim_b])
        assert any(
            w.code == WarningCode.CLAIM_SUPERSEDES_DANGLING for w in result.warnings
        )
        # Both still surfaced — dangling target was skipped, not dropped.
        # With both alive after step 3, the residual policy decides; here
        # both polarities are 'affirm' so recency tiebreak applies.
        surfaced_ids = {c["claim_id"] for c in result.surfaced}
        assert surfaced_ids == {A, B}


@pytest.mark.unit
class TestResidualPolicy:
    def test_polarity_divergence_returns_contradiction(self) -> None:
        adapter = AphelionReadAdapter()
        claim_a = _claim(A, polarity="affirm")
        claim_b = _claim(B, polarity="negate")
        result = adapter.query(subject="chris", candidate_claims=[claim_a, claim_b])
        assert result.conflict_class == ConflictClass.CONTRADICTION
        # Spec §6.3a: surface ALL claims on contradiction.
        assert len(result.surfaced) == 2
        assert result.primary is None

    def test_unknown_vs_definite_returns_ambiguity(self) -> None:
        adapter = AphelionReadAdapter()
        definite = _claim(A, polarity="affirm")
        abstain = _claim(B, polarity="unknown")
        result = adapter.query(
            subject="chris",
            candidate_claims=[definite, abstain],
        )
        assert result.conflict_class == ConflictClass.AMBIGUITY
        assert result.primary is not None
        assert result.primary["claim_id"] == A

    def test_recency_tiebreak_when_uniform_polarity(self) -> None:
        adapter = AphelionReadAdapter()
        old = _claim(A, created_at="2026-04-01T00:00:00Z")
        new = _claim(B, created_at="2026-05-09T10:00:00Z")
        result = adapter.query(subject="chris", candidate_claims=[old, new])
        assert result.conflict_class == ConflictClass.SUPERSESSION
        assert result.primary is not None
        assert result.primary["claim_id"] == B

    def test_residual_policy_is_deterministic(self) -> None:
        # Same inputs in the same order → same output.
        adapter = AphelionReadAdapter()
        claims = [_claim(A), _claim(B, polarity="negate")]
        a = adapter.query(subject="chris", candidate_claims=claims)
        b = adapter.query(subject="chris", candidate_claims=claims)
        assert a.conflict_class == b.conflict_class
        assert a.surfaced == b.surfaced


@pytest.mark.unit
class TestQueryTime:
    def test_default_query_time_is_now_utc_truncated(self) -> None:
        adapter = AphelionReadAdapter()
        result = adapter.query(subject="chris", candidate_claims=[])
        # Format: 20-char ISO 8601 UTC Z.
        assert len(result.used_query_time) == 20
        assert result.used_query_time.endswith("Z")

    def test_caller_supplied_query_time_truncated_to_seconds(self) -> None:
        adapter = AphelionReadAdapter()
        # Pass a microsecond-precision datetime; the echoed value is
        # second-precision (spec §6.4).
        sub = datetime(2026, 5, 9, 10, 0, 0, 500_000, tzinfo=timezone.utc)
        result = adapter.query(
            subject="chris", candidate_claims=[], query_time=sub
        )
        assert result.used_query_time == "2026-05-09T10:00:00Z"


@pytest.mark.unit
class TestStepZeroDefence:
    def test_subject_required_check_runs_before_filter(self) -> None:
        # A claim with R4 trigger but no subject must surface the
        # SchemaError even if the caller would have filtered it out.
        from aphelion.errors import SchemaError

        adapter = AphelionReadAdapter()
        bad = {"polarity": "affirm"}  # no subject; R4 trigger present
        with pytest.raises(SchemaError):
            adapter.query(subject="chris", candidate_claims=[bad])
