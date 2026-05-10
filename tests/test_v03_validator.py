"""Tests for aphelion.v03_validator (claim semantics R1-R4).

Spec ground truth: spec/v0.3-claim-semantics.md §3-§7.
"""

from __future__ import annotations

import pytest

from aphelion.error_codes import ErrorCode
from aphelion.errors import SchemaError
from aphelion.v03_validator import (
    R4_TRIGGER_FIELDS,
    validate_confidence,
    validate_key_order,
    validate_polarity,
    validate_reserved_fields,
    validate_subject_required_for_r4,
    validate_supersedes,
    validate_v03_fields,
    validate_validtime,
    validate_validtime_order,
)


CLAIM_ID = "0193e2b1-0001-7000-8000-000000000001"
OTHER_ID = "0193e2b1-0001-7000-8000-00000000aaaa"


# ---- R1: confidence ----------------------------------------------------------

@pytest.mark.unit
class TestConfidence:
    def test_accepts_valid_3dp_text(self) -> None:
        validate_confidence(0.85, raw_text="0.850")

    def test_accepts_in_range_without_raw_text(self) -> None:
        validate_confidence(0.5)
        validate_confidence(1.0)
        validate_confidence(0.0)

    def test_rejects_non_numeric(self) -> None:
        with pytest.raises(SchemaError) as exc:
            validate_confidence("0.5")
        assert exc.value.code == ErrorCode.CLAIM_CONFIDENCE_TYPE

    def test_rejects_bool_disguised_as_int(self) -> None:
        # bool is int subclass — must be rejected explicitly
        with pytest.raises(SchemaError) as exc:
            validate_confidence(True)
        assert exc.value.code == ErrorCode.CLAIM_CONFIDENCE_TYPE

    def test_rejects_out_of_range(self) -> None:
        with pytest.raises(SchemaError) as exc:
            validate_confidence(1.5)
        assert exc.value.code == ErrorCode.CLAIM_CONFIDENCE_RANGE
        with pytest.raises(SchemaError) as exc2:
            validate_confidence(-0.1)
        assert exc2.value.code == ErrorCode.CLAIM_CONFIDENCE_RANGE

    def test_rejects_2dp_serialization(self) -> None:
        with pytest.raises(SchemaError) as exc:
            validate_confidence(0.85, raw_text="0.85")
        assert exc.value.code == ErrorCode.CLAIM_CONFIDENCE_PRECISION

    def test_rejects_4dp_serialization(self) -> None:
        with pytest.raises(SchemaError) as exc:
            validate_confidence(0.85, raw_text="0.8500")
        assert exc.value.code == ErrorCode.CLAIM_CONFIDENCE_PRECISION

    def test_rejects_integer_serialization(self) -> None:
        with pytest.raises(SchemaError) as exc:
            validate_confidence(1, raw_text="1")
        assert exc.value.code == ErrorCode.CLAIM_CONFIDENCE_PRECISION


# ---- R2: valid_from / valid_until --------------------------------------------

@pytest.mark.unit
class TestValidTime:
    def test_accepts_strict_iso_z(self) -> None:
        validate_validtime("valid_from", "2026-05-09T10:00:00Z")

    def test_rejects_non_string(self) -> None:
        with pytest.raises(SchemaError) as exc:
            validate_validtime("valid_from", 1700000000)
        assert exc.value.code == ErrorCode.CLAIM_VALIDTIME_TYPE

    def test_rejects_fractional_seconds(self) -> None:
        # Spec §4: format is exactly 20 chars, no fractional seconds.
        with pytest.raises(SchemaError) as exc:
            validate_validtime("valid_from", "2026-05-09T10:00:00.500Z")
        assert exc.value.code == ErrorCode.CLAIM_VALIDTIME_FORMAT

    def test_rejects_missing_z(self) -> None:
        with pytest.raises(SchemaError) as exc:
            validate_validtime("valid_until", "2026-05-09T10:00:00")
        assert exc.value.code == ErrorCode.CLAIM_VALIDTIME_FORMAT

    @pytest.mark.parametrize("bad_ts", [
        "2026-13-01T00:00:00Z",  # month 13
        "2026-02-30T00:00:00Z",  # Feb 30
        "2026-00-00T00:00:00Z",  # month 0 / day 0
    ])
    def test_impossible_calendar_validtime_rejected(self, bad_ts: str) -> None:
        with pytest.raises(SchemaError) as exc:
            validate_validtime("valid_from", bad_ts)
        assert exc.value.code == ErrorCode.CLAIM_VALIDTIME_FORMAT

    def test_order_check_pass_when_both_present_and_ordered(self) -> None:
        validate_validtime_order("2026-05-09T10:00:00Z", "2026-12-31T23:59:59Z")

    def test_order_check_fail_when_reversed(self) -> None:
        with pytest.raises(SchemaError) as exc:
            validate_validtime_order("2026-12-31T23:59:59Z", "2026-05-09T10:00:00Z")
        assert exc.value.code == ErrorCode.CLAIM_VALIDTIME_ORDER

    def test_order_check_pass_when_either_absent(self) -> None:
        validate_validtime_order(None, "2026-12-31T23:59:59Z")
        validate_validtime_order("2026-05-09T10:00:00Z", None)
        validate_validtime_order(None, None)


# ---- R3: polarity ------------------------------------------------------------

@pytest.mark.unit
class TestPolarity:
    @pytest.mark.parametrize("value", ["affirm", "negate", "unknown"])
    def test_accepts_each_enum_value(self, value: str) -> None:
        validate_polarity(value)

    def test_rejects_uppercase(self) -> None:
        with pytest.raises(SchemaError) as exc:
            validate_polarity("Affirm")
        assert exc.value.code == ErrorCode.CLAIM_POLARITY_VALUE

    def test_rejects_unknown_value(self) -> None:
        with pytest.raises(SchemaError) as exc:
            validate_polarity("yes")
        assert exc.value.code == ErrorCode.CLAIM_POLARITY_VALUE

    def test_rejects_non_string(self) -> None:
        with pytest.raises(SchemaError) as exc:
            validate_polarity(1)
        assert exc.value.code == ErrorCode.CLAIM_POLARITY_TYPE


# ---- R4: supersedes ----------------------------------------------------------

@pytest.mark.unit
class TestSupersedes:
    def test_accepts_valid_uuid_v7_array(self) -> None:
        validate_supersedes([OTHER_ID], claim_id=CLAIM_ID)

    def test_accepts_empty_array(self) -> None:
        # Empty supersedes is valid — the field is optional but present-empty
        # is not forbidden.
        validate_supersedes([], claim_id=CLAIM_ID)

    def test_rejects_non_array(self) -> None:
        with pytest.raises(SchemaError) as exc:
            validate_supersedes("not-a-list", claim_id=CLAIM_ID)
        assert exc.value.code == ErrorCode.CLAIM_SUPERSEDES_TYPE

    def test_rejects_non_uuid_v7_entries(self) -> None:
        with pytest.raises(SchemaError) as exc:
            validate_supersedes(["not-a-uuid"], claim_id=CLAIM_ID)
        assert exc.value.code == ErrorCode.CLAIM_SUPERSEDES_TYPE

    def test_rejects_self_reference(self) -> None:
        with pytest.raises(SchemaError) as exc:
            validate_supersedes([CLAIM_ID], claim_id=CLAIM_ID)
        assert exc.value.code == ErrorCode.CLAIM_SUPERSEDES_SELF

    def test_rejects_duplicate_entries(self) -> None:
        with pytest.raises(SchemaError) as exc:
            validate_supersedes([OTHER_ID, OTHER_ID], claim_id=CLAIM_ID)
        assert exc.value.code == ErrorCode.CLAIM_SUPERSEDES_DUPLICATE


# ---- Reserved fields + key order --------------------------------------------

@pytest.mark.unit
class TestReservedAndKeyOrder:
    def test_conflict_class_in_frontmatter_rejected(self) -> None:
        with pytest.raises(SchemaError) as exc:
            validate_reserved_fields({"conflict_class": "none"})
        assert exc.value.code == ErrorCode.CLAIM_RESERVED_FIELD

    def test_no_reserved_fields_passes(self) -> None:
        validate_reserved_fields({"claim_id": CLAIM_ID, "subject": "chris"})

    def test_keys_in_canonical_order_passes(self) -> None:
        validate_key_order(["claim_id", "claim_instance_id", "subject", "type"])

    def test_keys_out_of_order_rejected(self) -> None:
        with pytest.raises(SchemaError) as exc:
            validate_key_order(["subject", "claim_id"])
        assert exc.value.code == ErrorCode.CLAIM_KEY_ORDER


# ---- Subject required when R4 (D1.5) -----------------------------------------

@pytest.mark.unit
class TestSubjectRequiredForR4:
    def test_no_r4_fields_no_subject_passes(self) -> None:
        # confidence is excluded from trigger list, so a claim with only
        # confidence and no subject is fine.
        validate_subject_required_for_r4({"confidence": 0.5})

    @pytest.mark.parametrize("trigger_field", sorted(R4_TRIGGER_FIELDS))
    def test_each_trigger_without_subject_rejected(self, trigger_field: str) -> None:
        with pytest.raises(SchemaError) as exc:
            validate_subject_required_for_r4({trigger_field: "any-value"})
        assert exc.value.code == ErrorCode.CLAIM_SUBJECT_REQUIRED_FOR_CONFLICT

    def test_trigger_with_subject_passes(self) -> None:
        validate_subject_required_for_r4({"polarity": "affirm", "subject": "chris"})

    def test_empty_subject_treated_as_missing(self) -> None:
        # Empty/whitespace string MUST NOT satisfy the requirement —
        # the spec rationale (§6.5) says a non-empty grouping key is
        # required for R4 detection to be meaningful.
        with pytest.raises(SchemaError) as exc:
            validate_subject_required_for_r4({"polarity": "affirm", "subject": "  "})
        assert exc.value.code == ErrorCode.CLAIM_SUBJECT_REQUIRED_FOR_CONFLICT

    def test_confidence_alone_does_not_trigger(self) -> None:
        # Phase-4 backward-compat carve-out — confidence is excluded.
        validate_subject_required_for_r4({"confidence": 0.85})


# ---- Aggregate validate_v03_fields -------------------------------------------

@pytest.mark.unit
class TestAggregate:
    def _valid_claim(self) -> dict[str, object]:
        return {
            "claim_id": CLAIM_ID,
            "subject": "chris",
            "polarity": "affirm",
            "confidence": 0.85,
            "valid_from": "2026-05-09T10:00:00Z",
        }

    def test_full_valid_claim_passes(self) -> None:
        validate_v03_fields(self._valid_claim(), raw_field_text={"confidence": "0.850"})

    def test_aggregate_surfaces_first_violation(self) -> None:
        claim = self._valid_claim()
        claim["polarity"] = "wrong-value"
        with pytest.raises(SchemaError) as exc:
            validate_v03_fields(claim)
        assert exc.value.code == ErrorCode.CLAIM_POLARITY_VALUE

    def test_aggregate_runs_subject_check_after_field_checks(self) -> None:
        claim = {"polarity": "affirm"}  # no subject; trigger present
        with pytest.raises(SchemaError) as exc:
            validate_v03_fields(claim)
        assert exc.value.code == ErrorCode.CLAIM_SUBJECT_REQUIRED_FOR_CONFLICT

    def test_key_order_only_checked_when_provided(self) -> None:
        # No keys_in_order arg — key order skipped even if dict iteration
        # were technically out of order.
        validate_v03_fields({"claim_id": CLAIM_ID})
        # With keys_in_order — enforced.
        with pytest.raises(SchemaError):
            validate_v03_fields(
                {"subject": "chris", "claim_id": CLAIM_ID},
                keys_in_order=["subject", "claim_id"],
            )

    def test_supersedes_self_uses_explicit_claim_id(self) -> None:
        claim = {
            "claim_id": CLAIM_ID,
            "subject": "chris",
            "supersedes": [OTHER_ID],
        }
        # Caller passes claim_id explicitly — falls back if absent
        validate_v03_fields(claim, claim_id=CLAIM_ID)
        with pytest.raises(SchemaError):
            validate_v03_fields(
                {**claim, "supersedes": [CLAIM_ID]},
                claim_id=CLAIM_ID,
            )
