"""Tests for Arm C — the aphelion claim-semantics store.

Covers the S1 acceptance contract for the arm under test:

* **Coalescing** happens iff ``claim_id`` *and* ``content_hash`` both match; a
  same-hash/different-lineage pair and a proximity-only pair must both survive
  as separate claims (the regression tests the design doc §2.3 mandates).
* **Conflict preservation** across every one of the five R4 fields the
  ``content_hash`` identity projection excludes — ``supersedes``, ``valid_from``,
  ``valid_until``, ``polarity``, ``conflict_class``. Each is checked twice: that
  it really is excluded from the hash, and that a cross-lineage pair differing
  only in it still reaches R4 instead of being merged away.
* **Surfacing** per verdict: ``contradiction`` surfaces every claim with no
  primary; ``superseded`` / ``withdrawn`` are suppressed.
* **Collision**: one lineage carrying two hashes is a hard
  ``ERR-SEM-DUPLICATE-HASH-COLLISION`` failure, not a silent merge.

All pure stdlib plus the ``aphelion`` package; no model or network calls.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from aphelion.content_hash import EXCLUDED_KEYS, IDENTITY_FIELDS
from aphelion.error_codes import ErrorCode
from aphelion.errors import SchemaError, SemanticError
from aphelion.read_adapter import ConflictClass
from aphelion.v03_validator import R4_TRIGGER_FIELDS

from benchmarks.longmemeval.arms.aphelion_arm import (
    SUPPRESSED_STATES,
    AphelionStore,
    CoalesceConflictError,
    claim_from_frontmatter,
    coalescing_key,
    content_hash_of,
)
from benchmarks.longmemeval.pipeline import MemoryStore
from benchmarks.longmemeval.retriever import BM25Retriever

# Pinned so R2 valid-time filtering is reproducible instead of tracking now().
QUERY_TIME = datetime(2026, 7, 17, tzinfo=timezone.utc)

# The five R4 fields the identity projection excludes (design doc §2.3
# amendment), each with two differing values.
R4_EXCLUDED_FIELDS: tuple[tuple[str, object, object], ...] = (
    ("supersedes", ["lineage-x"], ["lineage-y"]),
    ("valid_from", "2026-01-01T00:00:00Z", "2026-06-01T00:00:00Z"),
    ("valid_until", "2026-08-01T00:00:00Z", "2026-09-01T00:00:00Z"),
    ("polarity", "affirm", "negate"),
    ("conflict_class", "none", "contradiction"),
)

BASE_FIELDS = {
    "subject": "chris/5k-personal-best",
    "predicate": "equals",
    "object": "22:00",
    "state": "active",
    "type": "running_record",
}


def _store(**kwargs) -> AphelionStore:
    return AphelionStore(BM25Retriever(), query_time=QUERY_TIME, **kwargs)


def _claim(
    claim_id: str, *, record_id: str | None = None, text: str = "5K PB 22:00", **extra
):
    return claim_from_frontmatter(
        {**BASE_FIELDS, "claim_id": claim_id, **extra}, text, record_id=record_id
    )


# ---------------------------------------------------------------------------
# Coalescing — both conditions required
# ---------------------------------------------------------------------------


def test_same_lineage_and_same_hash_coalesces() -> None:
    """The one case that merges: same lineage, byte-equal content hash."""
    store = _store()
    store.add_claims([_claim("L1", record_id="r1"), _claim("L1", record_id="r2")])

    assert len(store.claims) == 1
    assert store.clusters == [["r1", "r2"]]


def test_same_content_hash_different_claim_id_does_not_coalesce() -> None:
    """The regression the design doc §2.3 explicitly requires.

    Byte-equal ``content_hash`` is *not* sufficient — coalescing is lineage
    scoped, so a cross-lineage pair must survive intact for R4 to classify.
    """
    left = _claim("L1", record_id="r1")
    right = _claim("L2", record_id="r2")
    assert content_hash_of(left) == content_hash_of(right)

    store = _store()
    store.add_claims([left, right])

    assert len(store.claims) == 2
    assert sorted(store.clusters) == [["r1"], ["r2"]]


def test_proximity_only_pair_does_not_coalesce() -> None:
    """No fuzzy/near-duplicate merging: similar text with different content stays split."""
    left = _claim("L1", record_id="r1", text="My 5K personal best is 22:00")
    right = _claim(
        "L2", record_id="r2", text="my 5k personal best is 22:00", object="22:01"
    )
    assert content_hash_of(left) != content_hash_of(right)

    store = _store()
    store.add_claims([left, right])
    assert len(store.claims) == 2


def test_coalescing_key_is_lineage_and_hash() -> None:
    claim = _claim("L1")
    assert coalescing_key(claim) == ("L1", content_hash_of(claim))


def test_same_claim_id_different_hash_is_a_collision_error() -> None:
    """spec/lifecycle-state-machine.md §5.1: MUST fail, no auto-reconciliation."""
    store = _store()
    with pytest.raises(SemanticError) as excinfo:
        store.add_claims(
            [_claim("L1", record_id="r1"), _claim("L1", record_id="r2", object="24:30")]
        )
    assert excinfo.value.code is ErrorCode.DUPLICATE_HASH_COLLISION


# ---------------------------------------------------------------------------
# Import-order irrelevance (spec/lifecycle-state-machine.md §5.3)
# ---------------------------------------------------------------------------


def _ingest_outcome(claims: list) -> tuple:
    """Everything one ingest order can be observed to produce.

    Either the loud error (type + message) or the full retained/retrieved state,
    rendered canonically so two orders compare byte-for-byte. Metadata is part of
    the comparison on purpose: the order-dependence being pinned here is invisible
    in the claim *count* and shows up only in the surviving frontmatter.
    """
    store = _store()
    try:
        store.add_claims(list(claims))
    except Exception as exc:  # noqa: BLE001 — the outcome under comparison
        return ("error", type(exc).__name__, str(exc))
    return (
        "ok",
        tuple(claim.id for claim in store.retrieve("5K personal best")),
        tuple(sorted(tuple(sorted(members)) for members in store.clusters)),
        tuple(
            json.dumps(claim.metadata, sort_keys=True, default=str)
            for claim in sorted(store.claims, key=lambda claim: claim.id)
        ),
    )


def test_expired_then_active_matches_active_then_expired() -> None:
    """The concrete import-order bug: R2 validity decided by ingest order.

    ``valid_until`` is excluded from the identity projection, so these two share
    a ``content_hash`` and the same lineage. Keeping whichever arrived first
    means expired-then-active retrieves nothing while active-then-expired
    surfaces the claim — M1/M3 would depend on corpus ordering.
    """
    expired = _claim("L1", record_id="r1", valid_until="2026-01-01T00:00:00Z")
    active = _claim("L1", record_id="r2")
    assert content_hash_of(expired) == content_hash_of(active)

    assert _ingest_outcome([expired, active]) == _ingest_outcome([active, expired])


@pytest.mark.parametrize("field,left,right", R4_EXCLUDED_FIELDS)
def test_same_lineage_r4_difference_is_import_order_independent(
    field: str, left: object, right: object
) -> None:
    """``import(A); import(B)`` must equal ``import(B); import(A)`` for every R4 field.

    ``spec/lifecycle-state-machine.md`` §5.3 makes this a MUST, and §5.1's second
    clause fixes the shape of the alternative: when a same-lineage pair cannot be
    reconciled, *both* orderings raise the same error.
    """
    a = _claim("L1", record_id="r1", **{field: left})
    b = _claim("L1", record_id="r2", **{field: right})
    assert content_hash_of(a) == content_hash_of(b)

    assert _ingest_outcome([a, b]) == _ingest_outcome([b, a])


@pytest.mark.parametrize("field,left,right", R4_EXCLUDED_FIELDS)
def test_conflicting_r4_metadata_is_rejected_not_silently_merged(
    field: str, left: object, right: object
) -> None:
    """Same lineage + same hash + disagreeing R4 is not a duplicate — fail loud."""
    store = _store()
    with pytest.raises(CoalesceConflictError, match=field):
        store.add_claims(
            [
                _claim("L1", record_id="r1", **{field: left}),
                _claim("L1", record_id="r2", **{field: right}),
            ]
        )


def test_identical_r4_metadata_still_coalesces() -> None:
    """The rejection is scoped to *disagreement*; a true duplicate still merges."""
    store = _store()
    store.add_claims(
        [
            _claim(
                "L1",
                record_id="r1",
                polarity="affirm",
                valid_from="2026-01-01T00:00:00Z",
            ),
            _claim(
                "L1",
                record_id="r2",
                polarity="affirm",
                valid_from="2026-01-01T00:00:00Z",
            ),
        ]
    )
    assert len(store.claims) == 1
    assert store.clusters == [["r1", "r2"]]


def test_missing_claim_id_fails_loud() -> None:
    """Arm C cannot place an un-lineaged claim on either side of its rule."""
    store = _store()
    unlineaged = claim_from_frontmatter({**BASE_FIELDS, "claim_id": "tmp"}, "x")
    unlineaged.metadata.pop("claim_id")
    with pytest.raises(ValueError, match="claim_id"):
        store.add_claims([unlineaged])


# ---------------------------------------------------------------------------
# Conflict preservation across every R4-excluded field
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("field,left,right", R4_EXCLUDED_FIELDS)
def test_r4_field_is_excluded_from_the_identity_projection(
    field: str, left: object, right: object
) -> None:
    """Two claims differing only in an R4 field share a ``content_hash``.

    Note *how* they are excluded: none of the five appears in ``EXCLUDED_KEYS``.
    They are dropped because ``IDENTITY_FIELDS`` is a whitelist and omits them —
    so a field added to the whitelist later would silently enter the hash. This
    test pins the resulting behaviour, not the mechanism.
    """
    assert field not in IDENTITY_FIELDS
    assert field not in EXCLUDED_KEYS

    a = _claim("L1", **{field: left})
    b = _claim("L1", **{field: right})
    assert content_hash_of(a) == content_hash_of(b)


@pytest.mark.parametrize("field,left,right", R4_EXCLUDED_FIELDS)
def test_cross_lineage_r4_difference_is_preserved_not_merged(
    field: str, left: object, right: object
) -> None:
    """A same-hash / different-lineage R4 pair must reach R4, not be coalesced.

    This is the conflict-preservation half of the §2.3 amendment: merging here
    would erase the conflict *before* R4 ran, inflating M2 with a false duplicate
    and poisoning M3 by hiding the stale value.
    """
    store = _store()
    store.add_claims(
        [
            _claim("L1", record_id="r1", **{field: left}),
            _claim("L2", record_id="r2", **{field: right}),
        ]
    )
    assert len(store.claims) == 2
    assert sorted(store.clusters) == [["r1"], ["r2"]]


def test_polarity_divergence_surfaces_every_claim_with_no_primary() -> None:
    """``contradiction`` yields NO primary — collapsing it would hide a live conflict."""
    store = _store()
    store.add_claims(
        [
            _claim("L1", record_id="r1", polarity="affirm"),
            _claim("L2", record_id="r2", polarity="negate"),
        ]
    )

    verdict = store.resolve_subject(BASE_FIELDS["subject"], store.claims)
    assert verdict.conflict_class is ConflictClass.CONTRADICTION
    assert verdict.primary is None

    assert {claim.id for claim in store.retrieve("5K personal best")} == {"r1", "r2"}


# ---------------------------------------------------------------------------
# Event state machine — read-only states never surface
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("state", sorted(SUPPRESSED_STATES))
def test_read_only_states_are_suppressed_from_surfacing(state: str) -> None:
    store = _store()
    store.add_claims(
        [
            _claim("L-old", record_id="old", object="24:30", state=state),
            _claim("L-new", record_id="new"),
        ]
    )

    assert len(store.claims) == 2, "suppression is a retrieval filter, not a drop"
    assert [claim.id for claim in store.retrieve("5K personal best")] == ["new"]


def test_supersession_surfaces_a_single_primary() -> None:
    store = _store()
    store.add_claims(
        [
            _claim("L-old", record_id="old", object="24:30", text="5K PB 24:30"),
            _claim("L-new", record_id="new", supersedes=["L-old"]),
        ]
    )

    verdict = store.resolve_subject(BASE_FIELDS["subject"], store.claims)
    assert verdict.conflict_class is ConflictClass.SUPERSESSION
    assert verdict.primary is not None
    assert [claim.id for claim in store.retrieve("5K personal best")] == ["new"]


def test_r2_valid_time_filters_an_expired_claim() -> None:
    """A claim whose validity window closed before the pinned query time is inactive."""
    store = _store()
    store.add_claims([_claim("L1", record_id="r1", valid_until="2026-01-01T00:00:00Z")])
    assert store.retrieve("5K personal best") == []


# ---------------------------------------------------------------------------
# Spec §6.5 — R4 metadata with no subject must fail, never surface
# ---------------------------------------------------------------------------

# One representative value per normative R4-trigger field (spec §6.5). The set is
# asserted against the package's own list below, so a spec change cannot leave
# this parametrisation quietly testing the wrong fields.
R4_TRIGGER_VALUES: tuple[tuple[str, object], ...] = (
    ("polarity", "affirm"),
    ("valid_from", "2026-01-01T00:00:00Z"),
    ("valid_until", "2026-09-01T00:00:00Z"),
    ("supersedes", ["L-old"]),
)


def _subjectless(claim_id: str, **extra) -> object:
    """A claim carrying every base field except ``subject``."""
    fields = {key: value for key, value in BASE_FIELDS.items() if key != "subject"}
    return claim_from_frontmatter(
        {**fields, "claim_id": claim_id, **extra}, "5K PB 22:00"
    )


def test_r4_trigger_values_cover_the_packages_normative_list() -> None:
    assert {field for field, _ in R4_TRIGGER_VALUES} == set(R4_TRIGGER_FIELDS)


@pytest.mark.parametrize("field,value", R4_TRIGGER_VALUES)
def test_r4_metadata_without_a_subject_raises_px_e_4144(
    field: str, value: object
) -> None:
    """spec §6.5 D1.5: an R4-trigger field with no ``subject`` is a hard failure.

    Arm C groups by subject before calling the adapter, so a subject-less claim
    never reaches the adapter's step-0 re-check. Surfacing it unchanged would
    make the update metadata silently inert — the stale claim and the current one
    both stay retrievable, corrupting M1 and M3.
    """
    store = _store()
    store.add_claims([_subjectless("L1", **{field: value})])

    with pytest.raises(SchemaError) as excinfo:
        store.retrieve("5K personal best")

    assert excinfo.value.code is ErrorCode.CLAIM_SUBJECT_REQUIRED_FOR_CONFLICT
    assert excinfo.value.code.value == "PX_E_4144"
    assert field in str(excinfo.value)


def test_a_subjectless_claim_with_no_r4_fields_still_surfaces() -> None:
    """R4 is subject-scoped: opting out of R4 entirely stays legal (spec §6.5)."""
    store = _store()
    store.add_claims([_subjectless("L1")])
    assert [claim.id for claim in store.retrieve("5K personal best")] == ["L1"]


def test_confidence_without_a_subject_is_not_an_r4_trigger() -> None:
    """spec §6.5 backward-compat carve-out: ``confidence`` never triggers PX_E_4144.

    Including it would have made every existing v0.4 claim that carries
    ``confidence`` without ``subject`` a validation error — breaking, not
    additive.
    """
    assert "confidence" not in R4_TRIGGER_FIELDS
    store = _store()
    store.add_claims([_subjectless("L1", confidence=0.850)])
    assert [claim.id for claim in store.retrieve("5K personal best")] == ["L1"]


# ---------------------------------------------------------------------------
# Arm plumbing
# ---------------------------------------------------------------------------


def test_arm_c_satisfies_the_memory_store_protocol() -> None:
    assert isinstance(_store(), MemoryStore)


def test_retrieval_preserves_retriever_rank_order() -> None:
    """R4 is a post-filter: it removes claims, it never reorders the survivors."""
    store = _store()
    store.add_claims(
        [
            _claim("L1", record_id="r1", subject="s1", text="alpha beta gamma"),
            _claim("L2", record_id="r2", subject="s2", text="beta gamma"),
            _claim("L3", record_id="r3", subject="s3", text="gamma"),
        ]
    )

    retrieved = [claim.id for claim in store.retrieve("gamma")]
    ranked = [
        claim.id
        for claim in BM25Retriever().rank("gamma", store.claims)
        if claim.id in set(retrieved)
    ]
    assert retrieved == ranked
