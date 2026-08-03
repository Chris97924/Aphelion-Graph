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

from datetime import datetime, timezone

import pytest

from aphelion.content_hash import EXCLUDED_KEYS, IDENTITY_FIELDS
from aphelion.error_codes import ErrorCode
from aphelion.errors import SemanticError
from aphelion.read_adapter import ConflictClass

from benchmarks.longmemeval.arms.aphelion_arm import (
    SUPPRESSED_STATES,
    AphelionStore,
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
