"""Parametrized conformance tests for content_hash canonicalization."""

from __future__ import annotations

import hashlib
import json
import unicodedata
from pathlib import Path

import pytest
from hypothesis import given, settings, strategies as st

from aphelion.content_hash import (
    EXCLUDED_KEYS,
    IDENTITY_FIELDS,
    RESERVED_PREFIXES,
    canonical_bytes,
    compute_content_hash,
    project,
)

VECTORS_PATH = Path(__file__).parent / "vectors" / "hash_vectors.json"


def _load_vectors() -> list[dict]:
    data = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))
    return data["vectors"]


VECTORS = _load_vectors()


@pytest.mark.parametrize("vec", VECTORS, ids=[v["name"] for v in VECTORS])
def test_vector_matches_expected_hash(vec: dict) -> None:
    hashed = compute_content_hash(vec["input_payload"])
    assert hashed == vec["expected_hash"], (
        f"vector {vec['name']}: expected {vec['expected_hash']}, got {hashed}"
    )


@pytest.mark.parametrize("vec", VECTORS, ids=[v["name"] for v in VECTORS])
def test_vector_canonical_bytes_match(vec: dict) -> None:
    projected = project(vec["input_payload"])
    canon = canonical_bytes(projected)
    assert canon.hex() == vec["canonical_bytes_hex"]


def test_hash_output_is_64_lowercase_hex() -> None:
    h = compute_content_hash({"type": "fact"})
    assert len(h) == 64
    assert h == h.lower()
    int(h, 16)  # raises if any non-hex char


def test_excluded_timestamps_do_not_change_hash() -> None:
    base = {"type": "fact"}
    with_ts = {
        "type": "fact",
        "created_at": "2026-04-21T00:00:00Z",
        "updated_at": "2026-04-22T00:00:00Z",
        "last_seen_at": "2026-04-23T00:00:00Z",
    }
    assert compute_content_hash(base) == compute_content_hash(with_ts)


def test_reserved_prefix_keys_excluded() -> None:
    base = {"type": "fact"}
    with_reserved = {
        "type": "fact",
        "parallax:aggregation_level": "raw",
        "internal:debug_trace_id": "abc",
    }
    assert compute_content_hash(base) == compute_content_hash(with_reserved)


def test_non_identity_fields_dropped() -> None:
    base = {"type": "fact"}
    polluted = {
        "type": "fact",
        "claim_id": "0193xxxx-0000-7000-8000-000000000000",
        "claim_instance_id": "0193xxxx-0000-7000-8000-aaaaaaaaaaaa",
        "package_id": "0193xxxx-0000-7000-8000-000000000001",
        "unrecognized_extra_field": "should be dropped",
    }
    assert compute_content_hash(base) == compute_content_hash(polluted)


def test_nfc_nfd_equivalence() -> None:
    nfc = {"type": "fact", "subject": "café"}
    nfd = {"type": "fact", "subject": unicodedata.normalize("NFD", "café")}
    assert compute_content_hash(nfc) == compute_content_hash(nfd)


def test_tag_order_irrelevant() -> None:
    a = {"type": "fact", "tags": ["zzz", "aaa", "mmm"]}
    b = {"type": "fact", "tags": ["aaa", "mmm", "zzz"]}
    assert compute_content_hash(a) == compute_content_hash(b)


def test_canonical_bytes_manual_sha256() -> None:
    payload = {"type": "fact"}
    cb = canonical_bytes(project(payload))
    manual = hashlib.sha256(cb).hexdigest()
    assert manual == compute_content_hash(payload)


def test_identity_fields_is_frozenset() -> None:
    assert isinstance(IDENTITY_FIELDS, frozenset)
    assert isinstance(EXCLUDED_KEYS, frozenset)
    assert "type" in IDENTITY_FIELDS
    assert "created_at" in EXCLUDED_KEYS


def test_reserved_prefixes_constant() -> None:
    assert "parallax:" in RESERVED_PREFIXES
    assert "internal:" in RESERVED_PREFIXES


# ---------- RFC 8785 §3.2.3: UTF-16 code-unit key ordering ----------


def test_canonical_bytes_sorts_supplementary_keys_by_utf16() -> None:
    """Object keys sort by UTF-16 code unit, not Unicode code point.

    U+1F600 (😀) encodes as the surrogate pair D83D DE00; U+FFFF encodes as
    the single unit FFFF. By UTF-16 code unit D83D < FFFF, so U+1F600 sorts
    *before* U+FFFF — the reverse of code-point order (U+1F600 = 0x1F600 >
    U+FFFF), which is what json.dumps(sort_keys=True) produced. This is the
    single case where JCS §3.2.3 and Python's code-point sort disagree.
    """
    projection = {"\U0001F600": 1, "￿": 2}
    out = canonical_bytes(projection).decode("utf-8")
    assert out == '{"\U0001F600":1,"￿":2}'
    assert out.index("\U0001F600") < out.index("￿")


def test_nested_labels_supplementary_key_order() -> None:
    """Nested object keys are also UTF-16-ordered through the projection path."""
    payload = {"type": "fact", "labels": {"\U0001F600": "a", "￿": "b"}}
    projection = project(payload)
    out = canonical_bytes(projection).decode("utf-8")
    # Within the labels object the astral key precedes U+FFFF.
    assert out.index("\U0001F600") < out.index("￿")


# ---------- Property: BMP inputs stay byte-identical to the legacy form ----------

# BMP, non-surrogate characters only. For these, UTF-16 code-unit order and
# Unicode code-point order coincide, so the new JCS serializer MUST reproduce
# the exact bytes of the previous json.dumps(sort_keys=True) implementation.
_bmp_chars = st.characters(max_codepoint=0xFFFF, blacklist_categories=("Cs",))
_bmp_key = st.text(alphabet=_bmp_chars, min_size=1, max_size=8)
_bmp_scalars = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-(2**53), max_value=2**53),
    st.text(alphabet=_bmp_chars, max_size=8),
)
_bmp_json = st.recursive(
    _bmp_scalars,
    lambda children: st.one_of(
        st.lists(children, max_size=4),
        st.dictionaries(keys=_bmp_key, values=children, max_size=4),
    ),
    max_leaves=8,
)
_bmp_projection = st.dictionaries(keys=_bmp_key, values=_bmp_json, max_size=6)


def _legacy_canonical_bytes(projection: dict) -> bytes:
    """The pre-fix implementation: json.dumps with code-point key sorting."""
    return json.dumps(
        projection,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


@given(projection=_bmp_projection)
@settings(max_examples=300)
def test_prop_bmp_canonical_bytes_matches_legacy(projection: dict) -> None:
    """For any BMP-only projection the JCS bytes equal the legacy bytes.

    Guards the hard requirement that BMP/ASCII content hashes never drift: the
    UTF-16 fix only reorders supplementary-plane keys, everything else must be
    reproduced verbatim.
    """
    assert canonical_bytes(projection) == _legacy_canonical_bytes(projection)
