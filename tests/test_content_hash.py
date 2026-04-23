"""Parametrized conformance tests for content_hash canonicalization."""

from __future__ import annotations

import hashlib
import json
import unicodedata
from pathlib import Path

import pytest

from dpkg.content_hash import (
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
