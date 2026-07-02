"""Claim-level content_hash computation (v0.3.0).

Implements the RFC 8785 JCS + SHA-256 pipeline specified in
``spec/content-hash.md``. Pure stdlib.

The canonical projection strips every field in ``EXCLUDED_KEYS`` or with
a reserved prefix (``parallax:``, ``internal:``) before canonicalization.
Any field not named in ``IDENTITY_FIELDS`` is dropped so that
adapter-specific additions cannot perturb the hash.
"""

from __future__ import annotations

import hashlib
import json
import unicodedata
from typing import Any, Iterable


IDENTITY_FIELDS: frozenset[str] = frozenset(
    {
        "annotations",
        "author",
        "author_uri",
        "confidence",
        "labels",
        "locale",
        "object",
        "predicate",
        "source",
        "state",
        "subject",
        "tags",
        "type",
    }
)

EXCLUDED_KEYS: frozenset[str] = frozenset(
    {
        "content_hash",
        "hash",
        "created_at",
        "updated_at",
        "last_seen_at",
        "package_id",
        "archive_digest",
        "tar_mtime",
        "tar_uid",
        "tar_gid",
        "tar_atime",
        "signature",
        "claim_id",
        "claim_instance_id",
        "format_version",
        "aphelion_spec_version",
        "exchange_profile_version",
    }
)

RESERVED_PREFIXES: tuple[str, ...] = ("parallax:", "internal:")


def _is_excluded(key: str) -> bool:
    if key in EXCLUDED_KEYS:
        return True
    for prefix in RESERVED_PREFIXES:
        if key.startswith(prefix):
            return True
    return False


def _nfc(value: Any) -> Any:
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, list):
        return [_nfc(item) for item in value]
    if isinstance(value, dict):
        return {_nfc(k): _nfc(v) for k, v in value.items()}
    return value


def project(payload: dict[str, Any],
            identity_fields: Iterable[str] = IDENTITY_FIELDS) -> dict[str, Any]:
    """Return the canonical projection used for identity hashing."""
    keep = frozenset(identity_fields)
    out: dict[str, Any] = {}
    for key, value in payload.items():
        if _is_excluded(key):
            continue
        if key not in keep:
            continue
        out[key] = _nfc(value)
    if "tags" in out and isinstance(out["tags"], list):
        out["tags"] = sorted(out["tags"])
    return out


def _jcs_sorted(value: Any) -> Any:
    """Return ``value`` with every object's members ordered per RFC 8785 §3.2.3.

    JCS sorts object keys by their **UTF-16 code units**, not by Unicode code
    point. The two orders agree for every BMP key (a BMP character's UTF-16
    encoding is a single code unit equal to its code point), so this reorders
    nothing in the common case; they diverge only when a key contains a
    supplementary-plane character (U+10000..U+10FFFF), which UTF-16 encodes as
    a surrogate pair whose leading unit (0xD800..0xDBFF) sorts below U+E000+.

    Comparing the big-endian UTF-16 byte encodings lexicographically is exactly
    a comparison of the underlying code-unit sequences, so ``utf-16-be`` is the
    sort key. Only member order changes; scalar values and list order are left
    untouched and later serialization is delegated to ``json.dumps``.
    """
    if isinstance(value, dict):
        return {
            key: _jcs_sorted(sub)
            for key, sub in sorted(
                value.items(), key=lambda item: item[0].encode("utf-16-be")
            )
        }
    if isinstance(value, list):
        return [_jcs_sorted(item) for item in value]
    return value


def canonical_bytes(projection: dict[str, Any]) -> bytes:
    """Render a projected payload as RFC 8785 JCS-canonical bytes.

    Object members are ordered by UTF-16 code unit per RFC 8785 §3.2.3 (see
    :func:`_jcs_sorted`); the keys are pre-ordered so json.dumps runs with
    ``sort_keys=False``. String escaping, compact separators, and number form
    are delegated to ``json.dumps``, which matches RFC 8785 for the subset of
    JSON Aphelion allows (no raw floats in identity fields apart from
    ``confidence``, which is expected to be pre-formatted). Non-ASCII
    characters are emitted as raw UTF-8 (ensure_ascii=False), matching
    JCS §3.2. BMP-only payloads are byte-identical to the previous
    code-point-sorted output.
    """
    text = json.dumps(
        _jcs_sorted(projection),
        sort_keys=False,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return text.encode("utf-8")


def compute_content_hash(payload: dict[str, Any],
                         exclusion: frozenset[str] | None = None,
                         identity_fields: Iterable[str] = IDENTITY_FIELDS) -> str:
    """Return the 64-char lowercase hex SHA-256 of the canonical payload.

    ``exclusion`` is informational; the effective exclusion set is
    always ``EXCLUDED_KEYS`` plus reserved prefixes. Accepting the
    argument keeps the public signature honest with ``spec/content-hash.md``
    and future-proofs against producers that want to extend the set.
    """
    if exclusion:
        effective = {k: v for k, v in payload.items() if k not in exclusion}
    else:
        effective = payload
    projection = project(effective, identity_fields=identity_fields)
    return hashlib.sha256(canonical_bytes(projection)).hexdigest()
