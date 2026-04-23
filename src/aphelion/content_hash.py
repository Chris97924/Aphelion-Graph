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
        "dpkg_spec_version",
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


def canonical_bytes(projection: dict[str, Any]) -> bytes:
    """Render a projected payload as RFC 8785 JCS-canonical bytes.

    Python's json.dumps with sort_keys=True and compact separators
    matches RFC 8785 for the subset of JSON Aphelion allows (no raw floats
    in identity fields apart from ``confidence``, which is expected to
    be pre-formatted). Non-ASCII characters are emitted as raw UTF-8
    (ensure_ascii=False), matching JCS §3.2.
    """
    text = json.dumps(
        projection,
        sort_keys=True,
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
