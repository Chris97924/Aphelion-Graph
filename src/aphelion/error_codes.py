"""Canonical Aphelion error code registry (v0.2.1+).

Codes follow the scheme ``PX_E_<CCNN>`` where ``CC`` is the two-digit
**category** band and ``NN`` is the sequence within that band:

    1NN — TYPE         wrong JSON type (str expected, got int, …)
    2NN — STRUCTURE    missing/extra/empty/forbidden fields, I/O boundary issues
    3NN — VERSION      format/spec version mismatch
    4NN — FORMAT       pattern, enum, const, duplicate-value violations
    5NN — CONSISTENCY  semantic cross-reference failure (hash/fileset/chain/ref)
    6NN — SECURITY     archive-extraction safety breach

The registry is the single source of truth. Downstream modules MUST import
the `ErrorCode` enum — do NOT hard-code string codes anywhere else.
"""

from __future__ import annotations

from enum import Enum


class ErrorCode(str, Enum):
    # --- 1NN TYPE ---------------------------------------------------------
    TYPE_MISMATCH = "PX_E_1001"

    # --- 2NN STRUCTURE ----------------------------------------------------
    REQUIRED_FIELD_MISSING = "PX_E_2001"
    EXTRA_FIELD = "PX_E_2002"
    EMPTY_VALUE = "PX_E_2003"
    FORBIDDEN_FIELD = "PX_E_2004"
    MISSING_FILE = "PX_E_2005"
    INIT_REFUSES_EXISTING = "PX_E_2006"
    INIT_MISSING_CONFIRMATION = "PX_E_2007"

    # --- 3NN VERSION ------------------------------------------------------
    UNSUPPORTED_SCHEMA_VERSION = "PX_E_3001"
    UNSUPPORTED_SPEC_VERSION = "PX_E_3002"
    VERSION_UNKNOWN_MAJOR = "PX_E_3003"  # ERR-SYN-VERSION-UNKNOWN-MAJOR
    VERSION_NOT_SEMVER = "PX_E_3004"  # ERR-SYN-VERSION-NOT-SEMVER
    TIMESTAMP_SUBMS_PRECISION = "PX_E_3005"  # ERR-SYN-TIMESTAMP-NS

    # --- 4NN FORMAT -------------------------------------------------------
    PATTERN_MISMATCH = "PX_E_4001"
    ENUM_INVALID = "PX_E_4002"
    CONST_MISMATCH = "PX_E_4003"
    DUPLICATE_CLAIM_ID = "PX_E_4004"
    DUPLICATE_TAG = "PX_E_4005"
    PARSE_ERROR = "PX_E_4006"
    DUPLICATE_JSON_KEY = "PX_E_4007"
    FLOAT_FORBIDDEN = "PX_E_4008"
    NAN_FORBIDDEN = "PX_E_4009"
    UTF8_INVALID = "PX_E_4010"

    # --- 5NN CONSISTENCY --------------------------------------------------
    HASH_MISMATCH = "PX_E_5001"
    FILESET_DIVERGENCE = "PX_E_5002"
    CHAIN_BROKEN = "PX_E_5003"
    DANGLING_REFERENCE = "PX_E_5004"
    LIFECYCLE_ILLEGAL = "PX_E_5101"  # ERR-SEM-LIFECYCLE-ILLEGAL
    REAFFIRM_MISSING_TARGET = "PX_E_5102"  # ERR-SEM-REAFFIRM-MISSING-TARGET
    DUPLICATE_HASH_COLLISION = "PX_E_5103"  # ERR-SEM-DUPLICATE-HASH-COLLISION

    # --- 6NN SECURITY -----------------------------------------------------
    PATH_TRAVERSAL = "PX_E_6001"
    ABSOLUTE_PATH = "PX_E_6002"
    WINDOWS_DRIVE = "PX_E_6003"
    WINDOWS_BACKSLASH = "PX_E_6004"
    PATH_TOO_LONG = "PX_E_6005"
    EMPTY_MEMBER_NAME = "PX_E_6006"
    DUPLICATE_MEMBER_PATH = "PX_E_6007"
    DISALLOWED_MEMBER_TYPE = "PX_E_6008"
    FILE_COUNT_EXCEEDED = "PX_E_6009"
    FILE_BYTES_EXCEEDED = "PX_E_6010"
    TOTAL_BYTES_EXCEEDED = "PX_E_6011"
    COMPRESSION_RATIO_EXCEEDED = "PX_E_6012"
    ARCHIVE_BOMB = "PX_E_6013"

    # --- 9NN GENERIC ------------------------------------------------------
    UNKNOWN = "PX_E_9001"


CATEGORY_LABELS: dict[str, str] = {
    "1": "type",
    "2": "structure",
    "3": "version",
    "4": "format",
    "5": "consistency",
    "6": "security",
    "9": "generic",
}


def category_of(code: ErrorCode | str) -> str:
    """Return the human label for a code's category band.

    Accepts either an ``ErrorCode`` member or the raw string (``"PX_E_2005"``).
    """
    raw = code.value if isinstance(code, ErrorCode) else code
    if not raw.startswith("PX_E_") or len(raw) < 6:
        return "generic"
    return CATEGORY_LABELS.get(raw[5], "generic")


ALL_CODES: frozenset[str] = frozenset(c.value for c in ErrorCode)
