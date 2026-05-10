"""Canonical Aphelion error code registry (v0.2.1+, v0.3-r1r4).

Codes follow the scheme ``PX_E_<CCNN>`` (errors) or ``PX_W_<CCNN>``
(warnings, introduced v0.3-r1r4) where ``CC`` is the two-digit
**category** band and ``NN`` is the sequence within that band:

    1NN — TYPE         wrong JSON type (str expected, got int, …)
    2NN — STRUCTURE    missing/extra/empty/forbidden fields, I/O boundary issues
    3NN — VERSION      format/spec version mismatch
    4NN — FORMAT       pattern, enum, const, duplicate-value violations
    5NN — CONSISTENCY  semantic cross-reference failure (hash/fileset/chain/ref)
    6NN — SECURITY     archive-extraction safety breach

Warnings (``PX_W_*``) MUST be emitted to logs/observation channels but
MUST NOT abort processing. Production deployments MUST surface them via a
metrics counter so silent occurrences are alertable.

The registry is the single source of truth. Downstream modules MUST import
the `ErrorCode` / `WarningCode` enum — do NOT hard-code string codes anywhere
else.
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

    # --- 4NN FORMAT (v0.3-r1r4 claim semantics, Chris-pinned 2026-05-09) --
    CLAIM_CONFIDENCE_TYPE = "PX_E_4101"
    CLAIM_CONFIDENCE_RANGE = "PX_E_4102"
    CLAIM_CONFIDENCE_PRECISION = "PX_E_4103"
    CLAIM_VALIDTIME_TYPE = "PX_E_4111"
    CLAIM_VALIDTIME_FORMAT = "PX_E_4112"
    CLAIM_VALIDTIME_ORDER = "PX_E_4113"
    CLAIM_POLARITY_TYPE = "PX_E_4121"
    CLAIM_POLARITY_VALUE = "PX_E_4122"
    CLAIM_SUPERSEDES_TYPE = "PX_E_4131"
    CLAIM_SUPERSEDES_SELF = "PX_E_4132"
    CLAIM_SUPERSEDES_DUPLICATE = "PX_E_4133"
    CLAIM_RESERVED_FIELD = "PX_E_4141"
    CLAIM_KEY_ORDER = "PX_E_4143"
    CLAIM_SUBJECT_REQUIRED_FOR_CONFLICT = "PX_E_4144"

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


class WarningCode(str, Enum):
    """Non-fatal validation signals (v0.3-r1r4+).

    Emitted to logs/observation channels but never abort processing.
    Production deployments MUST expose each warning via a Prometheus
    counter (see spec/error-codes.md and spec/v0.3-claim-semantics.md
    §6.2 D1.2). Log-only is insufficient — silent occurrences would
    let typos in cross-package supersedes references go un-applied
    with no human-visible signal.
    """

    # --- 4NN FORMAT warnings ---------------------------------------------
    CLAIM_SUPERSEDES_DANGLING = "PX_W_4151"


CATEGORY_LABELS: dict[str, str] = {
    "1": "type",
    "2": "structure",
    "3": "version",
    "4": "format",
    "5": "consistency",
    "6": "security",
    "9": "generic",
}


def category_of(code: ErrorCode | WarningCode | str) -> str:
    """Return the human label for a code's category band.

    Accepts ``ErrorCode``, ``WarningCode``, or raw string forms
    (``"PX_E_2005"`` / ``"PX_W_4151"``).
    """
    if isinstance(code, (ErrorCode, WarningCode)):
        raw = code.value
    else:
        raw = code
    if not (raw.startswith("PX_E_") or raw.startswith("PX_W_")) or len(raw) < 6:
        return "generic"
    return CATEGORY_LABELS.get(raw[5], "generic")


ALL_CODES: frozenset[str] = frozenset(
    [c.value for c in ErrorCode] + [w.value for w in WarningCode]
)
