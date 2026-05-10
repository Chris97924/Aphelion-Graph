"""Aphelion v0.3-r1r4 claim semantics validator.

Validates the four R1-R4 frontmatter fields plus the conditional-subject
requirement and reserved-field guard introduced in
``spec/v0.3-claim-semantics.md`` (Chris-pinned 2026-05-09).

This module is **frontmatter-level** — it inspects parsed YAML mappings
and (optionally) raw YAML text. It does NOT touch manifest.json or the
provenance stream; those are owned by :mod:`aphelion.validator`.

All raises use :class:`aphelion.errors.SchemaError` with a
:class:`aphelion.error_codes.ErrorCode` member. Warnings are returned by
the read adapter (see :mod:`aphelion.read_adapter`) rather than raised.

Spec ground truth: ``spec/v0.3-claim-semantics.md`` §3-§7.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Any, Final

from aphelion.error_codes import ErrorCode
from aphelion.errors import SchemaError


# 20-char ISO 8601 UTC ``Z`` form: YYYY-MM-DDTHH:MM:SSZ. v0.3 deliberately
# excludes fractional-second forms because R2 query-time semantics quantize
# to whole seconds (see spec §6.4 D1.4 resolution).
ISO_8601_UTC_Z_RE: Final = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$"
)

POLARITY_VALUES: Final = frozenset({"affirm", "negate", "unknown"})

# UUID v7 format used for claim_id values.
UUID_V7_RE: Final = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)

# Spec §6.5: required-when-R4 trigger list. ``confidence`` is deliberately
# excluded per Phase-4 backward-compat carve-out (Chris-confirmed 2026-05-09 PM).
R4_TRIGGER_FIELDS: Final = frozenset({"polarity", "valid_from", "valid_until", "supersedes"})

# Spec §7: reader-side derivation; MUST NOT appear in frontmatter.
RESERVED_DERIVATION_FIELDS: Final = frozenset({"conflict_class"})


def _raise(code: ErrorCode, msg: str, path: str | None = None) -> None:
    raise SchemaError(code=code, msg=msg, path=path)


def validate_confidence(value: Any, *, raw_text: str | None = None) -> None:
    """R1 — ``confidence`` semantic tightening of v0.4 field.

    Args:
        value: parsed YAML value (typically ``float`` or ``int``).
        raw_text: optional raw YAML scalar text (e.g. ``"0.900"``). When
            present, enables the 3dp precision check; when absent, only
            type and range are checked. Callers that load YAML through a
            parser that loses formatting MUST pass this for full v0.3
            compliance.

    Raises:
        SchemaError: on type, range, or precision violation.
    """
    # bool is a subclass of int — reject it explicitly so a stray ``true``
    # in the confidence slot does not slip through as 1.
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        _raise(
            ErrorCode.CLAIM_CONFIDENCE_TYPE,
            f"confidence must be a number, got {type(value).__name__}",
        )
    if not (0.0 <= float(value) <= 1.0):
        _raise(
            ErrorCode.CLAIM_CONFIDENCE_RANGE,
            f"confidence {value!r} outside [0.000, 1.000]",
        )
    if raw_text is not None:
        # Spec §3: serialization MUST be exactly 3 decimal digits. We do not
        # silently accept 4dp+ — those round-trip to a different on-the-wire
        # representation and would break content-hash assumptions in callers
        # that re-emit the YAML.
        stripped = raw_text.strip()
        # Accept optional sign + integer dot 3-digit fraction, nothing else.
        if not re.fullmatch(r"-?\d+\.\d{3}", stripped):
            _raise(
                ErrorCode.CLAIM_CONFIDENCE_PRECISION,
                f"confidence must serialize as exactly 3dp, got {raw_text!r}",
            )


def validate_validtime(name: str, value: Any) -> None:
    """R2 — single ``valid_from`` or ``valid_until`` field type/format.

    Order between the two is checked separately by
    :func:`validate_validtime_order`.
    """
    if not isinstance(value, str):
        _raise(
            ErrorCode.CLAIM_VALIDTIME_TYPE,
            f"{name} must be a string, got {type(value).__name__}",
        )
    if not ISO_8601_UTC_Z_RE.fullmatch(value):
        _raise(
            ErrorCode.CLAIM_VALIDTIME_FORMAT,
            f"{name} must match YYYY-MM-DDTHH:MM:SSZ (20 chars), got {value!r}",
        )
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        _raise(
            ErrorCode.CLAIM_VALIDTIME_FORMAT,
            f"{name} is not a valid calendar timestamp, got {value!r}: {exc}",
        )


def validate_validtime_order(valid_from: str | None, valid_until: str | None) -> None:
    """R2 ordering — both bounds present implies ``valid_from <= valid_until``.

    String comparison is correct for the strict 20-char ISO 8601 UTC ``Z``
    form because lexicographic order coincides with chronological order
    when the format is fixed-width (no fractional seconds, no offset, no
    timezone variance).
    """
    if valid_from is None or valid_until is None:
        return
    if valid_from > valid_until:
        _raise(
            ErrorCode.CLAIM_VALIDTIME_ORDER,
            f"valid_from {valid_from!r} must be <= valid_until {valid_until!r}",
        )


def validate_polarity(value: Any) -> None:
    """R3 — polarity is a strict-lowercase enum."""
    if not isinstance(value, str):
        _raise(
            ErrorCode.CLAIM_POLARITY_TYPE,
            f"polarity must be a string, got {type(value).__name__}",
        )
    if value not in POLARITY_VALUES:
        _raise(
            ErrorCode.CLAIM_POLARITY_VALUE,
            f"polarity must be one of {sorted(POLARITY_VALUES)}, got {value!r}",
        )


def validate_supersedes(value: Any, *, claim_id: str | None) -> None:
    """R4 — ``supersedes`` shape: array<UUID v7 string>, no self-ref, no dup.

    Cross-package references are NOT validated here — they are a
    reader-side concern (lenient W_CLAIM_SUPERSEDES_DANGLING; see
    :mod:`aphelion.read_adapter` and spec §6.2 D1.2).
    """
    if not isinstance(value, list):
        _raise(
            ErrorCode.CLAIM_SUPERSEDES_TYPE,
            f"supersedes must be an array, got {type(value).__name__}",
        )
    seen: set[str] = set()
    for entry in value:
        if not isinstance(entry, str) or not UUID_V7_RE.fullmatch(entry):
            _raise(
                ErrorCode.CLAIM_SUPERSEDES_TYPE,
                f"supersedes entries must be UUID v7 strings, got {entry!r}",
            )
        if claim_id is not None and entry == claim_id:
            _raise(
                ErrorCode.CLAIM_SUPERSEDES_SELF,
                f"supersedes contains the claim's own id {entry!r}",
            )
        if entry in seen:
            _raise(
                ErrorCode.CLAIM_SUPERSEDES_DUPLICATE,
                f"supersedes contains duplicate {entry!r}",
            )
        seen.add(entry)


def validate_reserved_fields(frontmatter: Mapping[str, Any]) -> None:
    """Reject reader-side derivation field names in frontmatter (spec §7)."""
    for name in RESERVED_DERIVATION_FIELDS:
        if name in frontmatter:
            _raise(
                ErrorCode.CLAIM_RESERVED_FIELD,
                f"field {name!r} is reserved for reader-side derivation; "
                "it cannot be set in frontmatter",
            )


def validate_key_order(keys: Sequence[str]) -> None:
    """Frontmatter keys MUST be ASCII-codepoint-ascending (spec rule 1).

    The validator does not auto-fix; callers should run
    ``aphe canonicalize`` to repair. ASCII codepoint order is what
    ``sorted()`` produces for plain ASCII strings; because all canonical
    Aphelion keys are ASCII, ``str.<`` is equivalent to codepoint order.
    """
    expected = sorted(keys)
    if list(keys) != expected:
        _raise(
            ErrorCode.CLAIM_KEY_ORDER,
            "frontmatter keys must be ASCII-codepoint-ascending; "
            f"got {list(keys)!r}, expected {expected!r}. "
            "Run `aphe canonicalize` to repair.",
        )


def validate_subject_required_for_r4(frontmatter: Mapping[str, Any]) -> None:
    """Spec §6.5 D1.5 — any R4-trigger field present implies subject required.

    The trigger list is the four v0.3 net-new fields
    (``polarity`` / ``valid_from`` / ``valid_until`` / ``supersedes``).
    ``confidence`` is excluded — see ADR-0002 backward-compat carve-out.
    """
    triggers_present = sorted(R4_TRIGGER_FIELDS & frontmatter.keys())
    if not triggers_present:
        return
    subject = frontmatter.get("subject")
    if not isinstance(subject, str) or not subject.strip():
        _raise(
            ErrorCode.CLAIM_SUBJECT_REQUIRED_FOR_CONFLICT,
            f"claim uses R4 fields ({triggers_present}) but missing required "
            "'subject' for conflict grouping. R4 conflict detection requires "
            "a grouping key.",
        )


def validate_v03_fields(
    frontmatter: Mapping[str, Any],
    *,
    claim_id: str | None = None,
    raw_field_text: Mapping[str, str] | None = None,
    keys_in_order: Sequence[str] | None = None,
) -> None:
    """Validate every v0.3-r1r4 invariant on a single claim frontmatter.

    Args:
        frontmatter: parsed YAML mapping for the claim.
        claim_id: the claim's own id (for R4 self-reference check). If
            absent, falls back to ``frontmatter.get("claim_id")``.
        raw_field_text: optional ``{field_name: raw_text}`` mapping for
            fields where serialization-form matters (today: ``confidence``
            for the 3dp precision check).
        keys_in_order: the YAML-parser-preserved key order for the key-order
            check. If absent, key order is NOT enforced (the caller chose
            not to track order).

    Raises:
        SchemaError: on the first invariant violation; the order is
            reserved-fields → per-field type/format → subject-required →
            key-order. Single-violation surfacing is intentional —
            multi-error aggregation is a v0.4 candidate.
    """
    validate_reserved_fields(frontmatter)

    if "confidence" in frontmatter:
        raw = None if raw_field_text is None else raw_field_text.get("confidence")
        validate_confidence(frontmatter["confidence"], raw_text=raw)

    if "valid_from" in frontmatter:
        validate_validtime("valid_from", frontmatter["valid_from"])
    if "valid_until" in frontmatter:
        validate_validtime("valid_until", frontmatter["valid_until"])
    validate_validtime_order(
        frontmatter.get("valid_from"), frontmatter.get("valid_until")
    )

    if "polarity" in frontmatter:
        validate_polarity(frontmatter["polarity"])

    if "supersedes" in frontmatter:
        own_id = claim_id if claim_id is not None else frontmatter.get("claim_id")
        own_id_str = own_id if isinstance(own_id, str) else None
        validate_supersedes(frontmatter["supersedes"], claim_id=own_id_str)

    validate_subject_required_for_r4(frontmatter)

    if keys_in_order is not None:
        validate_key_order(keys_in_order)
