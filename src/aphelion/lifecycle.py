"""Lifecycle state-machine enforcement for provenance event streams (v0.3.0).

Walks the events belonging to a single ``claim_id`` and verifies each
transition against the matrix in ``spec/lifecycle-state-machine.md``.

Pure stdlib. Does not import the rest of the validator pipeline; suitable
for use inside either ``aphelion validate`` (the independent CLI) or an
external reader.
"""

from __future__ import annotations

import re
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Iterable

from aphelion.error_codes import ErrorCode
from aphelion.errors import SchemaError


# --- Timestamp rules (§6 of spec/lifecycle-state-machine.md) -----------------
#
# UTC ISO-8601 with ``Z`` suffix; sub-second precision at most 3 digits.
# Offsets other than Z, and sub-millisecond precision, are rejected as
# ``ERR-SYN-TIMESTAMP-NS`` (``PX_E_3005``).
_TS_STRICT_RE = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,3}))?Z$"
)
_TS_ANY_FRACTION_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)


def check_timestamp(field: str, value: str) -> None:
    """Raise ``SchemaError`` if ``value`` is not an Aphelion-legal timestamp."""
    if not isinstance(value, str):
        raise SchemaError(
            code=ErrorCode.TYPE_MISMATCH,
            msg=f"field {field!r} must be str, got {type(value).__name__}",
        )
    if _TS_STRICT_RE.fullmatch(value):
        return
    if _TS_ANY_FRACTION_RE.fullmatch(value):
        raise SchemaError(
            code=ErrorCode.TIMESTAMP_SUBMS_PRECISION,
            msg=(
                f"field {field!r}: timestamp {value!r} has sub-millisecond "
                "precision or non-Z offset; Aphelion requires UTC Z with at most "
                "millisecond precision"
            ),
        )
    raise SchemaError(
        code=ErrorCode.PATTERN_MISMATCH,
        msg=f"field {field!r} is not a valid ISO-8601 timestamp: {value!r}",
    )


def timestamp_to_ms(value: str) -> int:
    """Return UTC epoch milliseconds for an Aphelion-legal timestamp.

    Caller is expected to have passed ``check_timestamp`` first.
    """
    m = _TS_STRICT_RE.fullmatch(value)
    if m is None:
        raise SchemaError(
            code=ErrorCode.PATTERN_MISMATCH,
            msg=f"timestamp {value!r} is not Aphelion-canonical",
        )
    y, mo, d, h, mi, s, frac = m.groups()
    dt = datetime(
        int(y), int(mo), int(d), int(h), int(mi), int(s), tzinfo=timezone.utc
    )
    ms = int(dt.timestamp() * 1000)
    if frac:
        ms += int(frac.ljust(3, "0"))
    return ms


# --- Lifecycle matrix (§4 of spec/lifecycle-state-machine.md) ----------------

# Persistent states that can appear on the event walk. Transient states
# (reaffirmed, revised) collapse immediately back to active.
_STATE_NEW = "(new)"
_STATE_DRAFT = "draft"
_STATE_ACTIVE = "active"
_STATE_SUPERSEDED = "superseded"
_STATE_WITHDRAWN = "withdrawn"

PERSISTENT_STATES: frozenset[str] = frozenset(
    {_STATE_DRAFT, _STATE_ACTIVE, _STATE_SUPERSEDED, _STATE_WITHDRAWN}
)

# (current_state, event_type) -> next_state
_MATRIX: dict[tuple[str, str], str] = {
    (_STATE_NEW, "create"): _STATE_ACTIVE,
    (_STATE_NEW, "publish"): _STATE_ACTIVE,
    (_STATE_DRAFT, "revise"): _STATE_DRAFT,
    (_STATE_DRAFT, "publish"): _STATE_ACTIVE,
    (_STATE_DRAFT, "withdraw"): _STATE_WITHDRAWN,
    (_STATE_ACTIVE, "reaffirm"): _STATE_ACTIVE,
    (_STATE_ACTIVE, "revise"): _STATE_ACTIVE,
    (_STATE_ACTIVE, "supersede"): _STATE_SUPERSEDED,
    (_STATE_ACTIVE, "withdraw"): _STATE_WITHDRAWN,
}

# Events on new claim_id that require a prior create.
_EVENTS_REQUIRING_PRIOR = frozenset(
    {"reaffirm", "revise", "supersede", "withdraw"}
)

# §5.5 target_claim_instance_id matrix. `create` and `publish` forbid it
# (neither has a prior instance to point at); reaffirm/revise/supersede/
# withdraw require it.
EVENTS_REQUIRE_TARGET: frozenset[str] = frozenset(
    {"reaffirm", "revise", "supersede", "withdraw"}
)
EVENTS_FORBID_TARGET: frozenset[str] = frozenset({"create", "publish"})


# --- Public API --------------------------------------------------------------


def _event_sort_key(event: dict[str, Any]) -> tuple[int, str]:
    return (timestamp_to_ms(event["timestamp"]), event["event_id"])


def check_lifecycle(events: Iterable[dict[str, Any]]) -> None:
    """Walk every claim_id's event stream and raise on the first violation.

    Events are grouped by ``claim_id``, sorted by the canonical key
    ``(occurred_at_ms, event_id_lex)``, then replayed through the matrix.
    """
    by_claim: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for ev in events:
        check_timestamp("event.timestamp", ev["timestamp"])
        by_claim[ev["claim_id"]].append(ev)

    for claim_id, claim_events in by_claim.items():
        claim_events.sort(key=_event_sort_key)
        _walk_single_claim(claim_id, claim_events)


def _walk_single_claim(claim_id: str, events: list[dict[str, Any]]) -> None:
    state = _STATE_NEW
    for ev in events:
        etype = ev["event_type"]
        has_target = "target_claim_instance_id" in ev
        # §5.5: reaffirm keeps its dedicated code for backward compat;
        # revise/supersede/withdraw missing target → generic lifecycle-illegal.
        if etype == "reaffirm" and not has_target:
            raise SchemaError(
                code=ErrorCode.REAFFIRM_MISSING_TARGET,
                msg=(
                    f"claim {claim_id}: reaffirm event {ev['event_id']!r} is "
                    "missing target_claim_instance_id"
                ),
            )
        if etype in EVENTS_REQUIRE_TARGET and etype != "reaffirm" and not has_target:
            raise SchemaError(
                code=ErrorCode.LIFECYCLE_ILLEGAL,
                msg=(
                    f"claim {claim_id}: {etype} event {ev['event_id']!r} is "
                    "missing target_claim_instance_id (spec §5.5)"
                ),
            )
        if etype in EVENTS_FORBID_TARGET and has_target:
            raise SchemaError(
                code=ErrorCode.LIFECYCLE_ILLEGAL,
                msg=(
                    f"claim {claim_id}: {etype} event {ev['event_id']!r} must "
                    "NOT carry target_claim_instance_id (spec §5.5)"
                ),
            )
        if state == _STATE_NEW and etype in _EVENTS_REQUIRING_PRIOR:
            raise SchemaError(
                code=ErrorCode.LIFECYCLE_ILLEGAL,
                msg=(
                    f"claim {claim_id}: first event must be create/publish, "
                    f"got {etype!r}"
                ),
            )
        next_state = _MATRIX.get((state, etype))
        if next_state is None:
            raise SchemaError(
                code=ErrorCode.LIFECYCLE_ILLEGAL,
                msg=(
                    f"claim {claim_id}: illegal transition "
                    f"{state!r} --{etype}--> (no rule); event_id={ev['event_id']!r}"
                ),
            )
        state = next_state
