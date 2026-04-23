"""Table-driven lifecycle state-machine conformance tests."""

from __future__ import annotations

import pytest

from aphelion.errors import SchemaError
from aphelion.lifecycle import (
    check_lifecycle,
    check_timestamp,
    timestamp_to_ms,
)


CLAIM = "01930001-0000-7000-8000-00000000aaaa"
INST_A = "01930001-0000-7000-8000-aaaaaaaaaaaa"
INST_B = "01930001-0000-7000-8000-bbbbbbbbbbbb"


def _ev(
    event_id: str,
    event_type: str,
    *,
    ts: str = "2026-04-21T00:00:00Z",
    prev: str | None = None,
    instance: str | None = None,
    target: str | None = None,
    extra: dict | None = None,
) -> dict:
    out: dict = {
        "actor": "gen",
        "claim_id": CLAIM,
        "event_id": event_id,
        "event_type": event_type,
        "timestamp": ts,
    }
    if prev is not None:
        out["prev_event_id"] = prev
    if instance is not None:
        out["claim_instance_id"] = instance
    if target is not None:
        out["target_claim_instance_id"] = target
    if extra:
        out.update(extra)
    return out


# ---------- legal sequences -------------------------------------------------

LEGAL_CASES = {
    "create-only": [_ev("01930001-0000-7000-8000-eeee00000001", "create", instance=INST_A)],
    "create-withdraw": [
        _ev("01930001-0000-7000-8000-eeee00000001", "create", instance=INST_A, ts="2026-04-21T00:00:00Z"),
        _ev(
            "01930001-0000-7000-8000-eeee00000002",
            "withdraw",
            ts="2026-04-21T00:00:01Z",
            prev="01930001-0000-7000-8000-eeee00000001",
            target=INST_A,
        ),
    ],
    "create-reaffirm-reaffirm": [
        _ev("01930001-0000-7000-8000-eeee00000001", "create", instance=INST_A, ts="2026-04-21T00:00:00Z"),
        _ev(
            "01930001-0000-7000-8000-eeee00000002",
            "reaffirm",
            ts="2026-04-21T00:00:01Z",
            prev="01930001-0000-7000-8000-eeee00000001",
            target=INST_A,
        ),
        _ev(
            "01930001-0000-7000-8000-eeee00000003",
            "reaffirm",
            ts="2026-04-21T00:00:02Z",
            prev="01930001-0000-7000-8000-eeee00000002",
            target=INST_A,
        ),
    ],
    "create-revise-withdraw": [
        _ev("01930001-0000-7000-8000-eeee00000001", "create", instance=INST_A, ts="2026-04-21T00:00:00Z"),
        _ev(
            "01930001-0000-7000-8000-eeee00000002",
            "revise",
            instance=INST_B,
            ts="2026-04-21T00:00:01Z",
            prev="01930001-0000-7000-8000-eeee00000001",
            target=INST_A,
        ),
        _ev(
            "01930001-0000-7000-8000-eeee00000003",
            "withdraw",
            ts="2026-04-21T00:00:02Z",
            prev="01930001-0000-7000-8000-eeee00000002",
            target=INST_B,
        ),
    ],
    "create-supersede": [
        _ev("01930001-0000-7000-8000-eeee00000001", "create", instance=INST_A, ts="2026-04-21T00:00:00Z"),
        _ev(
            "01930001-0000-7000-8000-eeee00000002",
            "supersede",
            instance=INST_B,
            ts="2026-04-21T00:00:01Z",
            prev="01930001-0000-7000-8000-eeee00000001",
            target=INST_A,
            extra={"superseded_by_claim_id": "01930001-0000-7000-8000-000000000bbb"},
        ),
    ],
}


@pytest.mark.parametrize("name", list(LEGAL_CASES))
def test_legal_sequences_pass(name: str) -> None:
    check_lifecycle(LEGAL_CASES[name])


# ---------- illegal sequences -----------------------------------------------

ILLEGAL_CASES = {
    "reaffirm-without-create": (
        [
            _ev(
                "01930001-0000-7000-8000-eeee00000001",
                "reaffirm",
                target=INST_A,
            )
        ],
        "PX_E_5101",
    ),
    "withdraw-then-reaffirm": (
        [
            _ev("01930001-0000-7000-8000-eeee00000001", "create", instance=INST_A, ts="2026-04-21T00:00:00Z"),
            _ev(
                "01930001-0000-7000-8000-eeee00000002",
                "withdraw",
                ts="2026-04-21T00:00:01Z",
                prev="01930001-0000-7000-8000-eeee00000001",
                target=INST_A,
            ),
            _ev(
                "01930001-0000-7000-8000-eeee00000003",
                "reaffirm",
                ts="2026-04-21T00:00:02Z",
                prev="01930001-0000-7000-8000-eeee00000002",
                target=INST_A,
            ),
        ],
        "PX_E_5101",
    ),
    "supersede-after-withdraw": (
        [
            _ev("01930001-0000-7000-8000-eeee00000001", "create", instance=INST_A, ts="2026-04-21T00:00:00Z"),
            _ev(
                "01930001-0000-7000-8000-eeee00000002",
                "withdraw",
                ts="2026-04-21T00:00:01Z",
                prev="01930001-0000-7000-8000-eeee00000001",
                target=INST_A,
            ),
            _ev(
                "01930001-0000-7000-8000-eeee00000003",
                "supersede",
                instance=INST_B,
                ts="2026-04-21T00:00:02Z",
                prev="01930001-0000-7000-8000-eeee00000002",
                target=INST_A,
                extra={"superseded_by_claim_id": "01930001-0000-7000-8000-000000000bbb"},
            ),
        ],
        "PX_E_5101",
    ),
    "reaffirm-missing-target": (
        [
            _ev("01930001-0000-7000-8000-eeee00000001", "create", instance=INST_A, ts="2026-04-21T00:00:00Z"),
            _ev(
                "01930001-0000-7000-8000-eeee00000002",
                "reaffirm",
                ts="2026-04-21T00:00:01Z",
                prev="01930001-0000-7000-8000-eeee00000001",
            ),
        ],
        "PX_E_5102",
    ),
    "revise-missing-target": (
        [
            _ev("01930001-0000-7000-8000-eeee00000001", "create", instance=INST_A, ts="2026-04-21T00:00:00Z"),
            _ev(
                "01930001-0000-7000-8000-eeee00000002",
                "revise",
                instance=INST_B,
                ts="2026-04-21T00:00:01Z",
                prev="01930001-0000-7000-8000-eeee00000001",
            ),
        ],
        "PX_E_5101",
    ),
    "supersede-missing-target": (
        [
            _ev("01930001-0000-7000-8000-eeee00000001", "create", instance=INST_A, ts="2026-04-21T00:00:00Z"),
            _ev(
                "01930001-0000-7000-8000-eeee00000002",
                "supersede",
                instance=INST_B,
                ts="2026-04-21T00:00:01Z",
                prev="01930001-0000-7000-8000-eeee00000001",
                extra={"superseded_by_claim_id": "01930001-0000-7000-8000-000000000bbb"},
            ),
        ],
        "PX_E_5101",
    ),
    "withdraw-missing-target": (
        [
            _ev("01930001-0000-7000-8000-eeee00000001", "create", instance=INST_A, ts="2026-04-21T00:00:00Z"),
            _ev(
                "01930001-0000-7000-8000-eeee00000002",
                "withdraw",
                ts="2026-04-21T00:00:01Z",
                prev="01930001-0000-7000-8000-eeee00000001",
            ),
        ],
        "PX_E_5101",
    ),
    "create-with-forbidden-target": (
        [
            _ev(
                "01930001-0000-7000-8000-eeee00000001",
                "create",
                instance=INST_A,
                target=INST_A,
                ts="2026-04-21T00:00:00Z",
            ),
        ],
        "PX_E_5101",
    ),
    "publish-with-forbidden-target": (
        [
            _ev(
                "01930001-0000-7000-8000-eeee00000001",
                "publish",
                instance=INST_A,
                target=INST_A,
                ts="2026-04-21T00:00:00Z",
            ),
        ],
        "PX_E_5101",
    ),
    "second-create-on-active": (
        [
            _ev("01930001-0000-7000-8000-eeee00000001", "create", instance=INST_A, ts="2026-04-21T00:00:00Z"),
            _ev("01930001-0000-7000-8000-eeee00000002", "create", instance=INST_B, ts="2026-04-21T00:00:01Z"),
        ],
        "PX_E_5101",
    ),
}


@pytest.mark.parametrize("name", list(ILLEGAL_CASES))
def test_illegal_sequences_rejected(name: str) -> None:
    events, expected_code = ILLEGAL_CASES[name]
    with pytest.raises(SchemaError) as exc:
        check_lifecycle(events)
    assert exc.value.code.value == expected_code, (
        f"{name}: expected {expected_code}, got {exc.value.code.value}"
    )


# ---------- ordering --------------------------------------------------------


def test_events_resorted_canonically() -> None:
    """Events supplied out of order MUST be re-sorted before the walk."""
    events = [
        _ev(
            "01930001-0000-7000-8000-eeee00000002",
            "reaffirm",
            ts="2026-04-21T00:00:01Z",
            prev="01930001-0000-7000-8000-eeee00000001",
            target=INST_A,
        ),
        _ev("01930001-0000-7000-8000-eeee00000001", "create", instance=INST_A, ts="2026-04-21T00:00:00Z"),
    ]
    check_lifecycle(events)


def test_event_id_tiebreaker() -> None:
    """Identical timestamps: tie broken by event_id lexicographic order."""
    events = [
        _ev(
            "01930001-0000-7000-8000-eeee00000002",
            "reaffirm",
            ts="2026-04-21T00:00:00Z",
            prev="01930001-0000-7000-8000-eeee00000001",
            target=INST_A,
        ),
        _ev("01930001-0000-7000-8000-eeee00000001", "create", instance=INST_A, ts="2026-04-21T00:00:00Z"),
    ]
    check_lifecycle(events)


# ---------- timestamp rules --------------------------------------------------


@pytest.mark.parametrize(
    "ts",
    [
        "2026-04-21T00:00:00Z",
        "2026-04-21T12:34:56.123Z",
    ],
)
def test_legal_timestamps(ts: str) -> None:
    check_timestamp("event.timestamp", ts)


@pytest.mark.parametrize(
    "ts",
    [
        "2026-04-21T00:00:00.123456Z",
        "2026-04-21T00:00:00.123456789Z",
        "2026-04-21T00:00:00+00:00",
        "2026-04-21T00:00:00-07:00",
    ],
)
def test_subms_or_offset_rejected(ts: str) -> None:
    with pytest.raises(SchemaError) as exc:
        check_timestamp("event.timestamp", ts)
    assert exc.value.code.value == "PX_E_3005"


@pytest.mark.parametrize(
    "ts",
    ["not-a-timestamp", "2026/04/21 00:00:00Z", "", "2026-04-21"],
)
def test_garbage_timestamp_rejected(ts: str) -> None:
    with pytest.raises(SchemaError) as exc:
        check_timestamp("event.timestamp", ts)
    assert exc.value.code.value == "PX_E_4001"


def test_timestamp_to_ms() -> None:
    base = timestamp_to_ms("2026-04-21T00:00:00Z")
    assert base == 1776729600000  # 2026-04-21T00:00:00+00 in epoch-ms
    assert timestamp_to_ms("2026-04-21T00:00:00.123Z") == base + 123
    assert timestamp_to_ms("2026-04-21T00:00:01Z") == base + 1000
