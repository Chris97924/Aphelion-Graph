"""Unit tests for aphelion.validator syntax-layer checks."""

from __future__ import annotations

import copy

import pytest

from aphelion.errors import SchemaError
from aphelion.validator import (
    validate_manifest,
    validate_package,
    validate_provenance_event,
)


UUID = "0191aaaa-0000-7000-8000-00000000aaaa"
UUID_INST = "0191aaaa-0000-7000-8000-aaaaaaaaaaaa"
UUID_EV = "0191aaaa-0000-7000-8000-eeee00000001"
UUID_EV2 = "0191aaaa-0000-7000-8000-eeee00000002"
UUID_PKG = "0191aaaa-0000-7000-8000-000000000001"
HASH_VALID = "a" * 64


BASE_MANIFEST = {
    "claims": [
        {
            "claim_id": UUID,
            "claim_instance_id": UUID_INST,
            "hash": HASH_VALID,
            "path": f"claims/{UUID}.md",
            "state": "active",
        }
    ],
    "aphelion_spec_version": "0.4.0",
    "created_at": "2026-04-21T00:00:00Z",
    "format_version": "2.0",
    "license": "Apache-2.0",
    "package_id": UUID_PKG,
    "producer": "aphelion-test",
    "provenance_path": "provenance.jsonl",
}

BASE_EVENT = {
    "actor": "test",
    "claim_id": UUID,
    "claim_instance_id": UUID_INST,
    "event_id": UUID_EV,
    "event_type": "create",
    "timestamp": "2026-04-21T00:00:00Z",
}


def test_base_manifest_valid() -> None:
    validate_manifest(copy.deepcopy(BASE_MANIFEST))


def test_base_event_valid() -> None:
    validate_provenance_event(copy.deepcopy(BASE_EVENT))


def test_manifest_missing_required() -> None:
    m = copy.deepcopy(BASE_MANIFEST)
    del m["license"]
    with pytest.raises(SchemaError) as exc:
        validate_manifest(m)
    assert exc.value.code == "PX_E_2001"


def test_manifest_wrong_type() -> None:
    m = copy.deepcopy(BASE_MANIFEST)
    m["claims"] = "not a list"
    with pytest.raises(SchemaError) as exc:
        validate_manifest(m)
    assert exc.value.code == "PX_E_1001"


def test_manifest_bad_version() -> None:
    m = copy.deepcopy(BASE_MANIFEST)
    m["format_version"] = "3.0"
    with pytest.raises(SchemaError) as exc:
        validate_manifest(m)
    assert exc.value.code == "PX_E_3003"


def test_manifest_extra_field() -> None:
    m = copy.deepcopy(BASE_MANIFEST)
    m["unknown_root_key"] = "boom"
    with pytest.raises(SchemaError) as exc:
        validate_manifest(m)
    assert exc.value.code == "PX_E_2002"


def test_manifest_claim_bad_state_enum() -> None:
    m = copy.deepcopy(BASE_MANIFEST)
    m["claims"][0]["state"] = "banana"
    with pytest.raises(SchemaError) as exc:
        validate_manifest(m)
    assert exc.value.code == "PX_E_4002"


def test_manifest_claim_bad_hash_pattern() -> None:
    m = copy.deepcopy(BASE_MANIFEST)
    m["claims"][0]["hash"] = "xx"
    with pytest.raises(SchemaError) as exc:
        validate_manifest(m)
    assert exc.value.code == "PX_E_4001"


def test_manifest_claim_bad_uuid() -> None:
    m = copy.deepcopy(BASE_MANIFEST)
    m["claims"][0]["claim_id"] = "not-a-uuid"
    with pytest.raises(SchemaError) as exc:
        validate_manifest(m)
    assert exc.value.code == "PX_E_4001"


def test_manifest_superseded_requires_target() -> None:
    m = copy.deepcopy(BASE_MANIFEST)
    m["claims"][0]["state"] = "superseded"
    with pytest.raises(SchemaError) as exc:
        validate_manifest(m)
    assert exc.value.code == "PX_E_2001"


def test_manifest_provenance_path_const() -> None:
    m = copy.deepcopy(BASE_MANIFEST)
    m["provenance_path"] = "other.jsonl"
    with pytest.raises(SchemaError) as exc:
        validate_manifest(m)
    assert exc.value.code == "PX_E_4003"


def test_event_create_forbids_prev() -> None:
    e = copy.deepcopy(BASE_EVENT)
    e["prev_event_id"] = UUID_EV2
    with pytest.raises(SchemaError) as exc:
        validate_provenance_event(e)
    assert exc.value.code == "PX_E_2004"


def test_event_non_create_requires_prev() -> None:
    e = copy.deepcopy(BASE_EVENT)
    e["event_type"] = "reaffirm"
    del e["claim_instance_id"]  # reaffirm forbids instance
    with pytest.raises(SchemaError) as exc:
        validate_provenance_event(e)
    assert exc.value.code == "PX_E_2001"


def test_event_reaffirm_forbids_instance() -> None:
    e = copy.deepcopy(BASE_EVENT)
    e["event_type"] = "reaffirm"
    e["prev_event_id"] = UUID_EV2
    with pytest.raises(SchemaError) as exc:
        validate_provenance_event(e)
    assert exc.value.code == "PX_E_2004"


def test_event_supersede_requires_target() -> None:
    e = copy.deepcopy(BASE_EVENT)
    e["event_type"] = "supersede"
    e["prev_event_id"] = UUID_EV2
    with pytest.raises(SchemaError) as exc:
        validate_provenance_event(e)
    assert exc.value.code == "PX_E_2001"


def test_event_bad_type_enum() -> None:
    e = copy.deepcopy(BASE_EVENT)
    e["event_type"] = "not-a-real-type"
    with pytest.raises(SchemaError) as exc:
        validate_provenance_event(e)
    assert exc.value.code == "PX_E_4002"


def test_validate_package_propagates_event_path() -> None:
    bad_event = copy.deepcopy(BASE_EVENT)
    bad_event["event_type"] = "banana"
    with pytest.raises(SchemaError) as exc:
        validate_package(copy.deepcopy(BASE_MANIFEST), [bad_event])
    assert exc.value.path == "provenance.jsonl:1"


def test_manifest_empty_license() -> None:
    m = copy.deepcopy(BASE_MANIFEST)
    m["license"] = ""
    with pytest.raises(SchemaError) as exc:
        validate_manifest(m)
    assert exc.value.code == "PX_E_2003"


def test_manifest_empty_producer() -> None:
    m = copy.deepcopy(BASE_MANIFEST)
    m["producer"] = ""
    with pytest.raises(SchemaError) as exc:
        validate_manifest(m)
    assert exc.value.code == "PX_E_2003"


def test_manifest_superseded_bad_target_pattern() -> None:
    m = copy.deepcopy(BASE_MANIFEST)
    m["claims"][0]["state"] = "superseded"
    m["claims"][0]["superseded_by_claim_id"] = "not-a-uuid"
    with pytest.raises(SchemaError) as exc:
        validate_manifest(m)
    assert exc.value.code == "PX_E_4001"


def test_manifest_claim_tags_wrong_type() -> None:
    m = copy.deepcopy(BASE_MANIFEST)
    m["claims"][0]["tags"] = "not-a-list"
    with pytest.raises(SchemaError) as exc:
        validate_manifest(m)
    assert exc.value.code == "PX_E_1001"


def test_manifest_claim_tag_empty() -> None:
    m = copy.deepcopy(BASE_MANIFEST)
    m["claims"][0]["tags"] = [""]
    with pytest.raises(SchemaError) as exc:
        validate_manifest(m)
    assert exc.value.code == "PX_E_2003"


def test_manifest_claim_tag_duplicate() -> None:
    m = copy.deepcopy(BASE_MANIFEST)
    m["claims"][0]["tags"] = ["foo", "foo"]
    with pytest.raises(SchemaError) as exc:
        validate_manifest(m)
    assert exc.value.code == "PX_E_4005"


def test_event_empty_actor() -> None:
    e = copy.deepcopy(BASE_EVENT)
    e["actor"] = ""
    with pytest.raises(SchemaError) as exc:
        validate_provenance_event(e)
    assert exc.value.code == "PX_E_2003"


def test_event_missing_required() -> None:
    e = copy.deepcopy(BASE_EVENT)
    del e["event_id"]
    with pytest.raises(SchemaError) as exc:
        validate_provenance_event(e)
    assert exc.value.code == "PX_E_2001"


def test_event_extra_field() -> None:
    e = copy.deepcopy(BASE_EVENT)
    e["bogus_event_field"] = "x"
    with pytest.raises(SchemaError) as exc:
        validate_provenance_event(e)
    assert exc.value.code == "PX_E_2002"


def test_event_non_create_requires_instance() -> None:
    e = copy.deepcopy(BASE_EVENT)
    e["event_type"] = "supersede"
    e["prev_event_id"] = UUID_EV2
    e["superseded_by_claim_id"] = "0191aaaa-0000-7000-8000-00000000bbbb"
    del e["claim_instance_id"]
    with pytest.raises(SchemaError) as exc:
        validate_provenance_event(e)
    assert exc.value.code == "PX_E_2001"


def test_event_target_instance_invalid_uuid() -> None:
    """Spec §5.5: target_claim_instance_id MUST match UUID-v7 pattern.

    A reaffirm event is used because it requires target_claim_instance_id.
    Malformed target pattern raises PX_E_4001 at the syntax layer, before
    the lifecycle walk can emit PX_E_5101 / PX_E_5102.
    """
    e = copy.deepcopy(BASE_EVENT)
    e["event_type"] = "reaffirm"
    e["prev_event_id"] = UUID_EV2
    del e["claim_instance_id"]  # reaffirm forbids claim_instance_id
    e["target_claim_instance_id"] = "not-a-uuid"
    with pytest.raises(SchemaError) as exc:
        validate_provenance_event(e)
    assert exc.value.code == "PX_E_4001"


def test_duplicate_claim_id_rejected() -> None:
    """Two distinct dict entries sharing the same claim_id must raise PX_E_4004.

    Regression for review FIX-B1: prior implementation used id(entry) which
    is always unique for freshly-parsed dicts, so duplicates slipped through.
    """
    m = copy.deepcopy(BASE_MANIFEST)
    m["claims"].append(copy.deepcopy(m["claims"][0]))
    assert m["claims"][0] is not m["claims"][1]
    assert m["claims"][0]["claim_id"] == m["claims"][1]["claim_id"]
    with pytest.raises(SchemaError) as exc:
        validate_manifest(m)
    assert exc.value.code == "PX_E_4004"
