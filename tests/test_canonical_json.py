"""Unit tests for aphelion.canonical_json."""

from __future__ import annotations

import hashlib
import unicodedata

import pytest

from aphelion.canonical_json import dumps, loads, normalize
from aphelion.errors import SchemaError


def test_worked_example_matches_spec() -> None:
    obj = normalize({"b": 2, "a": "café"})
    serialized = dumps(obj)
    assert len(serialized) == 20
    assert (
        hashlib.sha256(serialized).hexdigest()
        == "d2995dc401d3e4b85320775178dbf4cff5393f8ba3b6f63c489ea7acde97f682"
    )


def test_nfc_applied_at_insert_time() -> None:
    nfd = unicodedata.normalize("NFD", "café")
    nfc = unicodedata.normalize("NFC", "café")
    assert nfd != nfc
    norm = normalize({"x": nfd, nfd: 1})
    assert norm["x"] == nfc
    assert nfc in norm and nfd not in norm


def test_duplicate_keys_rejected() -> None:
    with pytest.raises(SchemaError) as exc:
        loads('{"a":1,"a":2}')
    assert exc.value.code == "PX_E_4007"


def test_nan_rejected() -> None:
    with pytest.raises(SchemaError) as exc:
        loads('{"x": NaN}')
    assert exc.value.code == "PX_E_4009"


def test_infinity_rejected() -> None:
    with pytest.raises(SchemaError) as exc:
        loads('{"x": Infinity}')
    assert exc.value.code == "PX_E_4009"


def test_floats_rejected_on_dumps() -> None:
    with pytest.raises(SchemaError) as exc:
        dumps({"x": 1.5})
    assert exc.value.code == "PX_E_4008"


def test_floats_rejected_on_normalize() -> None:
    with pytest.raises(SchemaError):
        normalize({"x": 1.5})


def test_non_string_key_rejected() -> None:
    with pytest.raises(SchemaError) as exc:
        normalize({1: "a"})
    assert exc.value.code == "PX_E_1001"


def test_invalid_utf8_bytes_rejected() -> None:
    with pytest.raises(SchemaError) as exc:
        loads(b"\xff\xfe not utf-8")
    assert exc.value.code == "PX_E_4010"


def test_parse_error_code() -> None:
    with pytest.raises(SchemaError) as exc:
        loads("not json")
    assert exc.value.code == "PX_E_4006"


def test_dumps_trailing_lf() -> None:
    assert dumps({}) == b"{}\n"
    assert dumps({"a": 1}).endswith(b"\n")


def test_dumps_sorts_keys_recursively() -> None:
    obj = normalize({"b": {"d": 1, "c": 2}, "a": 3})
    out = dumps(obj).decode("utf-8")
    assert out == '{"a":3,"b":{"c":2,"d":1}}\n'


def test_nested_list_of_dicts_normalized() -> None:
    norm = normalize([{"b": 2, "a": 1}])
    assert dumps(norm) == b'[{"a":1,"b":2}]\n'


def test_tuple_treated_as_list() -> None:
    norm = normalize((1, 2, 3))
    assert dumps(norm) == b"[1,2,3]\n"


def test_bool_and_none_preserved() -> None:
    norm = normalize({"f": False, "n": None, "t": True})
    assert dumps(norm) == b'{"f":false,"n":null,"t":true}\n'


def test_normalize_rejects_nfc_colliding_keys() -> None:
    """Two distinct input keys that collapse to the same NFC form must raise PX_E_4007.

    Regression for review FIX-M9: prior implementation silently overwrote one
    key with the other, losing data.
    """
    nfd = unicodedata.normalize("NFD", "café")
    nfc = unicodedata.normalize("NFC", "café")
    assert nfd != nfc
    with pytest.raises(SchemaError) as exc:
        normalize({nfd: 1, nfc: 2})
    assert exc.value.code == "PX_E_4007"
