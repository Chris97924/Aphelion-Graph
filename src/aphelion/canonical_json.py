"""Canonical JSON serializer/parser for Aphelion.

Strict subset of JSON:
  * object keys sorted by Unicode codepoint
  * UTF-8 NFC on every string (applied at INSERT time via normalize())
  * no floats (fail closed - must use int or decimal-as-string)
  * no duplicate keys on parse
  * no NaN / Infinity
  * no BOM; the serialized document ends with exactly one LF (0x0A), per
    spec/canonical-serialization.md Rule 1 §6 (reproducible via the 20-byte
    worked-example sha256 d2995dc4...f682)
"""

from __future__ import annotations

import json
import unicodedata
from typing import Any, Union

from aphelion.error_codes import ErrorCode
from aphelion.errors import SchemaError


JSONValue = Union[None, bool, int, str, list["JSONValue"], dict[str, "JSONValue"]]


def normalize(obj: Any) -> Any:
    """NFC-normalize all strings (keys and values) recursively.

    Floats are rejected here (caller must convert decimals to strings).
    """
    if obj is None or isinstance(obj, bool):
        return obj
    if isinstance(obj, int):
        return obj
    if isinstance(obj, float):
        raise SchemaError(
            code=ErrorCode.FLOAT_FORBIDDEN,
            msg="float values are forbidden in canonical JSON; use int or decimal-as-string",
        )
    if isinstance(obj, str):
        return unicodedata.normalize("NFC", obj)
    if isinstance(obj, (list, tuple)):
        return [normalize(item) for item in obj]
    if isinstance(obj, dict):
        out: dict[str, Any] = {}
        for key, value in obj.items():
            if not isinstance(key, str):
                raise SchemaError(
                    code=ErrorCode.TYPE_MISMATCH,
                    msg=f"object keys must be strings, got {type(key).__name__}",
                )
            nfc_key = unicodedata.normalize("NFC", key)
            if nfc_key in out:
                raise SchemaError(
                    code=ErrorCode.DUPLICATE_JSON_KEY,
                    msg=f"object keys collide under NFC normalization: {nfc_key!r}",
                )
            out[nfc_key] = normalize(value)
        return out
    raise SchemaError(
        code=ErrorCode.TYPE_MISMATCH,
        msg=f"unsupported type in canonical JSON: {type(obj).__name__}",
    )


def dumps(obj: Any) -> bytes:
    """Serialize to canonical-JSON bytes.

    Callers are expected to pass already-normalized data (via normalize()),
    but we defensively re-check for floats to fail closed.
    """
    _reject_floats(obj)
    text = json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return text.encode("utf-8") + b"\n"


def _reject_floats(obj: Any) -> None:
    if isinstance(obj, float):
        raise SchemaError(
            code=ErrorCode.FLOAT_FORBIDDEN,
            msg="float values are forbidden in canonical JSON",
        )
    if isinstance(obj, dict):
        for value in obj.values():
            _reject_floats(value)
    elif isinstance(obj, (list, tuple)):
        for value in obj:
            _reject_floats(value)


def _no_nan_constant(constant: str) -> Any:
    raise SchemaError(
        code=ErrorCode.NAN_FORBIDDEN,
        msg=f"NaN/Infinity literal is forbidden in canonical JSON: {constant}",
    )


def _strict_object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    seen: set[str] = set()
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in seen:
            raise SchemaError(
                code=ErrorCode.DUPLICATE_JSON_KEY,
                msg=f"duplicate JSON object key: {key!r}",
            )
        seen.add(key)
        out[key] = value
    return out


def loads(data: bytes | str, *, strict: bool = True) -> Any:
    """Parse JSON with duplicate-key detection and NaN/Infinity rejection.

    strict=True (default) enforces the full canonical subset.
    """
    if isinstance(data, bytes):
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise SchemaError(
                code=ErrorCode.UTF8_INVALID,
                msg=f"invalid UTF-8: {exc}",
            ) from exc
    else:
        text = data
    try:
        return json.loads(
            text,
            object_pairs_hook=_strict_object_pairs if strict else None,
            parse_constant=_no_nan_constant if strict else None,
        )
    except SchemaError:
        raise
    except json.JSONDecodeError as exc:
        raise SchemaError(
            code=ErrorCode.PARSE_ERROR,
            msg=f"JSON parse error: {exc.msg} at line {exc.lineno} col {exc.colno}",
        ) from exc
