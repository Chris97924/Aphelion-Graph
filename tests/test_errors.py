"""Unit tests for aphelion.errors + aphelion.error_codes."""

from __future__ import annotations

import io
import json

from aphelion.error_codes import ALL_CODES, ErrorCode, category_of
from aphelion.errors import (
    EXIT_GENERIC,
    EXIT_VALIDATION,
    AphelionError,
    SchemaError,
    SecurityError,
    SemanticError,
    VerificationError,
    emit_error,
    exit_code_for,
)


def test_emit_error_json_line() -> None:
    buf = io.StringIO()
    err = SchemaError(code=ErrorCode.TYPE_MISMATCH, msg="bad", path="a/b")
    emit_error(err, buf)
    parsed = json.loads(buf.getvalue().strip())
    assert parsed == {
        "code": "PX_E_1001",
        "severity": "error",
        "msg": "bad",
        "path": "a/b",
    }


def test_emit_error_omits_path_when_none() -> None:
    buf = io.StringIO()
    emit_error(SchemaError(code=ErrorCode.UNKNOWN, msg="m"), buf)
    parsed = json.loads(buf.getvalue().strip())
    assert "path" not in parsed


def test_exit_code_mapping() -> None:
    assert exit_code_for(SchemaError(code=ErrorCode.UNKNOWN, msg="")) == EXIT_VALIDATION
    assert exit_code_for(SecurityError(code=ErrorCode.UNKNOWN, msg="")) == EXIT_VALIDATION
    assert exit_code_for(SemanticError(code=ErrorCode.UNKNOWN, msg="")) == EXIT_VALIDATION
    assert exit_code_for(VerificationError(code=ErrorCode.UNKNOWN, msg="")) == EXIT_VALIDATION
    assert exit_code_for(AphelionError(code=ErrorCode.UNKNOWN, msg="")) == EXIT_GENERIC
    assert exit_code_for(RuntimeError("x")) == EXIT_GENERIC


def test_str_includes_code_and_path() -> None:
    err = SchemaError(code=ErrorCode.PATTERN_MISMATCH, msg="boom", path="p")
    s = str(err)
    assert "PX_E_4001" in s and "boom" in s and "p" in s


def test_all_codes_follow_registry_format() -> None:
    # v0.3-r1r4 introduced PX_W_* warning codes alongside PX_E_* errors;
    # both share the same 4-digit band convention.
    for code in ALL_CODES:
        assert code.startswith(("PX_E_", "PX_W_")), code
        digits = code[len("PX_E_"):]  # equal-length prefix slice for both
        assert digits.isdigit() and len(digits) == 4, code


def test_category_of_covers_six_buckets() -> None:
    categories = {category_of(c) for c in ErrorCode}
    required = {"type", "structure", "version", "format", "consistency", "security"}
    assert required.issubset(categories)


def test_emit_error_accepts_raw_string_code() -> None:
    """Backwards-compat: a raw string still serializes sensibly."""
    buf = io.StringIO()
    emit_error(SchemaError(code="PX_E_9001", msg="legacy"), buf)
    parsed = json.loads(buf.getvalue().strip())
    assert parsed["code"] == "PX_E_9001"


def test_category_of_known_bands() -> None:
    assert category_of(ErrorCode.TYPE_MISMATCH) == "type"
    assert category_of(ErrorCode.REQUIRED_FIELD_MISSING) == "structure"
    assert category_of(ErrorCode.UNSUPPORTED_SCHEMA_VERSION) == "version"
    assert category_of(ErrorCode.PATTERN_MISMATCH) == "format"
    assert category_of(ErrorCode.HASH_MISMATCH) == "consistency"
    assert category_of(ErrorCode.PATH_TRAVERSAL) == "security"
    assert category_of(ErrorCode.UNKNOWN) == "generic"


def test_category_of_accepts_raw_string() -> None:
    assert category_of("PX_E_2001") == "structure"
    assert category_of("PX_E_6004") == "security"


def test_category_of_unknown_returns_generic() -> None:
    """Codes outside the known bands or with malformed shape fall back to generic."""
    assert category_of("PX_E_7777") == "generic"
    assert category_of("GARBAGE") == "generic"
    assert category_of("PX_E_") == "generic"
