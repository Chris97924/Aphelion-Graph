"""Aphelion error hierarchy + machine-readable JSON error emission.

All error ``code`` values are drawn from :mod:`aphelion.error_codes`. Raising code
must never hard-code a string — always pass an ``ErrorCode`` member so the
registry stays the single source of truth.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from typing import IO, Union

from aphelion.error_codes import ErrorCode


EXIT_OK = 0
EXIT_GENERIC = 1
EXIT_USAGE = 2
EXIT_VALIDATION = 3


CodeLike = Union[ErrorCode, str]


def _code_str(code: CodeLike) -> str:
    return code.value if isinstance(code, ErrorCode) else code


@dataclass
class AphelionError(Exception):
    """Base for all Aphelion-level failures with a machine-readable code."""

    code: CodeLike = ErrorCode.UNKNOWN
    msg: str = ""
    path: str | None = None

    def __str__(self) -> str:
        base = f"[{_code_str(self.code)}] {self.msg}"
        if self.path:
            base += f" (at {self.path})"
        return base


@dataclass
class SchemaError(AphelionError):
    """Syntax-layer failure: types, enums, required fields, format."""


@dataclass
class SecurityError(AphelionError):
    """Archive extraction safety breach: traversal, bomb, disallowed member."""


@dataclass
class SemanticError(AphelionError):
    """Cross-reference / consistency failure at the semantic layer."""


@dataclass
class VerificationError(AphelionError):
    """Cryptographic / hash verification failure."""


def emit_error(err: AphelionError, stream: IO[str] | None = None) -> None:
    """Write a single JSON line describing the error to ``stream`` (default stderr)."""
    if stream is None:
        stream = sys.stderr
    payload = {
        "code": _code_str(err.code),
        "severity": "error",
        "msg": err.msg,
    }
    if err.path is not None:
        payload["path"] = err.path
    stream.write(json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n")
    stream.flush()


def exit_code_for(err: BaseException) -> int:
    """Map an exception to the canonical Aphelion exit code."""
    if isinstance(err, (SchemaError, SecurityError, SemanticError, VerificationError)):
        return EXIT_VALIDATION
    return EXIT_GENERIC
