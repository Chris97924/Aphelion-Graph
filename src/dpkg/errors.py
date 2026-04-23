"""DPKG error hierarchy + machine-readable JSON error emission.

All error ``code`` values are drawn from :mod:`dpkg.error_codes`. Raising code
must never hard-code a string — always pass an ``ErrorCode`` member so the
registry stays the single source of truth.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from typing import IO, Union

from dpkg.error_codes import ErrorCode


EXIT_OK = 0
EXIT_GENERIC = 1
EXIT_USAGE = 2
EXIT_VALIDATION = 3


CodeLike = Union[ErrorCode, str]


def _code_str(code: CodeLike) -> str:
    return code.value if isinstance(code, ErrorCode) else code


@dataclass
class DpkgError(Exception):
    """Base for all DPKG-level failures with a machine-readable code."""

    code: CodeLike = ErrorCode.UNKNOWN
    msg: str = ""
    path: str | None = None

    def __str__(self) -> str:
        base = f"[{_code_str(self.code)}] {self.msg}"
        if self.path:
            base += f" (at {self.path})"
        return base


@dataclass
class SchemaError(DpkgError):
    """Syntax-layer failure: types, enums, required fields, format."""


@dataclass
class SecurityError(DpkgError):
    """Archive extraction safety breach: traversal, bomb, disallowed member."""


@dataclass
class SemanticError(DpkgError):
    """Cross-reference / consistency failure at the semantic layer."""


@dataclass
class VerificationError(DpkgError):
    """Cryptographic / hash verification failure."""


def emit_error(err: DpkgError, stream: IO[str] | None = None) -> None:
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
    """Map an exception to the canonical DPKG exit code."""
    if isinstance(err, (SchemaError, SecurityError, SemanticError, VerificationError)):
        return EXIT_VALIDATION
    return EXIT_GENERIC
