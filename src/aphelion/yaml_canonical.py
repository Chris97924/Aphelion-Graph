"""Minimal stdlib-only YAML subset for canonical Aphelion claim frontmatter.

Aphelion's frontmatter is a strict subset of YAML — flat top-level
mapping with three value shapes:

  * scalar (string / int / float / bool / null)
  * block sequence of scalars (e.g. ``tags``, ``supersedes``)
  * block mapping with one nesting level (e.g. ``labels``, ``annotations``)

This module parses and emits that subset only. Anything richer
(anchors, aliases, flow style, multi-line strings, deeper nesting)
raises :class:`SchemaError` with :data:`ErrorCode.PARSE_ERROR`.

The hand-rolled pattern matches the rest of the aphelion package
(``canonical_json.py`` is also stdlib-only) and keeps the v0.3 ship
free of a YAML runtime dependency. PyYAML's full grammar is overkill
for the canonical claim form and would expand the supply chain.
"""

from __future__ import annotations

import re
from typing import Any

from aphelion.error_codes import ErrorCode
from aphelion.errors import SchemaError


_KEY_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*):(.*)$")
_LIST_ITEM_RE = re.compile(r"^\s+-\s+(.*)$")
_NESTED_KV_RE = re.compile(r"^\s+([A-Za-z_][A-Za-z0-9_]*):(.*)$")


def _err(msg: str, line_no: int) -> SchemaError:
    return SchemaError(
        code=ErrorCode.PARSE_ERROR,
        msg=f"{msg} (line {line_no})",
    )


def _parse_scalar(raw: str, line_no: int) -> Any:
    """Parse a scalar value: quoted string / unquoted string / number / bool / null."""
    text = raw.strip()
    if text == "" or text == "~" or text == "null":
        return None
    if text == "true":
        return True
    if text == "false":
        return False
    if (text.startswith('"') and text.endswith('"')) or (
        text.startswith("'") and text.endswith("'")
    ):
        if len(text) < 2:
            raise _err(f"unterminated quoted string {raw!r}", line_no)
        # No escape processing in canonical Aphelion frontmatter — the
        # value is the literal between quotes. Quoted values containing
        # the same quote char are out of scope (not used in canonical
        # claims).
        return text[1:-1]
    # Number (int or float)
    try:
        if "." in text or "e" in text or "E" in text:
            return float(text)
        return int(text)
    except ValueError:
        # Fall through — treat as unquoted string.
        return text


def parse_frontmatter(text: str) -> tuple[dict[str, Any], list[str]]:
    """Parse a YAML frontmatter blob into (mapping, key_order).

    Args:
        text: the raw YAML between ``---`` fences (no fences themselves).

    Returns:
        ``(data, key_order)`` — the mapping and the order of top-level
        keys as encountered.

    Raises:
        SchemaError: with :data:`ErrorCode.PARSE_ERROR` on any structure
        outside the canonical subset.
    """
    data: dict[str, Any] = {}
    order: list[str] = []
    lines = text.splitlines()
    idx = 0
    while idx < len(lines):
        line = lines[idx]
        line_no = idx + 1
        if line.strip() == "" or line.strip().startswith("#"):
            idx += 1
            continue
        match = _KEY_RE.match(line)
        if not match:
            raise _err(f"unexpected line {line!r}", line_no)
        key = match.group(1)
        rest = match.group(2)
        if rest.strip() == "":
            # Block scalar (sequence or mapping)
            block_lines: list[str] = []
            j = idx + 1
            while j < len(lines):
                if lines[j].strip() == "" or lines[j].strip().startswith("#"):
                    j += 1
                    continue
                if not (lines[j].startswith(" ") or lines[j].startswith("\t")):
                    break
                block_lines.append(lines[j])
                j += 1
            if not block_lines:
                raise _err(
                    f"key {key!r} has no value and no block follows",
                    line_no,
                )
            if _LIST_ITEM_RE.match(block_lines[0]):
                value: Any = []
                for raw in block_lines:
                    item_match = _LIST_ITEM_RE.match(raw)
                    if not item_match:
                        raise _err(f"mixed block under {key!r}", line_no)
                    value.append(_parse_scalar(item_match.group(1), line_no))
            elif _NESTED_KV_RE.match(block_lines[0]):
                value = {}
                for raw in block_lines:
                    kv = _NESTED_KV_RE.match(raw)
                    if not kv:
                        raise _err(f"mixed block under {key!r}", line_no)
                    inner_key = kv.group(1)
                    inner_rest = kv.group(2)
                    if inner_rest.strip() == "":
                        raise _err(
                            "nested mappings deeper than 1 level are not "
                            "in the canonical Aphelion frontmatter subset",
                            line_no,
                        )
                    value[inner_key] = _parse_scalar(inner_rest, line_no)
            else:
                raise _err(f"unknown block shape under {key!r}", line_no)
            idx = j
        else:
            value = _parse_scalar(rest, line_no)
            idx += 1
        if key in data:
            raise _err(f"duplicate top-level key {key!r}", line_no)
        data[key] = value
        order.append(key)
    return data, order


def _emit_scalar(value: Any) -> str:
    """Inverse of :func:`_parse_scalar` for the canonical subset.

    Strings are double-quoted; numbers / bools / null follow YAML.
    Strings that contain a double quote fall back to single quotes;
    strings containing both quote forms are out of scope and raise.
    """
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int) and not isinstance(value, bool):
        return str(value)
    if isinstance(value, float):
        return repr(value)
    if isinstance(value, str):
        if '"' not in value:
            return f'"{value}"'
        if "'" not in value:
            return f"'{value}'"
        raise SchemaError(
            code=ErrorCode.PARSE_ERROR,
            msg=f"string contains both quote forms: {value!r}",
        )
    raise SchemaError(
        code=ErrorCode.PARSE_ERROR,
        msg=f"unsupported scalar type {type(value).__name__}",
    )


def emit_frontmatter(data: dict[str, Any]) -> str:
    """Emit a canonical-form YAML frontmatter blob (no fences).

    Keys are emitted in the order of the input mapping — callers are
    responsible for ordering (typically via ``dict(sorted(data.items()))``
    upstream).

    Returns:
        a string ending with a newline. Caller is responsible for
        wrapping in ``---`` fences.
    """
    out: list[str] = []
    for key, value in data.items():
        if isinstance(value, list):
            if not value:
                out.append(f"{key}: []")
                continue
            out.append(f"{key}:")
            for item in value:
                out.append(f"  - {_emit_scalar(item)}")
        elif isinstance(value, dict):
            if not value:
                out.append(f"{key}: {{}}")
                continue
            out.append(f"{key}:")
            for inner_key in sorted(value.keys()):
                out.append(f"  {inner_key}: {_emit_scalar(value[inner_key])}")
        else:
            out.append(f"{key}: {_emit_scalar(value)}")
    return "\n".join(out) + "\n"


_FENCE_RE = re.compile(r"^---\s*$", re.MULTILINE)


def split_frontmatter(text: str) -> tuple[str, str]:
    """Split a markdown-with-frontmatter document into ``(yaml, body)``.

    The frontmatter is the content between the first two ``---`` lines.
    Documents without frontmatter raise :data:`ErrorCode.PARSE_ERROR`.
    """
    if not text.startswith("---"):
        raise SchemaError(
            code=ErrorCode.PARSE_ERROR,
            msg="document does not start with --- frontmatter fence",
        )
    rest = text[3:]
    # Strip the newline after the opening fence
    if rest.startswith("\r\n"):
        rest = rest[2:]
    elif rest.startswith("\n"):
        rest = rest[1:]
    closing = _FENCE_RE.search(rest)
    if not closing:
        raise SchemaError(
            code=ErrorCode.PARSE_ERROR,
            msg="frontmatter has no closing --- fence",
        )
    yaml_part = rest[: closing.start()]
    body_start = closing.end()
    body = rest[body_start:]
    if body.startswith("\r\n"):
        body = body[2:]
    elif body.startswith("\n"):
        body = body[1:]
    return yaml_part, body
