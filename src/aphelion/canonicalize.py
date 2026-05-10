"""Aphelion v0.3-r1r4 frontmatter canonicalization.

Implements the transforms behind ``aphe canonicalize`` (spec §9.1):

  * reorder frontmatter keys to ASCII-codepoint ascending
  * normalize ``confidence`` to exactly 3-decimal serialization
  * lex-sort and dedupe ``supersedes`` arrays

Identity-affecting fields (``claim_id``, ``content_hash`` inputs) are
preserved verbatim.

The CLI wrapper is in :mod:`aphelion.cli` (``_cmd_canonicalize``).
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from aphelion.error_codes import ErrorCode
from aphelion.errors import SchemaError
from aphelion.v03_validator import validate_v03_fields
from aphelion.yaml_canonical import (
    emit_frontmatter,
    parse_frontmatter,
    split_frontmatter,
)


@dataclass(frozen=True)
class CanonicalizeResult:
    """Outcome of one ``canonicalize_text`` invocation.

    ``changed`` is False when the input was already canonical (still a
    success — exit 0). The CLI prints ``"already canonical"`` in that case.
    """

    text: str
    changed: bool


def _normalize_confidence(value: Any) -> Any:
    """Round confidence to 3dp; preserve type so validator sees a number.

    Serialization to exactly 3dp digits happens at emit time
    (see :func:`_emit_with_confidence_fix`) — keeping the value as a
    plain float here means the validator can run on the canonicalized
    data unchanged.
    """
    if isinstance(value, bool):
        # Bool slipped past parsing — leave to validator.
        return value
    if isinstance(value, (int, float)):
        return round(float(value), 3)
    return value


def _normalize_supersedes(value: Any) -> Any:
    if not isinstance(value, list):
        return value
    seen: set[str] = set()
    out: list[Any] = []
    for entry in value:
        if not isinstance(entry, str):
            return value  # let validator catch the type error
        if entry in seen:
            continue
        seen.add(entry)
        out.append(entry)
    out.sort()
    return out


def _emit_with_confidence_fix(data: dict[str, Any]) -> str:
    """Emit YAML, then rewrite the confidence line to exactly 3 decimal digits.

    Why post-process: the emitter renders floats via ``repr``, which
    produces ``0.9`` for the value ``0.9`` and ``0.85`` for ``0.85`` —
    spec §3 mandates 3dp on the wire so we patch the single line we care
    about. Other float values are out of scope for canonical Aphelion
    frontmatter (canonical_json bans floats outright; YAML claim
    frontmatter only uses confidence).
    """
    text = emit_frontmatter(data)
    confidence = data.get("confidence")
    if not isinstance(confidence, (int, float)) or isinstance(confidence, bool):
        return text
    target = format(float(confidence), ".3f")
    new_lines: list[str] = []
    for line in text.splitlines():
        if line.startswith("confidence: "):
            new_lines.append(f"confidence: {target}")
        else:
            new_lines.append(line)
    return "\n".join(new_lines) + "\n"


def canonicalize_data(data: Mapping[str, Any]) -> dict[str, Any]:
    """Pure transform: sort keys, normalize confidence, sort+dedupe supersedes."""
    transformed: dict[str, Any] = {}
    for key in sorted(data.keys()):
        value = data[key]
        if key == "confidence":
            transformed[key] = _normalize_confidence(value)
        elif key == "supersedes":
            transformed[key] = _normalize_supersedes(value)
        else:
            transformed[key] = value
    return transformed


def canonicalize_text(document: str) -> CanonicalizeResult:
    """Canonicalize a markdown document with YAML frontmatter.

    Args:
        document: full file text (frontmatter + body).

    Returns:
        :class:`CanonicalizeResult` with the canonicalized text and a
        ``changed`` flag.

    Raises:
        SchemaError: with :data:`ErrorCode.PARSE_ERROR` on parse failure
            (CLI exit 1), or any v0.3 validator code on semantic
            violation discovered during canonicalization (CLI exit 2).
    """
    yaml_part, body = split_frontmatter(document)
    data, _key_order = parse_frontmatter(yaml_part)
    transformed = canonicalize_data(data)
    # Run the v0.3 validator on the canonicalized payload — semantic
    # violations surface here (spec §9.1 exit 2).
    validate_v03_fields(transformed)
    new_yaml = _emit_with_confidence_fix(transformed)
    new_doc = f"---\n{new_yaml}---\n{body}"
    return CanonicalizeResult(text=new_doc, changed=new_doc != document)


def canonicalize_path(
    src: Path,
    *,
    out: Path | None = None,
    in_place: bool = False,
) -> CanonicalizeResult:
    """Canonicalize a single ``.md`` file.

    Args:
        src: input path.
        out: write output to this path. Mutually exclusive with ``in_place``.
        in_place: rewrite ``src`` in place. Mutually exclusive with ``out``.

    If both ``out`` and ``in_place`` are absent, the canonicalized text
    is returned without writing — useful for CI dry-run.
    """
    if out is not None and in_place:
        raise SchemaError(
            code=ErrorCode.PARSE_ERROR,
            msg="--in-place and --out are mutually exclusive",
        )
    document = src.read_text(encoding="utf-8")
    result = canonicalize_text(document)
    target: Path | None = None
    if in_place:
        target = src
    elif out is not None:
        target = out
    if target is not None:
        target.write_text(result.text, encoding="utf-8", newline="\n")
    return result
