"""signatures.jsonl packager and extractor for Aphelion v0.5.

Implements spec/v0.5-signer-trust.md §2.4 canonical line layout:

- Each line is one ``SignatureEnvelope`` serialized as canonical JSON (v0.2
  §S2.1) followed by ``\\n``.
- The file MUST end with exactly one ``\\n``.
- Lines MUST be sorted lex-ascending by ``signer_id`` then ``signed_at_iso``.
- Deterministic round-trip: repacking the same envelopes in any input order
  produces byte-identical output.

§5 verification rule 3: Lines not sorted per §2.4 → ``E_SIGNATURE_ORDER``.
"""

from __future__ import annotations

from typing import Iterable

from aphelion.canonical_json import dumps, normalize
from aphelion.signer import SignatureEnvelope, SignerVerificationError, parse_envelope_line

__all__ = [
    "write_signatures_jsonl",
    "read_signatures_jsonl",
    "is_sorted_correctly",
]


def _sort_key(envelope: SignatureEnvelope) -> tuple[str, str]:
    return (envelope.signer_id, envelope.signed_at_iso)


def write_signatures_jsonl(envelopes: Iterable[SignatureEnvelope]) -> bytes:
    """Serialize envelopes to canonical signatures.jsonl byte content.

    Lines lex-sorted by (signer_id, signed_at_iso). UTF-8 encoded. Exactly
    one trailing \\n per non-empty file. Empty input returns ``b""``.
    Deterministic — round-trip property tested.
    """
    sorted_envelopes = sorted(envelopes, key=_sort_key)
    if not sorted_envelopes:
        return b""
    parts: list[bytes] = []
    for envelope in sorted_envelopes:
        payload = normalize(
            {
                "algorithm": envelope.algorithm,
                "package_canonical_hash": envelope.package_canonical_hash,
                "signature_b64": envelope.signature_b64,
                "signed_at_iso": envelope.signed_at_iso,
                "signer_id": envelope.signer_id,
            }
        )
        # dumps() appends a trailing \n — we collect each line with its \n
        parts.append(dumps(payload))
    return b"".join(parts)


def read_signatures_jsonl(content: bytes) -> tuple[SignatureEnvelope, ...]:
    """Parse signatures.jsonl bytes into a tuple of envelopes.

    Validates §2.4 line ordering. Raises ``SignerVerificationError(
    "E_SIGNATURE_ORDER", ...)`` if lines violate sort order.
    Raises ``SignerVerificationError("E_SIGNATURE_MALFORMED", ...)`` on JSON
    parse failure or schema violation.

    The file MUST end with exactly one ``\\n`` (spec §2.4 MUST). Double trailing
    newlines and missing trailing newlines both raise ``E_SIGNATURE_MALFORMED``.
    """
    # Validate trailing newline invariant per §2.4 MUST
    if not content.endswith(b"\n"):
        raise SignerVerificationError(
            "E_SIGNATURE_MALFORMED",
            "signatures.jsonl MUST end with exactly one \\n (spec §2.4)",
        )
    if content.endswith(b"\n\n"):
        raise SignerVerificationError(
            "E_SIGNATURE_MALFORMED",
            "signatures.jsonl MUST end with exactly one \\n; found double trailing newline (spec §2.4)",
        )

    raw_lines = content.split(b"\n")
    # split on \n always yields an empty last element when content ends with \n
    # e.g. b"a\nb\n".split(b"\n") -> [b"a", b"b", b""]
    # Drop the guaranteed trailing empty element
    lines = raw_lines[:-1]

    envelopes: list[SignatureEnvelope] = []
    for line in lines:
        envelopes.append(parse_envelope_line(line))

    # Validate §2.4 sort order per §5 rule 3
    for i in range(len(envelopes) - 1):
        if _sort_key(envelopes[i]) > _sort_key(envelopes[i + 1]):
            raise SignerVerificationError(
                "E_SIGNATURE_ORDER",
                f"signatures.jsonl lines not sorted per §2.4: "
                f"line {i + 1} ({envelopes[i].signer_id!r}, {envelopes[i].signed_at_iso!r}) "
                f"> line {i + 2} ({envelopes[i + 1].signer_id!r}, {envelopes[i + 1].signed_at_iso!r})",
            )

    return tuple(envelopes)


def is_sorted_correctly(envelopes: Iterable[SignatureEnvelope]) -> bool:
    """Return True iff envelopes are lex-sorted by (signer_id, signed_at_iso)."""
    seq = list(envelopes)
    for i in range(len(seq) - 1):
        if _sort_key(seq[i]) > _sort_key(seq[i + 1]):
            return False
    return True
