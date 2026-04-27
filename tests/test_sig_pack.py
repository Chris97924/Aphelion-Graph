"""TDD tests for sig_pack.py — signatures.jsonl packager/extractor.

Covers spec/v0.5-signer-trust.md §2.4 (canonical line layout) and §5
verification rule 3 (E_SIGNATURE_ORDER).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json

import pytest

from aphelion.sig_pack import (
    is_sorted_correctly,
    read_signatures_jsonl,
    write_signatures_jsonl,
)
from aphelion.signer import SignatureEnvelope, SignerVerificationError

# ---------------------------------------------------------------------------
# Test fixtures
# ---------------------------------------------------------------------------

SHARED_SECRET = b"phase-a-test-key-do-not-reuse-32"
PACKAGE_HASH = hashlib.sha256(b"sig-pack-test-canonical-hash").hexdigest()


def _make_envelope(
    signer_id: str = "alice",
    signed_at_iso: str = "2026-04-27T00:00:00.000Z",
    package_hash: str = PACKAGE_HASH,
) -> SignatureEnvelope:
    sig = hmac.new(SHARED_SECRET, bytes.fromhex(package_hash), hashlib.sha256).digest()
    return SignatureEnvelope(
        signer_id=signer_id,
        algorithm="hmac-sha256",
        signed_at_iso=signed_at_iso,
        package_canonical_hash=package_hash,
        signature_b64=base64.standard_b64encode(sig).decode("ascii"),
    )


# ---------------------------------------------------------------------------
# write_signatures_jsonl
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_write_empty_envelopes_returns_empty_bytes() -> None:
    """Empty input produces zero bytes (spec §2.4 does not mandate a file exists;
    an empty signatures.jsonl is equivalent to no signatures.jsonl).
    """
    result = write_signatures_jsonl([])
    assert result == b""


@pytest.mark.unit
def test_write_single_envelope_round_trip() -> None:
    """Write 1 envelope and read it back — exact round-trip equality."""
    env = _make_envelope()
    content = write_signatures_jsonl([env])
    (parsed,) = read_signatures_jsonl(content)
    assert parsed == env


@pytest.mark.unit
def test_write_multiple_envelopes_sorted_lex() -> None:
    """Input in reverse sort order — output must be lex-sorted by (signer_id, signed_at_iso)."""
    env_z = _make_envelope(signer_id="zara", signed_at_iso="2026-04-27T01:00:00.000Z")
    env_a = _make_envelope(signer_id="alice", signed_at_iso="2026-04-27T00:00:00.000Z")
    content = write_signatures_jsonl([env_z, env_a])
    envelopes = read_signatures_jsonl(content)
    assert envelopes[0].signer_id == "alice"
    assert envelopes[1].signer_id == "zara"


@pytest.mark.unit
def test_write_byte_identical_under_repack() -> None:
    """Deterministic round-trip: same envelope set, different input order → byte-identical output."""
    env_a = _make_envelope(signer_id="alice", signed_at_iso="2026-04-27T00:00:00.000Z")
    env_b = _make_envelope(signer_id="bob", signed_at_iso="2026-04-27T00:00:00.000Z")
    result_1 = write_signatures_jsonl([env_a, env_b])
    result_2 = write_signatures_jsonl([env_b, env_a])
    assert result_1 == result_2


@pytest.mark.unit
def test_write_single_envelope_ends_with_newline() -> None:
    """Spec §2.4: file MUST end with exactly one \\n."""
    env = _make_envelope()
    content = write_signatures_jsonl([env])
    assert content.endswith(b"\n")
    assert not content.endswith(b"\n\n")


@pytest.mark.unit
def test_write_two_envelopes_ends_with_single_newline() -> None:
    """Multi-envelope file also ends with exactly one \\n, no double newline."""
    env_a = _make_envelope(signer_id="alice")
    env_b = _make_envelope(signer_id="bob")
    content = write_signatures_jsonl([env_a, env_b])
    assert content.endswith(b"\n")
    assert not content.endswith(b"\n\n")


@pytest.mark.unit
def test_sort_stable_within_same_signer_id() -> None:
    """Two envelopes with same signer_id are ordered by signed_at_iso."""
    env_later = _make_envelope(signer_id="alice", signed_at_iso="2026-04-27T02:00:00.000Z")
    env_earlier = _make_envelope(signer_id="alice", signed_at_iso="2026-04-27T00:00:00.000Z")
    content = write_signatures_jsonl([env_later, env_earlier])
    envelopes = read_signatures_jsonl(content)
    assert envelopes[0].signed_at_iso == "2026-04-27T00:00:00.000Z"
    assert envelopes[1].signed_at_iso == "2026-04-27T02:00:00.000Z"


@pytest.mark.unit
def test_canonical_json_per_line() -> None:
    """Each line must be canonical JSON: sorted keys, no whitespace, UTF-8."""
    from aphelion.canonical_json import dumps, normalize

    env = _make_envelope()
    content = write_signatures_jsonl([env])
    line = content.rstrip(b"\n")
    # Reserialize through canonical_json and compare bytes
    parsed = json.loads(line.decode("utf-8"))
    expected_bytes = dumps(normalize(parsed)).rstrip(b"\n")
    assert line == expected_bytes


# ---------------------------------------------------------------------------
# read_signatures_jsonl
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_read_rejects_unsorted_lines() -> None:
    """Manually craft a jsonl where sort order is violated → E_SIGNATURE_ORDER."""
    env_z = _make_envelope(signer_id="zara")
    env_a = _make_envelope(signer_id="alice")
    # Write them in correct order then manually reverse the bytes
    correct = write_signatures_jsonl([env_a, env_z])
    lines = correct.split(b"\n")
    lines = [l for l in lines if l]  # drop empty
    reversed_content = b"\n".join(reversed(lines)) + b"\n"
    with pytest.raises(SignerVerificationError) as exc_info:
        read_signatures_jsonl(reversed_content)
    assert exc_info.value.code == "E_SIGNATURE_ORDER"


@pytest.mark.unit
def test_read_rejects_malformed_json() -> None:
    """Non-JSON line → E_SIGNATURE_MALFORMED."""
    bad = b"not-json-at-all\n"
    with pytest.raises(SignerVerificationError) as exc_info:
        read_signatures_jsonl(bad)
    assert exc_info.value.code == "E_SIGNATURE_MALFORMED"


@pytest.mark.unit
def test_read_rejects_missing_envelope_field() -> None:
    """JSON object missing required envelope field → E_SIGNATURE_MALFORMED."""
    incomplete = {"signer_id": "alice", "algorithm": "hmac-sha256"}
    line = json.dumps(incomplete, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    with pytest.raises(SignerVerificationError) as exc_info:
        read_signatures_jsonl(line)
    assert exc_info.value.code == "E_SIGNATURE_MALFORMED"


@pytest.mark.unit
def test_read_rejects_extra_envelope_field() -> None:
    """JSON with unknown field → E_SIGNATURE_MALFORMED (strict schema per §2.2)."""
    env = _make_envelope()
    env_dict = {
        "signer_id": env.signer_id,
        "algorithm": env.algorithm,
        "signed_at_iso": env.signed_at_iso,
        "package_canonical_hash": env.package_canonical_hash,
        "signature_b64": env.signature_b64,
        "unexpected_field": "oops",
    }
    line = json.dumps(env_dict, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    with pytest.raises(SignerVerificationError) as exc_info:
        read_signatures_jsonl(line)
    assert exc_info.value.code == "E_SIGNATURE_MALFORMED"


@pytest.mark.unit
def test_read_rejects_missing_trailing_newline() -> None:
    """Content not ending in \\n → E_SIGNATURE_MALFORMED (spec §2.4 MUST)."""
    env = _make_envelope()
    content_with_newline = write_signatures_jsonl([env])
    content_no_newline = content_with_newline.rstrip(b"\n")
    with pytest.raises(SignerVerificationError) as exc_info:
        read_signatures_jsonl(content_no_newline)
    assert exc_info.value.code == "E_SIGNATURE_MALFORMED"


@pytest.mark.unit
def test_read_rejects_double_trailing_newline() -> None:
    """Content ending with \\n\\n (double trailing newline) → E_SIGNATURE_MALFORMED."""
    env = _make_envelope()
    content = write_signatures_jsonl([env]) + b"\n"
    with pytest.raises(SignerVerificationError) as exc_info:
        read_signatures_jsonl(content)
    assert exc_info.value.code == "E_SIGNATURE_MALFORMED"


# ---------------------------------------------------------------------------
# is_sorted_correctly
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_is_sorted_correctly_empty() -> None:
    """Empty sequence is vacuously sorted."""
    assert is_sorted_correctly([]) is True


@pytest.mark.unit
def test_is_sorted_correctly_single() -> None:
    """Single envelope is always sorted."""
    assert is_sorted_correctly([_make_envelope()]) is True


@pytest.mark.unit
def test_is_sorted_correctly_sorted_order() -> None:
    env_a = _make_envelope(signer_id="alice")
    env_b = _make_envelope(signer_id="bob")
    assert is_sorted_correctly([env_a, env_b]) is True


@pytest.mark.unit
def test_is_sorted_correctly_reversed_order() -> None:
    env_a = _make_envelope(signer_id="alice")
    env_b = _make_envelope(signer_id="bob")
    assert is_sorted_correctly([env_b, env_a]) is False


@pytest.mark.unit
def test_is_sorted_correctly_same_signer_by_time() -> None:
    env_early = _make_envelope(signer_id="alice", signed_at_iso="2026-04-27T00:00:00.000Z")
    env_late = _make_envelope(signer_id="alice", signed_at_iso="2026-04-27T01:00:00.000Z")
    assert is_sorted_correctly([env_early, env_late]) is True
    assert is_sorted_correctly([env_late, env_early]) is False
