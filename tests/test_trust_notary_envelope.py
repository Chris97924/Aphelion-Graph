"""TDD tests for v0.6 R7.2 — notary attestation envelope format + verification.

Covers spec/v0.6-notary-attestation.md §2 (envelope) and §3 (verification
path). The v0.6 attestation envelope is strictly additive over the v0.5
trust extension point (spec/v0.5-signer-trust.md §4): the v0.5 ``resolve_notary``
stub and ``NotaryAttestation`` Literal are unchanged and exercised separately
in tests/test_trust.py.

The HMAC path (stdlib only) covers the bulk of the rule-sequence assertions so
the suite stays green without the ``signer`` extra; one ed25519 round-trip
guards the production algorithm when ``cryptography`` is available.
"""

from __future__ import annotations

import base64
import hashlib
import hmac

import pytest

from aphelion.canonical_json import dumps, normalize
from aphelion.signer import (
    SignerManifest,
    SignerVerificationError,
    compute_key_fingerprint,
)

# ---------------------------------------------------------------------------
# Constants / helpers
# ---------------------------------------------------------------------------

SIGNED_AT = "2026-06-20T00:00:00.000Z"


def _hmac_notary_material(
    *, notary_id: str = "acme-notary", mac_key: bytes | None = None
) -> tuple[bytes, SignerManifest]:
    """Return (mac_key, notary SignerManifest) for an hmac-sha256 notary.

    TEST-ONLY-DO-NOT-REUSE — hmac-sha256 has zero non-repudiation and is only
    used here for deterministic, dependency-free envelope round-trip coverage.
    """
    if mac_key is None:
        mac_key = b"\x11" * 32  # TEST-ONLY-DO-NOT-REUSE
    manifest = SignerManifest(
        signer_id=notary_id,
        algorithm="hmac-sha256",
        public_key_b64=base64.standard_b64encode(mac_key).decode("ascii"),
        key_fingerprint=compute_key_fingerprint(mac_key),
        notary_uri=None,
    )
    return mac_key, manifest


def _signer_manifest(
    *,
    signer_id: str = "alice",
    key_fingerprint: str = "a" * 64,
) -> SignerManifest:
    return SignerManifest(
        signer_id=signer_id,
        algorithm="ed25519",
        public_key_b64="AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
        key_fingerprint=key_fingerprint,
        notary_uri="https://notary.example.com",
    )


def _hmac_sign_attestation(mac_key: bytes, attestation_hash: str) -> str:
    """Produce a base64 hmac-sha256 signature over the attestation hash bytes."""
    sig = hmac.new(mac_key, bytes.fromhex(attestation_hash), hashlib.sha256).digest()
    return base64.standard_b64encode(sig).decode("ascii")


# ---------------------------------------------------------------------------
# §2.1 attestation canonical hash
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_attestation_canonical_hash_is_deterministic_and_key_order_independent() -> None:
    from aphelion.trust import compute_attestation_canonical_hash

    h1 = compute_attestation_canonical_hash(
        signer_id="alice", notary_id="acme-notary", key_fingerprint="b" * 64
    )
    h2 = compute_attestation_canonical_hash(
        notary_id="acme-notary", key_fingerprint="b" * 64, signer_id="alice"
    )
    assert h1 == h2
    assert len(h1) == 64
    int(h1, 16)  # hex


@pytest.mark.unit
def test_attestation_canonical_hash_matches_spec_formula() -> None:
    """The hash MUST be sha256(json_canonical({fingerprint, notary_id, signer_id}))."""
    from aphelion.trust import compute_attestation_canonical_hash

    expected = hashlib.sha256(
        dumps(
            normalize(
                {
                    "key_fingerprint": "c" * 64,
                    "notary_id": "acme-notary",
                    "signer_id": "alice",
                }
            )
        )
    ).hexdigest()
    got = compute_attestation_canonical_hash(
        signer_id="alice", notary_id="acme-notary", key_fingerprint="c" * 64
    )
    assert got == expected


@pytest.mark.unit
def test_attestation_canonical_hash_binds_each_field() -> None:
    """Changing signer_id, notary_id, or fingerprint changes the hash."""
    from aphelion.trust import compute_attestation_canonical_hash

    base = compute_attestation_canonical_hash(
        signer_id="alice", notary_id="acme-notary", key_fingerprint="d" * 64
    )
    assert base != compute_attestation_canonical_hash(
        signer_id="bob", notary_id="acme-notary", key_fingerprint="d" * 64
    )
    assert base != compute_attestation_canonical_hash(
        signer_id="alice", notary_id="other-notary", key_fingerprint="d" * 64
    )
    assert base != compute_attestation_canonical_hash(
        signer_id="alice", notary_id="acme-notary", key_fingerprint="e" * 64
    )


# ---------------------------------------------------------------------------
# §2.2 envelope dataclass + canonical serialization round-trip
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_envelope_has_exactly_spec_fields() -> None:
    from dataclasses import fields

    from aphelion.trust import NotaryAttestationEnvelope

    names = {f.name for f in fields(NotaryAttestationEnvelope)}
    assert names == {
        "notary_id",
        "signer_id",
        "key_fingerprint",
        "algorithm",
        "signed_at_iso",
        "signature_b64",
    }


@pytest.mark.unit
def test_envelope_is_frozen() -> None:
    from aphelion.trust import NotaryAttestationEnvelope

    env = NotaryAttestationEnvelope(
        notary_id="acme-notary",
        signer_id="alice",
        key_fingerprint="f" * 64,
        algorithm="hmac-sha256",
        signed_at_iso=SIGNED_AT,
        signature_b64="AA==",
    )
    with pytest.raises((AttributeError, Exception)):
        env.signer_id = "mallory"  # type: ignore[misc]


@pytest.mark.unit
def test_canonical_attestation_roundtrip() -> None:
    from aphelion.trust import (
        NotaryAttestationEnvelope,
        canonical_attestation_bytes,
        parse_attestation_line,
    )

    env = NotaryAttestationEnvelope(
        notary_id="acme-notary",
        signer_id="alice",
        key_fingerprint="0" * 64,
        algorithm="hmac-sha256",
        signed_at_iso=SIGNED_AT,
        signature_b64="QUJD",
    )
    line = canonical_attestation_bytes(env)
    assert line.endswith(b"\n")
    # Canonical bytes are stable on re-serialization.
    assert canonical_attestation_bytes(parse_attestation_line(line)) == line
    assert parse_attestation_line(line) == env


@pytest.mark.unit
def test_parse_attestation_rejects_missing_field() -> None:
    from aphelion.trust import parse_attestation_line

    bad = b'{"algorithm":"hmac-sha256","notary_id":"n","signer_id":"alice"}\n'
    with pytest.raises(SignerVerificationError) as exc:
        parse_attestation_line(bad)
    assert exc.value.code == "E_SIGNATURE_MALFORMED"


@pytest.mark.unit
def test_parse_attestation_rejects_extra_field() -> None:
    from aphelion.trust import (
        NotaryAttestationEnvelope,
        canonical_attestation_bytes,
        parse_attestation_line,
    )

    env = NotaryAttestationEnvelope(
        notary_id="n",
        signer_id="alice",
        key_fingerprint="1" * 64,
        algorithm="hmac-sha256",
        signed_at_iso=SIGNED_AT,
        signature_b64="QQ==",
    )
    line = canonical_attestation_bytes(env).rstrip(b"\n")
    tampered = line[:-1] + b',"x":1}\n'
    with pytest.raises(SignerVerificationError) as exc:
        parse_attestation_line(tampered)
    assert exc.value.code == "E_SIGNATURE_MALFORMED"


@pytest.mark.unit
def test_parse_attestation_rejects_non_object() -> None:
    from aphelion.trust import parse_attestation_line

    with pytest.raises(SignerVerificationError) as exc:
        parse_attestation_line(b"[1,2,3]\n")
    assert exc.value.code == "E_SIGNATURE_MALFORMED"


# ---------------------------------------------------------------------------
# §3 verification path — happy path
# ---------------------------------------------------------------------------


def _valid_attestation(
    *,
    signer_id: str = "alice",
    fingerprint: str = "9" * 64,
    notary_id: str = "acme-notary",
):
    """Build (signer_manifest, attestation, notary_manifest) that should verify."""
    from aphelion.trust import NotaryAttestationEnvelope, compute_attestation_canonical_hash

    mac_key, notary_manifest = _hmac_notary_material(notary_id=notary_id)
    signer_manifest = _signer_manifest(signer_id=signer_id, key_fingerprint=fingerprint)
    att_hash = compute_attestation_canonical_hash(
        signer_id=signer_id, notary_id=notary_id, key_fingerprint=fingerprint
    )
    attestation = NotaryAttestationEnvelope(
        notary_id=notary_id,
        signer_id=signer_id,
        key_fingerprint=fingerprint,
        algorithm="hmac-sha256",
        signed_at_iso=SIGNED_AT,
        signature_b64=_hmac_sign_attestation(mac_key, att_hash),
    )
    return signer_manifest, attestation, notary_manifest


@pytest.mark.unit
def test_resolve_notary_attestation_happy_path_returns_verified_by_notary() -> None:
    from aphelion.trust import resolve_notary_attestation

    signer_manifest, attestation, notary_manifest = _valid_attestation()
    result = resolve_notary_attestation(signer_manifest, attestation, notary_manifest)
    assert result == "verified-by-notary"


@pytest.mark.unit
def test_resolve_notary_attestation_result_is_acceptable_under_require_notary() -> None:
    """A verified-by-notary result must satisfy attestation_is_acceptable(strict)."""
    from aphelion.trust import attestation_is_acceptable, resolve_notary_attestation

    signer_manifest, attestation, notary_manifest = _valid_attestation()
    result = resolve_notary_attestation(signer_manifest, attestation, notary_manifest)
    assert attestation_is_acceptable(result, require_notary=True) is True


# ---------------------------------------------------------------------------
# §3 verification path — binding failures (E_SIGNER_NOTARY_INVALID)
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_signer_id_mismatch_rejected() -> None:
    from aphelion.trust import resolve_notary_attestation

    signer_manifest, attestation, notary_manifest = _valid_attestation()
    other_signer = _signer_manifest(signer_id="mallory", key_fingerprint=signer_manifest.key_fingerprint)
    with pytest.raises(SignerVerificationError) as exc:
        resolve_notary_attestation(other_signer, attestation, notary_manifest)
    assert exc.value.code == "E_SIGNER_NOTARY_INVALID"


@pytest.mark.unit
def test_key_fingerprint_mismatch_rejected() -> None:
    """Notary vouches for a different key than the signer used → reject."""
    from aphelion.trust import resolve_notary_attestation

    signer_manifest, attestation, notary_manifest = _valid_attestation()
    swapped_signer = _signer_manifest(
        signer_id=signer_manifest.signer_id, key_fingerprint="7" * 64
    )
    with pytest.raises(SignerVerificationError) as exc:
        resolve_notary_attestation(swapped_signer, attestation, notary_manifest)
    assert exc.value.code == "E_SIGNER_NOTARY_INVALID"


@pytest.mark.unit
def test_notary_id_mismatch_rejected() -> None:
    from aphelion.trust import resolve_notary_attestation

    signer_manifest, attestation, _ = _valid_attestation()
    _, other_notary = _hmac_notary_material(notary_id="impostor-notary")
    with pytest.raises(SignerVerificationError) as exc:
        resolve_notary_attestation(signer_manifest, attestation, other_notary)
    assert exc.value.code == "E_SIGNER_NOTARY_INVALID"


# ---------------------------------------------------------------------------
# §3 verification path — algorithm + crypto failures (reused v0.5 codes)
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_unknown_algorithm_rejected() -> None:
    from aphelion.trust import NotaryAttestationEnvelope, resolve_notary_attestation

    signer_manifest, attestation, notary_manifest = _valid_attestation()
    bad = NotaryAttestationEnvelope(
        notary_id=attestation.notary_id,
        signer_id=attestation.signer_id,
        key_fingerprint=attestation.key_fingerprint,
        algorithm="rot13",
        signed_at_iso=attestation.signed_at_iso,
        signature_b64=attestation.signature_b64,
    )
    with pytest.raises(SignerVerificationError) as exc:
        resolve_notary_attestation(signer_manifest, bad, notary_manifest)
    assert exc.value.code == "E_SIGNER_ALGORITHM_UNKNOWN"


@pytest.mark.unit
def test_algorithm_mismatch_with_notary_manifest_rejected() -> None:
    """Envelope claims a registry algorithm different from the notary manifest's."""
    from aphelion.trust import NotaryAttestationEnvelope, resolve_notary_attestation

    signer_manifest, attestation, notary_manifest = _valid_attestation()
    # notary_manifest.algorithm == 'hmac-sha256'; declare ed25519 in envelope.
    bad = NotaryAttestationEnvelope(
        notary_id=attestation.notary_id,
        signer_id=attestation.signer_id,
        key_fingerprint=attestation.key_fingerprint,
        algorithm="ed25519",
        signed_at_iso=attestation.signed_at_iso,
        signature_b64=attestation.signature_b64,
    )
    with pytest.raises(SignerVerificationError) as exc:
        resolve_notary_attestation(signer_manifest, bad, notary_manifest)
    assert exc.value.code == "E_SIGNER_ALGORITHM_MISMATCH"


@pytest.mark.unit
def test_notary_manifest_fingerprint_mismatch_rejected() -> None:
    from aphelion.trust import resolve_notary_attestation
    from dataclasses import replace

    signer_manifest, attestation, notary_manifest = _valid_attestation()
    corrupt_notary = replace(notary_manifest, key_fingerprint="2" * 64)
    with pytest.raises(SignerVerificationError) as exc:
        resolve_notary_attestation(signer_manifest, attestation, corrupt_notary)
    assert exc.value.code == "E_SIGNER_FINGERPRINT_MISMATCH"


@pytest.mark.unit
def test_tampered_signature_rejected() -> None:
    from aphelion.trust import NotaryAttestationEnvelope, resolve_notary_attestation

    signer_manifest, attestation, notary_manifest = _valid_attestation()
    raw = bytearray(base64.standard_b64decode(attestation.signature_b64))
    raw[0] ^= 0xFF
    tampered = NotaryAttestationEnvelope(
        notary_id=attestation.notary_id,
        signer_id=attestation.signer_id,
        key_fingerprint=attestation.key_fingerprint,
        algorithm=attestation.algorithm,
        signed_at_iso=attestation.signed_at_iso,
        signature_b64=base64.standard_b64encode(bytes(raw)).decode("ascii"),
    )
    with pytest.raises(SignerVerificationError) as exc:
        resolve_notary_attestation(signer_manifest, tampered, notary_manifest)
    assert exc.value.code == "E_SIGNATURE_INVALID"


@pytest.mark.unit
def test_signature_not_base64_rejected() -> None:
    from aphelion.trust import NotaryAttestationEnvelope, resolve_notary_attestation

    signer_manifest, attestation, notary_manifest = _valid_attestation()
    bad = NotaryAttestationEnvelope(
        notary_id=attestation.notary_id,
        signer_id=attestation.signer_id,
        key_fingerprint=attestation.key_fingerprint,
        algorithm=attestation.algorithm,
        signed_at_iso=attestation.signed_at_iso,
        signature_b64="not valid base64 !!!",
    )
    with pytest.raises(SignerVerificationError) as exc:
        resolve_notary_attestation(signer_manifest, bad, notary_manifest)
    assert exc.value.code == "E_SIGNATURE_MALFORMED"


@pytest.mark.unit
def test_signature_with_trailing_non_base64_junk_rejected() -> None:
    """An otherwise-valid signature with trailing junk MUST be rejected.

    ``base64.standard_b64decode`` silently discards trailing non-alphabet
    characters, so ``<good-sig>!!`` would decode identically to ``<good-sig>``
    and could still HMAC-verify. Strict decoding (validate=True) closes that
    gap; the helper promises E_SIGNATURE_MALFORMED for undecodable base64.
    """
    from aphelion.trust import NotaryAttestationEnvelope, resolve_notary_attestation

    signer_manifest, attestation, notary_manifest = _valid_attestation()
    # attestation.signature_b64 is a valid hmac-sha256 signature; appending
    # "!!" keeps the length divisible by 4 but injects non-base64 bytes.
    junked = attestation.signature_b64[:-2] + "!!"
    bad = NotaryAttestationEnvelope(
        notary_id=attestation.notary_id,
        signer_id=attestation.signer_id,
        key_fingerprint=attestation.key_fingerprint,
        algorithm=attestation.algorithm,
        signed_at_iso=attestation.signed_at_iso,
        signature_b64=junked,
    )
    with pytest.raises(SignerVerificationError) as exc:
        resolve_notary_attestation(signer_manifest, bad, notary_manifest)
    assert exc.value.code == "E_SIGNATURE_MALFORMED"


@pytest.mark.unit
def test_non_ascii_fingerprint_rejected_before_compare() -> None:
    """A non-ASCII key_fingerprint must surface E_SIGNER_NOTARY_INVALID.

    ``hmac.compare_digest`` raises a raw ``TypeError`` on non-ASCII ``str``
    input, so a malformed envelope could crash a verifier before it returns the
    spec error code. The §3.2 format guard (64 lowercase hex) rejects it first.
    """
    from aphelion.trust import NotaryAttestationEnvelope, resolve_notary_attestation

    signer_manifest, _, notary_manifest = _valid_attestation()
    bad = NotaryAttestationEnvelope(
        notary_id="acme-notary",
        signer_id="alice",
        key_fingerprint="é" * 64,  # non-ASCII: would crash compare_digest
        algorithm="hmac-sha256",
        signed_at_iso=SIGNED_AT,
        signature_b64="QUJD",
    )
    with pytest.raises(SignerVerificationError) as exc:
        resolve_notary_attestation(signer_manifest, bad, notary_manifest)
    assert exc.value.code == "E_SIGNER_NOTARY_INVALID"


@pytest.mark.unit
def test_non_ascii_notary_manifest_fingerprint_rejected_before_compare() -> None:
    """A non-ASCII notary-manifest key_fingerprint must surface E_SIGNER_FINGERPRINT_MISMATCH.

    The §3.6 path recomputes the notary fingerprint and compares it against the
    attacker-influenced ``notary_manifest.key_fingerprint`` via
    ``hmac.compare_digest``, which raises a raw ``TypeError`` on non-ASCII ``str``
    input. The §3.6 format guard (64 lowercase hex) rejects it first with the
    spec-mandated error code ``E_SIGNER_FINGERPRINT_MISMATCH`` (spec §3.6,
    lines 86-87 & 107-108), not the §3.2 attestation-binding code.
    """
    from dataclasses import replace

    from aphelion.trust import resolve_notary_attestation

    signer_manifest, attestation, notary_manifest = _valid_attestation()
    bad_notary = replace(notary_manifest, key_fingerprint="é" * 64)
    with pytest.raises(SignerVerificationError) as exc:
        resolve_notary_attestation(signer_manifest, attestation, bad_notary)
    assert exc.value.code == "E_SIGNER_FINGERPRINT_MISMATCH"


@pytest.mark.unit
def test_notary_key_with_trailing_non_base64_junk_rejected() -> None:
    """A notary public_key_b64 with trailing junk MUST be rejected at §3.6.

    ``base64.standard_b64decode`` silently discards trailing non-alphabet
    characters, so a malformed notary manifest could still recompute the right
    fingerprint and satisfy §3.6, returning ``verified-by-notary``. Strict
    decoding (validate=True) closes that gap → E_SIGNER_MALFORMED.
    """
    from dataclasses import replace

    from aphelion.trust import resolve_notary_attestation

    signer_manifest, attestation, notary_manifest = _valid_attestation()
    # public_key_b64 is otherwise-valid (already "="-padded); appending "!!"
    # after it is silently dropped by tolerant decode — it decodes to the exact
    # same 32 bytes, so the fingerprint recompute would still pass §3.6. Strict
    # decoding (validate=True) rejects the trailing junk instead.
    junked_key = notary_manifest.public_key_b64 + "!!"
    corrupt_notary = replace(notary_manifest, public_key_b64=junked_key)
    with pytest.raises(SignerVerificationError) as exc:
        resolve_notary_attestation(signer_manifest, attestation, corrupt_notary)
    assert exc.value.code == "E_SIGNER_MALFORMED"


# ---------------------------------------------------------------------------
# ed25519 production path (guarded by the signer extra)
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_ed25519_notary_attestation_roundtrip() -> None:
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from aphelion.trust import (
        NotaryAttestationEnvelope,
        compute_attestation_canonical_hash,
        resolve_notary_attestation,
    )

    priv = Ed25519PrivateKey.generate()  # TEST-ONLY-DO-NOT-REUSE
    pub_raw = priv.public_key().public_bytes_raw()
    pub_b64 = base64.standard_b64encode(pub_raw).decode("ascii")

    notary_manifest = SignerManifest(
        signer_id="acme-notary",
        algorithm="ed25519",
        public_key_b64=pub_b64,
        key_fingerprint=compute_key_fingerprint(pub_raw),
        notary_uri=None,
    )
    signer_manifest = _signer_manifest(signer_id="alice", key_fingerprint="3" * 64)
    att_hash = compute_attestation_canonical_hash(
        signer_id="alice", notary_id="acme-notary", key_fingerprint="3" * 64
    )
    sig = priv.sign(bytes.fromhex(att_hash))
    attestation = NotaryAttestationEnvelope(
        notary_id="acme-notary",
        signer_id="alice",
        key_fingerprint="3" * 64,
        algorithm="ed25519",
        signed_at_iso=SIGNED_AT,
        signature_b64=base64.standard_b64encode(sig).decode("ascii"),
    )
    result = resolve_notary_attestation(signer_manifest, attestation, notary_manifest)
    assert result == "verified-by-notary"


@pytest.mark.unit
def test_ed25519_malformed_notary_key_becomes_verification_error() -> None:
    """A notary key that decodes but is not a valid 32-byte ed25519 key.

    ``Ed25519PublicKey.from_public_bytes`` raises ``ValueError`` on non-32-byte
    input. If the manifest fingerprint is self-consistent (computed over those
    same malformed bytes), §3.6 passes and verification reaches
    from_public_bytes — which must surface as E_SIGNER_MALFORMED, not an
    uncaught exception that bypasses the SignerVerificationError.code contract.
    """
    pytest.importorskip("cryptography")

    from aphelion.trust import (
        NotaryAttestationEnvelope,
        resolve_notary_attestation,
    )

    # 16 bytes — decodes fine, but is not a valid ed25519 public key.
    bad_raw = b"\x07" * 16
    bad_b64 = base64.standard_b64encode(bad_raw).decode("ascii")
    # Fingerprint is computed over the malformed bytes so §3.6 (fingerprint
    # recompute) passes and execution reaches from_public_bytes.
    notary_manifest = SignerManifest(
        signer_id="acme-notary",
        algorithm="ed25519",
        public_key_b64=bad_b64,
        key_fingerprint=compute_key_fingerprint(bad_raw),
        notary_uri=None,
    )
    signer_manifest = _signer_manifest(signer_id="alice", key_fingerprint="5" * 64)
    # Signature content is irrelevant — the crash happens before verify().
    attestation = NotaryAttestationEnvelope(
        notary_id="acme-notary",
        signer_id="alice",
        key_fingerprint="5" * 64,
        algorithm="ed25519",
        signed_at_iso=SIGNED_AT,
        signature_b64=base64.standard_b64encode(b"\x00" * 64).decode("ascii"),
    )
    with pytest.raises(SignerVerificationError) as exc:
        resolve_notary_attestation(signer_manifest, attestation, notary_manifest)
    assert exc.value.code == "E_SIGNER_MALFORMED"


@pytest.mark.unit
def test_ed25519_notary_attestation_tamper_rejected() -> None:
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from aphelion.trust import (
        NotaryAttestationEnvelope,
        compute_attestation_canonical_hash,
        resolve_notary_attestation,
    )

    priv = Ed25519PrivateKey.generate()  # TEST-ONLY-DO-NOT-REUSE
    pub_raw = priv.public_key().public_bytes_raw()
    pub_b64 = base64.standard_b64encode(pub_raw).decode("ascii")
    notary_manifest = SignerManifest(
        signer_id="acme-notary",
        algorithm="ed25519",
        public_key_b64=pub_b64,
        key_fingerprint=compute_key_fingerprint(pub_raw),
        notary_uri=None,
    )
    signer_manifest = _signer_manifest(signer_id="alice", key_fingerprint="4" * 64)
    att_hash = compute_attestation_canonical_hash(
        signer_id="alice", notary_id="acme-notary", key_fingerprint="4" * 64
    )
    sig = bytearray(priv.sign(bytes.fromhex(att_hash)))
    sig[0] ^= 0xFF
    attestation = NotaryAttestationEnvelope(
        notary_id="acme-notary",
        signer_id="alice",
        key_fingerprint="4" * 64,
        algorithm="ed25519",
        signed_at_iso=SIGNED_AT,
        signature_b64=base64.standard_b64encode(bytes(sig)).decode("ascii"),
    )
    with pytest.raises(SignerVerificationError) as exc:
        resolve_notary_attestation(signer_manifest, attestation, notary_manifest)
    assert exc.value.code == "E_SIGNATURE_INVALID"


# ---------------------------------------------------------------------------
# v0.5 stub remains intact (regression guard)
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_v05_resolve_notary_stub_unchanged() -> None:
    """The v0.5 no-attestation stub still yields 'verified-locally'."""
    from aphelion.trust import resolve_notary

    assert resolve_notary(_signer_manifest()) == "verified-locally"


@pytest.mark.unit
def test_notary_attestation_literal_unchanged() -> None:
    """R7.2 must NOT widen the NotaryAttestation Literal (additive only)."""
    import typing

    from aphelion.trust import NotaryAttestation

    assert set(typing.get_args(NotaryAttestation)) == {
        "verified-locally",
        "verified-by-notary",
    }


# ---------------------------------------------------------------------------
# spec traceability
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_module_docstring_references_r72() -> None:
    import aphelion.trust as trust_module

    assert trust_module.__doc__ is not None
    assert "R7.2" in trust_module.__doc__
