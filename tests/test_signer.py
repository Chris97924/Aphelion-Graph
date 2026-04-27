"""TDD tests for v0.5 signer envelope + HMAC reference verifier.

Covers spec/v0.5-signer-trust.md §2 (envelope), §3 (algorithms),
§5 (verification rules subset), §6 (error codes).
"""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import hmac
import json
import sys
import unittest.mock

import pytest
from hypothesis import given, settings, strategies as st

from aphelion.signer import (
    ALGORITHM_REGISTRY,
    Ed25519Signer,
    Ed25519Verifier,
    HMACSigner,
    HMACVerifier,
    SignatureEnvelope,
    Signer,
    SignerManifest,
    SignerVerificationError,
    Verifier,
    canonical_envelope_bytes,
    compute_key_fingerprint,
    compute_package_canonical_hash,
    parse_envelope_line,
)

# Suppress the spec §3.2 hmac-sha256 TEST-ONLY warning across the whole
# test module — every fixture-driven verify() call would otherwise emit it.
# The dedicated test below explicitly asserts the warning fires.
pytestmark = pytest.mark.filterwarnings(
    "ignore:hmac-sha256 envelopes have zero non-repudiation:UserWarning"
)

# ---------------------------------------------------------------------------
# Constants used across tests; kept inline so failures point at concrete data
# ---------------------------------------------------------------------------

SHARED_SECRET = b"phase-a-test-key-do-not-reuse-32"
ALT_SECRET = b"different-key-for-negative-tests"

PACKAGE_HASH = hashlib.sha256(b"package-canonical-hash-input").hexdigest()
SIGNED_AT = "2026-04-27T00:00:00.000Z"  # millisecond precision per canonical-serialization Rule 4
SIGNER_ID = "alice"


def _envelope() -> SignatureEnvelope:
    sig = hmac.new(SHARED_SECRET, bytes.fromhex(PACKAGE_HASH), hashlib.sha256).digest()
    return SignatureEnvelope(
        signer_id=SIGNER_ID,
        algorithm="hmac-sha256",
        signed_at_iso=SIGNED_AT,
        package_canonical_hash=PACKAGE_HASH,
        signature_b64=base64.standard_b64encode(sig).decode("ascii"),
    )


# ---------------------------------------------------------------------------
# §2.2 envelope schema + immutability
# ---------------------------------------------------------------------------


def test_envelope_is_frozen_dataclass() -> None:
    env = _envelope()
    assert dataclasses.is_dataclass(env)
    with pytest.raises(dataclasses.FrozenInstanceError):
        env.signer_id = "mallory"  # type: ignore[misc]


def test_envelope_field_set_matches_spec_22() -> None:
    field_names = {f.name for f in dataclasses.fields(SignatureEnvelope)}
    assert field_names == {
        "signer_id",
        "algorithm",
        "signed_at_iso",
        "package_canonical_hash",
        "signature_b64",
    }


# ---------------------------------------------------------------------------
# §2.4 canonical JSONL line encoding round-trip
# ---------------------------------------------------------------------------


def test_canonical_envelope_bytes_round_trip() -> None:
    env = _envelope()
    line = canonical_envelope_bytes(env)
    assert line.endswith(b"\n"), "canonical envelope line must end with LF"
    payload = json.loads(line.decode("utf-8"))
    assert payload["signer_id"] == SIGNER_ID
    assert payload["algorithm"] == "hmac-sha256"
    assert payload["package_canonical_hash"] == PACKAGE_HASH


def test_canonical_envelope_bytes_keys_are_lex_sorted() -> None:
    env = _envelope()
    line = canonical_envelope_bytes(env).rstrip(b"\n").decode("utf-8")
    expected_order = [
        "algorithm",
        "package_canonical_hash",
        "signature_b64",
        "signed_at_iso",
        "signer_id",
    ]
    positions = [line.index(f'"{key}"') for key in expected_order]
    assert positions == sorted(
        positions
    ), f"keys not lex-sorted: {expected_order} positions {positions}"


# ---------------------------------------------------------------------------
# §3.1 algorithm registry
# ---------------------------------------------------------------------------


def test_registry_lists_hmac_sha256_and_ed25519() -> None:
    assert "hmac-sha256" in ALGORITHM_REGISTRY
    assert "ed25519" in ALGORITHM_REGISTRY


def test_unknown_algorithm_rejected_at_verify() -> None:
    env = dataclasses.replace(_envelope(), algorithm="md5")
    manifest = SignerManifest(
        signer_id=SIGNER_ID,
        algorithm="hmac-sha256",
        public_key_b64=base64.standard_b64encode(SHARED_SECRET).decode("ascii"),
        key_fingerprint=compute_key_fingerprint(SHARED_SECRET),
        notary_uri=None,
    )
    verifier = HMACVerifier()
    with pytest.raises(SignerVerificationError) as exc:
        verifier.verify(env, manifest, package_canonical_hash=PACKAGE_HASH)
    assert exc.value.code == "E_SIGNER_ALGORITHM_UNKNOWN"


# ---------------------------------------------------------------------------
# §3.2 hmac-sha256 round-trip
# ---------------------------------------------------------------------------


def test_hmac_signer_envelope_verifies() -> None:
    signer = HMACSigner(signer_id=SIGNER_ID, secret=SHARED_SECRET)
    env = signer.sign(package_canonical_hash=PACKAGE_HASH, signed_at_iso=SIGNED_AT)
    manifest = signer.manifest()
    HMACVerifier().verify(env, manifest, package_canonical_hash=PACKAGE_HASH)


def test_hmac_verifier_rejects_tampered_hash() -> None:
    signer = HMACSigner(signer_id=SIGNER_ID, secret=SHARED_SECRET)
    env = signer.sign(package_canonical_hash=PACKAGE_HASH, signed_at_iso=SIGNED_AT)
    manifest = signer.manifest()
    tampered = "0" * 64
    with pytest.raises(SignerVerificationError) as exc:
        HMACVerifier().verify(env, manifest, package_canonical_hash=tampered)
    assert exc.value.code == "E_SIGNATURE_HASH_MISMATCH"


def test_hmac_verifier_rejects_wrong_key() -> None:
    signer = HMACSigner(signer_id=SIGNER_ID, secret=SHARED_SECRET)
    env = signer.sign(package_canonical_hash=PACKAGE_HASH, signed_at_iso=SIGNED_AT)
    wrong_manifest = SignerManifest(
        signer_id=SIGNER_ID,
        algorithm="hmac-sha256",
        public_key_b64=base64.standard_b64encode(ALT_SECRET).decode("ascii"),
        key_fingerprint=compute_key_fingerprint(ALT_SECRET),
        notary_uri=None,
    )
    with pytest.raises(SignerVerificationError) as exc:
        HMACVerifier().verify(env, wrong_manifest, package_canonical_hash=PACKAGE_HASH)
    assert exc.value.code == "E_SIGNATURE_INVALID"


# ---------------------------------------------------------------------------
# §2.3 manifest fingerprint integrity
# ---------------------------------------------------------------------------


def test_manifest_fingerprint_matches_pubkey() -> None:
    fp = compute_key_fingerprint(SHARED_SECRET)
    assert len(fp) == 64
    assert fp == fp.lower()
    int(fp, 16)  # would raise on non-hex


def test_manifest_with_mismatched_fingerprint_rejected() -> None:
    bad_manifest = SignerManifest(
        signer_id=SIGNER_ID,
        algorithm="hmac-sha256",
        public_key_b64=base64.standard_b64encode(SHARED_SECRET).decode("ascii"),
        key_fingerprint="0" * 64,
        notary_uri=None,
    )
    env = HMACSigner(signer_id=SIGNER_ID, secret=SHARED_SECRET).sign(
        package_canonical_hash=PACKAGE_HASH, signed_at_iso=SIGNED_AT
    )
    with pytest.raises(SignerVerificationError) as exc:
        HMACVerifier().verify(env, bad_manifest, package_canonical_hash=PACKAGE_HASH)
    assert exc.value.code == "E_SIGNER_FINGERPRINT_MISMATCH"


# ---------------------------------------------------------------------------
# §2.1 package canonical hash determinism
# ---------------------------------------------------------------------------


def test_package_canonical_hash_is_order_independent_for_claims() -> None:
    base_args = {
        "format_version": "2.0",
        "package_id": "0191aaaa-0000-7000-8000-000000000001",
    }
    claims_a = [
        ("c1", "i1", "h1"),
        ("c2", "i2", "h2"),
    ]
    claims_b = list(reversed(claims_a))
    h1 = compute_package_canonical_hash(claims=claims_a, **base_args)
    h2 = compute_package_canonical_hash(claims=claims_b, **base_args)
    assert h1 == h2


def test_package_canonical_hash_changes_when_content_changes() -> None:
    base_args = {
        "format_version": "2.0",
        "package_id": "0191aaaa-0000-7000-8000-000000000001",
    }
    claims_a = [("c1", "i1", "h1")]
    claims_b = [("c1", "i1", "h2")]
    h1 = compute_package_canonical_hash(claims=claims_a, **base_args)
    h2 = compute_package_canonical_hash(claims=claims_b, **base_args)
    assert h1 != h2


# ---------------------------------------------------------------------------
# US-001: Negative-path coverage closes spec §5 + §6 error-code map
# ---------------------------------------------------------------------------


def _genuine_signer_pair() -> tuple[HMACSigner, SignerManifest]:
    signer = HMACSigner(signer_id=SIGNER_ID, secret=SHARED_SECRET)
    return signer, signer.manifest()


def test_verify_rejects_malformed_signature_b64() -> None:
    signer, manifest = _genuine_signer_pair()
    env = signer.sign(package_canonical_hash=PACKAGE_HASH, signed_at_iso=SIGNED_AT)
    bad_env = dataclasses.replace(env, signature_b64="!!!not-valid-base64!!!")
    with pytest.raises(SignerVerificationError) as exc:
        HMACVerifier().verify(bad_env, manifest, package_canonical_hash=PACKAGE_HASH)
    assert exc.value.code == "E_SIGNATURE_MALFORMED"


def test_verify_rejects_malformed_public_key_b64() -> None:
    signer, manifest = _genuine_signer_pair()
    env = signer.sign(package_canonical_hash=PACKAGE_HASH, signed_at_iso=SIGNED_AT)
    bad_manifest = dataclasses.replace(manifest, public_key_b64="!!!not-base64!!!")
    with pytest.raises(SignerVerificationError) as exc:
        HMACVerifier().verify(env, bad_manifest, package_canonical_hash=PACKAGE_HASH)
    assert exc.value.code == "E_SIGNER_MALFORMED"


def test_verify_rejects_signer_id_mismatch() -> None:
    signer, manifest = _genuine_signer_pair()
    env = signer.sign(package_canonical_hash=PACKAGE_HASH, signed_at_iso=SIGNED_AT)
    other_manifest = dataclasses.replace(manifest, signer_id="bob")
    with pytest.raises(SignerVerificationError) as exc:
        HMACVerifier().verify(env, other_manifest, package_canonical_hash=PACKAGE_HASH)
    assert exc.value.code == "E_SIGNER_MISSING"


def test_verify_rejects_non_hex_envelope_hash() -> None:
    signer, manifest = _genuine_signer_pair()
    env = signer.sign(package_canonical_hash=PACKAGE_HASH, signed_at_iso=SIGNED_AT)
    bad_env = dataclasses.replace(env, package_canonical_hash="zz" * 32)
    with pytest.raises(SignerVerificationError) as exc:
        HMACVerifier().verify(bad_env, manifest, package_canonical_hash="zz" * 32)
    assert exc.value.code == "E_SIGNATURE_MALFORMED"


def test_verify_rejects_uppercase_hex_envelope_hash() -> None:
    signer, manifest = _genuine_signer_pair()
    env = signer.sign(package_canonical_hash=PACKAGE_HASH, signed_at_iso=SIGNED_AT)
    bad_env = dataclasses.replace(env, package_canonical_hash=PACKAGE_HASH.upper())
    with pytest.raises(SignerVerificationError) as exc:
        HMACVerifier().verify(
            bad_env, manifest, package_canonical_hash=PACKAGE_HASH.upper()
        )
    assert exc.value.code == "E_SIGNATURE_MALFORMED"


def test_verify_rejects_short_envelope_hash() -> None:
    signer, manifest = _genuine_signer_pair()
    env = signer.sign(package_canonical_hash=PACKAGE_HASH, signed_at_iso=SIGNED_AT)
    bad_env = dataclasses.replace(env, package_canonical_hash="ab" * 31)
    with pytest.raises(SignerVerificationError) as exc:
        HMACVerifier().verify(bad_env, manifest, package_canonical_hash="ab" * 31)
    assert exc.value.code == "E_SIGNATURE_MALFORMED"


# ---------------------------------------------------------------------------
# US-002: Hypothesis property tests anchor sign/verify roundtrip + bit-flip
# ---------------------------------------------------------------------------

_secret_strategy = st.binary(min_size=1, max_size=256)
_hash_strategy = st.text(alphabet="0123456789abcdef", min_size=64, max_size=64)


@given(secret=_secret_strategy, hash_hex=_hash_strategy)
@settings(max_examples=100, deadline=None)
def test_property_sign_then_verify_always_succeeds(
    secret: bytes, hash_hex: str
) -> None:
    signer = HMACSigner(signer_id="prop-signer", secret=secret)
    env = signer.sign(package_canonical_hash=hash_hex, signed_at_iso=SIGNED_AT)
    HMACVerifier().verify(env, signer.manifest(), package_canonical_hash=hash_hex)


@given(secret=_secret_strategy, hash_hex=_hash_strategy)
@settings(max_examples=100, deadline=None)
def test_property_hmac_signature_is_deterministic(secret: bytes, hash_hex: str) -> None:
    signer = HMACSigner(signer_id="prop-signer", secret=secret)
    env_a = signer.sign(package_canonical_hash=hash_hex, signed_at_iso=SIGNED_AT)
    env_b = signer.sign(package_canonical_hash=hash_hex, signed_at_iso=SIGNED_AT)
    assert env_a.signature_b64 == env_b.signature_b64


@given(
    secret=_secret_strategy,
    hash_hex=_hash_strategy,
    bit_index=st.integers(min_value=0, max_value=255),
)
@settings(max_examples=100, deadline=None)
def test_property_single_bit_flip_breaks_verification(
    secret: bytes, hash_hex: str, bit_index: int
) -> None:
    signer = HMACSigner(signer_id="prop-signer", secret=secret)
    env = signer.sign(package_canonical_hash=hash_hex, signed_at_iso=SIGNED_AT)
    raw = bytearray(base64.standard_b64decode(env.signature_b64))
    byte_idx, bit_in_byte = divmod(bit_index, 8)
    raw[byte_idx] ^= 1 << bit_in_byte
    tampered = dataclasses.replace(
        env, signature_b64=base64.standard_b64encode(bytes(raw)).decode("ascii")
    )
    with pytest.raises(SignerVerificationError) as exc:
        HMACVerifier().verify(
            tampered, signer.manifest(), package_canonical_hash=hash_hex
        )
    assert exc.value.code == "E_SIGNATURE_INVALID"


# ---------------------------------------------------------------------------
# US-003: compute_package_canonical_hash regression vector + edge cases
# ---------------------------------------------------------------------------

REGRESSION_PKG_ID = "0191aaaa-0000-7000-8000-000000000001"
REGRESSION_CLAIMS = [("c1", "i1", "h1"), ("c2", "i2", "h2")]
REGRESSION_EXPECTED_HASH = (
    "b13026a2d9b096c8fb0c9b0c0a7df467d672e3d8a30749776cf8925564446e7c"
)
EMPTY_CLAIMS_EXPECTED_HASH = (
    "364619fd019df57db69335d60d9e59e5b2043c639810ada916bf06b4242b7f4b"
)


def test_regression_vector_pins_canonical_hash() -> None:
    """Drift guard — silent change to canonical encoding fails this test."""

    actual = compute_package_canonical_hash(
        format_version="2.0",
        package_id=REGRESSION_PKG_ID,
        claims=REGRESSION_CLAIMS,
    )
    assert actual == REGRESSION_EXPECTED_HASH, (
        "package_canonical_hash drifted from pinned regression vector — "
        "spec §2.1 changed without updating this fixture"
    )


def test_empty_claims_yields_deterministic_hash() -> None:
    actual = compute_package_canonical_hash(
        format_version="2.0", package_id=REGRESSION_PKG_ID, claims=[]
    )
    assert actual == EMPTY_CLAIMS_EXPECTED_HASH
    assert len(actual) == 64
    int(actual, 16)


def test_nfc_and_nfd_claim_ids_produce_same_hash() -> None:
    """canonical_json.normalize NFC-folds before hashing per spec §S2.1."""

    nfc = "é"  # é precomposed
    nfd = "é"  # e + combining acute
    assert nfc != nfd  # raw bytes differ
    h_nfc = compute_package_canonical_hash(
        format_version="2.0",
        package_id=REGRESSION_PKG_ID,
        claims=[(nfc, "i1", "h1")],
    )
    h_nfd = compute_package_canonical_hash(
        format_version="2.0",
        package_id=REGRESSION_PKG_ID,
        claims=[(nfd, "i1", "h1")],
    )
    assert h_nfc == h_nfd


def test_duplicate_claim_tuple_does_not_silently_dedup() -> None:
    """sorted() must NOT collapse duplicates — spec §2.1 requires the full set."""

    h_single = compute_package_canonical_hash(
        format_version="2.0",
        package_id=REGRESSION_PKG_ID,
        claims=[("c1", "i1", "h1")],
    )
    h_double = compute_package_canonical_hash(
        format_version="2.0",
        package_id=REGRESSION_PKG_ID,
        claims=[("c1", "i1", "h1"), ("c1", "i1", "h1")],
    )
    assert h_single != h_double


# ---------------------------------------------------------------------------
# US-004: Protocol conformance + spec drift guards
# ---------------------------------------------------------------------------

# Spec-declared field order — bumping this list requires a spec edit.
SPEC_ENVELOPE_FIELD_ORDER = (
    "signer_id",
    "algorithm",
    "signed_at_iso",
    "package_canonical_hash",
    "signature_b64",
)
SPEC_MANIFEST_FIELD_ORDER = (
    "signer_id",
    "algorithm",
    "public_key_b64",
    "key_fingerprint",
    "notary_uri",
)
SPEC_ALGORITHMS = frozenset({"hmac-sha256", "ed25519"})
SPEC_ERROR_CODES = frozenset(
    {
        "E_SIGNATURE_MALFORMED",
        "E_SIGNATURE_HASH_MISMATCH",
        "E_SIGNATURE_INVALID",
        "E_SIGNATURE_ORDER",
        "E_SIGNER_MISSING",
        "E_SIGNER_MALFORMED",
        "E_SIGNER_FINGERPRINT_MISMATCH",
        "E_SIGNER_ALGORITHM_UNKNOWN",
    }
)


def test_hmac_signer_satisfies_signer_protocol() -> None:
    instance = HMACSigner(signer_id="x", secret=b"k")
    assert isinstance(instance, Signer)


def test_hmac_verifier_satisfies_verifier_protocol() -> None:
    assert isinstance(HMACVerifier(), Verifier)


def test_envelope_field_order_matches_spec_22() -> None:
    declared = tuple(f.name for f in dataclasses.fields(SignatureEnvelope))
    assert declared == SPEC_ENVELOPE_FIELD_ORDER, (
        f"SignatureEnvelope field order {declared} drifted from spec §2.2 "
        f"{SPEC_ENVELOPE_FIELD_ORDER}"
    )


def test_manifest_field_order_matches_spec_23() -> None:
    declared = tuple(f.name for f in dataclasses.fields(SignerManifest))
    assert declared == SPEC_MANIFEST_FIELD_ORDER, (
        f"SignerManifest field order {declared} drifted from spec §2.3 "
        f"{SPEC_MANIFEST_FIELD_ORDER}"
    )


def test_algorithm_registry_matches_spec_31() -> None:
    assert frozenset(ALGORITHM_REGISTRY.keys()) == SPEC_ALGORITHMS, (
        "ALGORITHM_REGISTRY drifted from spec §3.1 — adding/removing an "
        "algorithm requires a spec edit"
    )


def test_hmac_verifier_only_raises_spec_6_error_codes() -> None:
    """Walk every verify() failure path and confirm each code is in spec §6."""

    signer = HMACSigner(signer_id=SIGNER_ID, secret=SHARED_SECRET)
    genuine = signer.sign(package_canonical_hash=PACKAGE_HASH, signed_at_iso=SIGNED_AT)
    manifest = signer.manifest()
    verifier = HMACVerifier()

    failure_envelopes = [
        # E_SIGNER_ALGORITHM_UNKNOWN
        (dataclasses.replace(genuine, algorithm="md5"), manifest, PACKAGE_HASH),
        (
            dataclasses.replace(genuine, algorithm="ed25519"),
            manifest,
            PACKAGE_HASH,
        ),
        # E_SIGNER_MISSING
        (
            genuine,
            dataclasses.replace(manifest, signer_id="bob"),
            PACKAGE_HASH,
        ),
        # E_SIGNATURE_MALFORMED (non-hex envelope hash)
        (
            dataclasses.replace(genuine, package_canonical_hash="zz" * 32),
            manifest,
            "zz" * 32,
        ),
        # E_SIGNER_MALFORMED
        (
            genuine,
            dataclasses.replace(manifest, public_key_b64="!!!"),
            PACKAGE_HASH,
        ),
        # E_SIGNER_FINGERPRINT_MISMATCH
        (
            genuine,
            dataclasses.replace(manifest, key_fingerprint="0" * 64),
            PACKAGE_HASH,
        ),
        # E_SIGNATURE_HASH_MISMATCH
        (genuine, manifest, "f" * 64),
        # E_SIGNATURE_INVALID (wrong key)
        (
            genuine,
            SignerManifest(
                signer_id=SIGNER_ID,
                algorithm="hmac-sha256",
                public_key_b64=base64.standard_b64encode(ALT_SECRET).decode("ascii"),
                key_fingerprint=compute_key_fingerprint(ALT_SECRET),
                notary_uri=None,
            ),
            PACKAGE_HASH,
        ),
        # E_SIGNATURE_MALFORMED (bad signature_b64)
        (
            dataclasses.replace(genuine, signature_b64="!!!"),
            manifest,
            PACKAGE_HASH,
        ),
    ]

    observed_codes: set[str] = set()
    for env, mfst, recomputed in failure_envelopes:
        with pytest.raises(SignerVerificationError) as exc:
            verifier.verify(env, mfst, package_canonical_hash=recomputed)
        observed_codes.add(exc.value.code)

    unspecced = observed_codes - SPEC_ERROR_CODES
    assert not unspecced, f"HMACVerifier raised codes not in spec §6: {unspecced}"


# ---------------------------------------------------------------------------
# Architect-review fixes (post US-005): spec §3.2 MUST warning + parse companion
# ---------------------------------------------------------------------------


def test_hmac_verify_emits_test_only_warning_per_spec_32() -> None:
    """Spec §3.2 MUST: validators emit a warning on hmac-sha256 verify."""
    signer = HMACSigner(signer_id=SIGNER_ID, secret=SHARED_SECRET)
    env = signer.sign(package_canonical_hash=PACKAGE_HASH, signed_at_iso=SIGNED_AT)
    manifest = signer.manifest()
    with pytest.warns(UserWarning, match="hmac-sha256"):
        HMACVerifier().verify(env, manifest, package_canonical_hash=PACKAGE_HASH)


def test_parse_envelope_line_round_trips_canonical_bytes() -> None:
    env = HMACSigner(signer_id=SIGNER_ID, secret=SHARED_SECRET).sign(
        package_canonical_hash=PACKAGE_HASH, signed_at_iso=SIGNED_AT
    )
    line = canonical_envelope_bytes(env)
    parsed = parse_envelope_line(line)
    assert parsed == env


def test_parse_envelope_line_rejects_non_utf8() -> None:
    with pytest.raises(SignerVerificationError) as exc:
        parse_envelope_line(b"\xff\xfe not utf-8")
    assert exc.value.code == "E_SIGNATURE_MALFORMED"


def test_parse_envelope_line_rejects_invalid_json() -> None:
    with pytest.raises(SignerVerificationError) as exc:
        parse_envelope_line(b"{not json}")
    assert exc.value.code == "E_SIGNATURE_MALFORMED"


def test_parse_envelope_line_rejects_non_object() -> None:
    with pytest.raises(SignerVerificationError) as exc:
        parse_envelope_line(b'["not", "an", "object"]\n')
    assert exc.value.code == "E_SIGNATURE_MALFORMED"


def test_parse_envelope_line_rejects_missing_field() -> None:
    incomplete = (
        b'{"algorithm":"hmac-sha256","package_canonical_hash":"'
        + PACKAGE_HASH.encode()
        + b'","signature_b64":"deadbeef","signed_at_iso":"'
        + SIGNED_AT.encode()
        + b'"}\n'
    )
    with pytest.raises(SignerVerificationError) as exc:
        parse_envelope_line(incomplete)
    assert exc.value.code == "E_SIGNATURE_MALFORMED"


def test_parse_envelope_line_rejects_extra_field() -> None:
    env = HMACSigner(signer_id=SIGNER_ID, secret=SHARED_SECRET).sign(
        package_canonical_hash=PACKAGE_HASH, signed_at_iso=SIGNED_AT
    )
    payload = json.loads(canonical_envelope_bytes(env).decode("utf-8"))
    payload["extra_field"] = "not-allowed"
    line = (json.dumps(payload, sort_keys=True) + "\n").encode("utf-8")
    with pytest.raises(SignerVerificationError) as exc:
        parse_envelope_line(line)
    assert exc.value.code == "E_SIGNATURE_MALFORMED"


def test_parse_envelope_line_rejects_non_string_field() -> None:
    env = HMACSigner(signer_id=SIGNER_ID, secret=SHARED_SECRET).sign(
        package_canonical_hash=PACKAGE_HASH, signed_at_iso=SIGNED_AT
    )
    payload = json.loads(canonical_envelope_bytes(env).decode("utf-8"))
    payload["signer_id"] = 123  # int instead of string
    line = (json.dumps(payload, sort_keys=True) + "\n").encode("utf-8")
    with pytest.raises(SignerVerificationError) as exc:
        parse_envelope_line(line)
    assert exc.value.code == "E_SIGNATURE_MALFORMED"


def test_signed_at_iso_uses_millisecond_precision_per_rule_4() -> None:
    """spec §2.2 was drift-fixed to millisecond per canonical-serialization Rule 4."""
    assert SIGNED_AT.count(".") == 1
    fractional = SIGNED_AT.split(".")[1].rstrip("Z")
    assert (
        len(fractional) == 3
    ), f"SIGNED_AT fixture must have 3-digit ms precision per Rule 4; got {SIGNED_AT}"


# ---------------------------------------------------------------------------
# §3.3 Ed25519 real implementation (Phase B)
# ---------------------------------------------------------------------------


def _generate_ed25519_keypair() -> tuple[bytes, bytes]:
    """Generate a fresh Ed25519 keypair; returns (private_key_raw_32, public_key_raw_32).

    TEST-ONLY-DO-NOT-REUSE
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    priv = Ed25519PrivateKey.generate()
    priv_raw = priv.private_bytes_raw()  # 32 bytes
    pub_raw = priv.public_key().public_bytes_raw()  # 32 bytes
    return priv_raw, pub_raw


@pytest.mark.unit
def test_ed25519_sign_verify_roundtrip() -> None:
    """Sign with Ed25519Signer, verify with Ed25519Verifier — no exception."""
    priv_raw, pub_raw = _generate_ed25519_keypair()  # TEST-ONLY-DO-NOT-REUSE
    priv_b64 = base64.standard_b64encode(priv_raw).decode("ascii")
    pub_b64 = base64.standard_b64encode(pub_raw).decode("ascii")

    signer = Ed25519Signer(signer_id="alice-ed25519", private_key_b64=priv_b64)
    env = signer.sign(package_canonical_hash=PACKAGE_HASH, signed_at_iso=SIGNED_AT)
    manifest = Ed25519Verifier(public_key_b64=pub_b64).build_manifest(
        signer_id="alice-ed25519"
    )
    Ed25519Verifier(public_key_b64=pub_b64).verify(
        env, manifest, package_canonical_hash=PACKAGE_HASH
    )


@pytest.mark.unit
def test_ed25519_tamper_detection() -> None:
    """Flipping a byte in the signature raises E_SIGNATURE_INVALID."""
    priv_raw, pub_raw = _generate_ed25519_keypair()  # TEST-ONLY-DO-NOT-REUSE
    priv_b64 = base64.standard_b64encode(priv_raw).decode("ascii")
    pub_b64 = base64.standard_b64encode(pub_raw).decode("ascii")

    signer = Ed25519Signer(signer_id="alice-ed25519", private_key_b64=priv_b64)
    env = signer.sign(package_canonical_hash=PACKAGE_HASH, signed_at_iso=SIGNED_AT)

    # Flip one byte in the 64-byte raw signature
    raw_sig = bytearray(base64.standard_b64decode(env.signature_b64))
    raw_sig[0] ^= 0xFF
    tampered_env = dataclasses.replace(
        env,
        signature_b64=base64.standard_b64encode(bytes(raw_sig)).decode("ascii"),
    )

    manifest = Ed25519Verifier(public_key_b64=pub_b64).build_manifest(
        signer_id="alice-ed25519"
    )
    with pytest.raises(SignerVerificationError) as exc:
        Ed25519Verifier(public_key_b64=pub_b64).verify(
            tampered_env, manifest, package_canonical_hash=PACKAGE_HASH
        )
    assert exc.value.code == "E_SIGNATURE_INVALID"


@pytest.mark.unit
def test_ed25519_fingerprint_recompute() -> None:
    """Verifier rejects manifest with wrong key_fingerprint (E_SIGNER_FINGERPRINT_MISMATCH)."""
    priv_raw, pub_raw = _generate_ed25519_keypair()  # TEST-ONLY-DO-NOT-REUSE
    priv_b64 = base64.standard_b64encode(priv_raw).decode("ascii")
    pub_b64 = base64.standard_b64encode(pub_raw).decode("ascii")

    signer = Ed25519Signer(signer_id="alice-ed25519", private_key_b64=priv_b64)
    env = signer.sign(package_canonical_hash=PACKAGE_HASH, signed_at_iso=SIGNED_AT)

    bad_manifest = SignerManifest(
        signer_id="alice-ed25519",
        algorithm="ed25519",
        public_key_b64=pub_b64,
        key_fingerprint="0" * 64,  # wrong fingerprint
        notary_uri=None,
    )
    with pytest.raises(SignerVerificationError) as exc:
        Ed25519Verifier(public_key_b64=pub_b64).verify(
            env, bad_manifest, package_canonical_hash=PACKAGE_HASH
        )
    assert exc.value.code == "E_SIGNER_FINGERPRINT_MISMATCH"


@pytest.mark.unit
def test_ed25519_wrong_public_key() -> None:
    """Signing with key A then verifying with key B raises E_SIGNATURE_INVALID."""
    priv_a_raw, _ = _generate_ed25519_keypair()  # TEST-ONLY-DO-NOT-REUSE
    _, pub_b_raw = _generate_ed25519_keypair()  # TEST-ONLY-DO-NOT-REUSE
    priv_a_b64 = base64.standard_b64encode(priv_a_raw).decode("ascii")
    pub_b_b64 = base64.standard_b64encode(pub_b_raw).decode("ascii")

    signer = Ed25519Signer(signer_id="alice-ed25519", private_key_b64=priv_a_b64)
    env = signer.sign(package_canonical_hash=PACKAGE_HASH, signed_at_iso=SIGNED_AT)

    # Build manifest for key B (correct fingerprint, wrong public key)
    manifest_b = Ed25519Verifier(public_key_b64=pub_b_b64).build_manifest(
        signer_id="alice-ed25519"
    )
    with pytest.raises(SignerVerificationError) as exc:
        Ed25519Verifier(public_key_b64=pub_b_b64).verify(
            env, manifest_b, package_canonical_hash=PACKAGE_HASH
        )
    assert exc.value.code == "E_SIGNATURE_INVALID"


@pytest.mark.unit
def test_ed25519_signature_length() -> None:
    """Ed25519 signature must be 64 raw bytes (RFC 8032); base64-encoded accordingly."""
    priv_raw, _ = _generate_ed25519_keypair()  # TEST-ONLY-DO-NOT-REUSE
    priv_b64 = base64.standard_b64encode(priv_raw).decode("ascii")

    signer = Ed25519Signer(signer_id="alice-ed25519", private_key_b64=priv_b64)
    env = signer.sign(package_canonical_hash=PACKAGE_HASH, signed_at_iso=SIGNED_AT)

    raw_sig = base64.standard_b64decode(env.signature_b64)
    assert len(raw_sig) == 64, f"Ed25519 signature must be 64 bytes; got {len(raw_sig)}"


@pytest.mark.unit
def test_ed25519_unavailable_when_extra_not_installed() -> None:
    """When cryptography is absent, import raises E_SIGNER_ALGORITHM_UNAVAILABLE."""
    import aphelion.signer as signer_mod

    with unittest.mock.patch.dict(
        sys.modules, {"cryptography.hazmat.primitives.asymmetric.ed25519": None}
    ):
        with pytest.raises(SignerVerificationError) as exc:
            signer_mod._require_cryptography()  # type: ignore[attr-defined]
    assert exc.value.code == "E_SIGNER_ALGORITHM_UNAVAILABLE"


@pytest.mark.unit
def test_ed25519_envelope_compatibility_with_signer_manifest() -> None:
    """Full round trip through SignatureEnvelope + SignerManifest fields."""
    priv_raw, pub_raw = _generate_ed25519_keypair()  # TEST-ONLY-DO-NOT-REUSE
    priv_b64 = base64.standard_b64encode(priv_raw).decode("ascii")
    pub_b64 = base64.standard_b64encode(pub_raw).decode("ascii")

    signer = Ed25519Signer(signer_id="alice-ed25519", private_key_b64=priv_b64)
    env = signer.sign(package_canonical_hash=PACKAGE_HASH, signed_at_iso=SIGNED_AT)

    # Verify envelope fields
    assert env.signer_id == "alice-ed25519"
    assert env.algorithm == "ed25519"
    assert env.package_canonical_hash == PACKAGE_HASH
    assert env.signed_at_iso == SIGNED_AT

    # Verify manifest fields
    manifest = signer.manifest()
    assert manifest.signer_id == "alice-ed25519"
    assert manifest.algorithm == "ed25519"
    assert manifest.public_key_b64 == pub_b64
    assert manifest.key_fingerprint == hashlib.sha256(pub_raw).hexdigest()

    # Full verify pass
    Ed25519Verifier(public_key_b64=pub_b64).verify(
        env, manifest, package_canonical_hash=PACKAGE_HASH
    )


@pytest.mark.unit
def test_ed25519_signer_satisfies_signer_protocol() -> None:
    priv_raw, _ = _generate_ed25519_keypair()  # TEST-ONLY-DO-NOT-REUSE
    priv_b64 = base64.standard_b64encode(priv_raw).decode("ascii")
    instance = Ed25519Signer(signer_id="x", private_key_b64=priv_b64)
    assert isinstance(instance, Signer)


@pytest.mark.unit
def test_ed25519_verifier_satisfies_verifier_protocol() -> None:
    _, pub_raw = _generate_ed25519_keypair()  # TEST-ONLY-DO-NOT-REUSE
    pub_b64 = base64.standard_b64encode(pub_raw).decode("ascii")
    assert isinstance(Ed25519Verifier(public_key_b64=pub_b64), Verifier)


@pytest.mark.unit
def test_ed25519_verifier_rejects_unknown_algorithm() -> None:
    """Ed25519Verifier rejects envelopes with algorithm not in registry."""
    priv_raw, pub_raw = _generate_ed25519_keypair()  # TEST-ONLY-DO-NOT-REUSE
    priv_b64 = base64.standard_b64encode(priv_raw).decode("ascii")
    pub_b64 = base64.standard_b64encode(pub_raw).decode("ascii")

    signer = Ed25519Signer(signer_id="alice-ed25519", private_key_b64=priv_b64)
    env = signer.sign(package_canonical_hash=PACKAGE_HASH, signed_at_iso=SIGNED_AT)
    manifest = Ed25519Verifier(public_key_b64=pub_b64).build_manifest(
        signer_id="alice-ed25519"
    )
    bad_env = dataclasses.replace(env, algorithm="rsa-2048-not-in-registry")
    with pytest.raises(SignerVerificationError) as exc:
        Ed25519Verifier(public_key_b64=pub_b64).verify(
            bad_env, manifest, package_canonical_hash=PACKAGE_HASH
        )
    assert exc.value.code == "E_SIGNER_ALGORITHM_UNKNOWN"


@pytest.mark.unit
def test_ed25519_verifier_rejects_hmac_algorithm_envelope() -> None:
    """Ed25519Verifier cannot verify hmac-sha256 envelopes."""
    priv_raw, pub_raw = _generate_ed25519_keypair()  # TEST-ONLY-DO-NOT-REUSE
    priv_b64 = base64.standard_b64encode(priv_raw).decode("ascii")
    pub_b64 = base64.standard_b64encode(pub_raw).decode("ascii")

    signer = Ed25519Signer(signer_id="alice-ed25519", private_key_b64=priv_b64)
    env = signer.sign(package_canonical_hash=PACKAGE_HASH, signed_at_iso=SIGNED_AT)
    manifest = Ed25519Verifier(public_key_b64=pub_b64).build_manifest(
        signer_id="alice-ed25519"
    )
    bad_env = dataclasses.replace(env, algorithm="hmac-sha256")
    with pytest.raises(SignerVerificationError) as exc:
        Ed25519Verifier(public_key_b64=pub_b64).verify(
            bad_env, manifest, package_canonical_hash=PACKAGE_HASH
        )
    assert exc.value.code == "E_SIGNER_ALGORITHM_UNKNOWN"


@pytest.mark.unit
def test_ed25519_verifier_rejects_signer_id_mismatch() -> None:
    """Ed25519Verifier rejects when envelope.signer_id != manifest.signer_id."""
    priv_raw, pub_raw = _generate_ed25519_keypair()  # TEST-ONLY-DO-NOT-REUSE
    priv_b64 = base64.standard_b64encode(priv_raw).decode("ascii")
    pub_b64 = base64.standard_b64encode(pub_raw).decode("ascii")

    signer = Ed25519Signer(signer_id="alice-ed25519", private_key_b64=priv_b64)
    env = signer.sign(package_canonical_hash=PACKAGE_HASH, signed_at_iso=SIGNED_AT)
    manifest = Ed25519Verifier(public_key_b64=pub_b64).build_manifest(
        signer_id="bob-ed25519"  # different signer_id
    )
    with pytest.raises(SignerVerificationError) as exc:
        Ed25519Verifier(public_key_b64=pub_b64).verify(
            env, manifest, package_canonical_hash=PACKAGE_HASH
        )
    assert exc.value.code == "E_SIGNER_MISSING"


@pytest.mark.unit
def test_ed25519_verifier_rejects_non_hex_envelope_hash() -> None:
    """Ed25519Verifier rejects non-hex package_canonical_hash."""
    priv_raw, pub_raw = _generate_ed25519_keypair()  # TEST-ONLY-DO-NOT-REUSE
    priv_b64 = base64.standard_b64encode(priv_raw).decode("ascii")
    pub_b64 = base64.standard_b64encode(pub_raw).decode("ascii")

    signer = Ed25519Signer(signer_id="alice-ed25519", private_key_b64=priv_b64)
    env = signer.sign(package_canonical_hash=PACKAGE_HASH, signed_at_iso=SIGNED_AT)
    manifest = Ed25519Verifier(public_key_b64=pub_b64).build_manifest(
        signer_id="alice-ed25519"
    )
    bad_env = dataclasses.replace(env, package_canonical_hash="zz" * 32)
    with pytest.raises(SignerVerificationError) as exc:
        Ed25519Verifier(public_key_b64=pub_b64).verify(
            bad_env, manifest, package_canonical_hash="zz" * 32
        )
    assert exc.value.code == "E_SIGNATURE_MALFORMED"


@pytest.mark.unit
def test_ed25519_verifier_rejects_malformed_public_key_b64() -> None:
    """Ed25519Verifier raises E_SIGNER_MALFORMED on bad base64 in manifest."""
    priv_raw, pub_raw = _generate_ed25519_keypair()  # TEST-ONLY-DO-NOT-REUSE
    priv_b64 = base64.standard_b64encode(priv_raw).decode("ascii")
    pub_b64 = base64.standard_b64encode(pub_raw).decode("ascii")

    signer = Ed25519Signer(signer_id="alice-ed25519", private_key_b64=priv_b64)
    env = signer.sign(package_canonical_hash=PACKAGE_HASH, signed_at_iso=SIGNED_AT)
    manifest = Ed25519Verifier(public_key_b64=pub_b64).build_manifest(
        signer_id="alice-ed25519"
    )
    bad_manifest = dataclasses.replace(manifest, public_key_b64="!!!not-base64!!!")
    with pytest.raises(SignerVerificationError) as exc:
        Ed25519Verifier(public_key_b64=pub_b64).verify(
            env, bad_manifest, package_canonical_hash=PACKAGE_HASH
        )
    assert exc.value.code == "E_SIGNER_MALFORMED"


@pytest.mark.unit
def test_ed25519_verifier_rejects_hash_mismatch() -> None:
    """Ed25519Verifier rejects when envelope hash != recomputed hash."""
    priv_raw, pub_raw = _generate_ed25519_keypair()  # TEST-ONLY-DO-NOT-REUSE
    priv_b64 = base64.standard_b64encode(priv_raw).decode("ascii")
    pub_b64 = base64.standard_b64encode(pub_raw).decode("ascii")

    signer = Ed25519Signer(signer_id="alice-ed25519", private_key_b64=priv_b64)
    env = signer.sign(package_canonical_hash=PACKAGE_HASH, signed_at_iso=SIGNED_AT)
    manifest = Ed25519Verifier(public_key_b64=pub_b64).build_manifest(
        signer_id="alice-ed25519"
    )
    with pytest.raises(SignerVerificationError) as exc:
        Ed25519Verifier(public_key_b64=pub_b64).verify(
            env, manifest, package_canonical_hash="f" * 64
        )
    assert exc.value.code == "E_SIGNATURE_HASH_MISMATCH"


@pytest.mark.unit
def test_ed25519_verifier_rejects_malformed_signature_b64() -> None:
    """Ed25519Verifier raises E_SIGNATURE_MALFORMED on bad signature base64."""
    priv_raw, pub_raw = _generate_ed25519_keypair()  # TEST-ONLY-DO-NOT-REUSE
    priv_b64 = base64.standard_b64encode(priv_raw).decode("ascii")
    pub_b64 = base64.standard_b64encode(pub_raw).decode("ascii")

    signer = Ed25519Signer(signer_id="alice-ed25519", private_key_b64=priv_b64)
    env = signer.sign(package_canonical_hash=PACKAGE_HASH, signed_at_iso=SIGNED_AT)
    manifest = Ed25519Verifier(public_key_b64=pub_b64).build_manifest(
        signer_id="alice-ed25519"
    )
    bad_env = dataclasses.replace(env, signature_b64="!!!not-valid-base64!!!")
    with pytest.raises(SignerVerificationError) as exc:
        Ed25519Verifier(public_key_b64=pub_b64).verify(
            bad_env, manifest, package_canonical_hash=PACKAGE_HASH
        )
    assert exc.value.code == "E_SIGNATURE_MALFORMED"
