"""Aphelion trust notary — v0.5 extension point + v0.6 R7.2 attestation envelope.

This module is the public surface for notary-aware verification.

* **v0.5** (spec/v0.5-signer-trust.md §4) defined only the *extension point*:
  every notary lookup yields the literal ``"verified-locally"`` and any I/O
  failure is non-fatal. That contract is unchanged — ``resolve_notary`` still
  returns ``"verified-locally"`` and performs no I/O.
* **v0.6 R7.2** (spec/v0.6-notary-attestation.md) pins the *notary attestation
  envelope format* and its verification path. A validator that is handed a
  ``NotaryAttestationEnvelope`` (plus the vouching notary's manifest) can now
  obtain ``"verified-by-notary"`` via ``resolve_notary_attestation``. This is
  strictly additive: no envelope present → fall back to the v0.5 stub.

The envelope binds the *signer identity* to a *public-key fingerprint* under a
*notary identity*; it deliberately does NOT bind a package hash, so one
attestation is reusable across every package that signer's key signs.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import re
from dataclasses import dataclass, fields
from typing import Literal

from aphelion.canonical_json import dumps, loads, normalize
from aphelion.signer import (  # re-export for spec §10
    ALGORITHM_REGISTRY,
    SignerManifest,
    SignerVerificationError,
    compute_key_fingerprint,
)

NotaryAttestation = Literal["verified-locally", "verified-by-notary"]

# A key fingerprint is ``sha256(...).hexdigest()`` (signer §2.3): exactly 64
# lowercase hex characters. Anything else cannot be a real fingerprint and must
# be rejected before it reaches ``hmac.compare_digest`` (which raises a raw
# ``TypeError`` on non-ASCII ``str`` input).
_FINGERPRINT_RE = re.compile(r"\A[0-9a-f]{64}\Z")


def _require_fingerprint_format(fingerprint: str, *, label: str) -> None:
    """Reject a fingerprint that is not 64 lowercase hex chars (§2.3).

    Raises ``SignerVerificationError(E_SIGNER_NOTARY_INVALID)`` so a malformed
    (e.g. non-ASCII) fingerprint surfaces as a verification error rather than
    crashing ``hmac.compare_digest`` with ``TypeError``.
    """
    if not _FINGERPRINT_RE.match(fingerprint):
        raise SignerVerificationError(
            "E_SIGNER_NOTARY_INVALID",
            f"{label} {fingerprint!r} is not a 64-char lowercase hex fingerprint",
        )


# ---------------------------------------------------------------------------
# v0.5 extension-point stub (§4) — UNCHANGED
# ---------------------------------------------------------------------------


def resolve_notary(manifest: SignerManifest) -> NotaryAttestation:
    """Stub resolver per spec §4.

    If manifest.notary_uri is None → return "verified-locally".
    If manifest.notary_uri is set → out-of-band lookup is unspecified in
    v0.5; this stub returns "verified-locally" without attempting I/O.

    Validators that do not understand or cannot reach a notary MUST
    treat the envelope as verified-locally only (spec §4). To upgrade a
    package to "verified-by-notary", a caller supplies a
    ``NotaryAttestationEnvelope`` to ``resolve_notary_attestation`` (v0.6 R7.2).
    """
    return "verified-locally"


def attestation_is_acceptable(
    attestation: NotaryAttestation,
    require_notary: bool = False,
) -> bool:
    """Return True if attestation passes caller's trust requirement.

    require_notary=False: any attestation is acceptable.
    require_notary=True: only "verified-by-notary" is acceptable.
    Provides a forward-compatible decision point for v0.6+ callers
    that may want to reject locally-verified packages.
    """
    if require_notary:
        return attestation == "verified-by-notary"
    return True


# ---------------------------------------------------------------------------
# v0.6 R7.2 — notary attestation envelope (spec/v0.6-notary-attestation.md §2)
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class NotaryAttestationEnvelope:
    """A notary's detached attestation of a signer's key→identity binding (§2.2).

    The envelope is signed by the *notary's* key over
    ``compute_attestation_canonical_hash`` (§2.1); it vouches that
    ``key_fingerprint`` is the key the notary associates with ``signer_id``.
    """

    notary_id: str
    signer_id: str
    key_fingerprint: str
    algorithm: str
    signed_at_iso: str
    signature_b64: str


def compute_attestation_canonical_hash(
    *,
    signer_id: str,
    notary_id: str,
    key_fingerprint: str,
) -> str:
    """Compute the attestation binding hash (spec/v0.6-notary-attestation.md §2.1).

    ``sha256(json_canonical({key_fingerprint, notary_id, signer_id}))``. Key
    order is irrelevant — canonical JSON sorts keys — so callers need not
    pre-order the fields.
    """
    payload = normalize(
        {
            "key_fingerprint": key_fingerprint,
            "notary_id": notary_id,
            "signer_id": signer_id,
        }
    )
    return hashlib.sha256(dumps(payload)).hexdigest()


def canonical_attestation_bytes(envelope: NotaryAttestationEnvelope) -> bytes:
    """Serialize one attestation as a canonical JSON line ending in LF (§2.2)."""
    payload = normalize(
        {
            "algorithm": envelope.algorithm,
            "key_fingerprint": envelope.key_fingerprint,
            "notary_id": envelope.notary_id,
            "signature_b64": envelope.signature_b64,
            "signed_at_iso": envelope.signed_at_iso,
            "signer_id": envelope.signer_id,
        }
    )
    return dumps(payload)


def parse_attestation_line(line: bytes) -> NotaryAttestationEnvelope:
    """Parse one canonical attestation line back into a ``NotaryAttestationEnvelope``.

    Inverse of :func:`canonical_attestation_bytes`. Raises
    ``SignerVerificationError`` with code ``E_SIGNATURE_MALFORMED`` on any
    structural failure (non-UTF-8, invalid JSON, non-object, missing/unknown
    fields, wrong field types).
    """
    try:
        payload = loads(line)
    except Exception as exc:  # SchemaError from canonical_json, et al.
        raise SignerVerificationError(
            "E_SIGNATURE_MALFORMED", f"attestation line not canonical JSON: {exc}"
        ) from exc
    if not isinstance(payload, dict):
        raise SignerVerificationError(
            "E_SIGNATURE_MALFORMED", "attestation line must be a JSON object"
        )
    expected = {f.name for f in fields(NotaryAttestationEnvelope)}
    missing = expected - payload.keys()
    extra = payload.keys() - expected
    if missing or extra:
        raise SignerVerificationError(
            "E_SIGNATURE_MALFORMED",
            f"attestation fields mismatch: missing={sorted(missing)} "
            f"extra={sorted(extra)}",
        )
    for name in expected:
        if not isinstance(payload[name], str):
            raise SignerVerificationError(
                "E_SIGNATURE_MALFORMED",
                f"attestation field {name!r} must be a string",
            )
    return NotaryAttestationEnvelope(
        notary_id=payload["notary_id"],
        signer_id=payload["signer_id"],
        key_fingerprint=payload["key_fingerprint"],
        algorithm=payload["algorithm"],
        signed_at_iso=payload["signed_at_iso"],
        signature_b64=payload["signature_b64"],
    )


def _verify_attestation_signature(
    *,
    notary_manifest: SignerManifest,
    attestation_hash: str,
    signature_b64: str,
) -> None:
    """Verify the notary's signature over ``attestation_hash``.

    Dispatches on ``notary_manifest.algorithm`` (already checked to match the
    envelope by the caller). Raises ``SignerVerificationError`` on failure:
    ``E_SIGNATURE_MALFORMED`` for un-decodable base64,
    ``E_SIGNATURE_INVALID`` for a signature that does not verify.
    """
    # validate=True so trailing non-base64 junk (e.g. an otherwise-valid
    # signature with "!!" appended) is rejected rather than silently dropped;
    # the v0.6 envelope requires base64-standard and this helper promises
    # E_SIGNATURE_MALFORMED for undecodable base64.
    try:
        signature = base64.b64decode(signature_b64, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise SignerVerificationError(
            "E_SIGNATURE_MALFORMED", f"signature_b64 not valid base64: {exc}"
        ) from exc

    message = bytes.fromhex(attestation_hash)

    if notary_manifest.algorithm == "hmac-sha256":
        # validate=True for the same reason as the signature decode above: a
        # tolerant decode would accept a notary key with trailing junk.
        try:
            mac_key = base64.b64decode(notary_manifest.public_key_b64, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise SignerVerificationError(
                "E_SIGNER_MALFORMED",
                f"notary public_key_b64 not valid base64: {exc}",
            ) from exc
        expected = hmac.new(mac_key, message, hashlib.sha256).digest()
        if not hmac.compare_digest(expected, signature):
            raise SignerVerificationError(
                "E_SIGNATURE_INVALID", "hmac-sha256 attestation signature mismatch"
            )
        return

    if notary_manifest.algorithm == "ed25519":
        # Lazy-import via the signer module so the [signer] extra requirement
        # and its E_SIGNER_ALGORITHM_UNAVAILABLE error stay DRY.
        from aphelion.signer import _require_cryptography

        _, Ed25519PublicKey = _require_cryptography()
        # validate=True: reject a notary key carrying trailing non-base64 junk.
        try:
            pub_raw = base64.b64decode(notary_manifest.public_key_b64, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise SignerVerificationError(
                "E_SIGNER_MALFORMED",
                f"notary public_key_b64 not valid base64: {exc}",
            ) from exc
        # from_public_bytes raises ValueError on non-32-byte input; wrap it so a
        # malformed notary key surfaces as E_SIGNER_MALFORMED rather than an
        # uncaught exception escaping the SignerVerificationError contract.
        try:
            pub = Ed25519PublicKey.from_public_bytes(pub_raw)
        except (ValueError, binascii.Error) as exc:
            raise SignerVerificationError(
                "E_SIGNER_MALFORMED",
                f"notary public_key_b64 is not a valid ed25519 public key: {exc}",
            ) from exc
        try:
            pub.verify(signature, message)
        except Exception as exc:  # cryptography raises InvalidSignature
            raise SignerVerificationError(
                "E_SIGNATURE_INVALID", f"ed25519 attestation verification failed: {exc}"
            ) from exc
        return

    # Unreachable: caller validates the algorithm against the registry first.
    raise SignerVerificationError(
        "E_SIGNER_ALGORITHM_UNKNOWN",
        f"unsupported notary algorithm {notary_manifest.algorithm!r}",
    )


def resolve_notary_attestation(
    signer_manifest: SignerManifest,
    attestation: NotaryAttestationEnvelope,
    notary_manifest: SignerManifest,
) -> NotaryAttestation:
    """Verify a notary attestation envelope (spec/v0.6-notary-attestation.md §3).

    Returns ``"verified-by-notary"`` iff every §3 rule holds; otherwise raises
    ``SignerVerificationError`` with the spec-mandated code:

    * identity / fingerprint binding failure → ``E_SIGNER_NOTARY_INVALID``
    * envelope algorithm not in registry → ``E_SIGNER_ALGORITHM_UNKNOWN``
    * envelope algorithm ≠ notary manifest algorithm → ``E_SIGNER_ALGORITHM_MISMATCH``
    * notary manifest fingerprint does not recompute → ``E_SIGNER_FINGERPRINT_MISMATCH``
    * signature does not verify → ``E_SIGNATURE_INVALID``

    A caller with no attestation MUST instead use :func:`resolve_notary` and
    obtain ``"verified-locally"`` (v0.5 §4 fallback).
    """
    # §3.1 signer identity binding.
    if attestation.signer_id != signer_manifest.signer_id:
        raise SignerVerificationError(
            "E_SIGNER_NOTARY_INVALID",
            f"attestation signer_id {attestation.signer_id!r} != signer manifest "
            f"{signer_manifest.signer_id!r}",
        )

    # §3.2 key-fingerprint binding — the notary must vouch for the same key the
    # package signer used (closes a key-substitution gap). Validate the format
    # first: a non-ASCII / non-hex fingerprint would make hmac.compare_digest
    # raise a raw TypeError instead of returning the spec error code.
    _require_fingerprint_format(
        attestation.key_fingerprint, label="attestation key_fingerprint"
    )
    if not hmac.compare_digest(
        attestation.key_fingerprint, signer_manifest.key_fingerprint
    ):
        raise SignerVerificationError(
            "E_SIGNER_NOTARY_INVALID",
            "attestation key_fingerprint does not match signer manifest fingerprint",
        )

    # §3.3 notary identity binding.
    if attestation.notary_id != notary_manifest.signer_id:
        raise SignerVerificationError(
            "E_SIGNER_NOTARY_INVALID",
            f"attestation notary_id {attestation.notary_id!r} != notary manifest "
            f"{notary_manifest.signer_id!r}",
        )

    # §3.4 algorithm in registry.
    if attestation.algorithm not in ALGORITHM_REGISTRY:
        raise SignerVerificationError(
            "E_SIGNER_ALGORITHM_UNKNOWN",
            f"attestation algorithm {attestation.algorithm!r} not in registry",
        )

    # §3.5 confused-deputy guard — envelope algorithm must match notary manifest
    # BEFORE verifier dispatch.
    if attestation.algorithm != notary_manifest.algorithm:
        raise SignerVerificationError(
            "E_SIGNER_ALGORITHM_MISMATCH",
            f"attestation algorithm {attestation.algorithm!r} != notary manifest "
            f"{notary_manifest.algorithm!r}",
        )

    # §3.6 notary manifest fingerprint recompute. validate=True so trailing
    # non-base64 junk appended to an otherwise-valid key is rejected rather than
    # silently dropped — a tolerant decode here would let a malformed notary
    # manifest still recompute the right fingerprint and pass §3.6.
    try:
        notary_pub = base64.b64decode(notary_manifest.public_key_b64, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise SignerVerificationError(
            "E_SIGNER_MALFORMED",
            f"notary public_key_b64 not valid base64: {exc}",
        ) from exc
    recomputed = compute_key_fingerprint(notary_pub)
    # The notary manifest fingerprint is attacker-influenced (notaries/<id>.json);
    # validate its format before compare_digest, which raises a raw TypeError on a
    # non-ASCII str rather than the spec error code (mirrors the §3.2 guard).
    _require_fingerprint_format(
        notary_manifest.key_fingerprint, label="notary manifest key_fingerprint"
    )
    if not hmac.compare_digest(recomputed, notary_manifest.key_fingerprint):
        raise SignerVerificationError(
            "E_SIGNER_FINGERPRINT_MISMATCH",
            f"recomputed notary fingerprint {recomputed!r} != declared "
            f"{notary_manifest.key_fingerprint!r}",
        )

    # §3.7 signature verification over the attestation canonical hash.
    attestation_hash = compute_attestation_canonical_hash(
        signer_id=attestation.signer_id,
        notary_id=attestation.notary_id,
        key_fingerprint=attestation.key_fingerprint,
    )
    _verify_attestation_signature(
        notary_manifest=notary_manifest,
        attestation_hash=attestation_hash,
        signature_b64=attestation.signature_b64,
    )

    return "verified-by-notary"


__all__ = [
    "NotaryAttestation",
    "NotaryAttestationEnvelope",
    "SignerManifest",
    "attestation_is_acceptable",
    "canonical_attestation_bytes",
    "compute_attestation_canonical_hash",
    "parse_attestation_line",
    "resolve_notary",
    "resolve_notary_attestation",
]
