"""v0.5 signer/trust reference implementation.

Implements spec/v0.5-signer-trust.md §1-§3, §5 verification subset, §6
error codes. Phase A scope:

- ``SignatureEnvelope`` and ``SignerManifest`` frozen dataclasses (§2.2,
  §2.3).
- Algorithm registry with ``hmac-sha256`` (test-only) and ``ed25519``
  (declared, real impl deferred to ``aphelion[signer]`` extra) entries
  (§3.1).
- ``HMACSigner`` / ``HMACVerifier`` reference impl using stdlib only
  (§3.2). Real Ed25519 lands in a follow-up under the optional dep.
- ``compute_package_canonical_hash`` per §2.1 — pure function, ordering
  guarantees applied here.
- ``canonical_envelope_bytes`` re-uses ``aphelion.canonical_json`` so the
  envelope canonical form matches every other v0.4 wire surface.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import re
import warnings
from dataclasses import dataclass, fields
from types import MappingProxyType
from typing import Iterable, Mapping, Protocol, runtime_checkable

from aphelion.canonical_json import dumps, normalize

_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_HMAC_TEST_ONLY_WARNING = (
    "hmac-sha256 envelopes have zero non-repudiation; algorithm is TEST-ONLY "
    "per spec/v0.5-signer-trust.md §3.2"
)

# ---------------------------------------------------------------------------
# Error type
# ---------------------------------------------------------------------------


class SignerVerificationError(Exception):
    """Raised when an envelope or manifest fails any §5 verification rule.

    ``code`` is one of the §6 error-code strings; consumers SHOULD branch
    on the code, never the message.
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


# ---------------------------------------------------------------------------
# Envelope and manifest (§2.2 / §2.3)
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class SignatureEnvelope:
    """Per-package detached signature record (§2.2)."""

    signer_id: str
    algorithm: str
    signed_at_iso: str
    package_canonical_hash: str
    signature_b64: str


@dataclass(frozen=True, slots=True)
class SignerManifest:
    """Public-key-and-identity record at ``signers/<signer_id>.json`` (§2.3)."""

    signer_id: str
    algorithm: str
    public_key_b64: str
    key_fingerprint: str
    notary_uri: str | None


# ---------------------------------------------------------------------------
# Algorithm registry (§3.1)
# ---------------------------------------------------------------------------


_REGISTRY: dict[str, str] = {
    "hmac-sha256": (
        "RFC 2104 with SHA-256; TEST-ONLY symmetric MAC. Provides no "
        "non-repudiation; never use for production attestation."
    ),
    "ed25519": (
        "RFC 8032 Ed25519 over the raw bytes of package_canonical_hash "
        "decoded as hex. Public key is the 32-byte raw form. Real impl "
        "requires the [signer] extra (cryptography>=42)."
    ),
}

ALGORITHM_REGISTRY: Mapping[str, str] = MappingProxyType(_REGISTRY)
"""Read-only view of the §3.1 algorithm registry."""


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------


def compute_key_fingerprint(public_key_bytes: bytes) -> str:
    """Lower-case hex sha256 of raw public-key (or shared-secret) bytes (§2.3)."""

    return hashlib.sha256(public_key_bytes).hexdigest()


def compute_package_canonical_hash(
    *,
    format_version: str,
    package_id: str,
    claims: Iterable[tuple[str, str, str]],
) -> str:
    """Compute the per-package binding hash (§2.1).

    ``claims`` is an iterable of ``(claim_id, claim_instance_id,
    content_hash)`` tuples. The function sorts the claims lexicographically
    so that envelope-time ordering of the input does not affect the hash —
    callers do not need to pre-sort.
    """

    payload = normalize([format_version, package_id, sorted(claims)])
    return hashlib.sha256(dumps(payload)).hexdigest()


def canonical_envelope_bytes(envelope: SignatureEnvelope) -> bytes:
    """Serialize one envelope as a canonical JSONL line ending in LF (§2.4)."""

    payload = normalize(
        {
            "algorithm": envelope.algorithm,
            "package_canonical_hash": envelope.package_canonical_hash,
            "signature_b64": envelope.signature_b64,
            "signed_at_iso": envelope.signed_at_iso,
            "signer_id": envelope.signer_id,
        }
    )
    return dumps(payload)


def parse_envelope_line(line: bytes) -> SignatureEnvelope:
    """Parse one canonical ``signatures.jsonl`` line back into a
    ``SignatureEnvelope`` (§2.4 inverse of ``canonical_envelope_bytes``).

    Raises ``SignerVerificationError`` with code ``E_SIGNATURE_MALFORMED`` on
    any structural failure (non-UTF-8, invalid JSON, missing/unknown fields,
    wrong field types). Use this paired with ``canonical_envelope_bytes`` to
    guarantee writer/reader round-trip determinism before the v0.6 JSONL
    file-level reader lands.
    """

    try:
        payload = json.loads(line.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SignerVerificationError(
            "E_SIGNATURE_MALFORMED", f"envelope line not canonical JSON: {exc}"
        ) from exc
    if not isinstance(payload, dict):
        raise SignerVerificationError(
            "E_SIGNATURE_MALFORMED", "envelope line must be a JSON object"
        )
    expected = {f.name for f in fields(SignatureEnvelope)}
    missing = expected - payload.keys()
    extra = payload.keys() - expected
    if missing or extra:
        raise SignerVerificationError(
            "E_SIGNATURE_MALFORMED",
            f"envelope field set drift — missing={sorted(missing)} extra={sorted(extra)}",
        )
    for key, value in payload.items():
        if not isinstance(value, str):
            raise SignerVerificationError(
                "E_SIGNATURE_MALFORMED",
                f"envelope field {key!r} must be string, got {type(value).__name__}",
            )
    return SignatureEnvelope(**payload)


# ---------------------------------------------------------------------------
# Signer / Verifier protocols
# ---------------------------------------------------------------------------


@runtime_checkable
class Signer(Protocol):
    """Anything that can produce a SignatureEnvelope for a given package hash."""

    def sign(
        self, *, package_canonical_hash: str, signed_at_iso: str
    ) -> SignatureEnvelope: ...

    def manifest(self) -> SignerManifest: ...


@runtime_checkable
class Verifier(Protocol):
    """Anything that can verify a SignatureEnvelope against a SignerManifest."""

    def verify(
        self,
        envelope: SignatureEnvelope,
        manifest: SignerManifest,
        *,
        package_canonical_hash: str,
    ) -> None: ...


# ---------------------------------------------------------------------------
# HMAC reference implementation (§3.2 — TEST ONLY)
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class HMACSigner:
    """HMAC-SHA256 reference signer; **TEST-ONLY**, no non-repudiation."""

    signer_id: str
    secret: bytes

    def sign(
        self, *, package_canonical_hash: str, signed_at_iso: str
    ) -> SignatureEnvelope:
        signature = hmac.new(
            self.secret, bytes.fromhex(package_canonical_hash), hashlib.sha256
        ).digest()
        return SignatureEnvelope(
            signer_id=self.signer_id,
            algorithm="hmac-sha256",
            signed_at_iso=signed_at_iso,
            package_canonical_hash=package_canonical_hash,
            signature_b64=base64.standard_b64encode(signature).decode("ascii"),
        )

    def manifest(self) -> SignerManifest:
        return SignerManifest(
            signer_id=self.signer_id,
            algorithm="hmac-sha256",
            public_key_b64=base64.standard_b64encode(self.secret).decode("ascii"),
            key_fingerprint=compute_key_fingerprint(self.secret),
            notary_uri=None,
        )


# ---------------------------------------------------------------------------
# Ed25519 real implementation (§3.3) — requires aphelion[signer] extra
# ---------------------------------------------------------------------------


def _require_cryptography() -> tuple[type, type]:
    """Lazy-import Ed25519 primitives; raises ``SignerVerificationError`` when
    the ``cryptography`` package is not installed.

    Returns ``(Ed25519PrivateKey, Ed25519PublicKey)`` type objects.
    """
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # type: ignore[import]
            Ed25519PrivateKey,
            Ed25519PublicKey,
        )
    except (ImportError, TypeError) as e:
        raise SignerVerificationError(
            "E_SIGNER_ALGORITHM_UNAVAILABLE",
            "ed25519 requires aphelion[signer] extra (pip install aphelion[signer])",
        ) from e
    return Ed25519PrivateKey, Ed25519PublicKey


@dataclass(frozen=True, slots=True)
class Ed25519Signer:
    """Ed25519 signer per spec §3.3.

    ``private_key_b64`` is the base64-standard-encoded 32-byte raw private key.
    Requires the ``cryptography>=42`` package (``aphelion[signer]`` extra).
    """

    signer_id: str
    private_key_b64: str

    def _private_key(self) -> object:
        Ed25519PrivateKey, _ = _require_cryptography()
        raw = base64.standard_b64decode(self.private_key_b64)
        return Ed25519PrivateKey.from_private_bytes(raw)

    def sign(
        self, *, package_canonical_hash: str, signed_at_iso: str
    ) -> SignatureEnvelope:
        """Sign the raw bytes of ``package_canonical_hash`` decoded as hex (§3.3)."""
        priv = self._private_key()
        msg = bytes.fromhex(package_canonical_hash)
        signature = priv.sign(msg)  # 64-byte raw
        return SignatureEnvelope(
            signer_id=self.signer_id,
            algorithm="ed25519",
            signed_at_iso=signed_at_iso,
            package_canonical_hash=package_canonical_hash,
            signature_b64=base64.standard_b64encode(signature).decode("ascii"),
        )

    def manifest(self) -> SignerManifest:
        """Return the ``SignerManifest`` corresponding to this signer's public key."""
        priv = self._private_key()
        pub_raw = priv.public_key().public_bytes_raw()
        return SignerManifest(
            signer_id=self.signer_id,
            algorithm="ed25519",
            public_key_b64=base64.standard_b64encode(pub_raw).decode("ascii"),
            key_fingerprint=compute_key_fingerprint(pub_raw),
            notary_uri=None,
        )


@dataclass(frozen=True, slots=True)
class Ed25519Verifier:
    """Ed25519 verifier per spec §3.3 + §5 rule sequence.

    ``public_key_b64`` is the base64-standard-encoded 32-byte raw public key.
    Requires the ``cryptography>=42`` package (``aphelion[signer]`` extra).
    """

    public_key_b64: str

    def _public_key(self) -> object:
        _, Ed25519PublicKey = _require_cryptography()
        raw = base64.standard_b64decode(self.public_key_b64)
        return Ed25519PublicKey.from_public_bytes(raw)

    def build_manifest(self, *, signer_id: str) -> SignerManifest:
        """Convenience: construct a ``SignerManifest`` from this verifier's public key."""
        pub_raw = base64.standard_b64decode(self.public_key_b64)
        return SignerManifest(
            signer_id=signer_id,
            algorithm="ed25519",
            public_key_b64=self.public_key_b64,
            key_fingerprint=compute_key_fingerprint(pub_raw),
            notary_uri=None,
        )

    def verify(
        self,
        envelope: SignatureEnvelope,
        manifest: SignerManifest,
        *,
        package_canonical_hash: str,
    ) -> None:
        """Execute the §5 rule sequence for ed25519 envelopes.

        Raises ``SignerVerificationError`` on any failure; the ``code``
        attribute is one of the §6 error-code strings.
        """
        if envelope.algorithm not in ALGORITHM_REGISTRY:
            raise SignerVerificationError(
                "E_SIGNER_ALGORITHM_UNKNOWN",
                f"algorithm {envelope.algorithm!r} not in registry",
            )
        if envelope.algorithm != "ed25519":
            raise SignerVerificationError(
                "E_SIGNER_ALGORITHM_UNKNOWN",
                f"Ed25519Verifier cannot verify algorithm {envelope.algorithm!r}",
            )

        if envelope.signer_id != manifest.signer_id:
            raise SignerVerificationError(
                "E_SIGNER_MISSING",
                f"envelope signer_id {envelope.signer_id!r} != manifest "
                f"{manifest.signer_id!r}",
            )

        if not _HEX64_RE.fullmatch(envelope.package_canonical_hash):
            raise SignerVerificationError(
                "E_SIGNATURE_MALFORMED",
                "envelope package_canonical_hash must be 64 lowercase hex chars; "
                f"got {envelope.package_canonical_hash!r}",
            )

        try:
            pub_raw = base64.standard_b64decode(manifest.public_key_b64)
        except (ValueError, binascii.Error) as exc:
            raise SignerVerificationError(
                "E_SIGNER_MALFORMED", f"public_key_b64 not valid base64: {exc}"
            ) from exc

        recomputed_fp = compute_key_fingerprint(pub_raw)
        if not hmac.compare_digest(recomputed_fp, manifest.key_fingerprint):
            raise SignerVerificationError(
                "E_SIGNER_FINGERPRINT_MISMATCH",
                f"recomputed fingerprint {recomputed_fp!r} != declared "
                f"{manifest.key_fingerprint!r}",
            )

        if not hmac.compare_digest(
            envelope.package_canonical_hash, package_canonical_hash
        ):
            raise SignerVerificationError(
                "E_SIGNATURE_HASH_MISMATCH",
                "envelope package_canonical_hash does not match recomputed value",
            )

        try:
            signature = base64.standard_b64decode(envelope.signature_b64)
        except (ValueError, binascii.Error) as exc:
            raise SignerVerificationError(
                "E_SIGNATURE_MALFORMED",
                f"signature_b64 not valid base64: {exc}",
            ) from exc

        pub = self._public_key()
        try:
            pub.verify(signature, bytes.fromhex(package_canonical_hash))
        except Exception as exc:  # cryptography raises InvalidSignature
            raise SignerVerificationError(
                "E_SIGNATURE_INVALID", f"Ed25519 verification failed: {exc}"
            ) from exc


class HMACVerifier:
    """Reference verifier executing the §5 rule sequence.

    Stateless class — kept as a class (not module-level function) so it
    satisfies the ``Verifier`` Protocol structurally and keeps an
    open seat for a future Ed25519/asymmetric verifier with the same
    surface.
    """

    def verify(
        self,
        envelope: SignatureEnvelope,
        manifest: SignerManifest,
        *,
        package_canonical_hash: str,
    ) -> None:
        if envelope.algorithm not in ALGORITHM_REGISTRY:
            raise SignerVerificationError(
                "E_SIGNER_ALGORITHM_UNKNOWN",
                f"algorithm {envelope.algorithm!r} not in registry",
            )
        if envelope.algorithm != "hmac-sha256":
            raise SignerVerificationError(
                "E_SIGNER_ALGORITHM_UNKNOWN",
                f"HMACVerifier cannot verify algorithm {envelope.algorithm!r}",
            )

        # Spec §3.2 MUST: warn on hmac-sha256 (caller can suppress via
        # ``warnings.simplefilter``; the ``--allow-test-algorithms`` CLI
        # toggle is Lane B work and lives outside this module).
        warnings.warn(_HMAC_TEST_ONLY_WARNING, UserWarning, stacklevel=2)
        if envelope.signer_id != manifest.signer_id:
            raise SignerVerificationError(
                "E_SIGNER_MISSING",
                f"envelope signer_id {envelope.signer_id!r} != manifest "
                f"{manifest.signer_id!r}",
            )

        if not _HEX64_RE.fullmatch(envelope.package_canonical_hash):
            raise SignerVerificationError(
                "E_SIGNATURE_MALFORMED",
                "envelope package_canonical_hash must be 64 lowercase hex chars; "
                f"got {envelope.package_canonical_hash!r}",
            )

        try:
            secret = base64.standard_b64decode(manifest.public_key_b64)
        except (ValueError, binascii.Error) as exc:
            raise SignerVerificationError(
                "E_SIGNER_MALFORMED", f"public_key_b64 not valid base64: {exc}"
            ) from exc

        recomputed_fp = compute_key_fingerprint(secret)
        if not hmac.compare_digest(recomputed_fp, manifest.key_fingerprint):
            raise SignerVerificationError(
                "E_SIGNER_FINGERPRINT_MISMATCH",
                f"recomputed fingerprint {recomputed_fp!r} != declared "
                f"{manifest.key_fingerprint!r}",
            )

        if not hmac.compare_digest(
            envelope.package_canonical_hash, package_canonical_hash
        ):
            raise SignerVerificationError(
                "E_SIGNATURE_HASH_MISMATCH",
                "envelope package_canonical_hash does not match recomputed value",
            )

        try:
            signature = base64.standard_b64decode(envelope.signature_b64)
        except (ValueError, binascii.Error) as exc:
            raise SignerVerificationError(
                "E_SIGNATURE_MALFORMED",
                f"signature_b64 not valid base64: {exc}",
            ) from exc

        expected = hmac.new(
            secret, bytes.fromhex(package_canonical_hash), hashlib.sha256
        ).digest()
        if not hmac.compare_digest(signature, expected):
            raise SignerVerificationError(
                "E_SIGNATURE_INVALID", "HMAC verification failed"
            )


__all__ = [
    "ALGORITHM_REGISTRY",
    "Ed25519Signer",
    "Ed25519Verifier",
    "HMACSigner",
    "HMACVerifier",
    "SignatureEnvelope",
    "Signer",
    "SignerManifest",
    "SignerVerificationError",
    "Verifier",
    "canonical_envelope_bytes",
    "compute_key_fingerprint",
    "compute_package_canonical_hash",
    "parse_envelope_line",
]
