"""TDD tests for v0.5 trust notary extension point.

Covers spec/v0.5-signer-trust.md §4 (trust notary extension point).
"""

from __future__ import annotations

import socket
import typing
import unittest.mock

import pytest

import aphelion.signer as _signer_module
from aphelion.signer import SignerManifest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _manifest(*, notary_uri: str | None = None) -> SignerManifest:
    return SignerManifest(
        signer_id="alice",
        algorithm="ed25519",
        public_key_b64="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        key_fingerprint="a" * 64,
        notary_uri=notary_uri,
    )


# ---------------------------------------------------------------------------
# Re-export smoke test
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_signer_manifest_reexported() -> None:
    """SignerManifest imported from trust must be the same class as signer.SignerManifest."""
    from aphelion.trust import SignerManifest as TrustSignerManifest

    assert TrustSignerManifest is _signer_module.SignerManifest


# ---------------------------------------------------------------------------
# resolve_notary
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_resolve_notary_returns_verified_locally_when_notary_uri_none() -> None:
    """manifest.notary_uri=None → 'verified-locally'."""
    from aphelion.trust import resolve_notary

    result = resolve_notary(_manifest(notary_uri=None))
    assert result == "verified-locally"


@pytest.mark.unit
def test_resolve_notary_returns_verified_locally_when_notary_uri_set() -> None:
    """v0.5 stub never reaches out; notary_uri set still returns 'verified-locally'."""
    from aphelion.trust import resolve_notary

    result = resolve_notary(_manifest(notary_uri="https://notary.example.com"))
    assert result == "verified-locally"


@pytest.mark.unit
def test_resolve_notary_does_not_perform_io() -> None:
    """resolve_notary must not perform I/O — patching socket.getaddrinfo to raise
    confirms no network call is attempted."""
    from aphelion.trust import resolve_notary

    with unittest.mock.patch("socket.getaddrinfo", side_effect=OSError("no network")):
        result = resolve_notary(_manifest(notary_uri="https://notary.example.com"))

    assert result == "verified-locally"


# ---------------------------------------------------------------------------
# attestation_is_acceptable
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_attestation_acceptable_default_accepts_anything() -> None:
    """require_notary=False (default) accepts both attestation values."""
    from aphelion.trust import attestation_is_acceptable

    assert attestation_is_acceptable("verified-locally") is True
    assert attestation_is_acceptable("verified-by-notary") is True


@pytest.mark.unit
def test_attestation_acceptable_strict_rejects_local_only() -> None:
    """require_notary=True rejects 'verified-locally'."""
    from aphelion.trust import attestation_is_acceptable

    assert attestation_is_acceptable("verified-locally", require_notary=True) is False


@pytest.mark.unit
def test_attestation_acceptable_strict_accepts_notary() -> None:
    """require_notary=True accepts 'verified-by-notary'."""
    from aphelion.trust import attestation_is_acceptable

    assert attestation_is_acceptable("verified-by-notary", require_notary=True) is True


# ---------------------------------------------------------------------------
# Literal type contract
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_notary_attestation_literal_values() -> None:
    """NotaryAttestation Literal must define exactly the two documented strings."""
    from aphelion.trust import NotaryAttestation

    args = typing.get_args(NotaryAttestation)
    assert set(args) == {"verified-locally", "verified-by-notary"}


# ---------------------------------------------------------------------------
# Spec traceability
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_module_docstring_references_spec_section_4() -> None:
    """trust module docstring must reference spec §4 for traceability."""
    import aphelion.trust as trust_module

    assert trust_module.__doc__ is not None
    assert "§4" in trust_module.__doc__
