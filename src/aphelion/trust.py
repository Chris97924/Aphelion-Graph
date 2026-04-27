"""v0.5 trust notary — extension point only (spec §4).

This module is the public surface for notary-aware verification. v0.5
defines only the extension-point contract; v0.6+ will pin a normative
resolver protocol. Until then, every notary lookup yields the literal
result ``"verified-locally"`` and any I/O failure is non-fatal.
"""

from __future__ import annotations

from typing import Literal

from aphelion.signer import SignerManifest  # re-export for spec §10

NotaryAttestation = Literal["verified-locally", "verified-by-notary"]


def resolve_notary(manifest: SignerManifest) -> NotaryAttestation:
    """Stub resolver per spec §4.

    If manifest.notary_uri is None → return "verified-locally".
    If manifest.notary_uri is set → out-of-band lookup is unspecified in
    v0.5; this stub returns "verified-locally" without attempting I/O.

    Validators that do not understand or cannot reach a notary MUST
    treat the envelope as verified-locally only (spec §4).
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


__all__ = [
    "NotaryAttestation",
    "SignerManifest",
    "attestation_is_acceptable",
    "resolve_notary",
]
