"""TDD tests for v0.5 signer/verifier wire integration.

Covers spec/v0.5-signer-trust.md §5 "Verification Rules" end-to-end,
wiring unpacker.py → validator.validate_signatures() → verifier.verify_package()
and the CLI `aphe sign` + extended `aphe verify` subcommands.

Decision on require_signed=False + signatures present:
  Presence of signatures.jsonl opts the package in to §5 verification
  regardless of require_signed. The require_signed flag ONLY controls
  whether ABSENCE of signatures is an error. So a malformed signature
  still fails even when require_signed=False.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
from pathlib import Path

import pytest

from aphelion.canonical_json import dumps as canonical_dumps
from aphelion.canonical_json import normalize
from aphelion.signer import (
    HMACSigner,
    SignatureEnvelope,
    SignerVerificationError,
    compute_key_fingerprint,
    compute_package_canonical_hash,
)
from aphelion.sig_pack import write_signatures_jsonl

# Suppress hmac-sha256 test-only warnings across this module
pytestmark = pytest.mark.filterwarnings(
    "ignore:hmac-sha256 envelopes have zero non-repudiation:UserWarning"
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

UUID_PKG = "0191bbbb-0000-7000-8000-000000000001"
UUID_CLAIM_A = "0191bbbb-0000-7000-8000-00000000aaaa"
UUID_INSTANCE_A = "0191bbbb-0000-7000-8000-aaaaaaaaaaaa"
UUID_EVENT_1 = "0191bbbb-0000-7000-8000-eeee00000001"

SHARED_SECRET = b"test-hmac-key-verifier-signed-32"
SIGNER_ID = "test-signer"
SIGNED_AT = "2026-04-27T00:00:00.000Z"

# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------


def _claim_bytes(title: str = "Test Claim") -> bytes:
    header = (
        '---\n'
        f'"body_format": "markdown"\n'
        f'"claim_id": "{UUID_CLAIM_A}"\n'
        f'"title": "{title}"\n'
        '---\n'
    )
    return header.encode("utf-8")


def _build_minimal_source(dest: Path, claim_bytes: bytes | None = None) -> None:
    """Write a minimal valid v0.4 source directory to dest."""
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "claims").mkdir(exist_ok=True)
    cbytes = claim_bytes if claim_bytes is not None else _claim_bytes()
    (dest / f"claims/{UUID_CLAIM_A}.md").write_bytes(cbytes)
    manifest = {
        "aphelion_spec_version": "0.4.0",
        "claims": [
            {
                "claim_id": UUID_CLAIM_A,
                "claim_instance_id": UUID_INSTANCE_A,
                "hash": hashlib.sha256(cbytes).hexdigest(),
                "path": f"claims/{UUID_CLAIM_A}.md",
                "state": "active",
            }
        ],
        "created_at": "2026-04-21T00:00:00Z",
        "format_version": "2.0",
        "license": "Apache-2.0",
        "package_id": UUID_PKG,
        "producer": "aphelion-test",
        "provenance_path": "provenance.jsonl",
    }
    (dest / "manifest.json").write_bytes(canonical_dumps(normalize(manifest)))
    event = {
        "actor": "test",
        "claim_id": UUID_CLAIM_A,
        "claim_instance_id": UUID_INSTANCE_A,
        "event_id": UUID_EVENT_1,
        "event_type": "create",
        "timestamp": "2026-04-21T00:00:00Z",
    }
    (dest / "provenance.jsonl").write_bytes(canonical_dumps(normalize(event)))


def _pack_source(source: Path, out: Path) -> Path:
    """Pack a source directory into a .aphelion.tar."""
    from aphelion.packer import pack

    return pack(source, out)


def _pack_tar_with_extra(
    source: Path,
    out: Path,
    extra_members: list[tuple[str, bytes]],
) -> Path:
    """Pack source dir and append extra (path, bytes) members to the tar."""
    from aphelion.packer import pack
    from aphelion.canonical_tar import read_members, TarMember
    from aphelion.canonical_tar import pack as tar_pack

    pack(source, out)
    existing = read_members(out.read_bytes())
    extra = [TarMember(path=p, data=d, is_dir=False) for p, d in extra_members]
    new_tar = tar_pack(existing + extra)
    out.write_bytes(new_tar)
    return out


def _make_signed_tar(
    tmp_path: Path,
    *,
    signer: HMACSigner | None = None,
    source_override: Path | None = None,
) -> Path:
    """Build a minimal package tar, sign it with HMAC, return tar path."""
    src = source_override or (tmp_path / "src")
    if source_override is None:
        _build_minimal_source(src)

    tar_path = tmp_path / "pkg.tar"
    _pack_source(src, tar_path)

    # Compute canonical hash from the manifest
    manifest_obj = normalize(json.loads(
        (src / "manifest.json").read_bytes()
    ))
    claims_tuples = [
        (c["claim_id"], c["claim_instance_id"], c["hash"])
        for c in manifest_obj["claims"]
    ]
    pkg_hash = compute_package_canonical_hash(
        format_version=manifest_obj["format_version"],
        package_id=manifest_obj["package_id"],
        claims=claims_tuples,
    )

    s = signer or HMACSigner(signer_id=SIGNER_ID, secret=SHARED_SECRET)
    envelope = s.sign(package_canonical_hash=pkg_hash, signed_at_iso=SIGNED_AT)
    manifest_record = s.manifest()

    sig_bytes = write_signatures_jsonl([envelope])
    manifest_json = canonical_dumps(normalize({
        "signer_id": manifest_record.signer_id,
        "algorithm": manifest_record.algorithm,
        "public_key_b64": manifest_record.public_key_b64,
        "key_fingerprint": manifest_record.key_fingerprint,
        "notary_uri": None,
    }))

    # Repack with signatures.jsonl + signers/<id>.json
    from aphelion.canonical_tar import read_members, TarMember
    from aphelion.canonical_tar import pack as tar_pack

    existing = read_members(tar_path.read_bytes())
    extra = [
        TarMember(path="signatures.jsonl", data=sig_bytes, is_dir=False),
        TarMember(path=f"signers/{SIGNER_ID}.json", data=manifest_json, is_dir=False),
    ]
    tar_path.write_bytes(tar_pack(existing + extra))
    return tar_path


# ---------------------------------------------------------------------------
# Tests: verifier internal helpers (defensive-branch coverage)
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_load_events_skips_blank_and_whitespace_lines(tmp_path: Path) -> None:
    """_load_events drops blank and whitespace-only lines between records."""
    from aphelion.verifier import _load_events

    event = {
        "actor": "test",
        "claim_id": UUID_CLAIM_A,
        "claim_instance_id": UUID_INSTANCE_A,
        "event_id": UUID_EVENT_1,
        "event_type": "create",
        "timestamp": "2026-04-21T00:00:00Z",
    }
    line = canonical_dumps(normalize(event))  # canonical line, already ends in \n
    p = tmp_path / "provenance.jsonl"
    # Interleave a blank line and a whitespace-only line between two records.
    p.write_bytes(line + b"\n" + b"   \n" + line)

    events = _load_events(p)
    assert len(events) == 2
    assert all(e["event_id"] == UUID_EVENT_1 for e in events)


@pytest.mark.unit
def test_check_provenance_chain_rejects_multiple_creates() -> None:
    """A claim with two create events trips the single-create guard (CHAIN_BROKEN)."""
    from aphelion.error_codes import ErrorCode
    from aphelion.errors import SemanticError
    from aphelion.verifier import _check_provenance_chain

    events = [
        {"claim_id": UUID_CLAIM_A, "event_id": UUID_EVENT_1, "event_type": "create"},
        {
            "claim_id": UUID_CLAIM_A,
            "event_id": "0191bbbb-0000-7000-8000-eeee00000002",
            "event_type": "create",
        },
    ]
    with pytest.raises(SemanticError) as exc:
        _check_provenance_chain(events)
    assert exc.value.code == ErrorCode.CHAIN_BROKEN


# ---------------------------------------------------------------------------
# Tests: unpacker accessors
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_extract_signatures_jsonl_absent(tmp_path: Path) -> None:
    """Returns None when signatures.jsonl is not present."""
    from aphelion.unpacker import extract_signatures_jsonl

    src = tmp_path / "src"
    _build_minimal_source(src)
    tar_path = tmp_path / "pkg.tar"
    _pack_source(src, tar_path)

    result = extract_signatures_jsonl(tar_path)
    assert result is None


@pytest.mark.unit
def test_extract_signatures_jsonl_present(tmp_path: Path) -> None:
    """Returns bytes when signatures.jsonl is present at archive root."""
    from aphelion.unpacker import extract_signatures_jsonl

    tar_path = _make_signed_tar(tmp_path)
    result = extract_signatures_jsonl(tar_path)
    assert result is not None
    assert result.endswith(b"\n")


@pytest.mark.unit
def test_extract_signer_manifests_absent(tmp_path: Path) -> None:
    """Returns empty dict when no signers/ directory."""
    from aphelion.unpacker import extract_signer_manifests

    src = tmp_path / "src"
    _build_minimal_source(src)
    tar_path = tmp_path / "pkg.tar"
    _pack_source(src, tar_path)

    result = extract_signer_manifests(tar_path)
    assert result == {}


@pytest.mark.unit
def test_extract_signer_manifests_present(tmp_path: Path) -> None:
    """Returns dict with signer_id -> raw bytes for each signer manifest."""
    from aphelion.unpacker import extract_signer_manifests

    tar_path = _make_signed_tar(tmp_path)
    result = extract_signer_manifests(tar_path)
    assert SIGNER_ID in result
    data = json.loads(result[SIGNER_ID])
    assert data["signer_id"] == SIGNER_ID


# ---------------------------------------------------------------------------
# Tests: validate_signatures()
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_validate_signatures_unsigned_returns_empty(tmp_path: Path) -> None:
    """validate_signatures returns empty tuple for packages without signatures."""
    from aphelion.validator import validate_signatures

    src = tmp_path / "src"
    _build_minimal_source(src)
    tar_path = tmp_path / "pkg.tar"
    _pack_source(src, tar_path)

    envelopes = validate_signatures(tar_path)
    assert envelopes == ()


@pytest.mark.unit
def test_validate_signatures_signed_returns_envelopes(tmp_path: Path) -> None:
    """validate_signatures returns one envelope for a validly-signed package."""
    from aphelion.validator import validate_signatures

    tar_path = _make_signed_tar(tmp_path)
    envelopes = validate_signatures(tar_path)
    assert len(envelopes) == 1
    assert envelopes[0].signer_id == SIGNER_ID


@pytest.mark.unit
def test_validate_signatures_missing_signer_manifest(tmp_path: Path) -> None:
    """E_SIGNER_MISSING when envelope references absent signers/<id>.json."""
    from aphelion.validator import validate_signatures
    from aphelion.packer import pack
    from aphelion.canonical_tar import read_members, TarMember
    from aphelion.canonical_tar import pack as tar_pack

    src = tmp_path / "src"
    _build_minimal_source(src)
    tar_path = tmp_path / "pkg.tar"
    pack(src, tar_path)

    manifest_obj = normalize(json.loads((src / "manifest.json").read_bytes()))
    claims_tuples = [
        (c["claim_id"], c["claim_instance_id"], c["hash"])
        for c in manifest_obj["claims"]
    ]
    pkg_hash = compute_package_canonical_hash(
        format_version=manifest_obj["format_version"],
        package_id=manifest_obj["package_id"],
        claims=claims_tuples,
    )
    s = HMACSigner(signer_id=SIGNER_ID, secret=SHARED_SECRET)
    envelope = s.sign(package_canonical_hash=pkg_hash, signed_at_iso=SIGNED_AT)
    sig_bytes = write_signatures_jsonl([envelope])

    existing = read_members(tar_path.read_bytes())
    # Only add signatures.jsonl — no signers manifest
    new_tar = tar_pack(existing + [TarMember(path="signatures.jsonl", data=sig_bytes, is_dir=False)])
    tar_path.write_bytes(new_tar)

    with pytest.raises(SignerVerificationError) as exc_info:
        validate_signatures(tar_path)
    assert exc_info.value.code == "E_SIGNER_MISSING"


@pytest.mark.unit
def test_validate_signatures_fingerprint_mismatch(tmp_path: Path) -> None:
    """E_SIGNER_FINGERPRINT_MISMATCH when key_fingerprint in manifest is wrong."""
    from aphelion.validator import validate_signatures
    from aphelion.packer import pack
    from aphelion.canonical_tar import read_members, TarMember
    from aphelion.canonical_tar import pack as tar_pack

    src = tmp_path / "src"
    _build_minimal_source(src)
    tar_path = tmp_path / "pkg.tar"
    pack(src, tar_path)

    manifest_obj = normalize(json.loads((src / "manifest.json").read_bytes()))
    claims_tuples = [
        (c["claim_id"], c["claim_instance_id"], c["hash"])
        for c in manifest_obj["claims"]
    ]
    pkg_hash = compute_package_canonical_hash(
        format_version=manifest_obj["format_version"],
        package_id=manifest_obj["package_id"],
        claims=claims_tuples,
    )
    s = HMACSigner(signer_id=SIGNER_ID, secret=SHARED_SECRET)
    envelope = s.sign(package_canonical_hash=pkg_hash, signed_at_iso=SIGNED_AT)
    m = s.manifest()
    sig_bytes = write_signatures_jsonl([envelope])

    # Tamper fingerprint
    tampered_manifest = canonical_dumps(normalize({
        "signer_id": m.signer_id,
        "algorithm": m.algorithm,
        "public_key_b64": m.public_key_b64,
        "key_fingerprint": "a" * 64,  # wrong fingerprint
        "notary_uri": None,
    }))

    existing = read_members(tar_path.read_bytes())
    new_tar = tar_pack(existing + [
        TarMember(path="signatures.jsonl", data=sig_bytes, is_dir=False),
        TarMember(path=f"signers/{SIGNER_ID}.json", data=tampered_manifest, is_dir=False),
    ])
    tar_path.write_bytes(new_tar)

    with pytest.raises(SignerVerificationError) as exc_info:
        validate_signatures(tar_path)
    assert exc_info.value.code == "E_SIGNER_FINGERPRINT_MISMATCH"


@pytest.mark.unit
def test_validate_signatures_unknown_algorithm(tmp_path: Path) -> None:
    """E_SIGNER_ALGORITHM_UNKNOWN when envelope uses an unregistered algorithm."""
    from aphelion.validator import validate_signatures
    from aphelion.packer import pack
    from aphelion.canonical_tar import read_members, TarMember
    from aphelion.canonical_tar import pack as tar_pack

    src = tmp_path / "src"
    _build_minimal_source(src)
    tar_path = tmp_path / "pkg.tar"
    pack(src, tar_path)

    manifest_obj = normalize(json.loads((src / "manifest.json").read_bytes()))
    claims_tuples = [
        (c["claim_id"], c["claim_instance_id"], c["hash"])
        for c in manifest_obj["claims"]
    ]
    pkg_hash = compute_package_canonical_hash(
        format_version=manifest_obj["format_version"],
        package_id=manifest_obj["package_id"],
        claims=claims_tuples,
    )

    # Build envelope with unknown algorithm directly
    bad_envelope = SignatureEnvelope(
        signer_id=SIGNER_ID,
        algorithm="future-algo",
        signed_at_iso=SIGNED_AT,
        package_canonical_hash=pkg_hash,
        signature_b64=base64.standard_b64encode(b"fake").decode(),
    )

    secret = SHARED_SECRET
    fp = compute_key_fingerprint(secret)
    signer_manifest_bytes = canonical_dumps(normalize({
        "signer_id": SIGNER_ID,
        "algorithm": "future-algo",
        "public_key_b64": base64.standard_b64encode(secret).decode(),
        "key_fingerprint": fp,
        "notary_uri": None,
    }))

    sig_bytes = write_signatures_jsonl([bad_envelope])

    existing = read_members(tar_path.read_bytes())
    new_tar = tar_pack(existing + [
        TarMember(path="signatures.jsonl", data=sig_bytes, is_dir=False),
        TarMember(path=f"signers/{SIGNER_ID}.json", data=signer_manifest_bytes, is_dir=False),
    ])
    tar_path.write_bytes(new_tar)

    with pytest.raises(SignerVerificationError) as exc_info:
        validate_signatures(tar_path)
    assert exc_info.value.code == "E_SIGNER_ALGORITHM_UNKNOWN"


@pytest.mark.unit
def test_validate_signatures_order_rejected(tmp_path: Path) -> None:
    """E_SIGNATURE_ORDER when signatures.jsonl is not sorted per §2.4."""
    from aphelion.validator import validate_signatures
    from aphelion.packer import pack
    from aphelion.canonical_tar import read_members, TarMember
    from aphelion.canonical_tar import pack as tar_pack

    src = tmp_path / "src"
    _build_minimal_source(src)
    tar_path = tmp_path / "pkg.tar"
    pack(src, tar_path)

    manifest_obj = normalize(json.loads((src / "manifest.json").read_bytes()))
    claims_tuples = [
        (c["claim_id"], c["claim_instance_id"], c["hash"])
        for c in manifest_obj["claims"]
    ]
    pkg_hash = compute_package_canonical_hash(
        format_version=manifest_obj["format_version"],
        package_id=manifest_obj["package_id"],
        claims=claims_tuples,
    )

    # Two envelopes from different signers with reverse signer_id order
    s1 = HMACSigner(signer_id="z-signer", secret=SHARED_SECRET)
    s2 = HMACSigner(signer_id="a-signer", secret=SHARED_SECRET)
    e1 = s1.sign(package_canonical_hash=pkg_hash, signed_at_iso=SIGNED_AT)
    e2 = s2.sign(package_canonical_hash=pkg_hash, signed_at_iso=SIGNED_AT)

    # Manually build reversed jsonl (z-signer first, then a-signer)
    from aphelion.signer import canonical_envelope_bytes
    reversed_jsonl = canonical_envelope_bytes(e1) + canonical_envelope_bytes(e2)

    # Both signer manifests
    m1 = s1.manifest()
    m2 = s2.manifest()
    m1_bytes = canonical_dumps(normalize({
        "signer_id": m1.signer_id, "algorithm": m1.algorithm,
        "public_key_b64": m1.public_key_b64, "key_fingerprint": m1.key_fingerprint,
        "notary_uri": None,
    }))
    m2_bytes = canonical_dumps(normalize({
        "signer_id": m2.signer_id, "algorithm": m2.algorithm,
        "public_key_b64": m2.public_key_b64, "key_fingerprint": m2.key_fingerprint,
        "notary_uri": None,
    }))

    existing = read_members(tar_path.read_bytes())
    new_tar = tar_pack(existing + [
        TarMember(path="signatures.jsonl", data=reversed_jsonl, is_dir=False),
        TarMember(path="signers/z-signer.json", data=m1_bytes, is_dir=False),
        TarMember(path="signers/a-signer.json", data=m2_bytes, is_dir=False),
    ])
    tar_path.write_bytes(new_tar)

    with pytest.raises(SignerVerificationError) as exc_info:
        validate_signatures(tar_path)
    assert exc_info.value.code == "E_SIGNATURE_ORDER"


def _rewrite_tar_manifest_as_dir(tar_path: Path) -> None:
    """Rewrite ``tar_path`` so ``manifest.json`` is a directory member.

    A directory member is non-regular, so ``tar.extractfile()`` returns None
    while ``tar.getmember("manifest.json")`` still succeeds. This is the
    crafted-archive shape that exercises the trust-boundary guard in
    ``validate_signatures``. We use the raw ``tarfile`` module here on purpose:
    ``canonical_tar`` would reject a non-regular member before it could be
    written.
    """
    import tarfile

    src_members: list[tuple[tarfile.TarInfo, bytes | None]] = []
    with tarfile.open(tar_path, mode="r") as tin:
        for info in tin.getmembers():
            if info.name == "manifest.json":
                continue  # drop the regular manifest member; re-add as dir below
            extracted = tin.extractfile(info) if info.isreg() else None
            data = extracted.read() if extracted is not None else None
            src_members.append((info, data))

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tout:
        dir_info = tarfile.TarInfo(name="manifest.json")
        dir_info.type = tarfile.DIRTYPE
        dir_info.mode = 0o755
        tout.addfile(dir_info)
        for info, data in src_members:
            if data is None:
                tout.addfile(info)
            else:
                tout.addfile(info, io.BytesIO(data))
    tar_path.write_bytes(buf.getvalue())


@pytest.mark.unit
def test_validate_signatures_non_regular_manifest_member(tmp_path: Path) -> None:
    """Crafted archive: manifest.json is a directory member (extractfile → None).

    Under ``python -O`` the prior ``assert manifest_member is not None`` guard is
    stripped, so ``.read()`` on None would raise a raw ``AttributeError`` instead
    of a clean typed validation error. This test asserts the typed
    ``AphelionError`` subclass is raised and that the same code path holds under
    optimized (assert-stripped) semantics.
    """
    from aphelion.errors import AphelionError, SchemaError, SecurityError

    tar_path = _make_signed_tar(tmp_path)
    _rewrite_tar_manifest_as_dir(tar_path)

    from aphelion.validator import validate_signatures

    with pytest.raises((SecurityError, SchemaError)) as exc_info:
        validate_signatures(tar_path)
    assert isinstance(exc_info.value, AphelionError)
    # Must NOT be a bare AttributeError leaking through the trust boundary.
    assert not isinstance(exc_info.value, AttributeError)

    # Verify under -O semantics: assert statements are stripped, so the guard
    # must hold without relying on `assert`. Re-import the validator under -O.
    import subprocess
    import sys
    import textwrap

    script = textwrap.dedent(
        f"""
        from aphelion.errors import AphelionError
        from aphelion.validator import validate_signatures
        try:
            validate_signatures(r{str(tar_path)!r})
        except AphelionError:
            raise SystemExit(0)
        except AttributeError:
            raise SystemExit(2)
        raise SystemExit(3)
        """
    )
    proc = subprocess.run(
        [sys.executable, "-O", "-c", script],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, (
        f"under -O expected typed AphelionError (rc=0), got rc={proc.returncode}\n"
        f"stdout={proc.stdout}\nstderr={proc.stderr}"
    )


def test_validate_signatures_absent_manifest_member(tmp_path: Path) -> None:
    """Crafted archive with signatures but no manifest.json → typed error, not KeyError.

    ``tar.getmember("manifest.json")`` raises ``KeyError`` when the member is
    absent; the guard must surface a typed validation error instead.
    """
    import tarfile

    from aphelion.errors import AphelionError, SchemaError, SecurityError

    tar_path = _make_signed_tar(tmp_path)

    # Rebuild the tar dropping manifest.json entirely (keep signatures + signer).
    kept: list[tuple[tarfile.TarInfo, bytes | None]] = []
    with tarfile.open(tar_path, mode="r") as tin:
        for info in tin.getmembers():
            if info.name == "manifest.json":
                continue
            extracted = tin.extractfile(info) if info.isreg() else None
            data = extracted.read() if extracted is not None else None
            kept.append((info, data))

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tout:
        for info, data in kept:
            if data is None:
                tout.addfile(info)
            else:
                tout.addfile(info, io.BytesIO(data))
    tar_path.write_bytes(buf.getvalue())

    from aphelion.validator import validate_signatures

    with pytest.raises((SecurityError, SchemaError)) as exc_info:
        validate_signatures(tar_path)
    assert isinstance(exc_info.value, AphelionError)
    assert not isinstance(exc_info.value, KeyError)


# ---------------------------------------------------------------------------
# Tests: verify_package() integration
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_unsigned_package_v04_remains_valid(tmp_path: Path) -> None:
    """v0.4 package with no signatures verifies successfully (backward-compat anchor)."""
    from aphelion.verifier import verify_package

    src = tmp_path / "src"
    _build_minimal_source(src)
    tar_path = tmp_path / "pkg.tar"
    _pack_source(src, tar_path)

    result = verify_package(tar_path)
    assert result.envelopes == ()
    assert result.attestations == ()


@pytest.mark.integration
def test_signed_package_round_trip_hmac(tmp_path: Path) -> None:
    """Sign with HMAC, verify succeeds, returns one envelope."""
    from aphelion.verifier import verify_package

    tar_path = _make_signed_tar(tmp_path)
    result = verify_package(tar_path)
    assert len(result.envelopes) == 1
    assert result.envelopes[0].signer_id == SIGNER_ID
    assert len(result.attestations) == 1


@pytest.mark.integration
def test_signed_package_round_trip_ed25519(tmp_path: Path) -> None:
    """Sign with Ed25519, verify succeeds, returns one envelope."""
    from aphelion.verifier import verify_package
    from aphelion.signer import Ed25519Signer, _require_cryptography

    pytest.importorskip("cryptography", reason="ed25519 requires cryptography extra")
    _require_cryptography()  # skip if not available

    src = tmp_path / "src"
    _build_minimal_source(src)
    tar_path = tmp_path / "pkg.tar"
    _pack_source(src, tar_path)

    # Generate Ed25519 key
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    priv = Ed25519PrivateKey.generate()
    priv_raw = priv.private_bytes_raw()
    priv_b64 = base64.standard_b64encode(priv_raw).decode()

    s = Ed25519Signer(signer_id="ed-signer", private_key_b64=priv_b64)

    manifest_obj = normalize(json.loads((src / "manifest.json").read_bytes()))
    claims_tuples = [
        (c["claim_id"], c["claim_instance_id"], c["hash"])
        for c in manifest_obj["claims"]
    ]
    pkg_hash = compute_package_canonical_hash(
        format_version=manifest_obj["format_version"],
        package_id=manifest_obj["package_id"],
        claims=claims_tuples,
    )
    envelope = s.sign(package_canonical_hash=pkg_hash, signed_at_iso=SIGNED_AT)
    m = s.manifest()
    sig_bytes = write_signatures_jsonl([envelope])
    manifest_json = canonical_dumps(normalize({
        "signer_id": m.signer_id, "algorithm": m.algorithm,
        "public_key_b64": m.public_key_b64, "key_fingerprint": m.key_fingerprint,
        "notary_uri": None,
    }))

    from aphelion.canonical_tar import read_members, TarMember
    from aphelion.canonical_tar import pack as tar_pack

    existing = read_members(tar_path.read_bytes())
    new_tar = tar_pack(existing + [
        TarMember(path="signatures.jsonl", data=sig_bytes, is_dir=False),
        TarMember(path="signers/ed-signer.json", data=manifest_json, is_dir=False),
    ])
    tar_path.write_bytes(new_tar)

    result = verify_package(tar_path)
    assert len(result.envelopes) == 1
    assert result.envelopes[0].signer_id == "ed-signer"


@pytest.mark.integration
def test_verify_with_require_signed_rejects_unsigned(tmp_path: Path) -> None:
    """require_signed=True on unsigned package → E_SIGNER_REQUIRED."""
    from aphelion.verifier import verify_package

    src = tmp_path / "src"
    _build_minimal_source(src)
    tar_path = tmp_path / "pkg.tar"
    _pack_source(src, tar_path)

    with pytest.raises(SignerVerificationError) as exc_info:
        verify_package(tar_path, require_signed=True)
    assert exc_info.value.code == "E_SIGNER_REQUIRED"


@pytest.mark.integration
def test_tampered_payload_fails_hash_check(tmp_path: Path) -> None:
    """Envelope carrying wrong package_canonical_hash → E_SIGNATURE_HASH_MISMATCH.

    Per spec §5 rule 1, claim-file tampering is caught first by v0.4 hash checks.
    To isolate E_SIGNATURE_HASH_MISMATCH we tamper the envelope's
    package_canonical_hash instead, keeping the claim files intact.
    """
    from aphelion.verifier import verify_package
    from aphelion.canonical_tar import read_members, TarMember
    from aphelion.canonical_tar import pack as tar_pack
    from aphelion.sig_pack import read_signatures_jsonl
    import dataclasses

    tar_path = _make_signed_tar(tmp_path)

    # Replace the envelope's package_canonical_hash with a wrong value
    members = read_members(tar_path.read_bytes())
    new_members = []
    for m in members:
        if m.path == "signatures.jsonl":
            assert m.data is not None
            envelopes = read_signatures_jsonl(m.data)
            e = envelopes[0]
            bad_e = dataclasses.replace(e, package_canonical_hash="a" * 64)
            new_members.append(TarMember(path=m.path, data=write_signatures_jsonl([bad_e]), is_dir=False))
        else:
            new_members.append(m)
    tar_path.write_bytes(tar_pack(new_members))

    with pytest.raises(SignerVerificationError) as exc_info:
        verify_package(tar_path)
    assert exc_info.value.code == "E_SIGNATURE_HASH_MISMATCH"


@pytest.mark.integration
def test_tampered_signature_fails_invalid(tmp_path: Path) -> None:
    """Flipping a signature byte → E_SIGNATURE_INVALID."""
    from aphelion.verifier import verify_package
    from aphelion.canonical_tar import read_members, TarMember
    from aphelion.canonical_tar import pack as tar_pack
    from aphelion.sig_pack import read_signatures_jsonl

    tar_path = _make_signed_tar(tmp_path)

    members = read_members(tar_path.read_bytes())
    new_members = []
    for m in members:
        if m.path == "signatures.jsonl":
            assert m.data is not None
            envelopes = read_signatures_jsonl(m.data)
            assert len(envelopes) == 1
            e = envelopes[0]
            # Flip one byte in the base64 signature
            sig_bytes = base64.standard_b64decode(e.signature_b64)
            flipped = bytes([sig_bytes[0] ^ 0xFF]) + sig_bytes[1:]
            import dataclasses
            bad_e = dataclasses.replace(e, signature_b64=base64.standard_b64encode(flipped).decode())
            new_members.append(TarMember(path=m.path, data=write_signatures_jsonl([bad_e]), is_dir=False))
        else:
            new_members.append(m)
    tar_path.write_bytes(tar_pack(new_members))

    with pytest.raises(SignerVerificationError) as exc_info:
        verify_package(tar_path)
    assert exc_info.value.code == "E_SIGNATURE_INVALID"


@pytest.mark.integration
def test_signer_fingerprint_mismatch(tmp_path: Path) -> None:
    """Wrong key_fingerprint in signer manifest → E_SIGNER_FINGERPRINT_MISMATCH."""
    from aphelion.verifier import verify_package

    src = tmp_path / "src"
    _build_minimal_source(src)
    tar_path = _make_signed_tar(tmp_path, source_override=src)

    # Overwrite signer manifest with wrong fingerprint
    from aphelion.canonical_tar import read_members, TarMember
    from aphelion.canonical_tar import pack as tar_pack

    members = read_members(tar_path.read_bytes())
    new_members = []
    for m in members:
        if m.path == f"signers/{SIGNER_ID}.json":
            data = json.loads(m.data)
            data["key_fingerprint"] = "b" * 64
            new_members.append(TarMember(
                path=m.path,
                data=canonical_dumps(normalize(data)),
                is_dir=False,
            ))
        else:
            new_members.append(m)
    tar_path.write_bytes(tar_pack(new_members))

    with pytest.raises(SignerVerificationError) as exc_info:
        verify_package(tar_path)
    assert exc_info.value.code == "E_SIGNER_FINGERPRINT_MISMATCH"


@pytest.mark.integration
def test_require_notary_rejects_local_only(tmp_path: Path) -> None:
    """require_notary=True with no notary_uri → E_SIGNER_NOTARY_REQUIRED."""
    from aphelion.verifier import verify_package

    tar_path = _make_signed_tar(tmp_path)

    with pytest.raises(SignerVerificationError) as exc_info:
        verify_package(tar_path, require_signed=True, require_notary=True)
    assert exc_info.value.code == "E_SIGNER_NOTARY_REQUIRED"


@pytest.mark.integration
def test_envelopes_present_but_require_signed_false_still_verifies_strictly(
    tmp_path: Path,
) -> None:
    """Presence of signatures.jsonl opts into §5 even when require_signed=False.

    A malformed/invalid signature still fails even without require_signed.
    """
    from aphelion.verifier import verify_package
    from aphelion.canonical_tar import read_members, TarMember
    from aphelion.canonical_tar import pack as tar_pack

    tar_path = _make_signed_tar(tmp_path)

    # Flip a signature byte so it's invalid
    members = read_members(tar_path.read_bytes())
    new_members = []
    for m in members:
        if m.path == "signatures.jsonl":
            assert m.data is not None
            from aphelion.sig_pack import read_signatures_jsonl
            envelopes = read_signatures_jsonl(m.data)
            e = envelopes[0]
            sig_bytes = base64.standard_b64decode(e.signature_b64)
            flipped = bytes([sig_bytes[0] ^ 0xFF]) + sig_bytes[1:]
            import dataclasses
            bad_e = dataclasses.replace(e, signature_b64=base64.standard_b64encode(flipped).decode())
            new_members.append(TarMember(path=m.path, data=write_signatures_jsonl([bad_e]), is_dir=False))
        else:
            new_members.append(m)
    tar_path.write_bytes(tar_pack(new_members))

    # Even without require_signed=True, the malformed signature fails
    with pytest.raises(SignerVerificationError) as exc_info:
        verify_package(tar_path, require_signed=False)
    assert exc_info.value.code == "E_SIGNATURE_INVALID"


# ---------------------------------------------------------------------------
# Tests: CLI integration
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_cli_aphe_verify_unsigned_without_flag_passes(tmp_path: Path) -> None:
    """aphe verify without --require-signed on unsigned package → exit 0."""
    import contextlib

    src = tmp_path / "src"
    _build_minimal_source(src)
    tar_path = tmp_path / "pkg.tar"
    _pack_source(src, tar_path)

    # Unpack first, then verify (the existing verify cmd takes an unpacked dir)
    from aphelion.unpacker import unpack
    dest = tmp_path / "unpacked"
    unpack(tar_path, dest)

    from aphelion.cli import main

    out = io.StringIO()
    err = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(["verify", str(dest)])
    assert code == 0


@pytest.mark.integration
def test_cli_aphe_verify_unsigned_with_flag_fails(tmp_path: Path) -> None:
    """aphe verify --require-signed on unsigned package → non-zero, E_SIGNER_REQUIRED in stderr."""
    import contextlib

    src = tmp_path / "src"
    _build_minimal_source(src)
    tar_path = tmp_path / "pkg.tar"
    _pack_source(src, tar_path)

    from aphelion.cli import main

    out = io.StringIO()
    err = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(["verify", str(tar_path), "--require-signed"])
    assert code != 0
    assert "E_SIGNER_REQUIRED" in err.getvalue()


@pytest.mark.unit
def test_validate_signatures_algorithm_mismatch_envelope_hmac_manifest_ed25519(
    tmp_path: Path,
) -> None:
    """E_SIGNER_ALGORITHM_MISMATCH: envelope=hmac-sha256 but manifest claims ed25519."""
    from aphelion.validator import validate_signatures
    from aphelion.packer import pack
    from aphelion.canonical_tar import read_members, TarMember
    from aphelion.canonical_tar import pack as tar_pack

    src = tmp_path / "src"
    _build_minimal_source(src)
    tar_path = tmp_path / "pkg.tar"
    pack(src, tar_path)

    manifest_obj = normalize(json.loads((src / "manifest.json").read_bytes()))
    claims_tuples = [
        (c["claim_id"], c["claim_instance_id"], c["hash"])
        for c in manifest_obj["claims"]
    ]
    pkg_hash = compute_package_canonical_hash(
        format_version=manifest_obj["format_version"],
        package_id=manifest_obj["package_id"],
        claims=claims_tuples,
    )
    # Envelope uses hmac-sha256 (valid HMAC signature)
    s = HMACSigner(signer_id=SIGNER_ID, secret=SHARED_SECRET)
    envelope = s.sign(package_canonical_hash=pkg_hash, signed_at_iso=SIGNED_AT)
    sig_bytes = write_signatures_jsonl([envelope])

    # Signer manifest lies: claims algorithm=ed25519 but fingerprint matches HMAC key
    fp = compute_key_fingerprint(SHARED_SECRET)
    lying_manifest = canonical_dumps(normalize({
        "signer_id": SIGNER_ID,
        "algorithm": "ed25519",  # mismatch: envelope says hmac-sha256
        "public_key_b64": base64.standard_b64encode(SHARED_SECRET).decode(),
        "key_fingerprint": fp,
        "notary_uri": None,
    }))

    existing = read_members(tar_path.read_bytes())
    new_tar = tar_pack(existing + [
        TarMember(path="signatures.jsonl", data=sig_bytes, is_dir=False),
        TarMember(path=f"signers/{SIGNER_ID}.json", data=lying_manifest, is_dir=False),
    ])
    tar_path.write_bytes(new_tar)

    with pytest.raises(SignerVerificationError) as exc_info:
        validate_signatures(tar_path)
    assert exc_info.value.code == "E_SIGNER_ALGORITHM_MISMATCH"


@pytest.mark.unit
def test_validate_signatures_algorithm_mismatch_envelope_ed25519_manifest_hmac(
    tmp_path: Path,
) -> None:
    """E_SIGNER_ALGORITHM_MISMATCH: envelope claims ed25519 but manifest says hmac-sha256."""
    from aphelion.validator import validate_signatures
    from aphelion.packer import pack
    from aphelion.canonical_tar import read_members, TarMember
    from aphelion.canonical_tar import pack as tar_pack

    src = tmp_path / "src"
    _build_minimal_source(src)
    tar_path = tmp_path / "pkg.tar"
    pack(src, tar_path)

    manifest_obj = normalize(json.loads((src / "manifest.json").read_bytes()))
    claims_tuples = [
        (c["claim_id"], c["claim_instance_id"], c["hash"])
        for c in manifest_obj["claims"]
    ]
    pkg_hash = compute_package_canonical_hash(
        format_version=manifest_obj["format_version"],
        package_id=manifest_obj["package_id"],
        claims=claims_tuples,
    )
    # Craft envelope claiming ed25519 (fake signature bytes, will be rejected at mismatch check)
    fake_envelope = SignatureEnvelope(
        signer_id=SIGNER_ID,
        algorithm="ed25519",
        signed_at_iso=SIGNED_AT,
        package_canonical_hash=pkg_hash,
        signature_b64=base64.standard_b64encode(b"\x00" * 64).decode(),
    )
    sig_bytes = write_signatures_jsonl([fake_envelope])

    # Signer manifest correctly says hmac-sha256
    fp = compute_key_fingerprint(SHARED_SECRET)
    hmac_manifest = canonical_dumps(normalize({
        "signer_id": SIGNER_ID,
        "algorithm": "hmac-sha256",  # mismatch: envelope says ed25519
        "public_key_b64": base64.standard_b64encode(SHARED_SECRET).decode(),
        "key_fingerprint": fp,
        "notary_uri": None,
    }))

    existing = read_members(tar_path.read_bytes())
    new_tar = tar_pack(existing + [
        TarMember(path="signatures.jsonl", data=sig_bytes, is_dir=False),
        TarMember(path=f"signers/{SIGNER_ID}.json", data=hmac_manifest, is_dir=False),
    ])
    tar_path.write_bytes(new_tar)

    with pytest.raises(SignerVerificationError) as exc_info:
        validate_signatures(tar_path)
    assert exc_info.value.code == "E_SIGNER_ALGORITHM_MISMATCH"


@pytest.mark.integration
def test_cli_sign_twice_same_signer_preserves_both_envelopes(tmp_path: Path) -> None:
    """Re-signing with the same signer_id appends rather than replacing prior envelope."""
    import contextlib

    src = tmp_path / "src"
    _build_minimal_source(src)
    tar_path = tmp_path / "pkg.tar"
    _pack_source(src, tar_path)

    key_file = tmp_path / "key.bin"
    key_file.write_bytes(SHARED_SECRET)

    signed_v1 = tmp_path / "signed_v1.tar"
    signed_v2 = tmp_path / "signed_v2.tar"

    from aphelion.cli import main

    # First sign
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        code = main([
            "sign",
            "--package", str(tar_path),
            "--signer-id", SIGNER_ID,
            "--algorithm", "hmac-sha256",
            "--key-file", str(key_file),
            "--out", str(signed_v1),
        ])
    assert code == 0

    # Second sign using the already-signed tar as input (same signer_id)
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        code2 = main([
            "sign",
            "--package", str(signed_v1),
            "--signer-id", SIGNER_ID,
            "--algorithm", "hmac-sha256",
            "--key-file", str(key_file),
            "--out", str(signed_v2),
        ])
    assert code2 == 0

    # Both envelopes must be present in the output
    from aphelion.canonical_tar import read_members
    from aphelion.sig_pack import read_signatures_jsonl

    members = read_members(signed_v2.read_bytes())
    sig_data = next(m.data for m in members if m.path == "signatures.jsonl")
    assert sig_data is not None
    envelopes = read_signatures_jsonl(sig_data)
    assert len(envelopes) == 2, f"expected 2 envelopes, got {len(envelopes)}"
    assert all(e.signer_id == SIGNER_ID for e in envelopes)


@pytest.mark.integration
def test_verify_package_accepts_two_envelopes_same_signer(tmp_path: Path) -> None:
    """verify_package succeeds when a package has two envelopes from the same signer."""
    from aphelion.verifier import verify_package
    from aphelion.canonical_tar import read_members, TarMember
    from aphelion.canonical_tar import pack as tar_pack

    src = tmp_path / "src"
    _build_minimal_source(src)
    tar_path = tmp_path / "pkg.tar"
    _pack_source(src, tar_path)

    manifest_obj = normalize(json.loads((src / "manifest.json").read_bytes()))
    claims_tuples = [
        (c["claim_id"], c["claim_instance_id"], c["hash"])
        for c in manifest_obj["claims"]
    ]
    pkg_hash = compute_package_canonical_hash(
        format_version=manifest_obj["format_version"],
        package_id=manifest_obj["package_id"],
        claims=claims_tuples,
    )

    s = HMACSigner(signer_id=SIGNER_ID, secret=SHARED_SECRET)
    env1 = s.sign(package_canonical_hash=pkg_hash, signed_at_iso="2026-04-01T00:00:00.000Z")
    env2 = s.sign(package_canonical_hash=pkg_hash, signed_at_iso="2026-04-27T00:00:00.000Z")
    sig_bytes = write_signatures_jsonl([env1, env2])

    m = s.manifest()
    manifest_json = canonical_dumps(normalize({
        "signer_id": m.signer_id,
        "algorithm": m.algorithm,
        "public_key_b64": m.public_key_b64,
        "key_fingerprint": m.key_fingerprint,
        "notary_uri": None,
    }))

    existing = read_members(tar_path.read_bytes())
    new_tar = tar_pack(existing + [
        TarMember(path="signatures.jsonl", data=sig_bytes, is_dir=False),
        TarMember(path=f"signers/{SIGNER_ID}.json", data=manifest_json, is_dir=False),
    ])
    tar_path.write_bytes(new_tar)

    result = verify_package(tar_path, require_signed=True)
    assert len(result.envelopes) == 2
    assert all(e.signer_id == SIGNER_ID for e in result.envelopes)


@pytest.mark.integration
def test_cli_aphe_sign_then_verify(tmp_path: Path) -> None:
    """aphe sign then aphe verify --require-signed → success end-to-end."""
    import contextlib

    src = tmp_path / "src"
    _build_minimal_source(src)
    tar_path = tmp_path / "pkg.tar"
    _pack_source(src, tar_path)

    # Write HMAC key to file
    key_file = tmp_path / "key.bin"
    key_file.write_bytes(SHARED_SECRET)

    signed_path = tmp_path / "signed.tar"

    from aphelion.cli import main

    out = io.StringIO()
    err = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main([
            "sign",
            "--package", str(tar_path),
            "--signer-id", SIGNER_ID,
            "--algorithm", "hmac-sha256",
            "--key-file", str(key_file),
            "--out", str(signed_path),
        ])
    assert code == 0, f"aphe sign failed: {err.getvalue()}"

    out2 = io.StringIO()
    err2 = io.StringIO()
    with contextlib.redirect_stdout(out2), contextlib.redirect_stderr(err2):
        code2 = main(["verify", str(signed_path), "--require-signed"])
    assert code2 == 0, f"aphe verify --require-signed failed: {err2.getvalue()}"
