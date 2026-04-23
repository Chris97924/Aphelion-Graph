"""``aphelion init`` — create an empty Aphelion skeleton in a directory.

A skeleton contains a valid ``manifest.json`` (zero claims) and an empty
``provenance.jsonl``; running ``aphelion validate`` against the result must
succeed. The command refuses by default if the destination already holds a
manifest — to overwrite, callers must pass **both** ``force=True`` and
``confirmed=True``, an explicit two-key gesture chosen to prevent accidental
destruction of existing data (e.g. the a2a 7000+ row corpus).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from aphelion import __version__ as DPKG_VERSION, SCHEMA_VERSION_MAX
from aphelion.canonical_json import dumps as canonical_dumps, normalize
from aphelion.error_codes import ErrorCode
from aphelion.errors import SchemaError
from aphelion.validator import TIMESTAMP_RE, UUID_V7_RE


SUPPORTED_SPEC_VERSIONS: frozenset[str] = frozenset(
    {"0.2.0", "0.2.1", "0.2.2", "0.3.0"}
)
DEFAULT_SPEC_VERSION = DPKG_VERSION


@dataclass(frozen=True)
class InitOptions:
    dest: Path
    spec_version: str = DEFAULT_SPEC_VERSION
    producer: str = "aphelion-init"
    license: str = "Apache-2.0"
    force: bool = False
    confirmed: bool = False  # must pair with force=True; cannot be silently assumed
    # Deterministic overrides (used by tests/fixtures for byte-equality).
    package_id: str | None = None
    created_at: str | None = None


def _new_uuid_v7() -> str:
    """Generate a UUID v7 (time-ordered, 128-bit) as lowercase hex string."""
    # Python 3.13's uuid.uuid7() is available; fall back to uuid4-but-v7-bit
    # stamp for older interpreters (still v7-pattern for our regex).
    if hasattr(uuid, "uuid7"):
        return str(uuid.uuid7())  # type: ignore[attr-defined]
    import secrets
    import time

    unix_ms = int(time.time() * 1000) & ((1 << 48) - 1)
    rand_a = secrets.randbits(12)
    rand_b = secrets.randbits(62)
    hi = (unix_ms << 16) | (0x7 << 12) | rand_a
    lo = (0b10 << 62) | rand_b
    raw = hi.to_bytes(8, "big") + lo.to_bytes(8, "big")
    return str(uuid.UUID(bytes=raw))


def _iso_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def init_skeleton(opts: InitOptions) -> dict[str, Any]:
    """Materialize a Aphelion skeleton under ``opts.dest``.

    Returns the written manifest dict on success. Raises :class:`SchemaError`
    on refusal (existing data, unsupported spec version, missing confirmation).
    """
    if opts.spec_version not in SUPPORTED_SPEC_VERSIONS:
        raise SchemaError(
            code=ErrorCode.UNSUPPORTED_SPEC_VERSION,
            msg=(
                f"spec_version {opts.spec_version!r} is not supported; "
                f"accepted: {sorted(SUPPORTED_SPEC_VERSIONS)!r}"
            ),
        )

    # Pre-validate caller-supplied overrides before touching the filesystem so
    # we fail fast with a clear error rather than writing a manifest that the
    # downstream validator would reject.
    if opts.package_id is not None and not UUID_V7_RE.fullmatch(opts.package_id):
        raise SchemaError(
            code=ErrorCode.PATTERN_MISMATCH,
            msg=f"package_id override {opts.package_id!r} is not a valid UUID v7",
            path="package_id",
        )
    if opts.created_at is not None and not TIMESTAMP_RE.fullmatch(opts.created_at):
        raise SchemaError(
            code=ErrorCode.PATTERN_MISMATCH,
            msg=(
                f"created_at override {opts.created_at!r} does not match "
                f"RFC3339 UTC pattern (YYYY-MM-DDTHH:MM:SS[.sss]Z)"
            ),
            path="created_at",
        )

    dest = Path(opts.dest)
    if dest.exists() and not dest.is_dir():
        raise SchemaError(
            code=ErrorCode.INIT_REFUSES_EXISTING,
            msg=(
                f"{dest} exists and is not a directory; refusing to init. "
                f"Remove it or choose a different destination."
            ),
            path=str(dest),
        )
    manifest_path = dest / "manifest.json"
    provenance_path = dest / "provenance.jsonl"
    claims_dir = dest / "claims"

    preexisting = manifest_path.exists() or provenance_path.exists()
    if preexisting and not opts.force:
        raise SchemaError(
            code=ErrorCode.INIT_REFUSES_EXISTING,
            msg=(
                f"{manifest_path} already exists; refusing to overwrite. "
                f"Pass force=True AND confirmed=True to proceed."
            ),
            path=str(dest),
        )
    if preexisting and opts.force and not opts.confirmed:
        raise SchemaError(
            code=ErrorCode.INIT_MISSING_CONFIRMATION,
            msg=(
                "force=True requires an explicit confirmation flag "
                "(--i-know-what-im-doing) to destroy existing Aphelion state."
            ),
            path=str(dest),
        )

    dest.mkdir(parents=True, exist_ok=True)
    claims_dir.mkdir(parents=True, exist_ok=True)

    manifest: dict[str, Any] = {
        "claims": [],
        "created_at": opts.created_at or _iso_now(),
        "format_version": SCHEMA_VERSION_MAX,
        "license": opts.license,
        "package_id": opts.package_id or _new_uuid_v7(),
        "producer": opts.producer,
        "provenance_path": "provenance.jsonl",
        "extensions": {
            "dpkg_spec_version": opts.spec_version,
        },
    }
    manifest_bytes = canonical_dumps(normalize(manifest))
    manifest_path.write_bytes(manifest_bytes)
    # Ensure an empty but present provenance file so the pair is consistent.
    provenance_path.write_bytes(b"")
    return manifest
