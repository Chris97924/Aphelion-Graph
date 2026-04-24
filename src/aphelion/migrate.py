"""``aphe migrate`` — one-shot v0.3 -> v0.4 wire migration.

v0.4 is a breaking wire bump (``format_version`` 1.x -> 2.0, manifest field
``dpkg_spec_version`` -> ``aphelion_spec_version``). This module provides the
pure data transform plus directory / archive wrappers so a legacy v0.3
Aphelion can be read once and reshaped into a v0.4 artifact that passes the
current strict validator.

The migration is intentionally NOT a generic framework. It is a single
forward step whose preconditions and postconditions are fixed by spec
``spec/migration-v0.3-to-v0.4.md``. Reverse migration is out of scope.
"""

from __future__ import annotations

import copy
import io
import os
import shutil
import tarfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from aphelion.canonical_json import dumps as canonical_dumps
from aphelion.canonical_json import loads as canonical_loads
from aphelion.canonical_json import normalize
from aphelion.error_codes import ErrorCode
from aphelion.errors import SchemaError

TARGET_FORMAT_VERSION = "2.0"
TARGET_SPEC_VERSION = "0.4.0"
LEGACY_FORMAT_VERSIONS: frozenset[str] = frozenset({"1.0", "1.1"})

# Archive migration runs against potentially-untrusted v0.3 input. Mirror
# the ExtractPolicy defaults in aphelion.unpacker so a hostile archive
# cannot OOM the migrator.
MAX_ARCHIVE_MEMBERS = 10_000
MAX_ARCHIVE_MEMBER_BYTES = 25 * 1024 * 1024
MAX_ARCHIVE_TOTAL_BYTES = 100 * 1024 * 1024


@dataclass(frozen=True)
class MigrateOptions:
    src: Path
    dst: Path
    force: bool = False


def migrate_v03_to_v04(manifest: dict[str, Any]) -> dict[str, Any]:
    """Return a new v0.4 manifest from a v0.3 ``manifest`` dict.

    The input must declare ``format_version`` 1.0 or 1.1. A v0.3
    ``dpkg_spec_version`` field (top-level or nested under ``extensions``)
    becomes top-level ``aphelion_spec_version`` = ``"0.4.0"``. All other
    fields pass through unchanged.

    Does not mutate the input.
    """
    if not isinstance(manifest, dict):
        raise SchemaError(
            code=ErrorCode.TYPE_MISMATCH,
            msg=f"manifest must be dict, got {type(manifest).__name__}",
        )
    fv = manifest.get("format_version")
    if fv not in LEGACY_FORMAT_VERSIONS:
        raise SchemaError(
            code=ErrorCode.UNSUPPORTED_SCHEMA_VERSION,
            msg=(
                f"migrate expects legacy v0.3 manifest (format_version in "
                f"{sorted(LEGACY_FORMAT_VERSIONS)}); got {fv!r}"
            ),
        )
    out: dict[str, Any] = {k: v for k, v in manifest.items() if k != "dpkg_spec_version"}
    if "extensions" in out and isinstance(out["extensions"], dict):
        # Strip the legacy nested spec version key; any remaining
        # extension keys are application-defined and pass through.
        extensions = {
            k: v for k, v in out["extensions"].items() if k != "dpkg_spec_version"
        }
        if extensions:
            out["extensions"] = extensions
        else:
            del out["extensions"]
    out["format_version"] = TARGET_FORMAT_VERSION
    out["aphelion_spec_version"] = TARGET_SPEC_VERSION
    return out


def migrate_directory(src: Path, dst: Path, *, force: bool = False) -> Path:
    """Migrate an unpacked v0.3 Aphelion directory to a v0.4 directory.

    Copies every claim / provenance / evidence byte verbatim; only
    ``manifest.json`` is rewritten through :func:`migrate_v03_to_v04` +
    canonical JSON. Refuses to overwrite a non-empty ``dst`` unless
    ``force`` is True.
    """
    src_path = Path(src)
    dst_path = Path(dst)
    manifest_in = src_path / "manifest.json"
    if not manifest_in.is_file():
        raise SchemaError(
            code=ErrorCode.MISSING_FILE,
            msg=f"source {src_path} does not contain manifest.json",
            path=str(manifest_in),
        )
    if dst_path.exists():
        if not force:
            raise SchemaError(
                code=ErrorCode.INIT_REFUSES_EXISTING,
                msg=f"destination {dst_path} already exists; pass force=True to overwrite",
                path=str(dst_path),
            )
        if dst_path.is_dir():
            shutil.rmtree(dst_path)
        else:
            dst_path.unlink()
    shutil.copytree(src_path, dst_path)
    new_manifest = migrate_v03_to_v04(canonical_loads(manifest_in.read_bytes()))
    (dst_path / "manifest.json").write_bytes(canonical_dumps(normalize(new_manifest)))
    return dst_path


def migrate_archive(src: Path, dst: Path, *, force: bool = False) -> Path:
    """Migrate a ``.aphelion.tar`` archive from v0.3 to v0.4 in-memory.

    Reads the legacy tar, rewrites ``manifest.json`` bytes through the
    migration transform, and writes a new tar where every other member
    is passed through byte-for-byte. Refuses to overwrite existing
    ``dst`` unless ``force`` is True.
    """
    src_path = Path(src)
    dst_path = Path(dst)
    if not src_path.is_file():
        raise SchemaError(
            code=ErrorCode.MISSING_FILE,
            msg=f"source archive {src_path} not found",
            path=str(src_path),
        )
    if dst_path.exists() and not force:
        raise SchemaError(
            code=ErrorCode.INIT_REFUSES_EXISTING,
            msg=f"destination {dst_path} already exists; pass force=True to overwrite",
            path=str(dst_path),
        )
    members: list[tuple[tarfile.TarInfo, bytes]] = []
    total_bytes = 0
    with tarfile.open(src_path, "r:") as tar_in:
        raw_members = tar_in.getmembers()
        if len(raw_members) > MAX_ARCHIVE_MEMBERS:
            raise SchemaError(
                code=ErrorCode.FILE_COUNT_EXCEEDED,
                msg=(
                    f"archive contains {len(raw_members)} members, exceeding "
                    f"migration cap of {MAX_ARCHIVE_MEMBERS}"
                ),
                path=str(src_path),
            )
        for source_info in raw_members:
            # Directories pass through as header-only entries; anything that
            # isn't a regular file or directory (symlink / hardlink / device /
            # fifo) is rejected the same way unpacker treats them.
            if source_info.isdir():
                info = copy.copy(source_info)
                members.append((info, b""))
                continue
            if not source_info.isreg():
                raise SchemaError(
                    code=ErrorCode.DISALLOWED_MEMBER_TYPE,
                    msg=(
                        f"migrate rejects non-regular tar member "
                        f"{source_info.name!r}"
                    ),
                    path=source_info.name,
                )
            if source_info.size > MAX_ARCHIVE_MEMBER_BYTES:
                raise SchemaError(
                    code=ErrorCode.FILE_BYTES_EXCEEDED,
                    msg=(
                        f"member {source_info.name!r} is {source_info.size} "
                        f"bytes, exceeding per-member cap of "
                        f"{MAX_ARCHIVE_MEMBER_BYTES}"
                    ),
                    path=source_info.name,
                )
            total_bytes += source_info.size
            if total_bytes > MAX_ARCHIVE_TOTAL_BYTES:
                raise SchemaError(
                    code=ErrorCode.TOTAL_BYTES_EXCEEDED,
                    msg=(
                        f"cumulative archive size exceeds cap of "
                        f"{MAX_ARCHIVE_TOTAL_BYTES} bytes"
                    ),
                    path=str(src_path),
                )
            info = copy.copy(source_info)
            extracted = tar_in.extractfile(source_info)
            data = b"" if extracted is None else extracted.read()
            if info.name == "manifest.json":
                new_manifest = migrate_v03_to_v04(canonical_loads(data))
                data = canonical_dumps(normalize(new_manifest))
                info.size = len(data)
            members.append((info, data))
    dst_path.parent.mkdir(parents=True, exist_ok=True)
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tar_out:
        for info, data in members:
            if info.isdir():
                tar_out.addfile(info)
            else:
                tar_out.addfile(info, io.BytesIO(data))
    # Atomic write: draft to a sibling tempfile, then rename into place so an
    # interrupted migration never leaves a half-written dst that the refuses-
    # existing branch would then lock in.
    tmp_path = dst_path.with_name(dst_path.name + ".tmp")
    tmp_path.write_bytes(buf.getvalue())
    os.replace(tmp_path, dst_path)
    return dst_path


def migrate(opts: MigrateOptions) -> Path:
    """Dispatch to :func:`migrate_directory` or :func:`migrate_archive`.

    Directory in -> directory out; ``.aphelion.tar`` in -> ``.aphelion.tar`` out.
    Mixed dir-in archive-out (and vice versa) is rejected to keep the contract
    deterministic.
    """
    src = Path(opts.src)
    dst = Path(opts.dst)
    src_is_archive = src.is_file() and src.suffix == ".tar"
    dst_is_archive = dst.suffix == ".tar"
    if src_is_archive and dst_is_archive:
        return migrate_archive(src, dst, force=opts.force)
    if src.is_dir() and not dst_is_archive:
        return migrate_directory(src, dst, force=opts.force)
    raise SchemaError(
        code=ErrorCode.TYPE_MISMATCH,
        msg=(
            "migrate requires directory-in/directory-out or "
            ".aphelion.tar-in/.aphelion.tar-out; mixed modes are not supported"
        ),
    )
