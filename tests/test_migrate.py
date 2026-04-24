"""Tests for ``aphelion.migrate`` (v0.3 -> v0.4 one-shot)."""

from __future__ import annotations

import hashlib
import io
import json
import tarfile
from pathlib import Path

import pytest

from aphelion.canonical_json import dumps, loads, normalize
from aphelion.error_codes import ErrorCode
from aphelion.errors import SchemaError
from aphelion.migrate import (
    LEGACY_FORMAT_VERSIONS,
    MigrateOptions,
    TARGET_FORMAT_VERSION,
    TARGET_SPEC_VERSION,
    migrate,
    migrate_archive,
    migrate_directory,
    migrate_v03_to_v04,
)
from aphelion.validator import validate_manifest


UUID_PKG = "0191aaaa-0000-7000-8000-000000000001"
UUID_CLAIM_A = "0191aaaa-0000-7000-8000-00000000aaaa"
UUID_INSTANCE_A = "0191aaaa-0000-7000-8000-aaaaaaaaaaaa"


def _v03_manifest(*, legacy_format: str = "1.1",
                  extensions: dict | None = None,
                  with_top_level_dpkg_spec: bool = False) -> dict:
    """A representative v0.3 manifest with optional ``extensions.dpkg_spec_version``."""
    manifest: dict = {
        "claims": [
            {
                "claim_id": UUID_CLAIM_A,
                "claim_instance_id": UUID_INSTANCE_A,
                "hash": "a" * 64,
                "path": f"claims/{UUID_CLAIM_A}.md",
                "state": "active",
            }
        ],
        "created_at": "2026-04-21T00:00:00Z",
        "format_version": legacy_format,
        "license": "Apache-2.0",
        "package_id": UUID_PKG,
        "producer": "aphelion-test",
        "provenance_path": "provenance.jsonl",
    }
    if extensions is not None:
        manifest["extensions"] = extensions
    if with_top_level_dpkg_spec:
        manifest["dpkg_spec_version"] = "0.3.0"
    return manifest


# ---------- pure transform ----------


@pytest.mark.parametrize("legacy", sorted(LEGACY_FORMAT_VERSIONS))
def test_migrate_transform_bumps_format_version(legacy: str) -> None:
    m = _v03_manifest(legacy_format=legacy)
    out = migrate_v03_to_v04(m)
    assert out["format_version"] == TARGET_FORMAT_VERSION
    assert out["aphelion_spec_version"] == TARGET_SPEC_VERSION


def test_migrate_transform_strips_extensions_dpkg_spec_version() -> None:
    m = _v03_manifest(extensions={"dpkg_spec_version": "0.2.1"})
    out = migrate_v03_to_v04(m)
    # All that was inside extensions was the legacy spec_version key, so
    # extensions itself is dropped rather than left as an empty object.
    assert "extensions" not in out
    assert "aphelion_spec_version" in out


def test_migrate_transform_preserves_unrelated_extensions() -> None:
    m = _v03_manifest(
        extensions={"dpkg_spec_version": "0.3.0", "vendor-x": "keep-me"}
    )
    out = migrate_v03_to_v04(m)
    assert out["extensions"] == {"vendor-x": "keep-me"}


def test_migrate_transform_strips_top_level_dpkg_spec_version() -> None:
    m = _v03_manifest(with_top_level_dpkg_spec=True)
    out = migrate_v03_to_v04(m)
    assert "dpkg_spec_version" not in out
    assert out["aphelion_spec_version"] == TARGET_SPEC_VERSION


def test_migrate_transform_does_not_mutate_input() -> None:
    m = _v03_manifest(extensions={"dpkg_spec_version": "0.3.0"})
    before = json.dumps(m, sort_keys=True)
    migrate_v03_to_v04(m)
    assert json.dumps(m, sort_keys=True) == before


def test_migrate_output_passes_v04_validator() -> None:
    m = _v03_manifest()
    out = migrate_v03_to_v04(m)
    validate_manifest(out)  # must not raise


def test_migrate_transform_rejects_non_legacy_format_version() -> None:
    m = _v03_manifest()
    m["format_version"] = "2.0"  # already v0.4 — migration is a one-way contract
    with pytest.raises(SchemaError) as exc:
        migrate_v03_to_v04(m)
    assert exc.value.code == ErrorCode.UNSUPPORTED_SCHEMA_VERSION


def test_migrate_transform_rejects_non_dict_input() -> None:
    with pytest.raises(SchemaError) as exc:
        migrate_v03_to_v04("not a dict")  # type: ignore[arg-type]
    assert exc.value.code == ErrorCode.TYPE_MISMATCH


# ---------- directory-in / directory-out ----------


def _write_v03_directory(dest: Path) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "claims").mkdir(exist_ok=True)
    claim_bytes = (
        "---\n"
        '"body_format": "markdown"\n'
        f'"claim_id": "{UUID_CLAIM_A}"\n'
        '"title": "hi"\n'
        "---\n"
    ).encode("utf-8")
    (dest / f"claims/{UUID_CLAIM_A}.md").write_bytes(claim_bytes)
    manifest = _v03_manifest()
    manifest["claims"][0]["hash"] = hashlib.sha256(claim_bytes).hexdigest()
    (dest / "manifest.json").write_bytes(dumps(normalize(manifest)))
    event = {
        "actor": "t",
        "claim_id": UUID_CLAIM_A,
        "claim_instance_id": UUID_INSTANCE_A,
        "event_id": "0191aaaa-0000-7000-8000-eeee00000001",
        "event_type": "create",
        "timestamp": "2026-04-21T00:00:00Z",
    }
    (dest / "provenance.jsonl").write_bytes(dumps(normalize(event)))


def test_migrate_directory_rewrites_only_manifest(tmp_path: Path) -> None:
    src = tmp_path / "v03"
    dst = tmp_path / "v04"
    _write_v03_directory(src)
    claim_bytes = (src / f"claims/{UUID_CLAIM_A}.md").read_bytes()
    prov_bytes = (src / "provenance.jsonl").read_bytes()

    migrate_directory(src, dst)

    assert (dst / f"claims/{UUID_CLAIM_A}.md").read_bytes() == claim_bytes
    assert (dst / "provenance.jsonl").read_bytes() == prov_bytes
    new_manifest = loads((dst / "manifest.json").read_bytes())
    assert new_manifest["format_version"] == "2.0"
    assert new_manifest["aphelion_spec_version"] == "0.4.0"


def test_migrate_directory_refuses_existing_dst_without_force(tmp_path: Path) -> None:
    src = tmp_path / "v03"
    dst = tmp_path / "v04"
    _write_v03_directory(src)
    dst.mkdir()
    with pytest.raises(SchemaError) as exc:
        migrate_directory(src, dst)
    assert exc.value.code == ErrorCode.INIT_REFUSES_EXISTING


def test_migrate_directory_overwrites_with_force(tmp_path: Path) -> None:
    src = tmp_path / "v03"
    dst = tmp_path / "v04"
    _write_v03_directory(src)
    dst.mkdir()
    (dst / "stale.txt").write_bytes(b"should vanish")
    migrate_directory(src, dst, force=True)
    assert not (dst / "stale.txt").exists()


def test_migrate_directory_missing_manifest_raises(tmp_path: Path) -> None:
    src = tmp_path / "empty"
    src.mkdir()
    with pytest.raises(SchemaError) as exc:
        migrate_directory(src, tmp_path / "v04")
    assert exc.value.code == ErrorCode.MISSING_FILE


# ---------- archive-in / archive-out ----------


def _write_v03_archive(src_dir: Path, archive: Path) -> None:
    _write_v03_directory(src_dir)
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        for p in sorted(src_dir.rglob("*")):
            if p.is_dir():
                continue
            info = tarfile.TarInfo(name=str(p.relative_to(src_dir)).replace("\\", "/"))
            data = p.read_bytes()
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    archive.write_bytes(buf.getvalue())


def test_migrate_archive_rewrites_manifest_and_preserves_rest(tmp_path: Path) -> None:
    src_dir = tmp_path / "pkg_v03"
    archive_in = tmp_path / "in.aphelion.tar"
    archive_out = tmp_path / "out.aphelion.tar"
    _write_v03_archive(src_dir, archive_in)

    migrate_archive(archive_in, archive_out)

    assert archive_out.is_file()
    with tarfile.open(archive_out, "r:") as tar:
        member_names = {m.name for m in tar.getmembers()}
        assert "manifest.json" in member_names
        manifest_bytes = tar.extractfile("manifest.json").read()
    new_manifest = loads(manifest_bytes)
    assert new_manifest["format_version"] == "2.0"
    assert new_manifest["aphelion_spec_version"] == "0.4.0"


def test_migrate_archive_refuses_existing_without_force(tmp_path: Path) -> None:
    src_dir = tmp_path / "pkg_v03"
    archive_in = tmp_path / "in.aphelion.tar"
    _write_v03_archive(src_dir, archive_in)
    archive_out = tmp_path / "out.aphelion.tar"
    archive_out.write_bytes(b"stale")
    with pytest.raises(SchemaError) as exc:
        migrate_archive(archive_in, archive_out)
    assert exc.value.code == ErrorCode.INIT_REFUSES_EXISTING


def test_migrate_archive_overwrites_with_force(tmp_path: Path) -> None:
    src_dir = tmp_path / "pkg_v03"
    archive_in = tmp_path / "in.aphelion.tar"
    _write_v03_archive(src_dir, archive_in)
    archive_out = tmp_path / "out.aphelion.tar"
    archive_out.write_bytes(b"stale-bytes-should-be-overwritten")
    migrate_archive(archive_in, archive_out, force=True)
    # Post-condition: the bytes on disk are a real tar, not the placeholder.
    with tarfile.open(archive_out, "r:") as tar:
        assert {m.name for m in tar.getmembers()} >= {"manifest.json"}


def test_migrate_archive_preserves_directory_entries(tmp_path: Path) -> None:
    """Directories passed through as header-only members (no bytes)."""
    src_dir = tmp_path / "pkg_v03"
    _write_v03_directory(src_dir)
    archive_in = tmp_path / "in.aphelion.tar"
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        dir_info = tarfile.TarInfo(name="claims/")
        dir_info.type = tarfile.DIRTYPE
        dir_info.mode = 0o755
        tar.addfile(dir_info)
        for p in sorted(src_dir.rglob("*")):
            if p.is_dir():
                continue
            info = tarfile.TarInfo(name=str(p.relative_to(src_dir)).replace("\\", "/"))
            data = p.read_bytes()
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    archive_in.write_bytes(buf.getvalue())
    archive_out = tmp_path / "out.aphelion.tar"
    migrate_archive(archive_in, archive_out)
    with tarfile.open(archive_out, "r:") as tar:
        types = {m.name.rstrip("/"): m.type for m in tar.getmembers()}
    assert types.get("claims") == tarfile.DIRTYPE


def test_migrate_archive_rejects_symlink_member(tmp_path: Path) -> None:
    archive_in = tmp_path / "evil.tar"
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        info = tarfile.TarInfo(name="link")
        info.type = tarfile.SYMTYPE
        info.linkname = "/etc/passwd"
        tar.addfile(info)
    archive_in.write_bytes(buf.getvalue())
    with pytest.raises(SchemaError) as exc:
        migrate_archive(archive_in, tmp_path / "out.aphelion.tar")
    assert exc.value.code == ErrorCode.DISALLOWED_MEMBER_TYPE


def test_migrate_archive_enforces_member_byte_cap(tmp_path: Path) -> None:
    """A single oversize member is rejected up front, before read()."""
    from aphelion.migrate import MAX_ARCHIVE_MEMBER_BYTES

    archive_in = tmp_path / "big.tar"
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        info = tarfile.TarInfo(name="bloat.bin")
        info.type = tarfile.REGTYPE
        info.mode = 0o644
        data = b"A" * (MAX_ARCHIVE_MEMBER_BYTES + 1)
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    archive_in.write_bytes(buf.getvalue())
    with pytest.raises(SchemaError) as exc:
        migrate_archive(archive_in, tmp_path / "out.aphelion.tar")
    assert exc.value.code == ErrorCode.FILE_BYTES_EXCEEDED


def test_migrate_archive_enforces_file_count_cap(tmp_path: Path) -> None:
    from aphelion.migrate import MAX_ARCHIVE_MEMBERS

    archive_in = tmp_path / "many.tar"
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        for i in range(MAX_ARCHIVE_MEMBERS + 1):
            info = tarfile.TarInfo(name=f"f/{i:06d}.txt")
            info.type = tarfile.REGTYPE
            info.mode = 0o644
            tar.addfile(info, io.BytesIO(b""))
    archive_in.write_bytes(buf.getvalue())
    with pytest.raises(SchemaError) as exc:
        migrate_archive(archive_in, tmp_path / "out.aphelion.tar")
    assert exc.value.code == ErrorCode.FILE_COUNT_EXCEEDED


def test_migrate_archive_atomic_write_no_leftover_tmp(tmp_path: Path) -> None:
    src_dir = tmp_path / "pkg_v03"
    archive_in = tmp_path / "in.aphelion.tar"
    archive_out = tmp_path / "out.aphelion.tar"
    _write_v03_archive(src_dir, archive_in)
    migrate_archive(archive_in, archive_out)
    assert archive_out.is_file()
    # The .tmp sibling must have been renamed, not left behind.
    assert not (tmp_path / "out.aphelion.tar.tmp").exists()


# ---------- dispatch ----------


def test_migrate_rejects_mixed_shapes(tmp_path: Path) -> None:
    src_dir = tmp_path / "pkg"
    _write_v03_directory(src_dir)
    with pytest.raises(SchemaError) as exc:
        migrate(MigrateOptions(src=src_dir, dst=tmp_path / "out.aphelion.tar"))
    assert exc.value.code == ErrorCode.TYPE_MISMATCH


# ---------- CLI integration ----------


def test_cli_migrate_directory_end_to_end(tmp_path: Path) -> None:
    from conftest import run_cli

    src = tmp_path / "v03"
    dst = tmp_path / "v04"
    _write_v03_directory(src)

    code, out, err = run_cli(["migrate", str(src), str(dst)])

    assert code == 0, err
    assert "v0.3 -> v0.4" in out
    new_manifest = loads((dst / "manifest.json").read_bytes())
    assert new_manifest["aphelion_spec_version"] == "0.4.0"
