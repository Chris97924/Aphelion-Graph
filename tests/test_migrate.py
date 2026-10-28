"""Tests for ``aphelion.migrate`` (v0.3 -> v0.4 one-shot)."""

from __future__ import annotations

import functools
import hashlib
import io
import json
import shutil
import tarfile
from pathlib import Path
from typing import Callable

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
from test_unpacker import (
    MOVES,
    STOPS,
    WARNING_FILTERS,
    WINDOWS_ONLY,
    _error,
    _named,
    _no_final_path,
    _not_found,
    _run_steps,
    run_python,
)


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


# ---------- --force checks the destination before removing anything ----------


def _snapshot(root: Path) -> dict[str, bytes | None]:
    return {
        p.relative_to(root).as_posix(): (None if p.is_dir() else p.read_bytes())
        for p in sorted(root.rglob("*"))
    }


def _symlink_or_skip(link: Path, target: Path) -> None:
    import os

    try:
        os.symlink(target, link, target_is_directory=target.is_dir())
    except (OSError, NotImplementedError) as exc:  # Windows without the privilege
        pytest.skip(f"cannot create symlinks here: {exc}")


def _assert_refused(src: Path, dst: Path) -> None:
    with pytest.raises(SchemaError) as exc:
        migrate(MigrateOptions(src=src, dst=dst, force=True))
    assert exc.value.code == ErrorCode.INIT_REFUSES_EXISTING


def test_force_refuses_destination_that_is_the_source(tmp_path: Path) -> None:
    """All platforms: --force refuses a destination that is the source and
    changes nothing."""
    src = tmp_path / "v03"
    _write_v03_directory(src)
    before = _snapshot(src)
    _assert_refused(src, src)
    assert _snapshot(src) == before


def test_force_refuses_destination_spelled_differently_but_same_dir(tmp_path: Path) -> None:
    """All platforms: the same for the source under another spelling
    (``v03/claims/..``)."""
    src = tmp_path / "v03"
    _write_v03_directory(src)
    before = _snapshot(src)
    _assert_refused(src, tmp_path / "v03" / "claims" / "..")
    assert _snapshot(src) == before


def test_force_refuses_destination_that_contains_the_source(tmp_path: Path) -> None:
    """All platforms: --force refuses a destination that contains the source."""
    parent = tmp_path / "work"
    src = parent / "v03"
    _write_v03_directory(src)
    (parent / "unrelated.txt").write_bytes(b"keep me")
    before = _snapshot(parent)
    _assert_refused(src, parent)
    assert _snapshot(parent) == before


def test_force_refuses_destination_inside_the_source(tmp_path: Path) -> None:
    """All platforms: --force refuses a destination inside the source."""
    src = tmp_path / "v03"
    _write_v03_directory(src)
    (src / "out").mkdir()
    before = _snapshot(src)
    _assert_refused(src, src / "out")
    assert _snapshot(src) == before


def test_force_refuses_symlink_resolving_to_the_source(tmp_path: Path) -> None:
    """All platforms that can create symlinks: --force refuses a destination
    that is a symlink to the source."""
    src = tmp_path / "v03"
    _write_v03_directory(src)
    link = tmp_path / "link"
    _symlink_or_skip(link, src)
    before = _snapshot(src)
    _assert_refused(src, link)
    assert _snapshot(src) == before


def test_force_refuses_symlink_resolving_to_a_parent_of_the_source(tmp_path: Path) -> None:
    """All platforms that can create symlinks: the same for a symlink to a
    directory that contains the source."""
    parent = tmp_path / "work"
    src = parent / "v03"
    _write_v03_directory(src)
    link = tmp_path / "link"
    _symlink_or_skip(link, parent)
    before = _snapshot(parent)
    _assert_refused(src, link)
    assert _snapshot(parent) == before


def test_force_refuses_source_reached_through_a_symlink(tmp_path: Path) -> None:
    """All platforms that can create symlinks: the same when the source is
    given through a symlink."""
    real = tmp_path / "real"
    _write_v03_directory(real)
    src_link = tmp_path / "src-link"
    _symlink_or_skip(src_link, real)
    before = _snapshot(real)
    _assert_refused(src_link, real)
    assert _snapshot(real) == before


def test_force_refuses_destination_differing_only_by_case(tmp_path: Path) -> None:
    """Windows and macOS (case-insensitive filesystems; skipped elsewhere):
    on NTFS / APFS ``V03`` is the same directory as ``v03``."""
    src = tmp_path / "v03"
    _write_v03_directory(src)
    if not (tmp_path / "V03").exists():
        pytest.skip("filesystem is case-sensitive; nothing to collide")
    before = _snapshot(src)
    _assert_refused(src, tmp_path / "V03")
    assert _snapshot(src) == before


def test_force_replaces_a_symlinked_destination_without_following_it(
    tmp_path: Path,
) -> None:
    """All platforms that can create symlinks: a destination that is a
    symlink is replaced as an entry; its target is not touched."""
    src = tmp_path / "v03"
    _write_v03_directory(src)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / "precious.txt").write_bytes(b"precious")
    dst = tmp_path / "v04"
    _symlink_or_skip(dst, elsewhere)

    migrate(MigrateOptions(src=src, dst=dst, force=True))

    assert (elsewhere / "precious.txt").read_bytes() == b"precious"
    assert not dst.is_symlink()
    assert (dst / "manifest.json").is_file()


def test_force_does_not_follow_symlinks_inside_the_destination(tmp_path: Path) -> None:
    """All platforms that can create symlinks: a symlink inside the old
    destination is removed, never followed."""
    src = tmp_path / "v03"
    _write_v03_directory(src)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / "precious.txt").write_bytes(b"precious")
    dst = tmp_path / "v04"
    dst.mkdir()
    (dst / "stale.txt").write_bytes(b"stale")
    _symlink_or_skip(dst / "linked", elsewhere)

    migrate(MigrateOptions(src=src, dst=dst, force=True))

    assert (elsewhere / "precious.txt").read_bytes() == b"precious"
    assert not (dst / "stale.txt").exists()
    assert not (dst / "linked").exists()


@pytest.mark.skipif(
    not shutil.rmtree.avoids_symlink_attacks,
    reason=(
        "known residual: where shutil.rmtree.avoids_symlink_attacks is false "
        "(Windows), rmtree cannot detect a directory replaced mid-removal"
    ),
)
def test_force_does_not_follow_a_directory_replaced_by_a_symlink_during_removal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """POSIX only (where rmtree can resist it): a directory inside the
    replaced destination is replaced by a symlink after it was inspected but
    before it is opened for listing, as another process could do. Removing
    the old tree (now in a backup directory) must stop there instead of
    deleting through the link; that only warns, since the new tree is
    already in place."""
    import os

    src = tmp_path / "v03"
    _write_v03_directory(src)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / "precious.txt").write_bytes(b"precious")
    dst = tmp_path / "v04"
    (dst / "swapped").mkdir(parents=True)
    (dst / "swapped" / "stale.txt").write_bytes(b"stale")

    real_open, real_scandir = os.open, os.scandir
    swaps: list[object] = []

    def swap_before_listing(path: object) -> None:
        if swaps or not isinstance(path, (str, os.PathLike)):
            return
        if os.path.basename(os.fspath(path)) == "swapped":
            swaps.append(path)
            old_tree = next(tmp_path.rglob("swapped"))  # wherever the old tree is now
            os.rename(old_tree, tmp_path / "moved-aside")
            os.symlink(elsewhere, old_tree, target_is_directory=True)

    def open_(path: object, *args: object, **kwargs: object) -> int:
        swap_before_listing(path)
        return real_open(path, *args, **kwargs)

    def scandir_(*args: object) -> object:
        if args:
            swap_before_listing(args[0])
        return real_scandir(*args)

    monkeypatch.setattr(os, "open", open_)
    monkeypatch.setattr(os, "scandir", scandir_)

    with pytest.warns(RuntimeWarning):
        migrate(MigrateOptions(src=src, dst=dst, force=True))

    assert swaps, "the directory was never opened for listing"
    assert (elsewhere / "precious.txt").exists()
    assert (elsewhere / "precious.txt").read_bytes() == b"precious"
    assert loads((dst / "manifest.json").read_bytes())["format_version"] == "2.0"
    assert not any(p.name.startswith(".v04.migrating-") for p in tmp_path.iterdir())


def test_force_keeps_destination_when_source_is_not_migratable(tmp_path: Path) -> None:
    """All platforms: the manifest check is a safety check too: it runs
    before the removal."""
    src = tmp_path / "v03"
    _write_v03_directory(src)
    manifest = loads((src / "manifest.json").read_bytes())
    manifest["format_version"] = "2.0"  # already v0.4: not migratable
    (src / "manifest.json").write_bytes(dumps(normalize(manifest)))
    dst = tmp_path / "v04"
    dst.mkdir()
    (dst / "keep.txt").write_bytes(b"keep")

    with pytest.raises(SchemaError) as exc:
        migrate(MigrateOptions(src=src, dst=dst, force=True))

    assert exc.value.code == ErrorCode.UNSUPPORTED_SCHEMA_VERSION
    assert _snapshot(dst) == {"keep.txt": b"keep"}


@pytest.mark.parametrize(
    "winerror", [None, pytest.param(53, marks=WINDOWS_ONLY), pytest.param(67, marks=WINDOWS_ONLY)]
)
def test_migrate_stops_when_the_destination_cannot_be_looked_at(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, winerror: int | None
) -> None:
    """All platforms: an error other than "no such file" while checking
    whether the destination exists (a transient I/O error, say) fails the
    migration before anything is written; it is not taken as "absent".
    Windows also: nor is a network path or share that cannot be reached
    (winerror 53, 67), which Windows raises as FileNotFoundError."""
    import errno
    import os

    src, dst, before = _force_setup(tmp_path)
    real_lstat = os.lstat
    if winerror is None:
        err = OSError(errno.EIO, "simulated I/O error", str(dst))
    else:
        err = _not_found(dst, winerror)

    def lstat(path: str, *args: object, **kwargs: object) -> os.stat_result:
        if os.path.abspath(os.fspath(path)) == str(dst):
            raise err
        return real_lstat(path, *args, **kwargs)

    monkeypatch.setattr(os, "lstat", lstat)

    with pytest.raises(OSError) as exc:
        migrate(MigrateOptions(src=src, dst=dst))
    monkeypatch.undo()

    assert exc.value is err
    assert _snapshot(dst) == before
    assert sorted(p.name for p in tmp_path.iterdir()) == ["v03", "v04"]


@WINDOWS_ONLY
@pytest.mark.parametrize("winerror, works", [(1, True), (50, True), (53, False)])
def test_migrate_works_where_the_source_volume_reports_no_final_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, winerror: int, works: bool
) -> None:
    """Windows only (simulated): on a volume whose driver cannot answer the
    final-path query (some RAM disks and mapped drives: winerror 1 or 50),
    migrate works; a strict look has already shown that the source exists.
    Any other error from that query (a network path that cannot be
    reached, 53) still fails it before anything is written."""
    src = tmp_path / "v03"
    _write_v03_directory(src)
    dst = tmp_path / "v04"
    _no_final_path(monkeypatch, src.resolve(), winerror)

    if works:
        migrate(MigrateOptions(src=src, dst=dst))
        monkeypatch.undo()
        assert loads((dst / "manifest.json").read_bytes())["format_version"] == "2.0"
    else:
        with pytest.raises(OSError) as exc:
            migrate(MigrateOptions(src=src, dst=dst))
        monkeypatch.undo()
        assert getattr(exc.value, "winerror", None) == winerror
        assert sorted(p.name for p in tmp_path.iterdir()) == ["v03"]


def test_force_refuses_archive_destination_that_is_the_source(tmp_path: Path) -> None:
    """All platforms: --force refuses an archive destination that is the
    source archive."""
    archive = tmp_path / "in.aphelion.tar"
    _write_v03_archive(tmp_path / "pkg_v03", archive)
    before = archive.read_bytes()
    _assert_refused(archive, archive)
    assert archive.read_bytes() == before


def test_force_refuses_archive_destination_symlinked_to_the_source(tmp_path: Path) -> None:
    """All platforms that can create symlinks: the same for a symlink to the
    source archive."""
    archive = tmp_path / "in.aphelion.tar"
    _write_v03_archive(tmp_path / "pkg_v03", archive)
    link = tmp_path / "out.aphelion.tar"
    _symlink_or_skip(link, archive)
    before = archive.read_bytes()
    _assert_refused(archive, link)
    assert archive.read_bytes() == before


def test_overlap_check_uses_filesystem_identity_not_spelling(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """All platforms: simulate a case-insensitive filesystem by making
    samefile() compare names case-insensitively, as NTFS/APFS lookups do.
    The check must rely on that identity, not on path string equality."""
    import os

    src = tmp_path / "work" / "v03"
    _write_v03_directory(src)
    real_samefile = os.path.samefile

    def samefile_ci(a: object, b: object) -> bool:
        if str(a).casefold() == str(b).casefold():
            return True
        return real_samefile(a, b)

    monkeypatch.setattr(os.path, "samefile", samefile_ci)
    before = _snapshot(tmp_path / "work")
    _assert_refused(src, tmp_path / "work" / "V03")  # is the source
    _assert_refused(src, tmp_path / "work" / "V03" / "out")  # inside it
    _assert_refused(src, tmp_path / "WORK")  # contains it
    assert _snapshot(tmp_path / "work") == before


def test_cli_migrate_force_onto_source_is_refused(tmp_path: Path) -> None:
    """All platforms: `aphe migrate --force` onto the source exits 3 with
    PX_E_2006 INIT_REFUSES_EXISTING and changes nothing."""
    from conftest import run_cli

    src = tmp_path / "v03"
    _write_v03_directory(src)
    before = _snapshot(src)

    code, _, err = run_cli(["migrate", str(src), str(src), "--force"])

    assert code == 3, err
    assert json.loads(err.strip().splitlines()[-1])["code"] == ErrorCode.INIT_REFUSES_EXISTING.value
    assert _snapshot(src) == before


def test_force_onto_current_directory_spelled_dot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """POSIX only (Windows cannot remove the current directory): Path(".")
    has no name; staging must use the absolute destination."""
    import sys

    if sys.platform == "win32":
        pytest.skip("Windows cannot remove the current working directory")
    src = tmp_path / "v03"
    _write_v03_directory(src)
    dst = tmp_path / "v04"
    dst.mkdir()
    (dst / "stale.txt").write_bytes(b"stale")
    monkeypatch.chdir(dst)

    migrate(MigrateOptions(src=src, dst=Path("."), force=True))

    assert not (dst / "stale.txt").exists()
    assert loads((dst / "manifest.json").read_bytes())["format_version"] == "2.0"


# ---------- --force keeps the old destination until the new one is in place ----------


def _force_setup(tmp_path: Path) -> tuple[Path, Path, dict[str, bytes | None]]:
    src = tmp_path / "v03"
    _write_v03_directory(src)
    dst = tmp_path / "v04"
    (dst / "sub").mkdir(parents=True)
    (dst / "keep.txt").write_bytes(b"keep")
    (dst / "sub" / "stale.txt").write_bytes(b"stale")
    return src, dst, _snapshot(dst)


def _fail_replace(monkeypatch: pytest.MonkeyPatch, *prefixes: str) -> None:
    """Make os.replace fail when its source name starts with one of ``prefixes``
    or lies in a directory that does."""
    import errno
    import os

    real_replace = os.replace

    def replace(src: str, dst: str, **kwargs: object) -> None:
        if any(p.startswith(prefixes) for p in Path(os.fspath(src)).parts):
            raise OSError(errno.EIO, "simulated I/O error", os.fspath(dst))
        real_replace(src, dst, **kwargs)

    monkeypatch.setattr(os, "replace", replace)


def test_force_keeps_destination_when_the_new_tree_cannot_be_moved_in(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """All platforms: if the new tree cannot be renamed into place, the old
    destination is put back."""
    src, dst, before = _force_setup(tmp_path)
    _fail_replace(monkeypatch, ".v04.migrating-")

    with pytest.raises(OSError) as exc:
        migrate(MigrateOptions(src=src, dst=dst, force=True))
    monkeypatch.undo()

    assert "simulated I/O error" in str(exc.value)
    assert _snapshot(dst) == before
    assert sorted(p.name for p in tmp_path.iterdir()) == ["v03", "v04"]


def test_force_names_the_backup_when_the_destination_cannot_be_restored(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """All platforms: if the old destination cannot be put back either, the
    error names the backup directory that holds it."""
    src, dst, before = _force_setup(tmp_path)
    _fail_replace(monkeypatch, ".v04.migrating-", ".v04.replaced-")

    with pytest.raises(OSError) as exc:
        migrate(MigrateOptions(src=src, dst=dst, force=True))
    monkeypatch.undo()

    backups = [p for p in tmp_path.iterdir() if p.name.startswith(".v04.replaced-")]
    assert len(backups) == 1
    assert str(backups[0]) in str(exc.value)
    assert "could not undo" in str(exc.value)
    (kept,) = backups[0].iterdir()
    assert _snapshot(kept) == before


def test_force_only_warns_when_the_old_destination_cannot_be_deleted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """All platforms: the new tree is already in place, so a leftover of
    the old one (a file held open, say) is reported, not raised."""
    import errno
    import os

    src, dst, _ = _force_setup(tmp_path)
    real_unlink = os.unlink

    def unlink(path: str, *args: object, **kwargs: object) -> None:
        if os.path.basename(os.fspath(path)) == "stale.txt":
            raise PermissionError(errno.EACCES, "Permission denied", os.fspath(path))
        real_unlink(path, *args, **kwargs)

    monkeypatch.setattr(os, "unlink", unlink)
    monkeypatch.setattr(os, "remove", unlink)

    with pytest.warns(RuntimeWarning, match="could not remove") as warned:
        migrate(MigrateOptions(src=src, dst=dst, force=True))
    monkeypatch.undo()

    assert loads((dst / "manifest.json").read_bytes())["format_version"] == "2.0"
    (backup,) = [p for p in tmp_path.iterdir() if p.name.startswith(".v04.replaced-")]
    assert any(str(backup) in str(w.message) for w in warned)


BACKUP_LEFT_AFTER_FORCE = """
import os, sys
from pathlib import Path
from aphelion.migrate import MigrateOptions, migrate

src, dst = Path(sys.argv[1]), Path(sys.argv[2])
real_rmdir = os.rmdir

def rmdir(path, *args, **kwargs):
    if ".replaced-" in os.path.basename(os.fspath(path)):
        raise PermissionError(13, "Permission denied", os.fspath(path))
    real_rmdir(path, *args, **kwargs)

os.rmdir = rmdir
migrate(MigrateOptions(src=src, dst=dst, force=True))
print("\\n".join(str(p) for p in dst.parent.iterdir() if ".replaced-" in p.name))
"""


@WARNING_FILTERS
def test_backup_left_after_force_reaches_stderr_once_whatever_the_warnings_filters(
    tmp_path: Path, warn: str | None
) -> None:
    """All platforms, run in a new interpreter: the old destination's backup
    directory that migrate --force cannot delete after success is named on
    stderr exactly once, with warnings shown, ignored (-W ignore) or turned
    into errors (-W error)."""
    src, dst, _ = _force_setup(tmp_path)

    run = run_python(BACKUP_LEFT_AFTER_FORCE, [str(src), str(dst)], warn)

    assert run.returncode == 0, run.stderr
    left = run.stdout.splitlines()
    assert len(left) == 1, (run.stdout, run.stderr)
    assert run.stderr.count(left[0]) == 1, run.stderr


# ---------- --force stopped at any step loses nothing ----------


def _force_call(tmp_path: Path) -> tuple[Callable[[], object], Path, dict[str, bytes | None]]:
    src, dst, before = _force_setup(tmp_path)
    return functools.partial(migrate, MigrateOptions(src=src, dst=dst, force=True)), dst, before


@pytest.mark.parametrize("kind, after", STOPS)
def test_force_stopped_at_any_step_leaves_destination_unchanged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: type[BaseException], after: bool
) -> None:
    """All platforms: migrate --force stopped at any rename or directory
    creation, also right after it returned (the move-aside of the old
    destination included), puts the destination back and raises that same
    error, an interrupt included."""
    call, _, _ = _force_call(tmp_path / "clean")
    steps, exc, _ = _run_steps(monkeypatch, call, {})
    assert exc is None
    forward = [n for n, line in enumerate(steps, 1) if not line.startswith("rmdir")]
    assert sum(steps[n - 1].startswith(MOVES) for n in forward) == 2  # aside, in

    for n in forward:
        work = tmp_path / str(n)
        call, dst, before = _force_call(work)
        error = _error(kind)
        _, exc, _ = _run_steps(monkeypatch, call, {n: (error, after)})
        assert exc is error, (steps[n - 1], exc)
        assert _snapshot(dst) == before, steps[n - 1]
        assert sorted(p.name for p in work.iterdir()) == ["v03", "v04"], steps[n - 1]


@pytest.mark.parametrize("kind, after", STOPS)
def test_force_undo_stopped_at_any_step_loses_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: type[BaseException], after: bool
) -> None:
    """All platforms: once moving the new tree in has failed, a second error
    at any step of putting the old destination back or cleaning up never
    loses it: it is back in place, or in a backup directory that the error
    or a warning names. An interrupt propagates as itself."""
    call, _, _ = _force_call(tmp_path / "clean")
    steps, _, _ = _run_steps(monkeypatch, call, {})
    moves = [n for n, line in enumerate(steps, 1) if line.startswith(MOVES)]
    assert len(moves) == 2
    for fail_at in moves:
        call, _, _ = _force_call(tmp_path / str(fail_at))
        undo, exc, _ = _run_steps(monkeypatch, call, {fail_at: (_error(OSError), False)})
        assert isinstance(exc, OSError)
        for n in range(fail_at + 1, len(undo) + 1):
            work = tmp_path / f"{fail_at}-{n}"
            call, dst, before = _force_call(work)
            error = _error(kind)
            plan = {fail_at: (_error(OSError), False), n: (error, after)}
            _, exc, warned = _run_steps(monkeypatch, call, plan)
            where = (steps[fail_at - 1], undo[n - 1])
            if kind is KeyboardInterrupt:
                assert exc is error, where
            else:
                assert isinstance(exc, OSError), where
            if dst.exists() and _snapshot(dst) == before:
                continue
            named = _named(exc, warned)
            backups = [b for b in work.glob(".v04.replaced-*") if str(b) in named]
            assert any(_snapshot(b / "0") == before for b in backups), (where, named)


@pytest.mark.parametrize(
    "layout, after",
    [("existing-dst", False), ("existing-dst", True), ("new-dst", True)],
    ids=["force-interrupt-before-step", "force-interrupt-after-step", "new-dst-after-rename"],
)
def test_interrupt_once_the_new_tree_is_in_place_says_migrate_completed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, layout: str, after: bool
) -> None:
    """All platforms: once the new tree is in place the migration has
    succeeded. An interrupt after that (while the old destination is
    deleted, or right after a new one is renamed into place) propagates with
    a note (Python 3.11+) and a warning saying migrate completed and naming
    the backup directory left over, and the destination holds the new tree."""

    def setup(work: Path) -> tuple[Callable[[], object], Path]:
        if layout == "existing-dst":
            call, dst, _ = _force_call(work)
            return call, dst
        src = work / "v03"
        _write_v03_directory(src)
        return functools.partial(migrate, MigrateOptions(src=src, dst=work / "v04")), work / "v04"

    call, _ = setup(tmp_path / "clean")
    steps, exc, _ = _run_steps(monkeypatch, call, {})
    assert exc is None
    last_move = max(n for n, line in enumerate(steps, 1) if line.startswith(MOVES))
    # The rename of a new dst completes it; swapping in the new tree over an
    # old one is still undone if interrupted (see the test above).
    finishing = range(last_move + (0 if layout == "new-dst" else 1), len(steps) + 1)
    assert finishing

    for n in finishing:
        work = tmp_path / str(n)
        call, dst = setup(work)
        error = KeyboardInterrupt()
        _, exc, warned = _run_steps(monkeypatch, call, {n: (error, after)})
        assert exc is error, steps[n - 1]
        named = _named(exc, warned)
        assert "migrate completed" in named, (steps[n - 1], named)
        assert loads((dst / "manifest.json").read_bytes())["format_version"] == "2.0"
        assert not (dst / "keep.txt").exists()
        for leftover in work.glob(".v04.replaced-*"):
            assert str(leftover) in named, (steps[n - 1], named)
