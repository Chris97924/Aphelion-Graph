"""Targeted security-guard tests for ``aphelion.unpacker``.

The fixture suite covers the common attack classes (traversal, absolute paths,
symlink/hardlink, zip-bomb-by-file-size, file-count overflow). This file adds
the remaining branches:

  * ExtractPolicy.default() classmethod
  * empty member name
  * Windows drive letter
  * path-too-long after NFC normalization
  * duplicate normalized member path
  * directory member extraction (isdir branch)
  * header-declared FILE_BYTES_EXCEEDED
  * streamed-past ARCHIVE_BOMB (per-file)
  * streamed-past ARCHIVE_BOMB (total)
  * COMPRESSION_RATIO_EXCEEDED
  * tar.extractfile() returning None
"""

from __future__ import annotations

import errno
import functools
import io
import os
import stat
import sys
import tarfile
import warnings
from pathlib import Path
from typing import Callable

import pytest

from aphelion.error_codes import ErrorCode
from aphelion.errors import SecurityError
from aphelion.unpacker import ExtractPolicy, unpack


def _write_tar(
    path: Path,
    members: list[tuple[tarfile.TarInfo, bytes | None]],
) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        for info, data in members:
            if data is None:
                tar.addfile(info)
            else:
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
    path.write_bytes(buf.getvalue())
    return path


def _reg(name: str, mode: int = 0o644) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name=name)
    info.type = tarfile.REGTYPE
    info.mode = mode
    return info


def _dir(name: str) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name=name)
    info.type = tarfile.DIRTYPE
    info.mode = 0o755
    return info


# ---------- ExtractPolicy.default() (line 37) ----------


def test_extract_policy_default_classmethod_returns_defaults() -> None:
    policy = ExtractPolicy.default()
    assert policy.max_files == 10_000
    assert policy.max_total_bytes == 100 * 1024 * 1024
    assert policy.max_file_bytes == 25 * 1024 * 1024
    assert policy.max_compression_ratio == 100
    assert policy.max_path_length == 512


def test_package_total_bytes_limit_constant() -> None:
    """v0.3.0 spec/packaging.md §7 fixes 100 MiB total-archive ceiling."""
    from aphelion.unpacker import PACKAGE_TOTAL_BYTES_LIMIT

    assert PACKAGE_TOTAL_BYTES_LIMIT == 104_857_600
    assert ExtractPolicy().max_total_bytes == PACKAGE_TOTAL_BYTES_LIMIT


# ---------- empty member name (line 47) ----------


def test_empty_member_name_rejected(tmp_path: Path) -> None:
    archive = _write_tar(
        tmp_path / "a.tar",
        [(_reg(""), b"x")],
    )
    with pytest.raises(SecurityError) as exc:
        unpack(archive, tmp_path / "dest")
    assert exc.value.code == ErrorCode.EMPTY_MEMBER_NAME


# ---------- Windows drive letter (line 61) ----------


def test_windows_drive_letter_rejected(tmp_path: Path) -> None:
    archive = _write_tar(tmp_path / "a.tar", [(_reg("C:evil.txt"), b"x")])
    with pytest.raises(SecurityError) as exc:
        unpack(archive, tmp_path / "dest")
    assert exc.value.code == ErrorCode.WINDOWS_DRIVE


# ---------- path too long (line 68) ----------


def test_path_longer_than_policy_rejected(tmp_path: Path) -> None:
    # ustar header caps member names at 100 bytes, but the pax/long-name
    # extensions let us embed longer names. Instead of fighting tarfile, we
    # lower the policy to a small value and use a modest overflow.
    archive = _write_tar(tmp_path / "a.tar", [(_reg("abcdefghij"), b"x")])
    policy = ExtractPolicy(max_path_length=5)
    with pytest.raises(SecurityError) as exc:
        unpack(archive, tmp_path / "dest", policy=policy)
    assert exc.value.code == ErrorCode.PATH_TOO_LONG


# ---------- duplicate member path (line 128) ----------


def test_duplicate_member_path_rejected(tmp_path: Path) -> None:
    archive = _write_tar(
        tmp_path / "a.tar",
        [
            (_reg("same.txt"), b"first"),
            (_reg("same.txt"), b"second"),
        ],
    )
    with pytest.raises(SecurityError) as exc:
        unpack(archive, tmp_path / "dest")
    assert exc.value.code == ErrorCode.DUPLICATE_MEMBER_PATH


# ---------- directory member extraction (lines 144-145) ----------


def test_directory_member_is_created(tmp_path: Path) -> None:
    archive = _write_tar(
        tmp_path / "a.tar",
        [
            (_dir("subdir"), None),
            (_reg("subdir/file.txt"), b"hi"),
        ],
    )
    dest = tmp_path / "dest"
    unpack(archive, dest)
    assert (dest / "subdir").is_dir()
    assert (dest / "subdir" / "file.txt").read_bytes() == b"hi"


# ---------- header-declared FILE_BYTES_EXCEEDED (line 160, 150-158 header guard) ----------


def test_declared_size_over_max_file_bytes_rejected(tmp_path: Path) -> None:
    archive = _write_tar(
        tmp_path / "a.tar",
        [(_reg("big.bin"), b"A" * 1024)],
    )
    policy = ExtractPolicy(max_file_bytes=100)
    with pytest.raises(SecurityError) as exc:
        unpack(archive, tmp_path / "dest", policy=policy)
    assert exc.value.code == ErrorCode.FILE_BYTES_EXCEEDED


# ---------- header-declared TOTAL_BYTES_EXCEEDED (line 159-165) ----------


def test_declared_total_size_over_max_total_bytes_rejected(tmp_path: Path) -> None:
    archive = _write_tar(
        tmp_path / "a.tar",
        [
            (_reg("a.bin"), b"A" * 60),
            (_reg("b.bin"), b"B" * 60),
        ],
    )
    policy = ExtractPolicy(max_file_bytes=200, max_total_bytes=100)
    with pytest.raises(SecurityError) as exc:
        unpack(archive, tmp_path / "dest", policy=policy)
    assert exc.value.code == ErrorCode.TOTAL_BYTES_EXCEEDED


# ---------- streaming per-file bomb (line 186-195) ----------


def test_streaming_per_file_bomb_rejected_via_chunked_loop(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A lying stream (declared size small, actual bytes larger) must be caught
    by the authoritative chunked-read budget inside the unpacker.

    We cannot produce this with ``tarfile`` alone because the library caps
    ``extractfile`` at the declared ``member.size``. The streaming guard is a
    defense-in-depth against a non-stdlib reader or a patched tarfile; to
    exercise it we monkeypatch ``extractfile`` to hand back a bigger stream.
    """
    archive = _write_tar(tmp_path / "a.tar", [(_reg("big.bin"), b"A" * 10)])

    real_open = tarfile.open

    class _Wrapped:
        def __init__(self, inner):
            self._inner = inner

        def __enter__(self):
            self._inner.__enter__()
            return self

        def __exit__(self, *a):
            return self._inner.__exit__(*a)

        def next(self):
            return self._inner.next()

        def extractfile(self, member):
            return io.BytesIO(b"A" * 5000)

    def _fake_open(*args, **kwargs):
        return _Wrapped(real_open(*args, **kwargs))

    import aphelion.unpacker as unpacker_mod

    monkeypatch.setattr(unpacker_mod.tarfile, "open", _fake_open)

    policy = ExtractPolicy(max_file_bytes=100, max_total_bytes=1_000_000)
    with pytest.raises(SecurityError) as exc:
        unpack(archive, tmp_path / "dest", policy=policy)
    assert exc.value.code == ErrorCode.ARCHIVE_BOMB
    # Partial output file must be cleaned up.
    assert not (tmp_path / "dest" / "big.bin").exists()


def test_streaming_total_bytes_bomb_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Same monkeypatch trick, aimed at the total-bytes streaming guard."""
    archive = _write_tar(tmp_path / "a.tar", [(_reg("big.bin"), b"A" * 10)])

    real_open = tarfile.open

    class _Wrapped:
        def __init__(self, inner):
            self._inner = inner

        def __enter__(self):
            self._inner.__enter__()
            return self

        def __exit__(self, *a):
            return self._inner.__exit__(*a)

        def next(self):
            return self._inner.next()

        def extractfile(self, member):
            return io.BytesIO(b"B" * 400)

    def _fake_open(*args, **kwargs):
        return _Wrapped(real_open(*args, **kwargs))

    import aphelion.unpacker as unpacker_mod

    monkeypatch.setattr(unpacker_mod.tarfile, "open", _fake_open)

    # per-file budget is huge, total budget is small
    policy = ExtractPolicy(max_file_bytes=10_000, max_total_bytes=100)
    with pytest.raises(SecurityError) as exc:
        unpack(archive, tmp_path / "dest", policy=policy)
    assert exc.value.code == ErrorCode.ARCHIVE_BOMB


def test_extractfile_returning_none_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If ``tar.extractfile`` hands back None for a regular file, it's a
    disallowed member (line 168-172)."""
    archive = _write_tar(tmp_path / "a.tar", [(_reg("only.txt"), b"hi")])

    real_open = tarfile.open

    class _Wrapped:
        def __init__(self, inner):
            self._inner = inner

        def __enter__(self):
            self._inner.__enter__()
            return self

        def __exit__(self, *a):
            return self._inner.__exit__(*a)

        def next(self):
            return self._inner.next()

        def extractfile(self, member):
            return None

    def _fake_open(*args, **kwargs):
        return _Wrapped(real_open(*args, **kwargs))

    import aphelion.unpacker as unpacker_mod

    monkeypatch.setattr(unpacker_mod.tarfile, "open", _fake_open)

    with pytest.raises(SecurityError) as exc:
        unpack(archive, tmp_path / "dest")
    assert exc.value.code == ErrorCode.DISALLOWED_MEMBER_TYPE


# ---------- compression ratio (line 212-223) ----------


def test_compression_ratio_exceeded(tmp_path: Path) -> None:
    # Build a tar with content that, uncompressed, vastly exceeds the archive
    # byte size * ratio. Using ratio=1 with any non-trivial content trips it.
    archive = _write_tar(tmp_path / "a.tar", [(_reg("small.txt"), b"A" * 2048)])
    # policy permits the per-file bytes but sets ratio=1 (uncompressed must
    # not exceed archive_size * 1). A ustar archive always adds padding, so
    # archive_size > 2048; but total_bytes also = 2048 — we make ratio tiny.
    policy = ExtractPolicy(max_file_bytes=10_000, max_compression_ratio=0)
    with pytest.raises(SecurityError) as exc:
        unpack(archive, tmp_path / "dest", policy=policy)
    assert exc.value.code == ErrorCode.COMPRESSION_RATIO_EXCEEDED


# ---------- A1: collisions after normalisation ----------


@pytest.mark.parametrize(
    "first, second",
    [
        ("manifest.json", "./manifest.json"),
        ("./manifest.json", "././manifest.json"),
        ("claims/a.md", "claims//a.md"),
        ("claims/a.md", "claims/./a.md"),
        ("manifest.json", "MANIFEST.json"),
        ("claims/a.md", "Claims/a.md"),
        ("straße.md", "STRASSE.md"),  # casefold, not lower()
        ("café.md", "café.md"),  # NFC vs NFD
        ("manifest.json", "manifest.json."),  # Windows strips trailing dots
        ("manifest.json", "manifest.json "),  # ... and trailing spaces
    ],
)
def test_names_colliding_after_normalisation_rejected(
    tmp_path: Path, first: str, second: str
) -> None:
    archive = _write_tar(
        tmp_path / "a.tar",
        [(_reg(first), b"first"), (_reg(second), b"second")],
    )
    dest = tmp_path / "dest"
    with pytest.raises(SecurityError) as exc:
        unpack(archive, dest)
    assert exc.value.code == ErrorCode.DUPLICATE_MEMBER_PATH
    # Rejected before extraction: nothing from the archive was written.
    assert not dest.exists() or not any(dest.iterdir())


def test_directory_component_colliding_by_case_rejected(tmp_path: Path) -> None:
    """``Claims/a.md`` and ``claims/b.md`` share one directory on NTFS/APFS
    but two on ext4, so the extracted tree would differ by platform."""
    archive = _write_tar(
        tmp_path / "a.tar",
        [(_reg("Claims/a.md"), b"a"), (_reg("claims/b.md"), b"b")],
    )
    with pytest.raises(SecurityError) as exc:
        unpack(archive, tmp_path / "dest")
    assert exc.value.code == ErrorCode.DUPLICATE_MEMBER_PATH


def test_file_and_directory_with_same_name_rejected(tmp_path: Path) -> None:
    archive = _write_tar(
        tmp_path / "a.tar",
        [(_reg("claims"), b"x"), (_reg("claims/a.md"), b"a")],
    )
    with pytest.raises(SecurityError) as exc:
        unpack(archive, tmp_path / "dest")
    assert exc.value.code == ErrorCode.DUPLICATE_MEMBER_PATH


def test_explicit_directory_entries_do_not_count_as_collisions(tmp_path: Path) -> None:
    """A directory member plus files inside it (and ``./`` prefixes as plain
    ``tar -C dir .`` produces) is a normal archive, not a collision."""
    archive = _write_tar(
        tmp_path / "a.tar",
        [
            (_dir("."), None),
            (_dir("./claims"), None),
            (_reg("./claims/a.md"), b"a"),
            (_reg("./manifest.json"), b"{}"),
        ],
    )
    dest = tmp_path / "dest"
    unpack(archive, dest)
    assert (dest / "claims" / "a.md").read_bytes() == b"a"
    assert (dest / "manifest.json").read_bytes() == b"{}"


# ---------- A8: a failed unpack leaves the destination as it was ----------


def _tree(root: Path) -> dict[str, bytes | None]:
    """Relative path -> bytes (files) or None (dirs), for exact comparison."""
    if not root.exists():
        return {}
    return {
        p.relative_to(root).as_posix(): (None if p.is_dir() else p.read_bytes())
        for p in sorted(root.rglob("*"))
    }


def _fails_after_first_member(tmp_path: Path) -> tuple[Path, ExtractPolicy]:
    """Archive whose first members extract fine and whose last member is over
    the per-file budget, so the failure comes after files were written."""
    archive = _write_tar(
        tmp_path / "a.tar",
        [
            (_dir("claims"), None),
            (_reg("claims/a.md"), b"new a"),
            (_reg("manifest.json"), b"new manifest"),
            (_reg("zz-big.bin"), b"B" * 4096),
        ],
    )
    return archive, ExtractPolicy(max_file_bytes=1024)


def test_failed_unpack_into_missing_dest_creates_nothing(tmp_path: Path) -> None:
    archive, policy = _fails_after_first_member(tmp_path)
    dest = tmp_path / "out" / "nested" / "dest"
    with pytest.raises(SecurityError) as exc:
        unpack(archive, dest, policy=policy)
    assert exc.value.code == ErrorCode.FILE_BYTES_EXCEEDED
    # Neither the destination nor the parents created for it remain.
    assert not (tmp_path / "out").exists()
    assert sorted(p.name for p in tmp_path.iterdir()) == ["a.tar"]


def test_failed_unpack_into_existing_dest_leaves_it_unchanged(tmp_path: Path) -> None:
    archive, policy = _fails_after_first_member(tmp_path)
    dest = tmp_path / "dest"
    (dest / "claims").mkdir(parents=True)
    (dest / "claims" / "a.md").write_bytes(b"old a")
    (dest / "keep.txt").write_bytes(b"keep")
    before = _tree(dest)

    with pytest.raises(SecurityError):
        unpack(archive, dest, policy=policy)

    assert _tree(dest) == before
    assert sorted(p.name for p in tmp_path.iterdir()) == ["a.tar", "dest"]


def test_failed_unpack_on_compression_ratio_leaves_nothing(tmp_path: Path) -> None:
    """The ratio check runs after a member is fully written (ratio 0, as in
    test_compression_ratio_exceeded: a plain ustar archive never expands)."""
    archive = _write_tar(
        tmp_path / "a.tar",
        [(_reg("one.txt"), b"1"), (_reg("two.txt"), b"A" * 2048)],
    )
    dest = tmp_path / "dest"
    with pytest.raises(SecurityError) as exc:
        unpack(archive, dest, policy=ExtractPolicy(max_compression_ratio=0))
    assert exc.value.code == ErrorCode.COMPRESSION_RATIO_EXCEEDED
    assert not dest.exists()
    assert sorted(p.name for p in tmp_path.iterdir()) == ["a.tar"]


def test_failed_unpack_on_streamed_bomb_leaves_nothing(tmp_path: Path) -> None:
    archive = _write_tar(
        tmp_path / "a.tar",
        [(_reg("one.txt"), b"1"), (_reg("two.txt"), b"x" * 2048)],
    )
    dest = tmp_path / "dest"
    dest.mkdir()
    with pytest.raises(SecurityError):
        unpack(archive, dest, policy=ExtractPolicy(max_total_bytes=1024))
    assert _tree(dest) == {}


def test_successful_unpack_into_existing_dest_merges_like_before(tmp_path: Path) -> None:
    """Success keeps the old contract: archive files are written into dest,
    replacing same-named files and leaving unrelated ones alone."""
    archive = _write_tar(
        tmp_path / "a.tar",
        [(_dir("claims"), None), (_reg("claims/a.md"), b"new a"), (_reg("m.json"), b"{}")],
    )
    dest = tmp_path / "dest"
    (dest / "claims").mkdir(parents=True)
    (dest / "claims" / "a.md").write_bytes(b"old a")
    (dest / "keep.txt").write_bytes(b"keep")

    assert unpack(archive, dest) == dest

    assert _tree(dest) == {
        "claims": None,
        "claims/a.md": b"new a",
        "keep.txt": b"keep",
        "m.json": b"{}",
    }
    assert sorted(p.name for p in tmp_path.iterdir()) == ["a.tar", "dest"]


def test_successful_unpack_into_new_dest(tmp_path: Path) -> None:
    archive = _write_tar(tmp_path / "a.tar", [(_reg("claims/a.md"), b"a")])
    dest = tmp_path / "new" / "dest"
    unpack(archive, dest)
    assert _tree(dest) == {"claims": None, "claims/a.md": b"a"}
    assert sorted(p.name for p in (tmp_path / "new").iterdir()) == ["dest"]


def test_unpack_into_existing_dest_moves_only_within_its_filesystem(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An existing dest may be a mount point, where a rename from anywhere
    outside it fails with EXDEV. Simulate that: the merge must not need one."""
    archive = _write_tar(
        tmp_path / "a.tar",
        [(_dir("claims"), None), (_reg("claims/a.md"), b"a"), (_reg("m.json"), b"{}")],
    )
    dest = tmp_path / "mnt"
    dest.mkdir()
    (dest / "keep.txt").write_bytes(b"keep")
    mount = dest.resolve()
    real_replace = os.replace

    def replace_within_mount(src: str, dst: str, **kwargs: object) -> None:
        def on_mount(p: str) -> bool:
            path = Path(os.path.abspath(p))
            return path == mount or mount in path.parents

        if on_mount(src) != on_mount(dst):
            raise OSError(errno.EXDEV, "Invalid cross-device link", str(src))
        real_replace(src, dst, **kwargs)

    monkeypatch.setattr(os, "replace", replace_within_mount)

    assert unpack(archive, dest) == dest

    assert _tree(dest) == {
        "claims": None,
        "claims/a.md": b"a",
        "keep.txt": b"keep",
        "m.json": b"{}",
    }
    assert sorted(p.name for p in tmp_path.iterdir()) == ["a.tar", "mnt"]


@pytest.mark.skipif(
    getattr(os, "geteuid", lambda: 0)() == 0,
    reason="directory write permission is only enforced on POSIX for non-root users",
)
def test_unpack_into_existing_dest_whose_parent_is_not_writable(tmp_path: Path) -> None:
    archive = _write_tar(tmp_path / "a.tar", [(_reg("claims/a.md"), b"a")])
    parent = tmp_path / "read-only"
    dest = parent / "dest"
    dest.mkdir(parents=True)
    (dest / "keep.txt").write_bytes(b"keep")
    parent.chmod(0o555)
    try:
        unpack(archive, dest)
    finally:
        parent.chmod(0o755)

    assert _tree(dest) == {"claims": None, "claims/a.md": b"a", "keep.txt": b"keep"}
    assert sorted(p.name for p in parent.iterdir()) == ["dest"]


def test_failed_merge_into_existing_dest_leaves_it_unchanged(tmp_path: Path) -> None:
    """Guards the in-dest staging placement rather than a past regression: a
    conflict found by the pre-move check leaves no staging dir inside dest."""
    archive = _write_tar(
        tmp_path / "a.tar", [(_reg("a.md"), b"new a"), (_reg("claims"), b"file")]
    )
    dest = tmp_path / "dest"
    (dest / "claims").mkdir(parents=True)
    (dest / "a.md").write_bytes(b"old a")
    before = _tree(dest)

    with pytest.raises(FileExistsError) as exc:
        unpack(archive, dest)

    assert "cannot unpack file over existing directory" in str(exc.value)
    assert _tree(dest) == before
    assert sorted(p.name for p in tmp_path.iterdir()) == ["a.tar", "dest"]


STAGING_NAME = ".unpacking-" + "00" * 8  # with secrets.token_hex patched to zeros
# A trailing-dot spelling is refused earlier, by the portable-name rule.
STAGING_ALIASES = [
    "exact",
    "case",
    pytest.param(
        "8.3",
        marks=pytest.mark.skipif(
            sys.platform != "win32", reason="8.3 short names exist only on Windows"
        ),
    ),
]


def _short_name(path: Path) -> str | None:
    """The 8.3 short name Windows gave ``path``, or None if it has none."""
    import ctypes

    buf = ctypes.create_unicode_buffer(32768)
    if not ctypes.windll.kernel32.GetShortPathNameW(str(path), buf, len(buf)):
        return None
    short = Path(buf.value).name
    return None if short == path.name else short


def _staging_alias(dest: Path, kind: str, name: str = STAGING_NAME) -> str:
    """A spelling, other than through a link, that names the directory
    ``name`` unpack will create in ``dest`` (the staging dir by default);
    skips when this filesystem has none."""
    probe = dest / name
    probe.mkdir()
    try:
        if kind == "8.3":
            alias = _short_name(probe)
        else:
            alias = {"exact": name, "case": name.upper()}[kind]
        if alias is None:
            pytest.skip("this volume does not generate 8.3 short names")
        if not (os.path.lexists(dest / alias) and os.path.samefile(dest / alias, probe)):
            pytest.skip(f"on this filesystem {alias!r} is a different name")
    finally:
        probe.rmdir()
    return alias


@pytest.mark.parametrize("kind", STAGING_ALIASES)
def test_member_reaching_the_staging_dir_is_not_silently_dropped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    """A member under a name that reaches the staging dir would be moved into
    the staging tree and deleted with it. It must be refused instead."""
    import secrets

    monkeypatch.setattr(secrets, "token_hex", lambda nbytes: "00" * nbytes)
    dest = tmp_path / "dest"
    dest.mkdir()
    (dest / "old.txt").write_bytes(b"old")
    alias = _staging_alias(dest, kind)
    archive = _write_tar(
        tmp_path / "a.tar", [(_reg(f"{alias}/lost.md"), b"lost"), (_reg("kept.md"), b"kept")]
    )

    with pytest.raises(OSError) as exc:
        unpack(archive, dest)

    assert _tree(dest) == {"old.txt": b"old"}
    assert "cannot unpack over the staging directory" in str(exc.value)


@pytest.mark.parametrize("kind", STAGING_ALIASES)
def test_member_reaching_the_staging_dir_is_refused_before_any_move(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    """Such a member also hides a conflict from the pre-move check (its target
    looks absent), so the merge would fail halfway. It must be refused before
    anything in dest changes."""
    import secrets

    monkeypatch.setattr(secrets, "token_hex", lambda nbytes: "00" * nbytes)
    dest = tmp_path / "dest"
    (dest / "zzz" / "f").mkdir(parents=True)
    (dest / "a.md").write_bytes(b"old a")
    alias = _staging_alias(dest, kind)
    archive = _write_tar(
        tmp_path / "a.tar",
        [(_reg("a.md"), b"new a"), (_reg(f"{alias}/zzz/f"), b"f"), (_reg("zzz/g"), b"g")],
    )
    before = _tree(dest)

    with pytest.raises(OSError) as exc:
        unpack(archive, dest)

    assert _tree(dest) == before
    assert "cannot unpack over the staging directory" in str(exc.value)


def _fail_to_unlink(monkeypatch: pytest.MonkeyPatch, name: str) -> None:
    """Make every attempt to delete a file called ``name`` fail, as an open
    handle or an access-denied entry would."""
    real_unlink = os.unlink

    def unlink(path: str, *args: object, **kwargs: object) -> None:
        if os.path.basename(os.fspath(path)) == name:
            raise PermissionError(errno.EACCES, "Permission denied", os.fspath(path))
        real_unlink(path, *args, **kwargs)

    real_rmdir = os.rmdir

    def rmdir(path: str, *args: object, **kwargs: object) -> None:
        if os.path.basename(os.fspath(path)) == name:
            raise PermissionError(errno.EACCES, "Permission denied", os.fspath(path))
        real_rmdir(path, *args, **kwargs)

    monkeypatch.setattr(os, "unlink", unlink)
    monkeypatch.setattr(os, "remove", unlink)
    monkeypatch.setattr(os, "rmdir", rmdir)  # a directory link may go by rmdir


def test_failed_unpack_names_a_staging_dir_it_cannot_remove(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    archive, policy = _fails_after_first_member(tmp_path)
    dest = tmp_path / "dest"
    dest.mkdir()
    (dest / "keep.txt").write_bytes(b"keep")
    _fail_to_unlink(monkeypatch, "manifest.json")

    with pytest.warns(RuntimeWarning) as warned, pytest.raises(SecurityError) as exc:
        unpack(archive, dest, policy=policy)
    monkeypatch.undo()

    assert exc.value.code == ErrorCode.FILE_BYTES_EXCEEDED
    leftover = [p for p in dest.resolve().iterdir() if p.name.startswith(".unpacking-")]
    assert len(leftover) == 1
    assert any(str(leftover[0]) in str(w.message) for w in warned)


def test_failed_unpack_keeps_its_error_when_warnings_are_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import warnings

    archive, policy = _fails_after_first_member(tmp_path)
    dest = tmp_path / "dest"
    dest.mkdir()
    _fail_to_unlink(monkeypatch, "manifest.json")

    with warnings.catch_warnings():
        warnings.simplefilter("error")
        with pytest.raises(SecurityError) as exc:
            unpack(archive, dest, policy=policy)
    monkeypatch.undo()

    assert exc.value.code == ErrorCode.FILE_BYTES_EXCEEDED
    if sys.version_info >= (3, 11):  # the warning was an error; a note still names it
        leftover = [p for p in dest.resolve().iterdir() if p.name.startswith(".unpacking-")]
        assert len(leftover) == 1
        assert any(str(leftover[0]) in note for note in exc.value.__notes__)


def test_failed_unpack_removes_read_only_staged_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A read-only file (the Windows attribute blocks deletion) in the staging
    tree is made writable and removed, not left inside dest. Guards Windows
    only: POSIX deletes a read-only file in a writable directory anyway."""
    import aphelion.unpacker as unpacker

    real_extract = unpacker._extract

    def extract_then_fail(*args: object) -> None:
        real_extract(*args)
        for path in args[1].rglob("*"):  # args[1] is the staging dir
            if path.is_file():
                path.chmod(stat.S_IREAD)
        raise RuntimeError("failed after extraction")

    monkeypatch.setattr(unpacker, "_extract", extract_then_fail)
    archive = _write_tar(tmp_path / "a.tar", [(_reg("claims/a.md"), b"a")])
    dest = tmp_path / "dest"
    dest.mkdir()
    (dest / "keep.txt").write_bytes(b"keep")

    with pytest.raises(RuntimeError, match="failed after extraction"):
        unpack(archive, dest)

    assert _tree(dest) == {"keep.txt": b"keep"}


@pytest.mark.parametrize(
    "link_kind",
    [
        "symlink",
        pytest.param(
            "junction",
            marks=pytest.mark.skipif(
                sys.platform != "win32", reason="junctions exist only on Windows"
            ),
        ),
    ],
)
def test_failed_unpack_never_changes_a_link_target_in_staging(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, link_kind: str
) -> None:
    """A link in the staging tree that cannot be removed is reported, never
    made writable: that would change the read-only entry it points to. The
    symlink case guards POSIX, where chmod follows links; Windows chmod did
    not change a symlink's target even before, and the junction case covers
    the other kind of Windows link."""
    import aphelion.unpacker as unpacker

    if link_kind == "symlink":
        outside = tmp_path / "outside.txt"
        outside.write_bytes(b"outside")
    else:
        outside = tmp_path / "outside"
        outside.mkdir()
    outside.chmod(stat.S_IREAD | (stat.S_IEXEC if outside.is_dir() else 0))
    mode_before = stat.S_IMODE(outside.stat().st_mode)
    real_extract = unpacker._extract

    def extract_then_fail(*args: object) -> None:
        real_extract(*args)
        link = args[1] / "link"  # args[1] is the staging dir
        try:
            if link_kind == "junction":
                import _winapi

                _winapi.CreateJunction(str(outside), str(link))
            else:
                os.symlink(outside, link)
        except (OSError, NotImplementedError) as exc:  # Windows without the privilege
            pytest.skip(f"cannot create {link_kind}s here: {exc}")
        raise RuntimeError("failed after extraction")

    monkeypatch.setattr(unpacker, "_extract", extract_then_fail)
    archive = _write_tar(tmp_path / "a.tar", [(_reg("a.md"), b"a")])
    dest = tmp_path / "dest"
    dest.mkdir()
    _fail_to_unlink(monkeypatch, "link")

    try:
        with pytest.warns(RuntimeWarning), pytest.raises(RuntimeError):
            unpack(archive, dest)
    finally:
        monkeypatch.undo()
        mode_after = stat.S_IMODE(outside.stat().st_mode)
        outside.chmod(stat.S_IREAD | stat.S_IWRITE | stat.S_IEXEC)

    assert mode_after == mode_before
    assert outside.exists()


# ---------- a failure while moving into an existing dest is undone ----------


def _merge_archive(tmp_path: Path) -> tuple[Path, Path, dict[str, bytes | None]]:
    """An existing dest and an archive that replaces two of its files and adds
    a directory, moved in that order (top-level files first)."""
    archive = _write_tar(
        tmp_path / "a.tar",
        [
            (_reg("a.md"), b"new a"),
            (_reg("z.md"), b"new z"),
            (_dir("new"), None),
            (_reg("new/f.md"), b"new f"),
        ],
    )
    dest = tmp_path / "dest"
    dest.mkdir()
    (dest / "a.md").write_bytes(b"old a")
    (dest / "z.md").write_bytes(b"old z")
    (dest / "keep.txt").write_bytes(b"keep")
    return archive, dest, _tree(dest)


def _fail_moves(
    monkeypatch: pytest.MonkeyPatch, *, nth_staged: int, restores: bool = False
) -> None:
    """Fail the ``nth_staged`` move of an extracted file out of staging, and
    with ``restores`` also every move back out of the backup directory."""
    real_replace = os.replace
    staged_moves = []

    def replace(src: str, dst: str, **kwargs: object) -> None:
        parts = Path(os.fspath(src)).parts
        in_staging = any(p.startswith(".unpacking-") for p in parts)
        in_backup = any(p.startswith(".backup-") for p in parts)
        if in_staging and not in_backup:
            staged_moves.append(src)
            if len(staged_moves) == nth_staged:
                raise OSError(errno.EIO, "simulated I/O error", os.fspath(dst))
        if restores and in_backup:
            raise OSError(errno.EIO, "simulated I/O error", os.fspath(dst))
        real_replace(src, dst, **kwargs)

    monkeypatch.setattr(os, "replace", replace)


def test_failed_move_into_existing_dest_is_undone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An OS error after some files were replaced (a full disk, a file held
    open on Windows) puts every replaced file back and removes what was added."""
    archive, dest, before = _merge_archive(tmp_path)
    _fail_moves(monkeypatch, nth_staged=3)  # after a.md and z.md were replaced

    with pytest.raises(OSError) as exc:
        unpack(archive, dest)
    monkeypatch.undo()

    assert "simulated I/O error" in str(exc.value)
    assert _tree(dest) == before
    assert sorted(p.name for p in tmp_path.iterdir()) == ["a.tar", "dest"]


def test_failed_undo_keeps_the_backup_and_names_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    archive, dest, _ = _merge_archive(tmp_path)
    _fail_moves(monkeypatch, nth_staged=3, restores=True)

    with pytest.raises(OSError) as exc:
        unpack(archive, dest)
    monkeypatch.undo()

    backups = list(dest.resolve().glob(".unpacking-*/.backup-*"))
    assert len(backups) == 1
    assert str(backups[0]) in str(exc.value)
    assert "could not undo" in str(exc.value)
    kept = sorted(p.read_bytes() for p in backups[0].iterdir())
    assert kept == [b"old a", b"old z"]


def test_new_file_that_cannot_be_moved_back_is_replaced_by_the_original(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """All platforms: if a file that was moved in cannot be moved out again,
    its original still goes back over it, so nothing is left to report."""
    archive, dest, before = _merge_archive(tmp_path)
    _fail_moves(monkeypatch, nth_staged=3)  # after a.md and z.md were replaced
    real_replace = os.replace

    def replace(src: str, dst: str, **kwargs: object) -> None:
        back_to_staging = ".unpacking-" in os.fspath(dst) and ".backup-" not in os.fspath(dst)
        if Path(os.fspath(src)) == dest / "a.md" and back_to_staging:
            raise PermissionError(errno.EACCES, "Permission denied", os.fspath(src))
        real_replace(src, dst, **kwargs)

    monkeypatch.setattr(os, "replace", replace)

    with pytest.raises(OSError) as exc:
        unpack(archive, dest)
    monkeypatch.undo()

    assert "simulated I/O error" in str(exc.value)
    assert "could not undo" not in str(exc.value)
    assert _tree(dest) == before


@pytest.mark.skipif(
    sys.platform != "win32",
    reason="only Windows refuses to rename a file that another handle holds open",
)
def test_unpack_over_a_file_held_open_leaves_dest_unchanged(tmp_path: Path) -> None:
    archive, dest, before = _merge_archive(tmp_path)

    with open(dest / "z.md", "rb"), pytest.raises(PermissionError) as exc:
        unpack(archive, dest)

    assert getattr(exc.value, "winerror", None) == 32  # sharing violation
    assert _tree(dest) == before


@pytest.mark.skipif(
    sys.platform != "win32",
    reason="only on Windows does the read-only attribute stop a file being replaced",
)
def test_unpack_replaces_a_read_only_file(tmp_path: Path) -> None:
    archive, dest, _ = _merge_archive(tmp_path)
    (dest / "z.md").chmod(stat.S_IREAD)

    unpack(archive, dest)

    assert (dest / "z.md").read_bytes() == b"new z"
    assert not [p for p in dest.iterdir() if p.name.startswith(".unpacking-")]


def test_staging_left_after_a_complete_merge_only_warns(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """dest is fully updated, so failing to remove the empty staging dir
    afterwards must not report the unpack as failed."""
    archive, dest, _ = _merge_archive(tmp_path)
    real_rmdir = os.rmdir

    def rmdir(path: str, *args: object, **kwargs: object) -> None:
        if os.path.basename(os.fspath(path)).startswith(".unpacking-"):
            raise PermissionError(errno.EACCES, "Permission denied", os.fspath(path))
        real_rmdir(path, *args, **kwargs)

    monkeypatch.setattr(os, "rmdir", rmdir)

    with pytest.warns(RuntimeWarning, match="could not remove"):
        assert unpack(archive, dest) == dest
    monkeypatch.undo()

    assert (dest / "a.md").read_bytes() == b"new a"
    assert (dest / "new" / "f.md").read_bytes() == b"new f"


BACKUP_NAME = ".backup-" + "00" * 8  # with secrets.token_hex patched to zeros


@pytest.mark.parametrize("kind", STAGING_ALIASES)
def test_member_reaching_the_backup_dir_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    """The backup directory for replaced files sits in staging; a member that
    reaches it under any spelling is refused before anything is moved."""
    import secrets

    monkeypatch.setattr(secrets, "token_hex", lambda nbytes: "00" * nbytes)
    probe = tmp_path / "probe"  # empty, as staging is when the backup is made
    probe.mkdir()
    alias = _staging_alias(probe, kind, BACKUP_NAME)
    _, dest, before = _merge_archive(tmp_path)
    archive = _write_tar(tmp_path / "b.tar", [(_reg(f"{alias}/x"), b"x"), (_reg("a.md"), b"a")])

    with pytest.raises(FileExistsError) as exc:
        unpack(archive, dest)

    assert "cannot unpack over the backup directory" in str(exc.value)
    assert _tree(dest) == before


# ---------- an error or interrupt at any step loses nothing ----------


def _steps(
    monkeypatch: pytest.MonkeyPatch, plan: dict[int, tuple[BaseException, bool]]
) -> list[str]:
    """Number every rename, directory creation and directory removal from now
    on (1, 2, ...) and return their log, one "kind path" line each.

    ``plan`` maps a step number to ``(error, after)``: the error is raised
    before the step runs or, with ``after``, once it has returned, where an
    interrupt such as Ctrl-C can land before the caller records the step.
    """
    log: list[str] = []
    real_replace, real_rmdir, real_mkdir = os.replace, os.rmdir, Path.mkdir

    def step(kind: str, path: os.PathLike[str] | str, run: Callable[[], object]) -> object:
        log.append(f"{kind} {os.fspath(path)}")
        error, after = plan.get(len(log), (None, False))
        if error is not None and not after:
            raise error
        result = run()
        if error is not None:
            raise error
        return result

    monkeypatch.setattr(
        os, "replace", lambda s, d, **kw: step("replace", s, lambda: real_replace(s, d, **kw))
    )
    monkeypatch.setattr(
        os, "rmdir", lambda p, *a, **kw: step("rmdir", p, lambda: real_rmdir(p, *a, **kw))
    )
    monkeypatch.setattr(
        Path, "mkdir", lambda p, *a, **kw: step("mkdir", p, lambda: real_mkdir(p, *a, **kw))
    )
    return log


def _run_steps(
    monkeypatch: pytest.MonkeyPatch,
    call: Callable[[], object],
    plan: dict[int, tuple[BaseException, bool]],
) -> tuple[list[str], BaseException | None, list[warnings.WarningMessage]]:
    """Run ``call`` under :func:`_steps`; return the step log, the exception
    it raised (None if it returned) and the warnings it gave."""
    with monkeypatch.context() as patch, warnings.catch_warnings(record=True) as warned:
        warnings.simplefilter("always")
        log = _steps(patch, plan)
        try:
            call()
        except BaseException as exc:  # KeyboardInterrupt included
            return log, exc, warned
    return log, None, warned


def _named(exc: BaseException, warned: list[warnings.WarningMessage]) -> str:
    """Everything that tells the caller where things are: the message, the
    notes (Python 3.11+) and the warnings."""
    notes = getattr(exc, "__notes__", ())
    return "\n".join([str(exc), *notes, *(str(w.message) for w in warned)])


def _error(kind: type[BaseException]) -> BaseException:
    if kind is KeyboardInterrupt:
        return KeyboardInterrupt()
    return OSError(errno.EIO, "simulated I/O error")


STOPS = [
    pytest.param(KeyboardInterrupt, False, id="interrupt-before-step"),
    pytest.param(KeyboardInterrupt, True, id="interrupt-after-step"),
    pytest.param(OSError, False, id="oserror-before-step"),
    pytest.param(OSError, True, id="oserror-after-step"),
]


def _unpack_merge(tmp_path: Path) -> tuple[Callable[[], object], Path, dict[str, bytes | None]]:
    archive, dest, before = _merge_archive(tmp_path)
    return functools.partial(unpack, archive, dest), dest, before


@pytest.mark.parametrize("kind, after", STOPS)
def test_merge_stopped_at_any_step_leaves_dest_unchanged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: type[BaseException], after: bool
) -> None:
    """All platforms: an unpack into an existing dest stopped at any rename or
    directory creation, also right after it returned (a move-aside included),
    puts dest back and raises that same error, an interrupt included."""
    call, _, _ = _unpack_merge(tmp_path / "clean")
    steps, exc, _ = _run_steps(monkeypatch, call, {})
    assert exc is None
    forward = [n for n, line in enumerate(steps, 1) if not line.startswith("rmdir")]
    # a.md and z.md: move aside, move in; new/f.md: move in.
    assert sum(steps[n - 1].startswith("replace") for n in forward) == 5

    for n in forward:
        call, dest, before = _unpack_merge(tmp_path / str(n))
        error = _error(kind)
        _, exc, _ = _run_steps(monkeypatch, call, {n: (error, after)})
        assert exc is error, (steps[n - 1], exc)
        left = _tree(dest)
        assert {p: d for p, d in left.items() if not p.startswith(".unpacking-")} == before, (
            steps[n - 1]
        )
        # Only an interrupt right after staging is made, before it is on
        # record, can leave staging behind, and then it is empty.
        assert all(d is None for p, d in left.items() if p.startswith(".unpacking-")), steps[n - 1]


@pytest.mark.parametrize("kind, after", STOPS)
def test_undo_stopped_at_any_step_loses_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: type[BaseException], after: bool
) -> None:
    """All platforms: once a move into an existing dest has failed, a second
    error at any step of putting things back or cleaning up never loses an
    original file: each is back in place, or in a backup directory that the
    error or a warning names. An interrupt propagates as itself."""
    call, _, _ = _unpack_merge(tmp_path / "clean")
    steps, _, _ = _run_steps(monkeypatch, call, {})
    moves = [n for n, line in enumerate(steps, 1) if line.startswith("replace")]
    assert len(moves) == 5
    for fail_at in moves:
        call, _, _ = _unpack_merge(tmp_path / f"{fail_at}")
        undo, exc, _ = _run_steps(monkeypatch, call, {fail_at: (_error(OSError), False)})
        assert isinstance(exc, OSError)
        for n in range(fail_at + 1, len(undo) + 1):
            call, dest, before = _unpack_merge(tmp_path / f"{fail_at}-{n}")
            error = _error(kind)
            plan = {fail_at: (_error(OSError), False), n: (error, after)}
            _, exc, warned = _run_steps(monkeypatch, call, plan)
            where = (steps[fail_at - 1], undo[n - 1])
            if kind is KeyboardInterrupt:
                assert exc is error, where
            else:
                assert isinstance(exc, OSError), where
            left = _tree(dest)
            named = _named(exc, warned)
            kept = [
                file.read_bytes()
                for backup in dest.resolve().glob(".unpacking-*/.backup-*")
                if str(backup) in named
                for file in backup.iterdir()
            ]
            for path, data in before.items():
                assert left.get(path) == data or data in kept, (where, path, left, named)


# ---------- two members that reach one entry are refused ----------


WINDOWS_83 = pytest.mark.skipif(
    sys.platform != "win32", reason="8.3 short names exist only on Windows"
)


def _short_alias(tmp_path: Path, long_name: str, *, directory: bool) -> str:
    """The 8.3 short name ``long_name`` gets in an empty directory on this
    volume, as it would in a fresh staging dir; skips where there is none."""
    probe = tmp_path / "probe-83" / long_name
    probe.parent.mkdir()
    if directory:
        probe.mkdir()
    else:
        probe.write_bytes(b"")
    short = _short_name(probe)
    if directory:
        probe.rmdir()
    else:
        probe.unlink()
    probe.parent.rmdir()
    if short is None:
        pytest.skip("this volume does not generate 8.3 short names")
    return short


@WINDOWS_83
@pytest.mark.parametrize("dest_exists", [False, True], ids=["new-dest", "existing-dest"])
@pytest.mark.parametrize("layout", ["file", "implicit-parent", "explicit-directory"])
def test_member_reaching_an_earlier_member_in_staging_is_refused(
    tmp_path: Path, dest_exists: bool, layout: str
) -> None:
    """Windows only (8.3 short names): a member spelled as the short name of
    an earlier member's file or directory reaches that same entry in staging.
    It is refused before dest changes, instead of overwriting the earlier
    file (which a signature was checked against) or merging into its
    directory."""
    if layout == "file":
        short = _short_alias(tmp_path, "longfilename.txt", directory=False)
        members = [(_reg("longfilename.txt"), b"signed"), (_reg(short), b"other")]
    else:
        short = _short_alias(tmp_path, "longdirectoryname", directory=True)
        if layout == "implicit-parent":
            members = [(_reg("longdirectoryname/a"), b"a"), (_reg(f"{short}/b"), b"b")]
        else:
            members = [(_dir("longdirectoryname"), None), (_dir(short), None)]
    archive = _write_tar(tmp_path / "a.tar", members)
    dest = tmp_path / "dest"
    if dest_exists:
        dest.mkdir()
        (dest / "keep.txt").write_bytes(b"keep")
    before = _tree(dest)

    with pytest.raises(SecurityError) as exc:
        unpack(archive, dest)

    assert exc.value.code == ErrorCode.DUPLICATE_MEMBER_PATH
    assert "reaches an entry an earlier member created" in str(exc.value)
    assert _tree(dest) == before
    assert sorted(p.name for p in tmp_path.iterdir()) == ["a.tar"] + (["dest"] if dest_exists else [])


@WINDOWS_83
@pytest.mark.parametrize("had_file", [False, True], ids=["new-file", "replaced-file"])
def test_member_reaching_an_earlier_member_in_dest_is_refused(
    tmp_path: Path, had_file: bool
) -> None:
    """Windows only (8.3 short names): a member spelled like a short name,
    extracted before the long name that will get that short name, is its own
    file in staging but the same file in dest. The merge refuses it and puts
    dest back, instead of replacing the long-named file with it."""
    short = _short_alias(tmp_path, "longfilename.txt", directory=False)
    archive = _write_tar(
        tmp_path / "a.tar", [(_reg(short), b"other"), (_reg("longfilename.txt"), b"signed")]
    )
    dest = tmp_path / "dest"
    dest.mkdir()
    (dest / "keep.txt").write_bytes(b"keep")
    if had_file:
        (dest / "longfilename.txt").write_bytes(b"old")
    before = _tree(dest)

    with pytest.raises(SecurityError) as exc:
        unpack(archive, dest)

    assert exc.value.code == ErrorCode.DUPLICATE_MEMBER_PATH
    assert "already put in place" in str(exc.value)
    assert _tree(dest) == before


# ---------- an error while looking at the tree is never skipped ----------


@pytest.mark.parametrize("listing", [1, 2], ids=["pre-move-check", "merge"])
def test_unpack_fails_when_a_staged_directory_cannot_be_listed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, listing: int
) -> None:
    """All platforms: a staged directory that cannot be listed (too many open
    files, a filter driver refusing access) fails the unpack, in the check
    before any move or in the merge, and dest is left as it was. It used to
    be skipped, and the unpack reported success with files missing."""
    archive, dest, before = _merge_archive(tmp_path)
    real_scandir = os.scandir
    listed: list[str] = []

    def scandir(*args: object) -> object:
        if args and isinstance(args[0], (str, os.PathLike)):
            path = os.fspath(args[0])
            if ".unpacking-" in path and os.path.basename(path) == "new":
                listed.append(path)
                if len(listed) == listing:
                    raise PermissionError(errno.EACCES, "Permission denied", path)
        return real_scandir(*args)

    monkeypatch.setattr(os, "scandir", scandir)

    with pytest.raises(PermissionError) as exc:
        unpack(archive, dest)
    monkeypatch.undo()

    assert exc.value.filename == listed[listing - 1]
    assert _tree(dest) == before


@pytest.mark.parametrize(
    "call, name",
    [("lstat", "dest"), ("lstat", "z.md"), ("samefile", "z.md")],
    ids=["dest-link-check", "existing-target", "staging-identity-check"],
)
def test_unpack_fails_when_an_entry_cannot_be_looked_at(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, call: str, name: str
) -> None:
    """All platforms: an error other than "no such file" while looking at dest
    or at a file in it (a transient I/O error, say) fails the unpack and
    leaves dest as it was. Taken as "not there", it let a file be replaced
    without a backup, or a check pass that never ran."""
    archive, dest, before = _merge_archive(tmp_path)
    broken = os.path.normcase(dest if name == "dest" else dest / name)
    module = os if call == "lstat" else os.path
    real = getattr(module, call)

    def failing(path: str, *args: object, **kwargs: object) -> object:
        if os.path.normcase(os.path.abspath(os.fspath(path))) == broken:
            raise OSError(errno.EIO, "simulated I/O error", os.fspath(path))
        return real(path, *args, **kwargs)

    monkeypatch.setattr(module, call, failing)

    with pytest.raises(OSError) as exc:
        unpack(archive, dest)
    monkeypatch.undo()

    assert exc.value.errno == errno.EIO
    assert _tree(dest) == before


# ---------- the destination itself must not be a link ----------


def _link_or_skip(link: Path, target: Path, kind: str) -> None:
    try:
        if kind == "junction":
            import _winapi

            _winapi.CreateJunction(str(target), str(link))
        else:
            os.symlink(target, link, target_is_directory=True)
    except (OSError, NotImplementedError, ImportError) as exc:
        pytest.skip(f"cannot create {kind}s here: {exc}")


LINK_KINDS = [
    "symlink",
    pytest.param(
        "junction",
        marks=pytest.mark.skipif(sys.platform != "win32", reason="junctions exist only on Windows"),
    ),
]


@pytest.mark.parametrize("kind", LINK_KINDS)
def test_unpack_refuses_a_dangling_link_as_destination(tmp_path: Path, kind: str) -> None:
    archive = _write_tar(tmp_path / "a.tar", [(_reg("a.md"), b"a")])
    target = tmp_path / "elsewhere" / "target"
    target.mkdir(parents=True)  # a junction can only be made to an existing dir
    dest = tmp_path / "dest"
    _link_or_skip(dest, target, kind)
    target.rmdir()
    target.parent.rmdir()

    with pytest.raises(FileExistsError) as exc:
        unpack(archive, dest)

    assert "symlink or junction" in str(exc.value)
    assert not (tmp_path / "elsewhere").exists()


@pytest.mark.parametrize("kind", LINK_KINDS)
def test_unpack_refuses_a_link_to_a_directory_as_destination(
    tmp_path: Path, kind: str
) -> None:
    archive = _write_tar(tmp_path / "a.tar", [(_reg("a.md"), b"a")])
    target = tmp_path / "target"
    target.mkdir()
    dest = tmp_path / "dest"
    _link_or_skip(dest, target, kind)

    with pytest.raises(FileExistsError) as exc:
        unpack(archive, dest)

    assert "symlink or junction" in str(exc.value)
    assert list(target.iterdir()) == []


# ---------- member names must be portable ----------


@pytest.mark.parametrize(
    "name",
    [
        "old.txt:evil",  # NTFS alternate data stream
        "a<b", "a>b", 'a"b', "a|b", "a?b", "a*b",
        "a\x01b", "a\x1fb",
        "CON", "con.txt", "Nul.tar.gz", "AUX", "PRN", "COM1", "com9.md", "LPT1", "lpt9",
        "COM¹", "CON .txt",
        "dir./f.md", "dir /f.md", "f.md.", "f.md ",
        "claims/NUL",
    ],
)
def test_non_portable_member_name_is_refused(tmp_path: Path, name: str) -> None:
    archive = _write_tar(tmp_path / "a.tar", [(_reg(name), b"x")])
    dest = tmp_path / "dest"

    with pytest.raises(SecurityError) as exc:
        unpack(archive, dest)

    assert exc.value.code == ErrorCode.PATH_TRAVERSAL
    assert "not a portable file name" in str(exc.value)
    assert not dest.exists()


@pytest.mark.parametrize("name", ["CONSOLE.md", "con-x.md", "COM10", "LPT0", "a.b.c", "nul_file"])
def test_portable_names_near_device_names_are_accepted(tmp_path: Path, name: str) -> None:
    archive = _write_tar(tmp_path / "a.tar", [(_reg(name), b"x")])
    unpack(archive, tmp_path / "dest")
    assert (tmp_path / "dest" / name).read_bytes() == b"x"


def test_stream_name_does_not_replace_an_existing_file(tmp_path: Path) -> None:
    archive = _write_tar(tmp_path / "a.tar", [(_reg("old.txt:evil"), b"x")])
    dest = tmp_path / "dest"
    dest.mkdir()
    (dest / "old.txt").write_bytes(b"old")

    with pytest.raises(SecurityError) as exc:
        unpack(archive, dest)

    assert exc.value.code == ErrorCode.PATH_TRAVERSAL
    assert _tree(dest) == {"old.txt": b"old"}


# ---------- only directories this call created are removed ----------


def test_failed_unpack_keeps_a_parent_another_process_created(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    archive, policy = _fails_after_first_member(tmp_path)
    shared = tmp_path / "shared"
    dest = shared / "mine" / "dest"
    real_mkdir = Path.mkdir

    def mkdir(self: Path, *args: object, **kwargs: object) -> None:
        if self == shared and not shared.exists():
            os.mkdir(shared)  # another process gets there first
            (shared / "theirs.txt").write_bytes(b"theirs")
        real_mkdir(self, *args, **kwargs)

    monkeypatch.setattr(Path, "mkdir", mkdir)

    with pytest.raises(SecurityError) as exc:
        unpack(archive, dest, policy=policy)
    monkeypatch.undo()

    assert exc.value.code == ErrorCode.FILE_BYTES_EXCEEDED
    assert _tree(shared) == {"theirs.txt": b"theirs"}


def test_failed_staging_dir_removes_the_parents_this_call_made(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """All platforms: if the staging directory cannot be created (a full disk,
    a path too long), the missing parents made for dest are removed again."""
    archive = _write_tar(tmp_path / "a.tar", [(_reg("a.md"), b"a")])
    dest = tmp_path / "p1" / "p2" / "dest"
    real_mkdir = Path.mkdir

    def mkdir(self: Path, *args: object, **kwargs: object) -> None:
        if self.name.startswith(".dest.unpacking-"):
            raise OSError(errno.ENOSPC, "No space left on device", str(self))
        real_mkdir(self, *args, **kwargs)

    monkeypatch.setattr(Path, "mkdir", mkdir)

    with pytest.raises(OSError) as exc:
        unpack(archive, dest)
    monkeypatch.undo()

    assert exc.value.errno == errno.ENOSPC
    assert sorted(p.name for p in tmp_path.iterdir()) == ["a.tar"]
