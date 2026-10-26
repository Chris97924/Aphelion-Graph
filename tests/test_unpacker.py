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
import io
import os
import stat
import tarfile
from pathlib import Path

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


def _short_name(path: Path) -> str | None:
    """The 8.3 short name Windows gave ``path``, or None if it has none."""
    import sys

    if sys.platform != "win32":
        return None
    import ctypes

    buf = ctypes.create_unicode_buffer(32768)
    if not ctypes.windll.kernel32.GetShortPathNameW(str(path), buf, len(buf)):
        return None
    short = Path(buf.value).name
    return None if short == path.name else short


def _staging_alias(dest: Path, kind: str) -> str:
    """A spelling, other than through a link, that names the staging dir
    unpack will create in ``dest``; skips when this filesystem has none."""
    probe = dest / STAGING_NAME
    probe.mkdir()
    try:
        alias = {
            "exact": STAGING_NAME,
            "case": STAGING_NAME.upper(),
            "trailing-dot": STAGING_NAME + ".",
            "8.3": _short_name(probe),
        }[kind]
        if alias is None:
            pytest.skip("this volume does not generate 8.3 short names")
        if not (os.path.lexists(dest / alias) and os.path.samefile(dest / alias, probe)):
            pytest.skip(f"on this filesystem {alias!r} is a different name")
    finally:
        probe.rmdir()
    return alias


@pytest.mark.parametrize("kind", ["exact", "case", "trailing-dot", "8.3"])
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


@pytest.mark.parametrize("kind", ["exact", "case", "trailing-dot", "8.3"])
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

    monkeypatch.setattr(os, "unlink", unlink)
    monkeypatch.setattr(os, "remove", unlink)


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


def test_failed_unpack_removes_read_only_staged_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A read-only file (the Windows attribute blocks deletion) in the staging
    tree is made writable and removed, not left inside dest."""
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
