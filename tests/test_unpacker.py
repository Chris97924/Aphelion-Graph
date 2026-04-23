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

import io
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
