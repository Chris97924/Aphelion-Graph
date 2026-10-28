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

import ast
import bz2
import contextlib
import errno
import functools
import gzip
import io
import lzma
import os
import random
import shutil
import stat
import subprocess
import sys
import tarfile
import warnings
from pathlib import Path
from typing import Callable, Iterator

import pytest

from aphelion.error_codes import ErrorCode
from aphelion.errors import SecurityError
from aphelion.unpacker import ExtractPolicy, unpack
from aphelion.unpacker import _GLOBAL_HEADER_BYTES as GLOBAL_HEADER_BYTES
from aphelion.unpacker import _HEADER_BYTES as HEADER_BYTES
from aphelion.unpacker import _header_bytes


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


# ---------- declared sizes are checked before the scan reads past a member ----------


BIG_MEMBER = 16 * 1024 * 1024  # zeros: about 160 KB once gzipped at level 1


def _count_decompressed(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    """A one-item list that counts the bytes gzip decompresses from now on."""
    import gzip

    reader = getattr(gzip, "_GzipReader", None)
    if reader is None:
        pytest.skip("this Python's gzip has no reader to count with")
    count = [0]
    real_read = reader.read

    def read(self: object, size: int = -1) -> bytes:
        data = real_read(self, size)
        count[0] += len(data)
        return data

    monkeypatch.setattr(reader, "read", read)
    return count


@pytest.mark.parametrize("via", ["unpack", "check_member_names"])
@pytest.mark.parametrize("budget", ["per-file", "total", "ratio"])
def test_member_over_a_budget_is_refused_before_its_data_is_decompressed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, budget: str, via: str
) -> None:
    """All platforms: in a compressed archive, reading on to the next header
    decompresses a member's data. A member whose declared size is over the
    per-file, the total or the compression-ratio budget is refused, with
    the code unpack uses for it, before that: what is decompressed stays
    within the budgets (here under 1 MiB, for a 16 MiB member), for unpack
    and for the header check signature validation runs."""
    from aphelion.unpacker import check_member_names

    archive = tmp_path / "a.tar.gz"
    with tarfile.open(archive, "w:gz", compresslevel=1) as tar:
        for name, size in [("a.bin", 4096), ("big.bin", BIG_MEMBER)]:
            info = tarfile.TarInfo(name)
            info.size = size
            tar.addfile(info, io.BytesIO(bytes(size)))
    policy, code = {
        "per-file": (ExtractPolicy(max_file_bytes=1024 * 1024), ErrorCode.FILE_BYTES_EXCEEDED),
        "total": (
            ExtractPolicy(max_file_bytes=2 * BIG_MEMBER, max_total_bytes=1024 * 1024),
            ErrorCode.TOTAL_BYTES_EXCEEDED,
        ),
        "ratio": (
            ExtractPolicy(
                max_file_bytes=2 * BIG_MEMBER,
                max_total_bytes=2 * BIG_MEMBER,
                max_compression_ratio=10,
            ),
            ErrorCode.COMPRESSION_RATIO_EXCEEDED,
        ),
    }[budget]
    count = _count_decompressed(monkeypatch)

    with pytest.raises(SecurityError) as exc:
        if via == "unpack":
            unpack(archive, tmp_path / "dest", policy=policy)
        else:
            check_member_names(archive, policy)
    decompressed = count[0]
    monkeypatch.undo()

    assert exc.value.code == code
    assert decompressed < 1024 * 1024, decompressed
    assert sorted(p.name for p in tmp_path.iterdir()) == ["a.tar.gz"]


# ---------- what is read stays bounded, whatever the headers say ----------


def _raw_header(name: bytes, size: int, typeflag: bytes = b"0") -> bytes:
    """A ustar header (a regular file by default); a negative size, or one
    too large for 11 octal digits, goes in base-256."""
    block = bytearray(512)
    block[0 : len(name)] = name
    block[100:108] = b"0000644\0"
    block[108:116] = b"0000000\0"
    block[116:124] = b"0000000\0"
    if 0 <= size < 8**11:
        block[124:136] = b"%011o\0" % size
    elif size > 0:
        block[124:136] = b"\x80" + size.to_bytes(11, "big")
    else:
        block[124:136] = b"\xff" + ((1 << 88) + size).to_bytes(11, "big")
    block[136:148] = b"00000000000\0"
    block[156:157] = typeflag
    block[257:263] = b"ustar\0"
    block[263:265] = b"00"
    block[148:156] = b" " * 8
    block[148:156] = b"%06o\0 " % sum(block)
    return bytes(block)


def _negative_size_chain(jumps: int, filler: int) -> bytes:
    """a.bin, whose data holds ``jumps`` headers and then random filler,
    followed by ``jumps`` headers declaring negative sizes. A tarfile that
    follows a negative size moves from each of those back into a.bin's data,
    where a header moves it forward to the next one."""
    data_len = 512 * jumps + filler
    tail = 512 + data_len
    body = bytearray(data_len)
    body[512 * jumps :] = random.Random(1).randbytes(filler)
    for k in range(jumps):
        here = 512 + 512 * k
        body[512 * k : 512 * (k + 1)] = _raw_header(
            b"c%05d" % k, tail + 512 * (k + 1) - (here + 512)
        )
    chain = b"".join(
        _raw_header(b"n%05d" % k, (512 + 512 * k) - (tail + 512 * k + 512))
        for k in range(jumps)
    )
    return _raw_header(b"a.bin", data_len) + bytes(body) + chain + bytes(1024)


@pytest.mark.parametrize("via", ["unpack", "check_member_names"])
@pytest.mark.parametrize(
    "pax",
    [
        {"GNU.sparse.size": "0"},
        {"GNU.sparse.size": "0", "GNU.sparse.map": "0,0", "GNU.sparse.name": "big.bin"},
        {"GNU.sparse.major": "1", "GNU.sparse.minor": "0", "GNU.sparse.realsize": "10"},
    ],
    ids=["sparse-0.0", "sparse-0.1", "sparse-1.0"],
)
def test_sparse_member_is_refused_before_its_data_is_decompressed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, pax: dict[str, str], via: str
) -> None:
    """All platforms: GNU sparse keywords make tarfile report a size far
    below the data it skips. A sparse member is refused (PX_E_6008) before
    the reader moves past its 16 MiB of stored data."""
    from aphelion.unpacker import check_member_names

    archive = tmp_path / "a.tar.gz"
    with tarfile.open(archive, "w:gz", compresslevel=1, format=tarfile.PAX_FORMAT) as tar:
        info = tarfile.TarInfo("big.bin")
        info.size = BIG_MEMBER
        info.pax_headers = dict(pax)
        data = bytearray(BIG_MEMBER)
        if "GNU.sparse.major" in pax:
            data[:7] = b"1\n0\n10\n"  # the sparse map that opens 1.0 data
        tar.addfile(info, io.BytesIO(bytes(data)))
        after = tarfile.TarInfo("after.md")
        after.size = 2
        tar.addfile(after, io.BytesIO(b"ok"))
    policy = ExtractPolicy(max_file_bytes=1024, max_total_bytes=4096)
    count = _count_decompressed(monkeypatch)

    with pytest.raises(SecurityError) as exc:
        if via == "unpack":
            unpack(archive, tmp_path / "dest", policy=policy)
        else:
            check_member_names(archive, policy)
    decompressed = count[0]
    monkeypatch.undo()

    assert exc.value.code == ErrorCode.DISALLOWED_MEMBER_TYPE
    assert "sparse" in str(exc.value)
    assert decompressed < 1024 * 1024, decompressed
    assert sorted(p.name for p in tmp_path.iterdir()) == ["a.tar.gz"]


_FORMATS = ["tar", "gz", "bz2", "xz", "zst"]


def _compressed(raw: bytes, fmt: str) -> bytes:
    if fmt == "gz":
        return gzip.compress(raw, mtime=0)
    if fmt == "bz2":
        return bz2.compress(raw)
    if fmt == "xz":
        return lzma.compress(raw)
    if fmt == "zst":
        zstd = pytest.importorskip("compression.zstd", reason="zstd needs Python 3.14+")
        return zstd.compress(raw)
    return raw


def _tar_bytes(members: list[tuple[str, bytes]]) -> bytes:
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as tar:
        for name, data in members:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return raw.getvalue()


LIMITS = ExtractPolicy(max_files=32, max_total_bytes=256 * 1024, max_file_bytes=64 * 1024)


@pytest.mark.parametrize("fmt", _FORMATS)
@pytest.mark.parametrize("shape", ["files-and-total-at-limit", "file-at-limit"])
def test_archive_at_the_limits_unpacks_in_full(tmp_path: Path, fmt: str, shape: str) -> None:
    """All platforms: an archive right at the policy's limits (32 members of
    8 KiB, 256 KiB in all, each with a pax header for its non-ASCII name; or
    one member of exactly max-file-bytes), in every compression tarfile
    reads, passes the header checks and unpacks in full."""
    from aphelion.unpacker import check_member_names

    rng = random.Random(shape)
    if shape == "file-at-limit":
        members = [("é-only.bin", rng.randbytes(LIMITS.max_file_bytes))]
    else:
        size = LIMITS.max_total_bytes // LIMITS.max_files
        members = [(f"é{i:03d}.bin", rng.randbytes(size)) for i in range(LIMITS.max_files)]
    archive = tmp_path / f"a.{fmt}"
    archive.write_bytes(_compressed(_tar_bytes(members), fmt))

    check_member_names(archive, LIMITS)
    dest = unpack(archive, tmp_path / "dest", policy=LIMITS)

    assert {p.name: p.read_bytes() for p in dest.iterdir()} == dict(members)


@pytest.mark.parametrize("fmt", _FORMATS)
def test_longest_paths_at_the_limits_pass_the_header_checks(tmp_path: Path, fmt: str) -> None:
    """All platforms: max-files members whose paths are max-path-length
    characters of four UTF-8 bytes each (the largest pax header a package
    needs), with block padding of 511 bytes after nearly every one and
    max-total-bytes of data in all, still pass the header checks."""
    from aphelion.unpacker import check_member_names

    rng = random.Random(3)
    stem = "\U0001d11e" * (LIMITS.max_path_length - 3)
    sizes = [8193] * (LIMITS.max_files - 1)
    sizes.append(LIMITS.max_total_bytes - sum(sizes))
    members = [(f"{i:03d}" + stem, rng.randbytes(size)) for i, size in enumerate(sizes)]
    archive = tmp_path / f"a.{fmt}"
    archive.write_bytes(_compressed(_tar_bytes(members), fmt))

    check_member_names(archive, LIMITS)


@pytest.mark.parametrize(
    "head",
    [b"\x1f\x8b\x08", b"BZh91AY&SY", b"\xfd7zXZ\x00", b"\x28\xb5\x2f\xfd"],
    ids=["gzip", "bzip2", "xz", "zstd"],
)
def test_a_file_that_only_starts_like_a_compressed_archive_is_not_a_tar_archive(
    tmp_path: Path, head: bytes
) -> None:
    """All platforms: as with tarfile.open, a file whose leading bytes name
    a compression but which does not decompress to a tar archive is a
    tarfile.ReadError."""
    from aphelion.unpacker import check_member_names

    path = tmp_path / "a.tar"
    path.write_bytes(head + bytes(1024))

    with pytest.raises(tarfile.ReadError):
        check_member_names(path)
    with pytest.raises(tarfile.ReadError):
        unpack(path, tmp_path / "dest")
    assert not (tmp_path / "dest").exists()


# ---------- one pass over an archive hands tarfile a bounded number of bytes ----------


@pytest.fixture
def passes(monkeypatch: pytest.MonkeyPatch) -> list:
    """Every reader tarfile reads an archive through from now on: one per
    pass over the archive, each counting the bytes it handed tarfile."""
    import aphelion.unpacker as unpacker

    made: list = []
    real_init = unpacker._ForwardReader.__init__

    def init(self: object, *args: object, **kwargs: object) -> None:
        real_init(self, *args, **kwargs)
        made.append(self)

    monkeypatch.setattr(unpacker._ForwardReader, "__init__", init)
    return made


def _pass_limit(policy: ExtractPolicy) -> int:
    """The most one pass may hand tarfile under ``policy``."""
    header_bytes = _header_bytes(policy)
    return (
        policy.max_total_bytes
        + policy.max_files * (header_bytes + 511)
        + header_bytes
        + GLOBAL_HEADER_BYTES
    )


FIRST_LIMIT = HEADER_BYTES + GLOBAL_HEADER_BYTES  # what tarfile may read before the first member
END = bytes(1024)


def _padded(data: bytes) -> bytes:
    return data + bytes(-len(data) % 512)


def _file(name: bytes, data: bytes) -> bytes:
    return _raw_header(name, len(data)) + _padded(data)


def _pax_record(key: str, value: str) -> bytes:
    body = f" {key}={value}\n".encode()
    length = len(body)
    while length != len(body) + len(str(length)):
        length = len(body) + len(str(length))
    return str(length).encode() + body


def _pax(records: dict[str, str], typeflag: bytes = b"x") -> bytes:
    """A pax header (``g``: a global one) holding ``records``."""
    body = b"".join(_pax_record(k, v) for k, v in records.items())
    return _raw_header(b"././@PaxHeader", len(body), typeflag) + _padded(body)


def _pax_blocks(blocks: int, typeflag: bytes = b"x") -> bytes:
    """A pax header whose records fill exactly ``blocks`` blocks."""
    size = 512 * blocks
    body = _pax_record("comment", "x" * (size - len(str(size)) - len(" comment=\n")))
    assert len(body) == size
    return _raw_header(b"././@PaxHeader", size, typeflag) + body


def _zero_member(name: bytes, size: int, before: bytes = b"") -> bytes:
    return before + _raw_header(name, size) + bytes(size + (-size % 512)) + END


def _compress(raw: bytes, fmt: str) -> bytes:
    if fmt == "gz":
        return gzip.compress(raw, compresslevel=1, mtime=0)
    return _compressed(raw, fmt)


def _outcome(call: Callable[[], object]) -> str:
    try:
        call()
    except SecurityError as exc:
        return str(exc.code)
    except tarfile.ReadError:
        return "ReadError"
    return "ok"


def _entries(archive: Path, dest: Path, policy: ExtractPolicy) -> dict[str, Callable[[], object]]:
    from aphelion.unpacker import (
        check_member_names,
        extract_signatures_jsonl,
        extract_signer_manifests,
    )

    return {
        "unpack": lambda: unpack(archive, dest, policy=policy),
        "check_member_names": lambda: check_member_names(archive, policy),
        "extract_signatures_jsonl": lambda: extract_signatures_jsonl(archive),
        "extract_signer_manifests": lambda: extract_signer_manifests(archive),
    }


MIB = 1024 * 1024


def _bounded_cases() -> list:
    """(build, format, policy, outcome, per-pass limit, entries) per case."""
    small = ExtractPolicy(max_file_bytes=1024)
    lax = ExtractPolicy(max_compression_ratio=10_000)
    every = ("unpack", "check_member_names", "extract_signatures_jsonl", "extract_signer_manifests")
    policy_bound = ("unpack", "check_member_names")
    return [
        pytest.param(
            lambda: _zero_member(b"zero.bin", 64 * MIB), "gz", small,
            ErrorCode.FILE_BYTES_EXCEEDED, FIRST_LIMIT, every, id="honest-64MiB-member",
        ),
        pytest.param(
            lambda: _zero_member(b"big.bin", 16 * MIB, _pax({"GNU.sparse.size": "16"})),
            "gz", None, ErrorCode.DISALLOWED_MEMBER_TYPE, FIRST_LIMIT, every,
            id="sparse-size-below-the-data",
        ),
        pytest.param(
            lambda: _zero_member(b"big.bin", 16 * MIB, _pax({"GNU.sparse.realsize": "16"})),
            "gz", None, ErrorCode.DISALLOWED_MEMBER_TYPE, FIRST_LIMIT, every,
            id="sparse-realsize-only",
        ),
        pytest.param(
            lambda: _zero_member(b"big.bin", 64 * MIB, _pax({"size": "0"}, b"g")),
            "gz", None, ErrorCode.FILE_BYTES_EXCEEDED, FIRST_LIMIT, every,
            id="global-size-over-the-data",
        ),
        pytest.param(
            lambda: _file(b"a.md", b"a" * 5) + _raw_header(b"n.md", -512) + bytes(10240),
            "gz", None, ErrorCode.FILE_BYTES_EXCEEDED, 1024 + HEADER_BYTES, every,
            id="negative-size-back-to-its-own-header",
        ),
        pytest.param(
            lambda: _negative_size_chain(50, 256 * 1024), "gz", None,
            ErrorCode.FILE_BYTES_EXCEEDED,
            512 * 51 + 256 * 1024 + HEADER_BYTES, every,
            id="negative-size-hides-members",
        ),
        pytest.param(
            lambda: _raw_header(b"huge.bin", 1 << 64), "tar", None,
            ErrorCode.FILE_BYTES_EXCEEDED, 512, every, id="size-2-64-and-no-data",
        ),
        pytest.param(
            lambda: _pax({"size": "0"}, b"g") + _raw_header(b"huge.bin", 1 << 64), "tar", None,
            ErrorCode.FILE_BYTES_EXCEEDED, 1536, every, id="global-size-over-2-64",
        ),
        pytest.param(
            lambda: _pax({"comment": "x" * (16 * MIB)}) + _file(b"a.md", b"a") + END,
            "gz", ExtractPolicy(max_file_bytes=4096), ErrorCode.ARCHIVE_BOMB, FIRST_LIMIT,
            every, id="16MiB-pax-record",
        ),
        pytest.param(
            lambda: _raw_header(b"././@LongLink", 16 * MIB, b"L") + _padded(b"n" * (16 * MIB))
            + _file(b"a.md", b"a") + END,
            "gz", None, ErrorCode.ARCHIVE_BOMB, FIRST_LIMIT, every, id="16MiB-long-name",
        ),
        pytest.param(
            lambda: _file(b"a.md", b"a") + b"\x01" * 512 + _file(b"b.md", b"b") + END,
            "tar", None, "ReadError", 1024 + HEADER_BYTES, every,
            id="damaged-header-between-members",
        ),
        *[
            pytest.param(
                lambda flag=flag: _raw_header(b"x", 0, flag) + END, "tar", None,
                ErrorCode.DISALLOWED_MEMBER_TYPE, 1536, every, id=f"type-{name}",
            )
            for flag, name in [
                (b"1", "hardlink"), (b"2", "symlink"), (b"3", "char"), (b"4", "block"),
                (b"6", "fifo"), (b"S", "gnu-sparse"),
            ]
        ],
        pytest.param(
            lambda: _pax({"size": "2048"}) + _file(b"a.md", b"a" * 1024) + bytes(1024) + END,
            "tar", None, ErrorCode.FILE_BYTES_EXCEEDED, FIRST_LIMIT, every,
            id="pax-size-over-the-header",
        ),
        pytest.param(
            lambda: _pax({"size": "0"}) + _file(b"a.md", b"a" * 1024) + END,
            "tar", None, ErrorCode.FILE_BYTES_EXCEEDED, FIRST_LIMIT, every,
            id="pax-size-under-the-header",
        ),
        pytest.param(
            lambda: _raw_header(b"cut.bin", MIB) + bytes(4096), "tar", lax,
            ErrorCode.ARCHIVE_BOMB, 512 + 4096, policy_bound, id="cut-short-in-the-data",
        ),
        pytest.param(
            lambda: _raw_header(b"a.bin", 25 * MIB) + bytes(512), "tar", None,
            ErrorCode.COMPRESSION_RATIO_EXCEEDED, 1024, policy_bound,
            id="ratio-1KB-archive-declaring-25MiB",
        ),
        pytest.param(
            lambda: _file(b"a.md", b"a") + END + b"\x01" * 512, "tar", None, "ReadError",
            1024 + HEADER_BYTES, every, id="data-after-the-end",
        ),
    ]


@pytest.mark.parametrize("build, fmt, policy, expected, limit, entries", _bounded_cases())
def test_a_pass_over_an_archive_hands_tarfile_a_bounded_number_of_bytes(
    tmp_path: Path,
    passes: list,
    build: Callable[[], bytes],
    fmt: str,
    policy: ExtractPolicy | None,
    expected: str,
    limit: int,
    entries: tuple[str, ...],
) -> None:
    """All platforms and Python versions: each archive is refused the same
    way, with tarfile handed at most ``limit`` bytes in every pass, whatever
    the headers declare. A negative size is refused with PX_E_6010 whether
    tarfile reports it or stops at its header. Nothing is left in the
    destination."""
    archive = tmp_path / f"a.tar.{fmt}"
    archive.write_bytes(_compress(build(), fmt))
    policy = policy or ExtractPolicy.default()
    calls = _entries(archive, tmp_path / "dest", policy)
    for entry in entries:
        passes.clear()
        assert _outcome(calls[entry]) == str(expected), entry
        assert passes, entry
        for reader in passes:
            assert reader.handed <= limit, (entry, reader.handed)
            assert reader._eof_reads <= 9, (entry, reader._eof_reads)
    assert sorted(p.name for p in tmp_path.iterdir()) == [archive.name]


def test_xz_archive_needing_more_decoder_memory_than_the_limit_is_refused(
    tmp_path: Path, passes: list
) -> None:
    """All platforms: an xz archive of a few bytes can declare a 4 GiB
    dictionary, which the decoder would allocate. It is refused (PX_E_6013)
    while the memory traced stays under the decoder limit, before tarfile
    is handed a byte; an archive compressed with xz -9e, the largest
    preset, unpacks."""
    import struct
    import tracemalloc
    import zlib

    from aphelion.unpacker import _XZ_MEMLIMIT, check_member_names

    stream = bytearray(lzma.compress(bytes(1024), filters=[{"id": lzma.FILTER_LZMA2, "preset": 1}]))
    header = stream[12 : 12 + (stream[12] + 1) * 4]
    assert header[2:4] == b"\x21\x01"  # one LZMA2 filter, one property byte
    header[4] = 40  # the largest dictionary the format can declare
    header[-4:] = struct.pack("<I", zlib.crc32(bytes(header[:-4])))
    stream[12 : 12 + len(header)] = header
    archive = tmp_path / "a.tar.xz"
    archive.write_bytes(bytes(stream))
    assert len(stream) < 100

    tracemalloc.start()
    try:
        with pytest.raises(SecurityError) as exc:
            check_member_names(archive)
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert exc.value.code == ErrorCode.ARCHIVE_BOMB
    assert peak < _XZ_MEMLIMIT, peak
    assert [reader.handed for reader in passes] == [0]

    members = [("a.md", b"a" * 4096), ("b/c.md", b"c")]
    raw = _tar_bytes(members)
    archive.write_bytes(lzma.compress(raw, preset=9 | lzma.PRESET_EXTREME))
    dest = unpack(archive, tmp_path / "dest")
    assert (dest / "a.md").read_bytes() == b"a" * 4096
    assert (dest / "b" / "c.md").read_bytes() == b"c"
    assert all(reader.handed <= len(raw) for reader in passes)


def test_xz_and_lzma_archives_read_concatenated_streams_and_ignore_what_follows(
    tmp_path: Path,
) -> None:
    """All platforms: as lzma.LZMAFile reads them, an archive split over
    concatenated xz streams is read in full, and bytes after the last
    stream that are not a stream are ignored; an LZMA-alone archive is
    read too."""
    data = random.Random(6).randbytes(40_000)
    raw = _file(b"a.md", data) + _file(b"b.md", b"b") + END
    archive = tmp_path / "a.tar.xz"
    archive.write_bytes(lzma.compress(raw[:20_000]) + lzma.compress(raw[20_000:]) + b"\x01" * 32)
    dest = unpack(archive, tmp_path / "dest")
    assert {p.name: p.read_bytes() for p in dest.iterdir()} == {"a.md": data, "b.md": b"b"}
    alone = tmp_path / "a.tar.lzma"
    alone.write_bytes(lzma.compress(raw, format=lzma.FORMAT_ALONE))
    assert unpack(alone, tmp_path / "dest2").joinpath("b.md").read_bytes() == b"b"


def test_zstd_frames_outside_the_supported_form_are_not_tar_archives(
    tmp_path: Path, passes: list
) -> None:
    """Python 3.14+: a zstd frame that needs a 2 GiB window is refused by
    the decoder before tarfile is handed a byte, and an archive starting
    with a skippable frame is not read as zstd; both are tarfile.ReadError."""
    pytest.importorskip("compression.zstd", reason="zstd needs Python 3.14+")
    from aphelion.unpacker import check_member_names

    raw = _tar_bytes([("a.md", b"a")])
    # frame header: no single segment, window descriptor 2**31; one raw last block
    frame = b"\x28\xb5\x2f\xfd\x00\xa8" + ((len(raw) << 3) | 1).to_bytes(3, "little") + raw
    skippable = b"\x50\x2a\x4d\x18" + (4).to_bytes(4, "little") + b"skip"
    for body, limit in ((frame, 0), (skippable + frame, FIRST_LIMIT)):
        archive = tmp_path / "a.tar.zst"
        archive.write_bytes(body)
        passes.clear()
        with pytest.raises(tarfile.ReadError):
            check_member_names(archive)
        assert [reader.handed <= limit for reader in passes] == [True]


@pytest.mark.parametrize("body", [bytes(1024), bytes(10240), bytes(512), b""],
                         ids=["two-zero-blocks", "zero-record", "one-zero-block", "empty-file"])
def test_archive_of_zero_blocks_only_is_empty(tmp_path: Path, passes: list, body: bytes) -> None:
    """All platforms and Python versions: an archive of zero blocks only has
    no members (Python 3.10's tarfile reads past it by seeking back, which
    stream mode cannot do); an empty file is not an archive."""
    from aphelion.unpacker import check_member_names

    archive = tmp_path / "a.tar"
    archive.write_bytes(body)
    if not body:
        with pytest.raises(tarfile.ReadError):
            check_member_names(archive)
        return
    check_member_names(archive)
    assert list(unpack(archive, tmp_path / "dest").iterdir()) == []
    assert all(reader.handed <= len(body) for reader in passes)


# Header blocks: a pax header of n blocks is 512 * (n + 1) bytes, and a member's
# own ustar header 512 more.
@pytest.mark.parametrize(
    "build, ok",
    [
        pytest.param(lambda: _pax_blocks(6) + _file(b"a.md", b"a") + END, True,
                     id="first-member-4096"),
        pytest.param(lambda: _pax_blocks(7) + _file(b"a.md", b"a") + END, False,
                     id="first-member-4608"),
        pytest.param(lambda: _file(b"a.md", b"a") + _pax_blocks(6) + _file(b"b.md", b"b") + END,
                     True, id="later-member-4096"),
        pytest.param(lambda: _file(b"a.md", b"a") + _pax_blocks(7) + _file(b"b.md", b"b") + END,
                     False, id="later-member-4608"),
        pytest.param(lambda: _pax_blocks(1, b"g") + _pax_blocks(6) + _file(b"a.md", b"a") + END,
                     True, id="global-and-first-member-5120"),
        pytest.param(lambda: _pax_blocks(2, b"g") + _pax_blocks(6) + _file(b"a.md", b"a") + END,
                     False, id="global-and-first-member-5632"),
        pytest.param(lambda: _pax_blocks(1, b"g") + _pax_blocks(7) + _file(b"a.md", b"a") + END,
                     False, id="global-and-first-member-5632-local"),
        pytest.param(lambda: _pax_blocks(1, b"g") + _pax_blocks(5) + _file(b"a.md", b"a") + END,
                     True, id="global-and-first-member-4608"),
        pytest.param(lambda: _file(b"a.md", b"a") + _pax_blocks(1, b"g") + _pax_blocks(5)
                     + _file(b"b.md", b"b") + END, False, id="global-and-later-member-4608"),
        pytest.param(lambda: _file(b"a.md", b"a") + _pax_blocks(1, b"g") + _pax_blocks(4)
                     + _file(b"b.md", b"b") + END, True, id="global-and-later-member-4096"),
    ],
)
def test_header_blocks_of_a_member_stay_within_their_allowance(
    tmp_path: Path, passes: list, build: Callable[[], bytes], ok: bool
) -> None:
    """All platforms and Python versions: a member's header blocks may take
    4,096 bytes, and the first member's 1,024 more for a global pax header
    before it; a later global header gets no more. One block over is
    refused (PX_E_6013), and tarfile is never handed a byte past the
    allowance: header blocks come in 512 bytes, so the next block is the
    one that would need the first byte over."""
    from aphelion.unpacker import check_member_names

    raw = build()
    archive = tmp_path / "a.tar.gz"
    archive.write_bytes(gzip.compress(raw, mtime=0))
    first_end = 1024 if raw.startswith(b"a.md") else 0
    if ok:
        check_member_names(archive)
        assert unpack(archive, tmp_path / "dest").joinpath("a.md").read_bytes() == b"a"
        return
    for call in (lambda: check_member_names(archive), lambda: unpack(archive, tmp_path / "dest")):
        passes.clear()
        with pytest.raises(SecurityError) as exc:
            call()
        assert exc.value.code == ErrorCode.ARCHIVE_BOMB
        limit = first_end + HEADER_BYTES if first_end else FIRST_LIMIT
        assert all(reader.handed <= limit for reader in passes), [r.handed for r in passes]
    assert not (tmp_path / "dest").exists()


def test_data_after_the_end_of_the_archive_is_not_ignored(tmp_path: Path, passes: list) -> None:
    """All platforms: non-zero bytes within 4,096 bytes after the end of the
    last member make every reader fail with tarfile.ReadError, none of them
    returning as if the archive ended there; past that they are not read,
    as tar reads the first of two archives written one after the other."""
    from aphelion.unpacker import (
        check_member_names,
        extract_signatures_jsonl,
        extract_signer_manifests,
    )

    first = _tar_bytes([("signatures.jsonl", b"{}\n"), ("signers/s.json", b"{}")])
    archive = tmp_path / "a.tar"
    archive.write_bytes(first[:2048] + bytes(1024) + b"\x01" + bytes(511) + END)
    for call in (
        lambda: unpack(archive, tmp_path / "dest"),
        lambda: check_member_names(archive),
        lambda: extract_signatures_jsonl(archive),
        lambda: extract_signer_manifests(archive),
    ):
        with pytest.raises(tarfile.ReadError, match="after the end"):
            call()
    assert not (tmp_path / "dest").exists()

    archive.write_bytes(first + _tar_bytes([("other.md", b"x")]))
    assert extract_signatures_jsonl(archive) == b"{}\n"
    assert sorted(p.name for p in unpack(archive, tmp_path / "dest").iterdir()) == [
        "signatures.jsonl",
        "signers",
    ]
    assert len(passes) == 7
    assert all(reader.handed <= 2048 + HEADER_BYTES for reader in passes)


@pytest.mark.parametrize("via", ["unpack", "check_member_names"])
def test_negative_member_size_is_refused_before_tarfile_moves_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, via: str
) -> None:
    """All platforms and Python versions: a negative size would make tarfile
    move backwards, which its stream mode cannot. It is refused (PX_E_6010)
    whether tarfile reports such a member or stops at its header, and what
    is decompressed stays under 1 MiB for a 0.3 MB archive."""
    from aphelion.unpacker import check_member_names

    archive = tmp_path / "a.tar.gz"
    archive.write_bytes(gzip.compress(_negative_size_chain(50, 256 * 1024), mtime=0))
    count = _count_decompressed(monkeypatch)

    outcome = _outcome(
        (lambda: unpack(archive, tmp_path / "dest"))
        if via == "unpack"
        else (lambda: check_member_names(archive))
    )
    decompressed = count[0]
    monkeypatch.undo()

    assert decompressed < 1024 * 1024, decompressed
    assert outcome == str(ErrorCode.FILE_BYTES_EXCEEDED)


@pytest.mark.parametrize("fmt", ["gz", "bz2", "xz"])
@pytest.mark.parametrize("accessor", ["extract_signatures_jsonl", "extract_signer_manifests"])
def test_accessors_refuse_a_member_whose_size_leads_back_to_its_own_header(
    tmp_path: Path, passes: list, fmt: str, accessor: str
) -> None:
    """All platforms and Python versions: a member whose negative size would
    send tarfile back to its own header is refused by the accessors as by
    unpack, in one pass that reads no more than the archive holds, in
    little memory."""
    import tracemalloc

    import aphelion.unpacker as unpacker

    raw = _file(b"a.md", b"x" * 5) + _raw_header(b"n.md", -512) + bytes(10240)
    archive = tmp_path / f"a.tar.{fmt}"
    archive.write_bytes(_compressed(raw, fmt))
    tracemalloc.start()
    try:
        outcome = _outcome(lambda: getattr(unpacker, accessor)(archive))
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert peak < 16 * MIB, peak
    assert outcome == str(ErrorCode.FILE_BYTES_EXCEEDED)
    assert len(passes) == 1
    assert passes[0].handed <= len(raw)


def _negative_size_before(kind: bytes) -> bytes:
    """a.md, then a pax (``x``) or GNU long-name (``L``) header declaring a
    negative size, its data, the header of hidden.md, and z's header, which
    starts 512 or 2,560 bytes before byte 5,120: up to there tarfile may
    read before a.md's headers are checked. A tarfile that reads a negative
    size as "all but that many of the bytes it holds" takes z for the next
    header and never reports hidden.md."""
    if kind == b"x":
        middle = (
            _raw_header(b"././@PaxHeader", -512, b"x")
            + _padded(_pax_record("path", "b.md"))
            + _file(b"hidden.md", b"h" * 2048)
        )
    else:
        middle = (
            _raw_header(b"././@LongLink", -2560, b"L")
            + _padded(b"b.md")
            + _raw_header(b"hidden.md", 0)
        )
    return _file(b"a.md", b"a") + middle + _raw_header(b"z", 0) + bytes(10240)


@pytest.mark.parametrize("fmt", ["tar", "gz"])
@pytest.mark.parametrize("kind", [b"x", b"L"], ids=["pax-header", "long-name"])
def test_a_negative_size_in_the_headers_before_a_member_is_refused_on_every_release(
    tmp_path: Path, passes: list, kind: bytes, fmt: str
) -> None:
    """All platforms and Python versions: a pax or GNU long-name header
    declaring a negative size is refused (PX_E_6010) by every entry point,
    whether this release's tarfile stops at it or reads on to a later
    header. The header blocks before a member are read again from the
    bytes handed to tarfile, so the outcome does not depend on what tarfile
    made of them."""
    archive = tmp_path / f"a.tar.{fmt}"
    archive.write_bytes(_compress(_negative_size_before(kind), fmt))
    for entry, call in _entries(archive, tmp_path / "dest", ExtractPolicy.default()).items():
        passes.clear()
        assert _outcome(call) == str(ErrorCode.FILE_BYTES_EXCEEDED), entry
        assert all(reader.handed <= FIRST_LIMIT for reader in passes), entry
    assert sorted(p.name for p in tmp_path.iterdir()) == [archive.name]


@pytest.mark.parametrize(
    "records",
    [{"size": "-512"}, {"size": "x", "GNU.sparse.size": "-512"}, {"GNU.sparse.realsize": "-1"}],
    ids=["size", "sparse-size-after-an-unreadable-size", "sparse-realsize"],
)
def test_a_negative_size_in_a_pax_record_is_refused_on_every_release(
    tmp_path: Path, records: dict[str, str]
) -> None:
    """All platforms and Python versions: a pax record giving a member a
    negative size is refused (PX_E_6010) by every entry point, whether this
    release's tarfile reports the member, skips it or stops there."""
    raw = (
        _pax(records) + _file(b"a.md", b"a" * 600) + _raw_header(b"d", 0, b"5")
        + _file(b"b.md", b"b") + END
    )
    archive = tmp_path / "a.tar"
    archive.write_bytes(raw)
    calls = _entries(archive, tmp_path / "dest", ExtractPolicy.default())
    assert {entry: _outcome(call) for entry, call in calls.items()} == dict.fromkeys(
        calls, str(ErrorCode.FILE_BYTES_EXCEEDED)
    )


def _pax_declaring(body: bytes, size: int, typeflag: bytes = b"x") -> bytes:
    """A pax header declaring ``size`` bytes of records and holding
    ``body``, padded to whole blocks: what lies past ``size`` is in the
    padding, which tarfile reads as records too."""
    assert -(-size // 512) == -(-len(body) // 512)
    return _raw_header(b"././@PaxHeader", size, typeflag) + _padded(body)


def _pax_record_cases() -> list:
    a = _file(b"a.md", b"a" * 10)
    b = _file(b"b.md", b"b")
    path = _pax_record("path", "c.md")
    size = _pax_record("size", "-1")
    comment = _pax_record("comment", "x" * 20)
    one = _pax_record("size", "1")
    first = _pax_record("comment", "g")
    cases = {
        "size-in-the-padding-first": _pax_declaring(path + size, len(path)) + b,
        "size-in-the-padding": a + _pax_declaring(path + size, len(path)) + b,
        "record-across-the-declared-size": a + _pax_declaring(comment + size, len(comment) + 6) + b,
        "realsize-in-the-padding": (
            a + _pax_declaring(one + _pax_record("GNU.sparse.realsize", "-1"), len(one)) + b
        ),
        "global-size-in-the-padding": (
            _pax_declaring(first + size, len(first), b"g") + _pax({"comment": "c"}) + b
        ),
        "arabic-indic-digit": a + _pax({"size": "-١"}) + b,
        "fullwidth-digit": a + _pax({"size": "-１"}) + b,
        "unicode-space": a + _pax({"size": " -1"}) + b,
        "realsize-after-a-size": a + _pax({"size": "1", "GNU.sparse.realsize": "-١"}) + b,
    }
    return [pytest.param(raw + END, id=name) for name, raw in cases.items()]


@pytest.mark.parametrize("fmt", ["tar", "gz"])
@pytest.mark.parametrize("raw", _pax_record_cases())
def test_pax_records_are_read_as_tarfile_reads_them(
    tmp_path: Path, raw: bytes, fmt: str
) -> None:
    """All platforms and Python versions: pax records are read as tarfile
    reads them, from the header's data padded to whole blocks (up to the
    first NUL byte), with each value decoded as UTF-8 and read with int(),
    which takes any Unicode decimal digit and space. A negative size found
    so is refused (PX_E_6010) by every entry point, whether this release's
    tarfile reports the member, skips it or stops there."""
    archive = tmp_path / f"a.tar.{fmt}"
    archive.write_bytes(_compress(raw, fmt))
    calls = _entries(archive, tmp_path / "dest", ExtractPolicy.default())
    assert {entry: _outcome(call) for entry, call in calls.items()} == dict.fromkeys(
        calls, str(ErrorCode.FILE_BYTES_EXCEEDED)
    )
    assert sorted(p.name for p in tmp_path.iterdir()) == [archive.name]


def _header_chain_cases() -> list:
    """Members after more than one extension header (pax x, X or g, GNU L
    or K), where tarfile keeps the first pax header's keys in pax_headers
    but may take the member's size from a later one, and their one-header
    counterparts."""
    a = _file(b"a.md", b"a" * 10)
    comment = _pax({"comment": "c"})
    long_name = _raw_header(b"././@LongLink", 6, b"L") + _padded(b"e.md" + bytes(2))
    long_link = _raw_header(b"././@LongLink", 5, b"K") + _padded(b"t.md\0")
    size = _pax({"size": "10"})
    realsize = _pax({"GNU.sparse.realsize": "10"})
    negative = _raw_header(b"q.md", -512) + _padded(b"q" * 10)
    q = _file(b"q.md", b"q" * 10)
    too_big = str(ErrorCode.FILE_BYTES_EXCEEDED)
    sparse = str(ErrorCode.DISALLOWED_MEMBER_TYPE)
    cases = {
        "own-negative-after-a-size-in-a-second-pax-header": (a + comment + size + negative, too_big),
        "own-negative-after-a-size-in-a-second-pax-header-first-member": (
            comment + size + negative, too_big
        ),
        "own-far-below-zero-after-a-size-in-a-second-pax-header": (
            a + comment + size + _raw_header(b"q.md", -(1 << 40)) + _padded(b"q" * 10), too_big
        ),
        "own-negative-after-a-long-name-and-a-size": (a + long_name + size + negative, too_big),
        "own-negative-after-a-long-name-between-pax-headers": (
            a + comment + long_name + size + negative, too_big
        ),
        "own-negative-after-a-global-size": (
            a + comment + _pax({"size": "0"}, b"g") + _raw_header(b"q.md", -512), too_big
        ),
        "own-negative-after-a-realsize-in-a-second-pax-header": (
            a + comment + realsize + negative, too_big
        ),
        "own-negative-after-a-global-realsize": (
            a + comment + _pax({"GNU.sparse.realsize": "0"}, b"g") + _raw_header(b"q.md", -512),
            too_big,
        ),
        "directory-negative-after-a-size-in-a-second-pax-header": (
            a + comment + _pax({"size": "0"}) + _raw_header(b"dd/", -512, b"5"), too_big
        ),
        "directory-negative": (a + _raw_header(b"dd/", -512, b"5"), too_big),
        "own-negative-after-a-size": (a + size + negative, too_big),
        "own-negative-after-a-comment-and-a-size": (
            a + _pax({"comment": "c", "size": "10"}) + negative, too_big
        ),
        "size-in-a-second-pax-header": (a + comment + size + q, too_big),
        "size": (a + size + q, too_big),
        "realsize-in-a-second-pax-header": (a + comment + realsize + q, sparse),
        "realsize": (a + realsize + q, sparse),
        "global-size-after-a-pax-header": (
            a + comment + _pax({"size": "1"}, b"g") + _file(b"q.md", b"q"), too_big
        ),
        "own-negative-after-a-size-in-a-second-solaris-header": (
            a + _pax({"comment": "c"}, b"X") + _pax({"size": "10"}, b"X") + negative, too_big
        ),
        "realsize-in-a-solaris-header-after-a-pax-header": (
            a + comment + _pax({"GNU.sparse.realsize": "10"}, b"X") + q, sparse
        ),
        "own-negative-after-a-long-link-and-a-size": (a + long_link + size + negative, too_big),
        "size-after-a-long-link": (a + long_link + comment + size + q, too_big),
    }
    b = _file(b"b.md", b"b")
    return [
        pytest.param(
            raw + b + END, outcome, FIRST_LIMIT if raw[:512] != a[:512] else len(a) + HEADER_BYTES,
            id=name,
        )
        for name, (raw, outcome) in cases.items()
    ]


def _typed_by_release_cases() -> list:
    """A regular-file header in the old form (NUL typeflag) whose name field
    ends in '/', after each kind of extension header, followed by a block
    that is a header where that header is read as a directory and data
    where it is read as a regular file; then the same header with no
    extension header before it, and headers that every release types
    alike."""
    a = _file(b"a.md", b"a" * 10)
    before = {
        "pax": _pax({"path": "dir.md"}),
        "pax-comment": _pax({"comment": "c"}),
        "solaris": _pax({"path": "dir.md"}, b"X"),
        "global": _pax({"comment": "c"}, b"g"),
        "long-name": _raw_header(b"././@LongLink", 7, b"L") + _padded(b"dir.md\0"),
        "long-link": _raw_header(b"././@LongLink", 5, b"K") + _padded(b"t.md\0"),
    }
    block = {
        "symlink": _raw_header(b"s.md", 0, b"2"),
        "parent-path": _raw_header(b"../c.md", 0),
        "file": _raw_header(b"c.md", 0),
        "negative": _raw_header(b"n.md", -512),
    }
    slash = _raw_header(b"d/", 512, b"\0")
    refused = str(ErrorCode.DISALLOWED_MEMBER_TYPE)
    cases = {}
    for kind, header in before.items():
        for content, data in block.items():
            cases[f"after-{kind}-{content}"] = (a + header + slash + data, refused)
            cases[f"after-{kind}-{content}-first-member"] = (header + slash + data, refused)
    signatures = _raw_header(b"signatures.jsonl", 2) + _padded(b"x\n")
    cases["after-pax-signatures"] = (
        a + before["pax"] + _raw_header(b"d/", 1024, b"\0") + signatures, refused
    )
    # With no extension header before it, every release reads it as a
    # directory with no data, and some tar programs as one followed by as
    # much data as its size says, so a size other than 0 is refused.
    cases["no-extension-header-symlink"] = (a + slash + block["symlink"], refused)
    cases["no-extension-header-size-1-first-member"] = (
        _raw_header(b"d/", 1, b"\0") + _padded(b"x"), refused
    )
    cases["no-extension-header-signatures"] = (
        a + _raw_header(b"d/", 1024, b"\0") + signatures, refused
    )
    cases["no-extension-header-directory"] = (
        a + _raw_header(b"d/", 0, b"\0") + _file(b"d/c.md", b"c"), "ok"
    )
    cases["no-extension-header-directory-first-member"] = (
        _raw_header(b"d/", 0, b"\0") + _file(b"d/c.md", b"c"), "ok"
    )
    cases["directory-with-a-size"] = (a + _raw_header(b"d/", 512, b"5") + block["file"], "ok")
    cases["after-pax-old-form-file"] = (
        a + _pax({"path": "q.md"}) + _raw_header(b"q.md", 3, b"\0") + _padded(b"qqq"), "ok"
    )
    cases["after-pax-directory"] = (a + _pax({"path": "e"}) + _raw_header(b"e/", 0, b"5"), "ok")
    b = _file(b"b.md", b"b")
    params = []
    for name, (raw, outcome) in cases.items():
        full = raw + b + END
        if outcome == "ok":
            bound = len(full) - len(END) + HEADER_BYTES  # b.md is the last member
        else:
            bound = FIRST_LIMIT if raw[:512] != a[:512] else len(a) + HEADER_BYTES
        params.append(pytest.param(full, outcome, bound, id=name))
    return params


@pytest.mark.parametrize("raw, expected, bound", _typed_by_release_cases())
def test_a_header_whose_type_depends_on_the_release_is_refused(
    tmp_path: Path, passes: list, raw: bytes, expected: str, bound: int
) -> None:
    """All platforms and Python versions: a member's type is read from its
    own header. A regular-file header in the old form (NUL typeflag) whose
    name field ends in '/' is a directory where it is the member's first
    header, as every release reads it, and is refused (PX_E_6008) if its
    size field is not 0, which tar programs read differently (as a
    directory with no data, or followed by that many bytes); after a pax
    (x, X or g) or GNU long-name (L or K) header, releases differ (a
    directory on some, a regular file followed by its data on others), so
    it is refused (PX_E_6008) by every entry point, whatever the block after
    it holds. Headers every release types alike are read as before. tarfile
    is handed no more than H bytes past the end of the last member read
    (H + 1,024 from the start, before the first)."""
    archive = tmp_path / "a.tar"
    archive.write_bytes(raw)
    calls = _entries(archive, tmp_path / "dest", ExtractPolicy.default())
    for entry, call in calls.items():
        passes.clear()
        assert _outcome(call) == expected, entry
        assert all(reader.handed <= bound for reader in passes), entry
    left = {"a.tar"} | ({"dest"} if expected == "ok" else set())
    assert {p.name for p in tmp_path.iterdir()} == left


def test_refusals_of_what_releases_type_or_size_differently_name_no_path(
    tmp_path: Path,
) -> None:
    """All platforms and Python versions: the refusals of a header that
    releases read as different types, and of a negative size, say where in
    the archive the header is and give no member path, so their message is
    the same on every release (the member's name, which these releases
    give differently, is not used)."""
    from aphelion.unpacker import check_member_names

    a = _file(b"a.md", b"a")
    slash = _raw_header(b"d/", 512, b"\0")
    cases = {
        "the header at byte 2048 has a NUL typeflag and a name field ending in '/' ('d/')": (
            a + _pax({"comment": "c"}) + slash + _raw_header(b"c.md", 0)
        ),
        "the header at byte 1024 has a NUL typeflag, a name field ending in '/' ('d/') "
        "and a size of 512": a + slash + _raw_header(b"c.md", 0),
        "a header at byte 1024 declares a negative size -1": (
            a + _pax({"size": "-1"}) + slash + _raw_header(b"c.md", 0)
        ),
    }
    archive = tmp_path / "a.tar"
    for message, raw in cases.items():
        archive.write_bytes(raw + END)
        with pytest.raises(SecurityError) as exc:
            check_member_names(archive)
        assert str(exc.value.msg).startswith(message), exc.value.msg
        assert exc.value.path is None


@pytest.mark.parametrize("change", ["type", "size"])
def test_a_member_tarfile_reports_otherwise_than_its_header_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, change: str
) -> None:
    """All platforms and Python versions: a member that tarfile reports
    with another type or size than its own header gives (here tarfile is
    made to report a regular file as a directory, or one byte longer) is
    refused (PX_E_6013) by every entry point."""
    real = tarfile.TarInfo._proc_member

    def proc_member(self: tarfile.TarInfo, tar: tarfile.TarFile) -> tarfile.TarInfo:
        member = real(self, tar)
        if member.name == "q.md":
            if change == "type":
                member.type = tarfile.DIRTYPE
            else:
                member.size += 1
        return member

    monkeypatch.setattr(tarfile.TarInfo, "_proc_member", proc_member)
    archive = tmp_path / "a.tar"
    archive.write_bytes(_file(b"a.md", b"a") + _file(b"q.md", b"q" * 10) + END)
    calls = _entries(archive, tmp_path / "dest", ExtractPolicy.default())
    assert {entry: _outcome(call) for entry, call in calls.items()} == dict.fromkeys(
        calls, str(ErrorCode.ARCHIVE_BOMB)
    )
    assert sorted(p.name for p in tmp_path.iterdir()) == [archive.name]


@pytest.mark.parametrize("fmt", ["tar", "gz"])
@pytest.mark.parametrize("raw, expected, bound", _header_chain_cases())
def test_every_header_before_a_member_is_read_from_the_bytes(
    tmp_path: Path, passes: list, raw: bytes, expected: str, bound: int, fmt: str
) -> None:
    """All platforms and Python versions: every header block before a
    member's data, the member's own header included, and the records of
    every pax header there (local or global, first or later) are read from
    the bytes handed to tarfile, not from what tarfile made of them. A
    negative size in any of them is refused (PX_E_6010), as is a size
    given in any of those pax headers; a GNU.sparse.* key in any of them is
    refused as sparse (PX_E_6008). Every entry point gives the same
    outcome on every release, with tarfile handed no more than H bytes past
    the end of the last member read (H + 1,024 before the first)."""
    archive = tmp_path / f"a.tar.{fmt}"
    archive.write_bytes(_compress(raw, fmt))
    calls = _entries(archive, tmp_path / "dest", ExtractPolicy.default())
    for entry, call in calls.items():
        passes.clear()
        assert _outcome(call) == expected, entry
        assert all(reader.handed <= bound for reader in passes), entry
    assert sorted(p.name for p in tmp_path.iterdir()) == [archive.name]


def _whole_or_not() -> dict[str, tuple[bytes, bool]]:
    """Pax header data, after a whole record, and whether every record in
    it is whole: a length of 1 to 20 digits and a space, of at least 5
    bytes and within the data, a key that is not empty followed by '=', and
    a newline at its end. tarfile from Python 3.10.15, 3.11.10 and 3.12.6
    on fails on one that is not; before, it stops reading the records
    there, or reads them differently, and reads on."""
    c = _pax_record("comment", "c")
    return {
        "no-digits": (c + b"x comment=c\n", False),
        "leading-space": (c + b" 13 comment=c\n", False),
        "plus-sign": (c + b"+13 comment=c\n", False),
        "arabic-indic-digits": (c + "١٣".encode() + b" comment=c\n", False),
        "21-digits": (c + b"%021d comment=c\n" % 32, False),
        "no-space": (c + b"13comment=c\n", False),
        "length-0": (c + b"0 comment=c\n", False),
        "length-0-no-equals": (c + b"0 \n", False),
        "length-1": (c + b"1 x=c\n", False),
        "length-4": (c + b"4 a=\n" + c, False),
        "past-the-data": (c + b"600 comment=c\n", False),
        "one-byte-short": (c + b"12 comment=c\n", False),
        "no-newline": (c + b"13 comment=cc", False),
        "no-equals-then-a-record": (c + b"9 comment\n" + _pax_record("path", "p.md"), False),
        "no-equals": (c + b"9 comment\n", False),
        "empty-key": (c + b"5 =c\n", False),
        "junk-after-the-records": (c + b"junk", False),
        "size-after-a-short-record": (c + b"5 a=b9 size=1\n", False),
        "negative-size-after-a-short-record": (c + b"5 a=b11 size=-1\n", False),
        "20-digits": (c + b"%020d comment=c\n" % 31, True),
        "two-spaces": (c + b"14  comment=c\n", True),
        "nul-in-a-value": (c + _pax_record("comment", "c\0d"), True),
        "nul-after-the-records": (c + b"\0junk", True),
    }


@pytest.mark.parametrize("fmt", ["tar", "gz"])
@pytest.mark.parametrize("typeflag", [b"x", b"g"])
@pytest.mark.parametrize("first", [True, False], ids=["first-member", "later-member"])
@pytest.mark.parametrize("data, whole", _whole_or_not().values(), ids=_whole_or_not().keys())
def test_a_pax_record_that_is_not_whole_is_a_read_error_on_every_release(
    tmp_path: Path, passes: list, data: bytes, whole: bool, typeflag: bytes, first: bool, fmt: str
) -> None:
    """All platforms and Python versions: a pax header (local or global)
    with a record that is not whole is a read error (tarfile.ReadError) for
    every entry point, whether this release's tarfile fails on it or stops
    reading its records there and reads on; one whose records are all
    whole is read. tarfile is handed no more than H bytes past the end of
    the last member read (H + 1,024 before the first)."""
    a = _file(b"a.md", b"a")
    raw = (b"" if first else a) + _pax_declaring(data, len(data), typeflag) + _file(b"b.md", b"b")
    archive = tmp_path / f"a.tar.{fmt}"
    archive.write_bytes(_compress(raw + END, fmt))
    expected = "ok" if whole else "ReadError"
    bound = len(raw) + HEADER_BYTES if whole else FIRST_LIMIT if first else len(a) + HEADER_BYTES
    for entry, call in _entries(archive, tmp_path / "dest", ExtractPolicy.default()).items():
        passes.clear()
        assert _outcome(call) == expected, entry
        assert all(reader.handed <= bound for reader in passes), entry


@pytest.mark.parametrize("data, whole", _whole_or_not().values(), ids=_whole_or_not().keys())
def test_records_that_are_not_whole_are_found_where_tarfile_reads_on(
    monkeypatch: pytest.MonkeyPatch, data: bytes, whole: bool
) -> None:
    """All platforms and Python versions: the header walk finds a pax
    record that is not whole where it is told this release's tarfile reads
    on past one (as before Python 3.10.15, 3.11.10 and 3.12.6); where it is
    not, this release's tarfile fails on the header itself."""
    import aphelion.unpacker as unpacker

    raw = _pax_declaring(data, len(data)) + _file(b"b.md", b"b") + END
    monkeypatch.setattr(unpacker, "_PAX_READ_ON", True)
    assert unpacker._header_chain(raw, 0)[4] == (None if whole else (0, True))
    monkeypatch.undo()
    if not unpacker._PAX_READ_ON and not whole:
        with pytest.raises(tarfile.ReadError):
            tarfile.open(fileobj=io.BytesIO(raw), mode="r|").next()


PROBE_FAILS = """
import sys, tarfile

error = {
    "tar-error": tarfile.HeaderError("header"),
    "value-error": ValueError("value"),
    "other": EOFError("other"),
}[sys.argv[1]]


def fail(self, *args, **kwargs):
    raise error


tarfile.TarFile.next = fail
import aphelion.unpacker as unpacker

info = tarfile.TarInfo("a")
info.pax_headers = {"comment": "c"}
raw = info.tobuf(tarfile.PAX_FORMAT, "utf-8", "surrogateescape")
raw = raw.replace(b"13 comment=c\\n", b"13 comment=cc") + bytes(1024)
print(unpacker._PAX_READ_ON, unpacker._header_chain(raw, 0)[4])
"""


@pytest.mark.parametrize("kind", ["tar-error", "value-error", "other"])
def test_a_failing_look_at_how_tarfile_reads_pax_records_reads_them_all(kind: str) -> None:
    """All platforms and Python versions: if reading the pax header that
    shows whether this release's tarfile reads on past a record that is
    not whole fails other than with tarfile.ReadError, the module still
    imports and every pax header's records are read, so such a record is
    found even in a header with no size, GNU.sparse. or hdrcharset key."""
    result = run_python(PROBE_FAILS, [kind], None)
    assert result.returncode == 0, result.stderr
    assert result.stdout.split() == ["True", "(0,", "True)"]


def _read_alike_cases() -> list:
    """Pax headers whose records are whole but which Python releases read
    differently: the encoding of the names in a header (``hdrcharset``),
    which tarfile from Python 3.10.15, 3.11.10 and 3.12.6 on takes from the
    header's first hdrcharset record and before from the first match found
    anywhere in its data (failing if that is not UTF-8), or from a global
    header's for the headers after it; and GNU sparse 0.0 offsets and sizes,
    which tarfile from those releases on reads with int() from the records
    named so (failing if it cannot) and before as digits found anywhere in
    the data."""
    p = _pax_record("path", "p.md")
    c = _pax_record("comment", "c")
    error = "ReadError"
    sparse = str(ErrorCode.DISALLOWED_MEMBER_TYPE)
    sparse_size = _pax_record("GNU.sparse.size", "1")
    shapes = {
        "charset-binary-first": (_pax_record("hdrcharset", "BINARY") + p, "ok", error),
        "charset-utf8": (_pax_record("hdrcharset", "ISO-IR 10646 2000 UTF-8") + p, "ok", error),
        "charset-binary-second": (
            _pax_record("hdrcharset", "UTF-8") + _pax_record("hdrcharset", "BINARY"), "ok", error
        ),
        "charset-not-utf8": (c + b"16 hdrcharset=\xff\n", error, error),
        "charset-in-a-comment": (_pax_record("comment", "1 hdrcharset=BINARY\n") + p, error, error),
        "charset-not-utf8-in-a-comment": (c + b"27 comment=1 hdrcharset=\xff\n\n", error, error),
        "charset-after-the-nul": (c + b"\0" + _pax_record("hdrcharset", "BINARY"), error, error),
        "charset-in-a-comment-without-a-length": (
            _pax_record("comment", "hdrcharset=BINARY") + p, "ok", "ok"
        ),
        "sparse-offset-not-a-number": (
            sparse_size + _pax_record("GNU.sparse.offset", "abc"), error, error
        ),
        "sparse-offset-not-utf8": (sparse_size + b"23 GNU.sparse.offset=\xff\n", error, error),
        "sparse-numbytes-with-a-sign": (
            sparse_size + _pax_record("GNU.sparse.numbytes", "+1"), sparse, sparse
        ),
        "sparse-offset-in-a-comment": (
            sparse_size + _pax_record("comment", "1 GNU.sparse.offset=7\n"), sparse, sparse
        ),
        "sparse-map-and-a-bad-offset": (
            _pax_record("GNU.sparse.map", "0,1") + sparse_size
            + _pax_record("GNU.sparse.offset", "abc"), sparse, sparse
        ),
    }
    a = _file(b"a.md", b"a")
    b = _file(b"b.md", b"b")
    params = []
    for name, (data, local, global_) in shapes.items():
        for typeflag, expected in ((b"x", local), (b"g", global_)):
            for first in (True, False):
                raw = (b"" if first else a) + _pax_declaring(data, len(data), typeflag) + b + END
                where = "first-member" if first else "later-member"
                params.append(pytest.param(raw, expected, id=f"{name}-{typeflag.decode()}-{where}"))
    params.append(pytest.param(
        a + _pax({"GNU.sparse.size": "1"}, b"g") + _pax({"GNU.sparse.offset": "abc"}) + b + END,
        error, id="sparse-size-global-offset-local",
    ))
    params.append(pytest.param(
        a + _pax({"GNU.sparse.size": "1"}) + _pax({"GNU.sparse.offset": "abc"}) + b + END,
        sparse, id="sparse-size-and-offset-in-two-local-headers",
    ))
    return params


@pytest.mark.parametrize("raw, expected", _read_alike_cases())
def test_a_pax_header_releases_read_differently_is_refused_on_every_release(
    tmp_path: Path, raw: bytes, expected: str
) -> None:
    """All platforms and Python versions: a pax header whose records are
    whole but that Python releases read differently is a read error
    (tarfile.ReadError) for every entry point, as on the releases that
    fail on it: a hdrcharset other than a local header's first such record
    (any in a global header, one found elsewhere in the data, or one that
    is not UTF-8), and, for a GNU sparse 0.0 member, an offset or size that
    int() cannot read. Other sparse headers are refused as sparse
    (PX_E_6008), and the encoding a local header names in its first record
    is read as before."""
    archive = tmp_path / "a.tar"
    archive.write_bytes(raw)
    calls = _entries(archive, tmp_path / "dest", ExtractPolicy.default())
    assert {entry: _outcome(call) for entry, call in calls.items()} == dict.fromkeys(
        calls, expected
    )


def _stopped_at_cases() -> list:
    """What comes first where a release stops reading the archive at a pax
    header: a negative size before or after it, a read past what may be
    read, and the checks of the member after it."""
    a = _file(b"a.md", b"a")
    b = _file(b"b.md", b"b")
    short = _pax_record("comment", "c") + b"12 comment=c\n"  # its last byte is not a newline
    bad = _pax_declaring(short, len(short))
    negative = _pax_record("size", "-1")
    far = _pax({"comment": "x" * 4000})
    error = "ReadError"
    too_big = str(ErrorCode.FILE_BYTES_EXCEEDED)
    bomb = str(ErrorCode.ARCHIVE_BOMB)
    cases = {
        "negative-size-record-before": (a + _pax_declaring(negative + short, 40) + b, too_big),
        "negative-size-record-after": (a + _pax_declaring(short + negative, 40) + b, error),
        "own-negative-size-after": (a + bad + _raw_header(b"q.md", -512) + b, too_big),
        "negative-size-header-after": (
            a + bad + _raw_header(b"././@PaxHeader", -512, b"x") + b, too_big
        ),
        "then-past-the-limit": (a + bad + far + b, error),
        "then-past-the-limit-first-member": (bad + far + far + b, error),
        "itself-past-the-limit": (
            a + _pax_declaring(_pax_record("comment", "x" * 4500) + b"12 comment=c\n", 4520) + b,
            bomb,
        ),
        "read-differently-then-past-the-limit": (
            a + _pax({"comment": "1 hdrcharset=BINARY\n"}) + far + b, bomb
        ),
        "not-utf8-charset-then-past-the-limit": (
            a + _pax_declaring(b"16 hdrcharset=\xff\n", 16) + far + b, error
        ),
        "then-a-name-field-ending-in-a-slash": (a + bad + _raw_header(b"d/", 512, b"\0") + b, error),
        "then-a-symlink": (a + bad + _raw_header(b"s.md", 0, b"2") + b, error),
        "then-a-size": (a + bad + _pax({"size": "1"}) + b, error),
        "after-a-long-name": (
            a + _raw_header(b"././@LongLink", 5, b"L") + _padded(b"e.md\0") + bad + b, error
        ),
        "in-the-padding": (a + _pax_declaring(short, 13) + b, error),
        "after-the-last-member": (a + bad, error),
    }
    return [pytest.param(raw + END, expected, id=n) for n, (raw, expected) in cases.items()]


@pytest.mark.parametrize("fmt", ["tar", "gz", "xz"])
@pytest.mark.parametrize("raw, expected", _stopped_at_cases())
def test_what_comes_first_where_a_release_stops_at_a_pax_header(
    tmp_path: Path, raw: bytes, expected: str, fmt: str
) -> None:
    """All platforms and Python versions: where a release stops reading the
    archive at a pax header, every entry point reports it as that release
    does, whether this release's tarfile stopped there or read on: a
    negative size in the header blocks from the end of the member before
    is refused (PX_E_6010) first, then the header is a read error
    (tarfile.ReadError), before any check of the member after it, and also
    where reading on would go past what may be read. A header whose own
    data goes past that is refused (PX_E_6013), as is a header that every
    release reads on past and that is then followed by too much."""
    archive = tmp_path / f"a.tar.{fmt}"
    archive.write_bytes(_compress(raw, fmt))
    calls = _entries(archive, tmp_path / "dest", ExtractPolicy.default())
    assert {entry: _outcome(call) for entry, call in calls.items()} == dict.fromkeys(
        calls, expected
    )
    assert sorted(p.name for p in tmp_path.iterdir()) == [archive.name]


@pytest.mark.parametrize(
    "after, expected",
    [
        (_pax_declaring(b"13 comment=cc", 13) + _file(b"b.md", b"b"), "ReadError"),
        (_raw_header(b"b.md", -512), str(ErrorCode.FILE_BYTES_EXCEEDED)),
        (_file(b"b.md", b"b"), str(ErrorCode.FILE_COUNT_EXCEEDED)),
    ],
    ids=["record-not-whole", "negative-size", "file"],
)
def test_a_member_past_max_files_that_a_release_stops_at_is_refused_as_there(
    tmp_path: Path, after: bytes, expected: str
) -> None:
    """All platforms and Python versions: a member past ``max_files`` is
    refused as a release that stops reading the archive at its headers
    reports it (a pax record that is not whole, a negative size), whether
    this release's tarfile stopped there or reported the member; any other
    member past ``max_files`` is refused as one too many (PX_E_6009)."""
    from aphelion.unpacker import check_member_names

    archive = tmp_path / "a.tar"
    archive.write_bytes(_file(b"a.md", b"a") + after + END)
    policy = ExtractPolicy(max_files=1)
    calls = {
        "unpack": lambda: unpack(archive, tmp_path / "dest", policy=policy),
        "check_member_names": lambda: check_member_names(archive, policy),
    }
    assert {entry: _outcome(call) for entry, call in calls.items()} == dict.fromkeys(
        calls, expected
    )


def _xz_needing_too_much_memory(raw: bytes) -> bytes:
    """An xz stream of ``raw`` that declares the largest dictionary the
    format can, which the decoder limit refuses."""
    import struct
    import zlib

    stream = bytearray(lzma.compress(raw, filters=[{"id": lzma.FILTER_LZMA2, "preset": 0}]))
    header = stream[12 : 12 + (stream[12] + 1) * 4]
    assert header[2:4] == b"\x21\x01"  # one LZMA2 filter, one property byte
    header[4] = 40
    header[-4:] = struct.pack("<I", zlib.crc32(bytes(header[:-4])))
    stream[12 : 12 + len(header)] = header
    return bytes(stream)


@pytest.mark.parametrize(
    "tail",
    [
        _raw_header(b"././@PaxHeader", -512, b"x"),
        _raw_header(b"././@LongLink", -512, b"L"),
        _pax({"size": "-1"}) + _raw_header(b"b.md", 1),
    ],
    ids=["pax-header", "long-name", "pax-record"],
)
def test_a_negative_size_before_a_failing_read_after_the_last_member_is_refused(
    tmp_path: Path, tail: bytes
) -> None:
    """All platforms and Python versions: when reading the bytes after the
    last member fails (here, the next xz stream needs more decoder memory
    than the limit), a negative size in the header blocks read there is
    still refused (PX_E_6010) by every entry point, whether this release's
    tarfile reported a member there or stopped."""
    archive = tmp_path / "a.tar.xz"
    archive.write_bytes(
        lzma.compress(_file(b"a.md", b"a" * 10) + tail)
        + _xz_needing_too_much_memory(b"b" + bytes(511) + END)
    )
    calls = _entries(archive, tmp_path / "dest", ExtractPolicy.default())
    assert {entry: _outcome(call) for entry, call in calls.items()} == dict.fromkeys(
        calls, str(ErrorCode.FILE_BYTES_EXCEEDED)
    )
    assert sorted(p.name for p in tmp_path.iterdir()) == [archive.name]


@pytest.mark.parametrize(
    "max_path_length, path",
    [(4000, "a" * 3500), (1000, "\U0001d11e" * 1000)],
    ids=["4000-ascii-3500", "1000-four-byte-1000"],
)
def test_header_allowance_grows_with_the_longest_path_the_policy_allows(
    tmp_path: Path, passes: list, max_path_length: int, path: str
) -> None:
    """All platforms: under a policy allowing paths longer than 512
    characters, a member whose pax header holds such a path and about 1 KiB
    of other records passes the header checks; a member whose header blocks
    take one block more than the allowance is refused (PX_E_6013)."""
    from aphelion.unpacker import check_member_names

    policy = ExtractPolicy(max_path_length=max_path_length)
    allowance = _header_bytes(policy)
    assert allowance > HEADER_BYTES
    member = _pax({"path": path, "comment": "c" * 990}) + _file(b"x", b"x")
    assert len(member) - 512 <= allowance
    archive = tmp_path / "a.tar.gz"
    archive.write_bytes(gzip.compress(_file(b"a.md", b"a") + member + END, mtime=0))
    check_member_names(archive, policy)

    over = _pax_blocks((allowance - 1024) // 512 + 1) + _file(b"b.md", b"b")
    archive.write_bytes(gzip.compress(_file(b"a.md", b"a") + over + END, mtime=0))
    passes.clear()
    with pytest.raises(SecurityError) as exc:
        check_member_names(archive, policy)
    assert exc.value.code == ErrorCode.ARCHIVE_BOMB
    assert [reader.handed <= 1024 + allowance for reader in passes] == [True]


@pytest.mark.parametrize(
    "pax",
    [
        {"GNU.sparse.map": "x"},
        {"GNU.sparse.size": "x"},
        {"GNU.sparse.realsize": "x"},
        {"GNU.sparse.major": "1", "GNU.sparse.minor": "0"},
    ],
    ids=["map", "size", "realsize", "1.0-map"],
)
def test_sparse_keys_tarfile_cannot_parse_are_a_read_error(
    tmp_path: Path, pax: dict[str, str]
) -> None:
    """All platforms and Python versions: GNU sparse keys whose values
    tarfile cannot parse make it fail inside its header parsing (with
    ValueError); every entry point reports that as tarfile.ReadError. Keys
    it can parse are refused as sparse (PX_E_6008), and a refusal of the
    header checks raised while tarfile reads keeps its code."""
    raw = _pax(pax) + _file(b"a.md", b"zz") + END
    archive = tmp_path / "a.tar"
    archive.write_bytes(raw)
    calls = _entries(archive, tmp_path / "dest", ExtractPolicy.default())
    assert {entry: _outcome(call) for entry, call in calls.items()} == dict.fromkeys(
        calls, "ReadError"
    )
    archive.write_bytes(_pax({"GNU.sparse.size": "2"}) + _file(b"a.md", b"zz") + END)
    assert {_outcome(call) for call in calls.values()} == {str(ErrorCode.DISALLOWED_MEMBER_TYPE)}
    archive.write_bytes(_pax({"GNU.sparse.map": "x", "comment": "x" * 8000}) + raw)
    assert {_outcome(call) for call in calls.values()} == {str(ErrorCode.ARCHIVE_BOMB)}
    assert sorted(p.name for p in tmp_path.iterdir()) == [archive.name]


@pytest.mark.parametrize(
    "body, ok",
    [
        (bytes(1024) + b"\x01" * 512, False),
        (bytes(4095) + b"\x01" + bytes(512), False),
        (bytes(4096) + b"\x01" * 512, True),
        (_file(b"a.md", b"a") + bytes(4095) + b"\x01", False),
        (_file(b"a.md", b"a") + bytes(4096) + b"\x01" * 512, True),
    ],
    ids=["zero-blocks-then-data", "no-member-byte-4095", "no-member-byte-4096",
         "after-a-member-byte-4095", "after-a-member-byte-4096"],
)
def test_only_the_allowance_after_the_last_member_is_checked_for_data(
    tmp_path: Path, body: bytes, ok: bool
) -> None:
    """All platforms and Python versions: a non-zero byte within 4,096
    bytes after the end of the last member (or of the archive's start, if
    it has none) is data after the end of the archive (tarfile.ReadError,
    also on Python 3.10, whose tarfile reads past leading zero blocks by
    seeking back); one further on is not looked at."""
    from aphelion.unpacker import check_member_names, extract_signer_manifests

    archive = tmp_path / "a.tar"
    archive.write_bytes(body)
    for call in (lambda: check_member_names(archive), lambda: extract_signer_manifests(archive)):
        if ok:
            call()
        else:
            with pytest.raises(tarfile.ReadError, match="after the end"):
                call()


def test_directory_with_a_size_is_read_as_a_directory(tmp_path: Path, passes: list) -> None:
    """All platforms and Python versions: a directory member's size is not
    the size of any data after it (tarfile reads the next header right
    after it, as tar does), so a directory declaring 4,096 bytes, followed
    by a file, unpacks to that directory and file."""
    raw = _raw_header(b"d", 4096, b"5") + _file(b"d/a.md", b"a") + END
    archive = tmp_path / "a.tar"
    archive.write_bytes(raw)
    dest = unpack(archive, tmp_path / "dest")
    assert sorted(str(p.relative_to(dest).as_posix()) for p in dest.rglob("*")) == ["d", "d/a.md"]
    assert (dest / "d" / "a.md").read_bytes() == b"a"
    assert all(reader.handed <= len(raw) for reader in passes)


@pytest.mark.parametrize(
    "before",
    [
        _raw_header(b"././@PaxHeader", 0, b"g"),
        _raw_header(b"././@PaxHeader", 0, b"g") + _pax_blocks(6),
    ],
    ids=["empty-global-header", "empty-global-header-and-4096"],
)
def test_empty_global_pax_header_before_the_first_member(tmp_path: Path, before: bytes) -> None:
    """All platforms and Python versions: a global pax header with no
    records before the first member is read as there, and its 512 bytes
    count towards the first member's extra allowance."""
    from aphelion.unpacker import check_member_names

    archive = tmp_path / "a.tar"
    archive.write_bytes(before + _file(b"a.md", b"a") + END)
    check_member_names(archive)
    assert unpack(archive, tmp_path / "dest").joinpath("a.md").read_bytes() == b"a"


def test_a_pass_keeps_no_member_it_has_moved_past(tmp_path: Path) -> None:
    """All platforms and Python versions: a pass keeps no list of the
    members tarfile has read, so 1,000 members whose pax headers each hold
    300 records (tens of kilobytes each once parsed) are checked in a few
    MiB of memory."""
    import tracemalloc

    from aphelion.unpacker import check_member_names

    pax = _pax({f"k{j:03d}": "1" for j in range(300)})
    assert len(pax) + 512 == HEADER_BYTES
    raw = b"".join(pax + _raw_header(b"m%04d" % i, 0) for i in range(1000)) + END
    archive = tmp_path / "a.tar.gz"
    archive.write_bytes(gzip.compress(raw, mtime=0))
    tracemalloc.start()
    try:
        check_member_names(archive)
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert peak < 8 * MIB, peak


def _damaged(fmt: str, how: str) -> bytes:
    if how == "checksum":
        # A small archive, read to its end, with a bit of the stream's own
        # checksum flipped (gzip: its CRC-32; bzip2: the stream CRC).
        data = bytearray(_compressed(_file(b"a.md", b"a") + END, fmt))
        data[-8 if fmt == "gz" else -2] ^= 1
        return bytes(data)
    raw = _tar_bytes([("a.md", random.Random(9).randbytes(20_000)), ("b.md", b"b")])
    data = bytearray(_compressed(raw, fmt))
    if how == "cut":
        return bytes(data[: len(data) // 2])
    if how == "block":
        data[10] |= 0x06  # the first deflate block is of the reserved type
        return bytes(data)
    data[len(data) // 2] ^= 0x55
    return bytes(data)


@pytest.mark.parametrize(
    "fmt, how",
    [
        ("gz", "cut"), ("gz", "block"), ("gz", "checksum"), ("xz", "flip"), ("xz", "cut"),
        ("bz2", "cut"), ("bz2", "checksum"), ("zst", "cut"),
    ],
)
def test_damaged_compressed_archive_is_a_read_error(tmp_path: Path, fmt: str, how: str) -> None:
    """All platforms: whatever the decompressor raises for a compressed
    archive that is damaged or cut short (EOFError, gzip's BadGzipFile,
    zlib.error, LZMAError, bz2's OSError without an errno, ZstdError) every
    entry point reports as tarfile.ReadError."""
    archive = tmp_path / f"a.tar.{fmt}"
    archive.write_bytes(_damaged(fmt, how))
    calls = _entries(archive, tmp_path / "dest", ExtractPolicy.default())
    assert {entry: _outcome(call) for entry, call in calls.items()} == dict.fromkeys(
        calls, "ReadError"
    )
    assert sorted(p.name for p in tmp_path.iterdir()) == [archive.name]


class _FailingFile:
    """An archive file whose reads fail with EIO once ``at`` bytes of it
    have been read (``at`` 0: from the first read after the one that tells
    the compression). Each read hands out at most 4,096 bytes."""

    def __init__(self, path: Path, at: int) -> None:
        self._file = open(path, "rb")
        self._at = at
        self._reads = 0

    def read(self, size: int | None = -1) -> bytes:
        self._reads += 1
        if self._reads > 1 and self._file.tell() >= self._at:
            raise OSError(errno.EIO, "Input/output error")
        return self._file.read(4096 if size is None or size < 0 else min(size, 4096))

    def __getattr__(self, name: str) -> object:
        return getattr(self._file, name)

    def __enter__(self) -> _FailingFile:
        return self

    def __exit__(self, *exc: object) -> None:
        self._file.close()


@pytest.mark.parametrize("fmt", _FORMATS)
@pytest.mark.parametrize("where", ["first-read", "half-way"])
def test_an_error_reading_the_archive_file_is_raised_unchanged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fmt: str, where: str
) -> None:
    """All platforms and Python versions: an operating-system error reading
    the archive file (here EIO, on the first read of its data or half-way
    through it) reaches the caller of every entry point unchanged, whatever
    the compression; it is not reported as a damaged archive."""
    import aphelion.unpacker as unpacker

    raw = _file(b"a.md", random.Random(5).randbytes(40_000)) + END
    archive = tmp_path / f"a.tar.{fmt}"
    archive.write_bytes(_compressed(raw, fmt))
    at = 0 if where == "first-read" else archive.stat().st_size // 2

    def failing_open(path: Path, mode: str = "r") -> object:
        assert mode == "rb"
        return _FailingFile(path, at)

    monkeypatch.setattr(unpacker, "open", failing_open, raising=False)
    for entry, call in _entries(archive, tmp_path / "dest", ExtractPolicy.default()).items():
        with pytest.raises(OSError) as exc:
            call()
        assert exc.value.errno == errno.EIO, entry
    assert sorted(p.name for p in tmp_path.iterdir()) == [archive.name]


@pytest.mark.parametrize("kind", ["one-byte-files", "empty-files", "directories"])
def test_many_tiny_members_in_a_compressed_archive_are_accepted(
    tmp_path: Path, passes: list, kind: str
) -> None:
    """All platforms: a gzip-compressed archive of 10,000 one-byte files,
    empty files or directories, the most members the default policy allows,
    is read in full at the default policy, however well its headers
    compress: the compression-ratio limit counts the members' declared
    sizes, and header bytes are bounded by the per-member allowance."""
    from aphelion.unpacker import check_member_names, extract_signer_manifests

    if kind == "directories":
        raw = b"".join(_raw_header(b"d%05d" % i, 0, b"5") for i in range(10_000)) + END
    else:
        data = b"x" if kind == "one-byte-files" else b""
        raw = b"".join(_file(b"m%05d" % i, data) for i in range(10_000)) + END
    archive = tmp_path / "a.tar.gz"
    archive.write_bytes(gzip.compress(raw, compresslevel=9, mtime=0))

    check_member_names(archive)
    assert dict(extract_signer_manifests(archive)) == {}
    if kind == "one-byte-files":
        dest = unpack(archive, tmp_path / "dest")
        assert len(list(dest.iterdir())) == 10_000
    assert len(passes) == (4 if kind == "one-byte-files" else 2)
    assert all(reader.handed <= len(raw) for reader in passes)


def test_header_bytes_of_max_files_members_stay_within_the_pass_bound(
    tmp_path: Path, passes: list
) -> None:
    """All platforms: as many members as the default policy allows, each
    with 4,096 bytes of header blocks (a pax header of 3 KiB of records and
    its own header) and one byte of data, come to 46 MB that compress to a
    few hundred kilobytes. Whatever the outcome, no pass hands tarfile more
    than the per-pass bound: header bytes are bounded per member."""
    from aphelion.unpacker import check_member_names, extract_signer_manifests

    assert len(_pax({"comment": "y" * 3000}) + _raw_header(b"m", 1)) == HEADER_BYTES
    raw = b"".join(
        _pax({"comment": "y" * 3000}) + _file(b"m%05d" % i, b"x") for i in range(10_000)
    )
    archive = tmp_path / "a.tar.gz"
    archive.write_bytes(gzip.compress(raw + END, compresslevel=9, mtime=0))

    outcomes = [
        _outcome(lambda: check_member_names(archive)),
        _outcome(lambda: extract_signer_manifests(archive)),
    ]
    assert len(passes) == 2
    assert all(reader.handed <= _pass_limit(ExtractPolicy.default()) for reader in passes)
    assert all(reader.handed <= len(raw) + HEADER_BYTES for reader in passes)
    assert outcomes == ["ok", "ok"]


def test_unpack_refuses_an_archive_that_changes_between_its_passes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, passes: list
) -> None:
    """All platforms: unpack checks every header, then reads the archive
    again to write the members. If the second pass sees a member the first
    did not (another name, type, size or place, one more or one less), the
    unpack is refused (PX_E_6013) before that member is written, and
    nothing is left in the destination."""
    import aphelion.unpacker as unpacker

    first = _tar_bytes([("a.md", b"a"), ("b.md", b"b")])
    archive = tmp_path / "a.tar"
    real_scan = unpacker._scan
    for second in (
        _tar_bytes([("a.md", b"a"), ("b.md", b"bb")]),
        _tar_bytes([("a.md", b"a"), ("c.md", b"b")]),
        _tar_bytes([("a.md", b"a"), ("b.md", b"b"), ("c.md", b"c")]),
        _tar_bytes([("a.md", b"a")]),
    ):
        archive.write_bytes(first)

        def scan_then_change(*args: object, second: bytes = second, **kwargs: object) -> object:
            seen = real_scan(*args, **kwargs)
            archive.write_bytes(second)
            return seen

        monkeypatch.setattr(unpacker, "_scan", scan_then_change)
        passes.clear()
        with pytest.raises(SecurityError) as exc:
            unpack(archive, tmp_path / "dest")
        assert exc.value.code == ErrorCode.ARCHIVE_BOMB
        assert "changed" in str(exc.value)
        assert sorted(p.name for p in tmp_path.iterdir()) == ["a.tar"]
        assert len(passes) == 2
        assert passes[0].handed <= len(first) and passes[1].handed <= len(second)


def test_each_entry_point_reads_the_archive_a_fixed_number_of_times(
    tmp_path: Path, passes: list
) -> None:
    """All platforms: check_member_names and each accessor read an archive
    once, unpack twice, whatever it holds, and no pass hands tarfile more
    than the archive holds."""
    from aphelion.unpacker import (
        check_member_names,
        extract_signatures_jsonl,
        extract_signer_manifests,
    )

    raw = _tar_bytes(
        [
            ("data/big.bin", random.Random(5).randbytes(MIB)),
            ("signatures.jsonl", b"{}\n"),
            ("signers/s.json", b"{}"),
        ]
    )
    archive = tmp_path / "a.tar.gz"
    archive.write_bytes(gzip.compress(raw, compresslevel=1, mtime=0))
    for call, count in (
        (lambda: check_member_names(archive), 1),
        (lambda: extract_signatures_jsonl(archive), 1),
        (lambda: extract_signer_manifests(archive), 1),
        (lambda: unpack(archive, tmp_path / "dest"), 2),
    ):
        passes.clear()
        call()
        assert len(passes) == count
        assert all(reader.handed <= len(raw) for reader in passes)


def test_accessors_take_the_last_member_of_a_repeated_name(tmp_path: Path, passes: list) -> None:
    """All platforms: when a name repeats, the accessors read the last
    member of that name, as ``TarFile.getmember`` finds it (a directory
    last means no signatures), while unpack refuses the archive."""
    from aphelion.unpacker import extract_signatures_jsonl, extract_signer_manifests

    archive = tmp_path / "a.tar"
    raw = (
        _file(b"signatures.jsonl", b"first")
        + _file(b"signers/s.json", b"one")
        + _file(b"signatures.jsonl", b"last")
        + _file(b"signers/s.json", b"two")
        + END
    )
    archive.write_bytes(raw)
    assert extract_signatures_jsonl(archive) == b"last"
    assert dict(extract_signer_manifests(archive)) == {"s": b"two"}
    with pytest.raises(SecurityError) as exc:
        unpack(archive, tmp_path / "dest")
    assert exc.value.code == ErrorCode.DUPLICATE_MEMBER_PATH
    assert len(passes) == 3
    assert all(reader.handed <= len(raw) for reader in passes)

    archive.write_bytes(
        _file(b"signatures.jsonl", b"first") + _raw_header(b"signatures.jsonl", 0, b"5") + END
    )
    assert extract_signatures_jsonl(archive) is None


@pytest.mark.parametrize("fmt", _FORMATS)
@pytest.mark.parametrize("tar_format", ["pax", "gnu", "ustar"])
def test_ordinary_archives_are_read_in_full(
    tmp_path: Path, passes: list, fmt: str, tar_format: str
) -> None:
    """All platforms: archives tarfile writes in each format and compression,
    with directories, an empty file, nested and non-ASCII names, long names
    (pax and GNU) and a global pax header with a comment record (pax),
    unpack in full; every pass hands tarfile at most the archive's bytes."""
    from aphelion.unpacker import check_member_names, extract_signatures_jsonl

    files = {
        "signatures.jsonl": b"{}\n",
        "claims/中文.md": "中文".encode() * 100,
        "claims/empty.md": b"",
        "a/b/c/d.bin": random.Random(7).randbytes(70_000),
    }
    if tar_format != "ustar":
        files["long/" + "é" * 120 + ".md"] = b"long"
    form = {"pax": tarfile.PAX_FORMAT, "gnu": tarfile.GNU_FORMAT, "ustar": tarfile.USTAR_FORMAT}
    raw = io.BytesIO()
    extra = {"pax_headers": {"comment": "0123abcd" * 5}} if tar_format == "pax" else {}
    with tarfile.open(fileobj=raw, mode="w", format=form[tar_format], **extra) as tar:
        for directory in ("claims", "a"):
            tar.addfile(_dir(directory))
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    archive = tmp_path / f"a.tar.{fmt}"
    archive.write_bytes(_compressed(raw.getvalue(), fmt))

    check_member_names(archive)
    assert extract_signatures_jsonl(archive) == b"{}\n"
    dest = unpack(archive, tmp_path / "dest")
    for name, data in files.items():
        assert (dest / name).read_bytes() == data
    assert all(reader.handed <= len(raw.getvalue()) for reader in passes)


def test_global_and_local_pax_headers_and_a_gnu_long_name_together(
    tmp_path: Path, passes: list
) -> None:
    """All platforms: a global pax header, a member with its own pax header
    and one with a GNU long name in one archive unpack in full."""
    long_name = b"d/" + b"n" * 110
    raw = (
        _pax({"comment": "abc123"}, b"g")
        + _pax({"path": "p/" + "é" * 60})
        + _file(b"short", b"one")
        + _raw_header(b"././@LongLink", len(long_name) + 1, b"L")
        + _padded(long_name + b"\0")
        + _file(b"short2", b"two")
        + END
    )
    archive = tmp_path / "a.tar"
    archive.write_bytes(raw)
    dest = unpack(archive, tmp_path / "dest")
    assert (dest / "p" / ("é" * 60)).read_bytes() == b"one"
    assert (dest / long_name.decode()).read_bytes() == b"two"
    assert len(passes) == 2
    assert all(reader.handed <= len(raw) for reader in passes)


def test_a_member_of_max_file_bytes_unpacks(tmp_path: Path, passes: list) -> None:
    """All platforms: a 25 MiB member, the most the default policy allows,
    in a compressed archive unpacks."""
    data = random.Random(8).randbytes(25 * MIB)
    raw = _tar_bytes([("big.bin", data)])
    archive = tmp_path / "a.tar.gz"
    archive.write_bytes(gzip.compress(raw, compresslevel=1, mtime=0))
    assert unpack(archive, tmp_path / "dest").joinpath("big.bin").read_bytes() == data
    assert len(passes) == 2
    assert all(reader.handed <= len(raw) for reader in passes)


def test_max_files_members_pass_the_header_checks_in_bounded_memory(
    tmp_path: Path, passes: list
) -> None:
    """All platforms: 10,000 members, the most the default policy allows,
    pass the header checks in one pass, holding under 64 MiB; one more is
    refused (PX_E_6009)."""
    import tracemalloc

    from aphelion.unpacker import check_member_names

    def archive_of(count: int) -> Path:
        path = tmp_path / f"{count}.tar"
        path.write_bytes(b"".join(_file(b"m%05d" % i, b"x") for i in range(count)) + END)
        return path

    tracemalloc.start()
    try:
        check_member_names(archive_of(10_000))
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert peak < 64 * MIB, peak
    assert passes[0].handed <= _pass_limit(ExtractPolicy.default())
    with pytest.raises(SecurityError) as exc:
        check_member_names(archive_of(10_001))
    assert exc.value.code == ErrorCode.FILE_COUNT_EXCEEDED


def test_long_numeric_pax_records_in_every_member(tmp_path: Path, passes: list) -> None:
    """All platforms: members whose pax headers hold 3 KiB numeric records,
    which older tarfile releases parse slowly, are read; at most 4,096
    bytes of header per member reach tarfile (scaled to 300 members)."""
    from aphelion.unpacker import check_member_names

    member = _pax({"comment": "7" * 3000}) + _raw_header(b"m", 1)
    assert len(member) == HEADER_BYTES
    raw = b"".join(
        _pax({"comment": "7" * 3000}) + _file(b"m%03d" % i, b"x") for i in range(300)
    )
    archive = tmp_path / "a.tar"
    archive.write_bytes(raw + END)
    check_member_names(archive)
    assert len(passes) == 1
    assert passes[0].handed <= len(raw) + HEADER_BYTES


def _flip(raw: bytes, rng: random.Random) -> bytes:
    """``raw`` with one byte of one header changed and its checksum redone."""
    data = bytearray(raw)
    headers = [i for i in range(0, len(data) - 511, 512) if data[i + 257 : i + 262] == b"ustar"]
    start = rng.choice(headers)
    field = rng.choice([(0, 100), (124, 136), (156, 157), (345, 500)])
    data[start + rng.randrange(*field)] = rng.randrange(256)
    data[start + 148 : start + 156] = b" " * 8
    data[start + 148 : start + 156] = b"%06o\0 " % sum(data[start : start + 512])
    return bytes(data)


def test_changed_headers_are_refused_or_read_within_the_limit(
    tmp_path: Path, passes: list
) -> None:
    """All platforms and Python versions: changing one header byte (name,
    size, type, prefix) and adding random pax keys never makes a pass hand
    tarfile more than the per-pass limit, and every result is the archive
    read or refused with an Aphelion or tarfile error (scaled to 300
    archives)."""
    from aphelion.unpacker import check_member_names, extract_signer_manifests

    rng = random.Random(24)
    keys = ["size", "path", "GNU.sparse.size", "comment", "linkpath", "mtime", "uid"]
    base = (
        _pax({"comment": "abc"}, b"g")
        + _pax({"path": "p.md"})
        + _file(b"a.md", b"a" * 700)
        + _file(b"signers/s.json", b"{}")
        + _raw_header(b"dir", 0, b"5")
        + END
    )
    limit = _pass_limit(ExtractPolicy.default())
    archive = tmp_path / "a.tar"
    outcomes = set()
    for _ in range(300):
        raw = _flip(base, rng)
        if rng.random() < 0.3:
            raw = _pax({rng.choice(keys): str(rng.randrange(-2, 1 << 20))}) + raw
        archive.write_bytes(raw)
        for call in (lambda: check_member_names(archive), lambda: extract_signer_manifests(archive)):
            passes.clear()
            try:
                call()
                outcomes.add("ok")
            except (SecurityError, tarfile.TarError) as exc:
                outcomes.add(type(exc).__name__)
            assert all(reader.handed <= min(limit, len(raw) + 512) for reader in passes)
    assert "ok" in outcomes and "SecurityError" in outcomes


# ---------- collisions after normalisation ----------

WIN32_STRIPS_TRAILING = pytest.mark.skipif(
    sys.platform != "win32", reason="only Win32 drops trailing dots and spaces from names"
)


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
        # Windows strips trailing dots and spaces; elsewhere these are two files.
        pytest.param("manifest.json", "manifest.json.", marks=WIN32_STRIPS_TRAILING),
        pytest.param("manifest.json", "manifest.json ", marks=WIN32_STRIPS_TRAILING),
    ],
)
def test_names_colliding_after_normalisation_rejected(
    tmp_path: Path, first: str, second: str
) -> None:
    """All platforms (the trailing dot and space pairs on Windows only): two
    members whose names reach one file once normalized (``./``, case, Unicode
    form, trailing dots or spaces) are refused before anything is written."""
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
    """All platforms: ``Claims/a.md`` and ``claims/b.md`` share one directory on
    NTFS/APFS but two on ext4, so the extracted tree would differ by platform."""
    archive = _write_tar(
        tmp_path / "a.tar",
        [(_reg("Claims/a.md"), b"a"), (_reg("claims/b.md"), b"b")],
    )
    with pytest.raises(SecurityError) as exc:
        unpack(archive, tmp_path / "dest")
    assert exc.value.code == ErrorCode.DUPLICATE_MEMBER_PATH


def test_file_and_directory_with_same_name_rejected(tmp_path: Path) -> None:
    """All platforms: a file member and a directory member of one name are refused."""
    archive = _write_tar(
        tmp_path / "a.tar",
        [(_reg("claims"), b"x"), (_reg("claims/a.md"), b"a")],
    )
    with pytest.raises(SecurityError) as exc:
        unpack(archive, tmp_path / "dest")
    assert exc.value.code == ErrorCode.DUPLICATE_MEMBER_PATH


def test_explicit_directory_entries_do_not_count_as_collisions(tmp_path: Path) -> None:
    """All platforms: a directory member plus files inside it (and ``./``
    prefixes as plain ``tar -C dir .`` produces) is a normal archive, not a
    collision."""
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


# ---------- a failed unpack leaves the destination as it was ----------


def _tree(root: Path) -> dict[str, bytes | None]:
    """Relative path -> bytes (files) or None (dirs), for exact comparison."""
    if not root.exists():
        return {}
    return {
        p.relative_to(root).as_posix(): (None if p.is_dir() else p.read_bytes())
        for p in sorted(root.rglob("*"))
    }


def _fails_after_first_member(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[Path, ExtractPolicy]:
    """Archive whose first members extract fine and whose last member, within
    the per-file budget by its header, streams past it (ARCHIVE_BOMB), so
    the failure comes after files were written: a size the header declares
    over the budget is refused before anything is written."""
    archive = _write_tar(
        tmp_path / "a.tar",
        [
            (_dir("claims"), None),
            (_reg("claims/a.md"), b"new a"),
            (_reg("manifest.json"), b"new manifest"),
            (_reg("zz-big.bin"), b"B" * 10),
        ],
    )
    real_extractfile = tarfile.TarFile.extractfile

    def extractfile(self: tarfile.TarFile, member: object) -> object:
        if getattr(member, "name", member) == "zz-big.bin":
            return io.BytesIO(b"B" * 4096)
        return real_extractfile(self, member)

    monkeypatch.setattr(tarfile.TarFile, "extractfile", extractfile)
    return archive, ExtractPolicy(max_file_bytes=1024)


def test_failed_unpack_into_missing_dest_creates_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """All platforms: a failed unpack into a missing dest leaves neither dest nor
    the parents it made for it."""
    archive, policy = _fails_after_first_member(tmp_path, monkeypatch)
    dest = tmp_path / "out" / "nested" / "dest"
    with pytest.raises(SecurityError) as exc:
        unpack(archive, dest, policy=policy)
    assert exc.value.code == ErrorCode.ARCHIVE_BOMB
    # Neither the destination nor the parents created for it remain.
    assert not (tmp_path / "out").exists()
    assert sorted(p.name for p in tmp_path.iterdir()) == ["a.tar"]


def test_failed_unpack_into_existing_dest_leaves_it_unchanged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """All platforms: a failed unpack into an existing dest leaves it exactly as
    it was, with no staging dir beside it."""
    archive, policy = _fails_after_first_member(tmp_path, monkeypatch)
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
    """All platforms: an archive over the compression-ratio budget (ratio 0,
    as in test_compression_ratio_exceeded: a plain ustar archive never
    expands) is refused, and nothing is left."""
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
    """All platforms: an archive over the total byte budget leaves an existing
    empty dest empty."""
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
    """All platforms: success keeps the old contract: archive files are written
    into dest, replacing same-named files and leaving unrelated ones alone."""
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
    """All platforms: an unpack into a missing dest creates it, and nothing else
    beside it."""
    archive = _write_tar(tmp_path / "a.tar", [(_reg("claims/a.md"), b"a")])
    dest = tmp_path / "new" / "dest"
    unpack(archive, dest)
    assert _tree(dest) == {"claims": None, "claims/a.md": b"a"}
    assert sorted(p.name for p in (tmp_path / "new").iterdir()) == ["dest"]


def test_unpack_into_existing_dest_moves_only_within_its_filesystem(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """All platforms: an existing dest may be a mount point (on POSIX; Windows
    refuses a mounted folder as dest), where a rename from anywhere outside it
    fails with EXDEV. Simulate that: the merge must not need one."""
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
    """POSIX only, not as root (where directory write permission is enforced):
    an existing dest in a read-only parent is still unpacked into, since
    staging sits inside dest."""
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
    """All platforms: guards the in-dest staging placement rather than a past
    regression: a conflict found by the pre-move check leaves no staging dir
    inside dest."""
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
    """All platforms (the case spelling where names are case-insensitive, the
    8.3 spelling on Windows): a member under a name that reaches the staging
    dir would be moved into the staging tree and deleted with it. It must be
    refused instead."""
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
    """All platforms (the case spelling where names are case-insensitive, the
    8.3 spelling on Windows): such a member also hides a conflict from the
    pre-move check (its target looks absent), so the merge would fail halfway.
    It must be refused before anything in dest changes."""
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
    """All platforms: a staging dir that a failed unpack cannot remove is named
    in a RuntimeWarning."""
    archive, policy = _fails_after_first_member(tmp_path, monkeypatch)
    dest = tmp_path / "dest"
    dest.mkdir()
    (dest / "keep.txt").write_bytes(b"keep")
    _fail_to_unlink(monkeypatch, "manifest.json")

    with pytest.warns(RuntimeWarning) as warned, pytest.raises(SecurityError) as exc:
        unpack(archive, dest, policy=policy)
    monkeypatch.undo()

    assert exc.value.code == ErrorCode.ARCHIVE_BOMB
    leftover = [p for p in dest.resolve().iterdir() if p.name.startswith(".unpacking-")]
    assert len(leftover) == 1
    assert any(str(leftover[0]) in str(w.message) for w in warned)


def test_failed_unpack_keeps_its_error_when_warnings_are_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """All platforms: with warnings turned into errors, the unpack's own error is
    still raised (and on Python 3.11+ a note names the staging dir left)."""
    import warnings

    archive, policy = _fails_after_first_member(tmp_path, monkeypatch)
    dest = tmp_path / "dest"
    dest.mkdir()
    _fail_to_unlink(monkeypatch, "manifest.json")

    with warnings.catch_warnings():
        warnings.simplefilter("error")
        with pytest.raises(SecurityError) as exc:
            unpack(archive, dest, policy=policy)
    monkeypatch.undo()

    assert exc.value.code == ErrorCode.ARCHIVE_BOMB
    if sys.version_info >= (3, 11):  # the warning was an error; a note still names it
        leftover = [p for p in dest.resolve().iterdir() if p.name.startswith(".unpacking-")]
        assert len(leftover) == 1
        assert any(str(leftover[0]) in note for note in exc.value.__notes__)


def test_failed_unpack_removes_read_only_staged_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Windows (runs everywhere; POSIX deletes a read-only file in a writable
    directory anyway): a read-only file in the staging tree, which the Windows
    attribute keeps from being deleted, is made writable and removed, not left
    inside dest."""
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
    """POSIX (symlink case, where chmod follows links) and Windows (junction
    case): a link in the staging tree that cannot be removed is reported, never
    made writable: that would change the read-only entry it points to. Windows
    chmod did not change a symlink's target even before."""
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
    """All platforms: an OS error after some files were replaced (a full disk, a
    file held open on Windows) puts every replaced file back and removes what
    was added."""
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
    """All platforms: if replaced files cannot be put back either, the backup
    holding them is kept and named in the error."""
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
        if Path(os.fspath(src)) == dest.resolve() / "a.md" and back_to_staging:
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
    """Windows only: a file another handle holds open cannot be replaced, so the
    merge is undone and dest is left unchanged."""
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
    """Windows only: a file with the read-only attribute in dest is still
    replaced, and no staging dir is left."""
    archive, dest, _ = _merge_archive(tmp_path)
    (dest / "z.md").chmod(stat.S_IREAD)

    unpack(archive, dest)

    assert (dest / "z.md").read_bytes() == b"new z"
    assert not [p for p in dest.iterdir() if p.name.startswith(".unpacking-")]


def test_staging_left_after_a_complete_merge_only_warns(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """All platforms: dest is fully updated, so failing to remove the empty
    staging dir afterwards must not report the unpack as failed."""
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
    """All platforms (the case spelling where names are case-insensitive, the
    8.3 spelling on Windows): the backup directory for replaced files sits in
    staging; a member that reaches it under any spelling is refused before
    anything is moved."""
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


# The kinds of step that move an entry (os.rename places what was found absent).
MOVES = ("replace", "rename")


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
    real_replace, real_rename = os.replace, os.rename
    real_rmdir, real_mkdir = os.rmdir, Path.mkdir

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
        os, "rename", lambda s, d, **kw: step("rename", s, lambda: real_rename(s, d, **kw))
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
    puts dest back and raises that same error, an interrupt included. An
    OSError from mkdir means it made nothing, so the undo never removes a
    directory for one: raised after a mkdir in dest that returned, which no
    real mkdir does, it leaves that one directory, empty."""
    call, _, _ = _unpack_merge(tmp_path / "clean")
    steps, exc, _ = _run_steps(monkeypatch, call, {})
    assert exc is None
    forward = [n for n, line in enumerate(steps, 1) if not line.startswith("rmdir")]
    # a.md and z.md: move aside, move in; new/f.md: move in.
    assert sum(steps[n - 1].startswith(MOVES) for n in forward) == 5

    for n in forward:
        call, dest, before = _unpack_merge(tmp_path / str(n))
        error = _error(kind)
        _, exc, _ = _run_steps(monkeypatch, call, {n: (error, after)})
        assert exc is error, (steps[n - 1], exc)
        left = _tree(dest)
        if kind is OSError and after and steps[n - 1].startswith("mkdir"):
            made = Path(steps[n - 1].split(" ", 1)[1])  # as the first run spelled it
            if made.parent.parent == (tmp_path / "clean").resolve() and made.name[0] != ".":
                assert left.pop(made.name) is None, steps[n - 1]
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
    moves = [n for n, line in enumerate(steps, 1) if line.startswith(MOVES)]
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


MERGED = {
    "a.md": b"new a",
    "keep.txt": b"keep",
    "new": None,
    "new/f.md": b"new f",
    "z.md": b"new z",
}


@pytest.mark.parametrize(
    "layout, after",
    [("merge", False), ("merge", True), ("new-dest", True)],
    ids=["merge-interrupt-before-step", "merge-interrupt-after-step", "new-dest-after-rename"],
)
def test_interrupt_once_every_entry_is_in_place_says_the_unpack_completed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, layout: str, after: bool
) -> None:
    """All platforms: once every entry is in place the unpack has succeeded.
    An interrupt after that (while the replaced files are deleted, or right
    after a new dest is renamed into place) propagates with a note (Python
    3.11+) and a warning saying the unpack completed and naming what is
    left over, and dest keeps the archive's files."""

    def setup(work: Path) -> tuple[Callable[[], object], Path, dict[str, bytes | None]]:
        if layout == "merge":
            return _unpack_merge(work)
        archive = _write_tar(work / "a.tar", [(_reg("a.md"), b"a")])
        return functools.partial(unpack, archive, work / "dest"), work / "dest", {"a.md": b"a"}

    call, _, _ = setup(tmp_path / "clean")
    steps, exc, _ = _run_steps(monkeypatch, call, {})
    assert exc is None
    last_move = max(n for n, line in enumerate(steps, 1) if line.startswith(MOVES))
    # The rename of a new dest completes it; the merge's last move is still
    # undone if interrupted (see test_merge_stopped_at_any_step_leaves_dest_unchanged).
    finishing = range(last_move + (0 if layout == "new-dest" else 1), len(steps) + 1)
    assert finishing

    for n in finishing:
        call, dest, done = setup(tmp_path / str(n))
        error = KeyboardInterrupt()
        _, exc, warned = _run_steps(monkeypatch, call, {n: (error, after)})
        assert exc is error, steps[n - 1]
        named = _named(exc, warned)
        assert "the unpack completed" in named, (steps[n - 1], named)
        left = _tree(dest)
        assert {p: d for p, d in left.items() if not p.startswith(".unpacking-")} == (
            MERGED if layout == "merge" else done
        )
        for leftover in [p for p in left if p.startswith(".unpacking-") and "/" not in p]:
            assert str(dest.resolve() / leftover) in named, (steps[n - 1], named)


WARNING_FILTERS = pytest.mark.parametrize(
    "warn", [None, "ignore", "error"], ids=["warnings-default", "warnings-ignored", "warnings-errors"]
)


def run_python(script: str, args: list[str], warn: str | None) -> subprocess.CompletedProcess[str]:
    """Run ``script`` in a new interpreter like this one, with ``-W warn`` if
    given and PYTHONWARNINGS unset, so its stderr is what a user would see."""
    import aphelion

    env = {k: v for k, v in os.environ.items() if k != "PYTHONWARNINGS"}
    env["PYTHONPATH"] = str(Path(str(aphelion.__file__)).parents[1])
    options = ["-W", warn] if warn else []
    return subprocess.run(
        [sys.executable, *options, "-c", script, *args],
        capture_output=True,
        text=True,
        env=env,
        timeout=120,
    )


LEFTOVER_AFTER_UNPACK = """
import os, sys, traceback
from pathlib import Path
from aphelion.unpacker import unpack

archive, dest, case = sys.argv[1], Path(sys.argv[2]).resolve(), sys.argv[3]
real_rmdir, real_replace = os.rmdir, os.replace
moves = []

def rmdir(path, *args, **kwargs):
    if os.path.basename(os.fspath(path)).startswith(".unpacking-"):
        raise PermissionError(13, "Permission denied", os.fspath(path))
    real_rmdir(path, *args, **kwargs)

def replace(src, dst, **kwargs):
    moves.append(src)
    if len(moves) == 4:  # moving the new z.md in fails,
        raise OSError(5, "simulated I/O error")
    if len(moves) == 5:  # and Ctrl-C lands on putting the old one back
        raise KeyboardInterrupt
    real_replace(src, dst, **kwargs)

if case == "staging-after-success":
    os.rmdir = rmdir
    unpack(archive, dest)
    left = [p for p in dest.iterdir() if p.name.startswith(".unpacking-")]
else:
    os.replace = replace
    try:
        unpack(archive, dest)
    except BaseException as exc:
        traceback.print_exception(exc)
    os.replace = real_replace
    left = list(dest.glob(".unpacking-*/.backup-*"))
print("\\n".join(map(str, left)))
"""


@WARNING_FILTERS
@pytest.mark.parametrize("case", ["staging-after-success", "backup-after-failure"])
def test_leftover_reaches_stderr_once_whatever_the_warnings_filters(
    tmp_path: Path, case: str, warn: str | None
) -> None:
    """All platforms, run in a new interpreter: a staging dir left after a
    complete merge, or a backup kept after a failed one (a move fails and
    Ctrl-C lands on putting a file back), is named on stderr exactly once,
    with warnings shown, ignored (-W ignore) or turned into errors (-W
    error). Where a note on the error cannot name it (Python 3.10, or no
    error at all), its RuntimeWarning is shown past the filters."""
    archive, dest, _ = _merge_archive(tmp_path)

    run = run_python(LEFTOVER_AFTER_UNPACK, [str(archive), str(dest), case], warn)

    assert run.returncode == 0, run.stderr
    left = run.stdout.splitlines()
    assert len(left) == 1, (run.stdout, run.stderr)
    assert run.stderr.count(left[0]) == 1, run.stderr


@pytest.mark.parametrize("case", ["staging-after-success", "backup-after-failure"])
def test_leftover_reaches_stderr_once_where_warnings_go_to_logging(
    tmp_path: Path, case: str
) -> None:
    """All platforms, run in a new interpreter: where an application sends
    warnings to logging (logging.captureWarnings) and has no handler, which
    shows nothing, a leftover that no note on an error can name (Python
    3.10, or no error at all) is still named on stderr, exactly once."""
    archive, dest, _ = _merge_archive(tmp_path)
    script = "import logging\nlogging.captureWarnings(True)\n" + LEFTOVER_AFTER_UNPACK

    run = run_python(script, [str(archive), str(dest), case], None)

    assert run.returncode == 0, run.stderr
    left = run.stdout.splitlines()
    assert len(left) == 1, (run.stdout, run.stderr)
    assert run.stderr.count(left[0]) == 1, run.stderr


# ---------- two members that reach one entry are refused ----------


WINDOWS_83 = pytest.mark.skipif(
    sys.platform != "win32", reason="8.3 short names exist only on Windows"
)
WINDOWS_ONLY = pytest.mark.skipif(sys.platform != "win32", reason="winerror exists only on Windows")


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
    file in staging but the same file in dest. It is refused, instead of
    replacing the long-named file: before anything moves when that file is
    already in dest, and otherwise during the merge (which gives the long
    name the short name), which is then undone."""
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
    assert "filesystem alias" in str(exc.value)
    assert _tree(dest) == before


@WINDOWS_83
@pytest.mark.parametrize("layout", ["files", "explicit-directories"])
def test_members_reaching_one_directory_in_dest_are_refused_before_anything_moves(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, layout: str
) -> None:
    """Windows only (8.3 short names): two members, one spelled as the short
    name of a directory already in dest and one as its long name, are two
    directories in staging but one in dest. They are refused before
    anything in dest changes, instead of being merged into one directory."""
    dest = tmp_path / "dest"
    (dest / "longdirectoryname").mkdir(parents=True)
    (dest / "longdirectoryname" / "old.md").write_bytes(b"old")
    short = _short_name(dest / "longdirectoryname")
    if short is None:
        pytest.skip("this volume does not generate 8.3 short names")
    if layout == "files":
        members = [(_reg(f"{short}/a.md"), b"a"), (_reg("longdirectoryname/b.md"), b"b")]
    else:
        members = [(_dir(short), None), (_dir("longdirectoryname"), None)]
    archive = _write_tar(tmp_path / "a.tar", members)
    before = _tree(dest)

    steps, exc, _ = _run_steps(monkeypatch, functools.partial(unpack, archive, dest), {})

    assert isinstance(exc, SecurityError)
    assert exc.code == ErrorCode.DUPLICATE_MEMBER_PATH
    assert "filesystem alias" in str(exc)
    assert [s for s in steps if ".unpacking-" not in s] == []  # nothing outside staging
    assert _tree(dest) == before


def _hard_link(existing: Path, new: Path) -> None:
    try:
        os.link(existing, new)
    except OSError as exc:  # a filesystem without hard links
        pytest.skip(f"cannot make a hard link here: {exc}")


def test_hard_links_in_dest_are_each_replaced(tmp_path: Path) -> None:
    """All platforms: two names in dest that are hard links of one file are two
    directory entries, not one entry reached twice: an archive with both
    names replaces each, as it would two separate files."""
    dest = tmp_path / "dest"
    dest.mkdir()
    (dest / "a.md").write_bytes(b"old")
    _hard_link(dest / "a.md", dest / "b.md")
    archive = _write_tar(tmp_path / "a.tar", [(_reg("a.md"), b"new a"), (_reg("b.md"), b"new b")])

    assert unpack(archive, dest) == dest

    assert _tree(dest) == {"a.md": b"new a", "b.md": b"new b"}


def _no_final_path(monkeypatch: pytest.MonkeyPatch, volume: Path, winerror: int) -> None:
    """Make Windows' final-path query fail with ``winerror`` for every path in
    ``volume``, as on a RAM disk or mapped drive whose driver cannot answer
    it (1: ERROR_INVALID_FUNCTION, 50: ERROR_NOT_SUPPORTED)."""
    import ntpath

    real = ntpath._getfinalpathname  # type: ignore[attr-defined]
    prefix = os.path.normcase(str(volume))

    def final_path(path: str) -> str:
        if os.path.normcase(os.fspath(path)).startswith(prefix):
            raise OSError(0, "simulated: no final path here", os.fspath(path), winerror)
        return real(path)

    monkeypatch.setattr(ntpath, "_getfinalpathname", final_path)


@WINDOWS_ONLY
@pytest.mark.parametrize("winerror", [1, 50])
def test_hard_links_in_dest_are_each_replaced_where_no_final_path_is_reported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, winerror: int
) -> None:
    """Windows only (simulated): on a volume whose driver cannot answer the
    final-path query, two hard links in dest are still two entries, each
    replaced; the name each is stored under comes from the fallback the
    standard library uses there."""
    dest = tmp_path / "dest"
    dest.mkdir()
    (dest / "a.md").write_bytes(b"old")
    _hard_link(dest / "a.md", dest / "b.md")
    archive = _write_tar(tmp_path / "a.tar", [(_reg("a.md"), b"new a"), (_reg("b.md"), b"new b")])
    _no_final_path(monkeypatch, dest.resolve(), winerror)

    assert unpack(archive, dest) == dest
    monkeypatch.undo()

    assert _tree(dest) == {"a.md": b"new a", "b.md": b"new b"}


@WINDOWS_83
def test_short_name_of_a_hard_linked_file_in_dest_is_refused_before_anything_moves(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Windows only (8.3 short names): a file in dest that has a second hard
    link, reached by two members (its long name and its short name), is one
    entry reached twice, not two hard links: refused before anything in dest
    changes."""
    dest = tmp_path / "dest"
    dest.mkdir()
    (dest / "longfilename.txt").write_bytes(b"old")
    _hard_link(dest / "longfilename.txt", dest / "other.txt")
    short = _short_name(dest / "longfilename.txt")
    if short is None:
        pytest.skip("this volume does not generate 8.3 short names")
    archive = _write_tar(
        tmp_path / "a.tar", [(_reg(short), b"other"), (_reg("longfilename.txt"), b"new")]
    )
    before = _tree(dest)

    steps, exc, _ = _run_steps(monkeypatch, functools.partial(unpack, archive, dest), {})

    assert isinstance(exc, SecurityError)
    assert exc.code == ErrorCode.DUPLICATE_MEMBER_PATH
    assert "filesystem alias" in str(exc)
    assert [s for s in steps if ".unpacking-" not in s] == []  # nothing outside staging
    assert _tree(dest) == before


def test_existing_entries_are_refused_where_the_filesystem_reports_no_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """All platforms (simulated): os.lstat reports inode number 0 for the
    entries in dest, but not for staging, so whether two members reach one
    entry in dest cannot be checked. Adding a new top-level file still
    works; replacing an existing file fails closed, and dest is left as it
    was. (Where os.stat reports inode number 0 too, an unpack into an
    existing dest fails earlier, with FileExistsError, in more cases.)"""
    dest = tmp_path / "dest"
    dest.mkdir()
    (dest / "keep.md").write_bytes(b"keep")
    inside = os.path.normcase(str(dest.resolve()))
    real_lstat = os.lstat

    class NoIdentity:
        st_ino = 0

        def __init__(self, st: os.stat_result) -> None:
            self._st = st

        def __getattr__(self, name: str) -> object:
            return getattr(self._st, name)

    def lstat(path: str, *args: object, **kwargs: object) -> object:
        st = real_lstat(path, *args, **kwargs)
        name = os.path.normcase(os.path.abspath(os.fspath(path)))
        if not kwargs.get("dir_fd") and name.startswith(inside) and ".unpacking-" not in name:
            return NoIdentity(st)
        return st

    monkeypatch.setattr(os, "lstat", lstat)

    unpack(_write_tar(tmp_path / "new.tar", [(_reg("new.md"), b"new")]), dest)
    assert _tree(dest) == {"keep.md": b"keep", "new.md": b"new"}

    before = _tree(dest)
    with pytest.raises(SecurityError) as exc:
        unpack(_write_tar(tmp_path / "old.tar", [(_reg("keep.md"), b"other")]), dest)
    monkeypatch.undo()

    assert exc.value.code == ErrorCode.DUPLICATE_MEMBER_PATH
    assert "no file identity" in str(exc.value)
    assert _tree(dest) == before


# ---------- an error while looking at the tree is never skipped ----------


def test_unpack_fails_when_a_staged_directory_cannot_be_listed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """All platforms: a staged directory that cannot be listed (too many open
    files, a filter driver refusing access) fails the unpack before anything
    moves, and dest is left as it was. It used to be skipped, and the unpack
    reported success with files missing. (Staging is listed once, before any
    move; the merge then works from that listing.)"""
    archive, dest, before = _merge_archive(tmp_path)
    real_scandir = os.scandir
    listed: list[str] = []

    def scandir(*args: object) -> object:
        if args and isinstance(args[0], (str, os.PathLike)):
            path = os.fspath(args[0])
            if ".unpacking-" in path and os.path.basename(path) == "new" and not listed:
                listed.append(path)  # once: cleaning up afterwards lists it again
                raise PermissionError(errno.EACCES, "Permission denied", path)
        return real_scandir(*args)

    monkeypatch.setattr(os, "scandir", scandir)

    with pytest.raises(PermissionError) as exc:
        unpack(archive, dest)
    monkeypatch.undo()

    assert exc.value.filename == listed[0]
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
    # unpack looks at dest as given, and at files in it through dest resolved.
    broken = os.path.normcase(dest if name == "dest" else dest.resolve() / name)
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


# ---------- types and existence come only from a look that cannot fail silently ----------

# Checks that answer False when the entry cannot be looked at (pathlib's and
# os.path's on Python 3.14 do so on any OSError, DirEntry's on some), and
# os.walk / Path.walk, which take an entry whose type cannot be read for a file.
SWALLOWING_ANYWHERE = {
    "exists", "lexists", "is_dir", "is_file", "is_symlink", "is_junction", "is_mount", "walk",
}
# os.path's forms, also the names of TarInfo methods, so these count only as
# os.path functions or bare names.
SWALLOWING_OS_PATH = {"isdir", "isfile", "islink", "isjunction", "ismount"}
SWALLOWING_IN_OS = {"access"}  # os.access answers False on any error
# The os.path functions unpack and migrate may use; any other is flagged.
OS_PATH_ALLOWED = {"abspath", "normcase", "realpath", "samefile"}
OS_PATH_MODULES = {"ntpath", "posixpath", "genericpath"}


def _swallowing_checks(source: str) -> list[str]:
    """``line: code`` for every swallowing type or existence check in
    ``source``, whether reached as an attribute, a bare name, through
    ``getattr`` or through an alias of os or os.path, and for every os.path
    function outside :data:`OS_PATH_ALLOWED`."""
    tree = ast.parse(source)
    os_names, path_names = {"os"}, set(OS_PATH_MODULES)
    for node in ast.walk(tree):
        for alias in node.names if isinstance(node, ast.Import) else ():
            if alias.name == "os":
                os_names.add(alias.asname or "os")
            elif alias.name == "os.path" and alias.asname:  # plain "import os.path" binds os
                path_names.add(alias.asname)
            elif alias.name in OS_PATH_MODULES:
                path_names.add(alias.asname or alias.name)

    def is_os(node: ast.expr) -> bool:
        return isinstance(node, ast.Name) and node.id in os_names

    def is_os_path(node: ast.expr) -> bool:
        return (isinstance(node, ast.Attribute) and node.attr == "path" and is_os(node.value)) or (
            isinstance(node, ast.Name) and node.id in path_names
        )

    def swallows(owner: ast.expr, name: str) -> bool:
        if name in SWALLOWING_ANYWHERE:
            return True
        if is_os_path(owner):
            return name not in OS_PATH_ALLOWED
        return is_os(owner) and name in SWALLOWING_IN_OS

    found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module in {"os", "os.path", *OS_PATH_MODULES}:
            if node.module == "os":
                names = SWALLOWING_ANYWHERE | SWALLOWING_IN_OS | {"path"}
                found += [f"{node.lineno}: import {a.name}" for a in node.names if a.name in names]
            else:
                found += [
                    f"{node.lineno}: import {a.name}"
                    for a in node.names
                    if a.name not in OS_PATH_ALLOWED
                ]
        elif isinstance(node, ast.Attribute) and swallows(node.value, node.attr):
            found.append(f"{node.lineno}: {ast.unparse(node)}")
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id in SWALLOWING_ANYWHERE | SWALLOWING_OS_PATH | SWALLOWING_IN_OS:
                found.append(f"{node.lineno}: {node.func.id}()")
            elif node.func.id == "getattr" and len(node.args) >= 2:
                owner, name = node.args[0], node.args[1]
                if isinstance(name, ast.Constant) and isinstance(name.value, str):
                    if swallows(owner, name.value):
                        found.append(f"{node.lineno}: {ast.unparse(node)}")
                elif is_os(owner) or is_os_path(owner):  # a name chosen at run time
                    found.append(f"{node.lineno}: {ast.unparse(node)}")
    return found


def test_unpack_and_migrate_never_use_a_check_that_swallows_errors() -> None:
    """All platforms: every function in aphelion/unpacker.py and
    aphelion/migrate.py decides whether an entry exists, and what it is,
    only through the strict lstat helper, never through a pathlib, os.path
    or DirEntry predicate, os.access or os.walk, which turn an error into
    "absent" or "not a directory", whether called directly, through getattr
    or through an alias of os.path; and uses only the os.path functions on
    an allow-list. Such a check let unpack move a whole directory in dest
    aside and delete it; this keeps one from coming back unnoticed."""
    import aphelion.migrate as migrate_module
    import aphelion.unpacker as unpacker_module

    may_use = [
        "import os.path as osp",
        "import ntpath",
        "member.isdir()",  # TarInfo
        "os.path.samefile(a, b)",
        "os.path.realpath(p, strict=True)",
        'getattr(st, "st_file_attributes", 0)',
        "path.name",
    ]
    must_find = [
        "os.path.isdir(p)",
        "Path(p).is_dir()",
        "os.walk(p)",
        "entry.is_file()",
        "osp.isdir(p)",
        "ntpath.exists(p)",
        'getattr(os.path, "isdir")(p)',
        'getattr(p, "is_dir")()',
        "getattr(os.path, name)(p)",
        "os.access(p, os.F_OK)",
        "os.path.getsize(p)",
        "from os.path import isdir as d",
    ]
    found = _swallowing_checks("\n".join(may_use + must_find))
    lines = range(len(may_use) + 1, len(may_use) + len(must_find) + 1)
    assert {int(f.split(":")[0]) for f in found} == set(lines), found  # each, and only those
    for module in (unpacker_module, migrate_module):
        source = Path(str(module.__file__)).read_text(encoding="utf-8")
        assert _swallowing_checks(source) == [], module.__name__
    # Only migrate puts something in place whatever is there; unpack's merge
    # moves aside regular files only.
    unpacker_tree = ast.parse(Path(str(unpacker_module.__file__)).read_text(encoding="utf-8"))
    assert not [
        node.lineno
        for node in ast.walk(unpacker_tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "replace_entry"
    ]


def _from_aphelion() -> bool:
    """Whether the call being made comes from aphelion code, and not by way of
    shutil, whose rmtree cleans up only after the call has decided."""
    frame = sys._getframe(2)
    while frame is not None:
        module = frame.f_globals.get("__name__", "")
        if module == "shutil":
            return False
        if module.startswith("aphelion."):
            return True
        frame = frame.f_back
    return False


def _looks_at(
    monkeypatch: pytest.MonkeyPatch, path: Path, fail_at: int | None = None
) -> list[str]:
    """Record every look aphelion takes at ``path`` and make the ``fail_at``-th
    one fail: lstat, stat, scandir and samefile raise EIO, and the os.path
    predicates return False, as Python 3.14's do on any error."""
    looks: list[str] = []
    want = os.path.normcase(os.path.abspath(path))

    def wrap(module: object, name: str, swallows: bool) -> None:
        real = getattr(module, name)

        def look(*args: object, **kwargs: object) -> object:
            paths = [a for a in args[: 2 if name == "samefile" else 1] if isinstance(a, (str, os.PathLike))]
            if (
                not kwargs.get("dir_fd")
                and any(os.path.normcase(os.path.abspath(os.fspath(p))) == want for p in paths)
                and _from_aphelion()
            ):
                looks.append(name)
                if len(looks) == fail_at:
                    if swallows:
                        return False
                    raise OSError(errno.EIO, "simulated I/O error", os.fspath(path))
            return real(*args, **kwargs)

        monkeypatch.setattr(module, name, look)

    for name in ("lstat", "stat", "scandir"):
        wrap(os, name, swallows=False)
    wrap(os.path, "samefile", swallows=False)
    for name in ("exists", "lexists", "isdir", "isfile", "islink"):
        wrap(os.path, name, swallows=True)
    return looks


def _dir_in_dest(work: Path, archive_has: str) -> tuple[Path, Path, dict[str, bytes | None]]:
    """dest holds keep.md and sub/precious.md, which the archive does not
    name; the archive has top.md and a directory ``sub`` with new.md in it
    (``archive_has="dir"``) or a file ``sub`` (``"file"``)."""
    sub = (_reg("sub/new.md"), b"new") if archive_has == "dir" else (_reg("sub"), b"new")
    archive = _write_tar(work / "a.tar", [sub, (_reg("top.md"), b"top")])
    dest = work / "dest"
    (dest / "sub").mkdir(parents=True)
    (dest / "sub" / "precious.md").write_bytes(b"precious")
    (dest / "keep.md").write_bytes(b"keep")
    return archive, dest, _tree(dest)


MERGED_DIR = {
    "keep.md": b"keep",
    "sub": None,
    "sub/new.md": b"new",
    "sub/precious.md": b"precious",
    "top.md": b"top",
}


class _TypelessEntry:
    """A directory entry that cannot tell its type, as on a filesystem without
    d_type after a transient stat error."""

    def __init__(self, entry: os.DirEntry[str]) -> None:
        self.name, self.path = entry.name, entry.path

    def _fail(self, *args: object, **kwargs: object) -> bool:
        raise OSError(errno.EIO, "simulated I/O error", self.path)

    is_dir = is_file = is_symlink = is_junction = stat = inode = _fail

    def __fspath__(self) -> str:
        return self.path


class _Listing:
    """``os.scandir`` whose entry ``name`` is a :class:`_TypelessEntry`."""

    def __init__(self, listing: Iterator[os.DirEntry[str]], name: str) -> None:
        self._listing, self._name = listing, name

    def __iter__(self) -> _Listing:
        return self

    def __next__(self) -> object:
        entry = next(self._listing)
        return _TypelessEntry(entry) if entry.name == self._name else entry

    def __enter__(self) -> _Listing:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        self._listing.close()  # type: ignore[attr-defined]


@pytest.mark.parametrize("listing", [1, 2], ids=["first-listing", "second-listing"])
def test_merge_takes_no_type_from_a_directory_listing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, listing: int
) -> None:
    """All platforms: a staged directory whose type the listing of staging
    cannot tell is still merged as a directory, since the merge looks at
    each entry itself. os.walk took it for a file, so the merge moved the
    user's directory of that name in dest aside, deleted it with everything
    in it, and reported success."""
    archive, dest, before = _dir_in_dest(tmp_path, "dir")
    real_scandir = os.scandir
    listed: list[str] = []

    def scandir(*args: object) -> object:
        found = real_scandir(*args)
        path = os.fspath(args[0]) if args and isinstance(args[0], (str, os.PathLike)) else ""
        if os.path.basename(path).startswith(".unpacking-") and _from_aphelion():
            listed.append(path)
            if len(listed) == listing:
                return _Listing(found, "sub")
        return found

    monkeypatch.setattr(os, "scandir", scandir)
    try:
        unpack(archive, dest)
        failed = False
    except OSError:
        failed = True
    monkeypatch.undo()

    assert _tree(dest) == (before if failed else MERGED_DIR)


def test_staged_directory_is_merged_only_after_a_look_that_cannot_fail_silently(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """All platforms: the merge reads a staged directory's type from an lstat
    of the entry itself, and a failure of any look unpack takes at it fails
    the call and leaves dest as it was."""
    import secrets

    monkeypatch.setattr(secrets, "token_hex", lambda nbytes: "00" * nbytes)
    archive, dest, _ = _dir_in_dest(tmp_path / "clean", "dir")
    with monkeypatch.context() as patch:
        looks = _looks_at(patch, dest.resolve() / STAGING_NAME / "sub")
        unpack(archive, dest)
    assert _tree(dest) == MERGED_DIR
    assert "lstat" in looks, looks

    for n in range(1, len(looks) + 1):
        archive, dest, before = _dir_in_dest(tmp_path / str(n), "dir")
        with monkeypatch.context() as patch:
            _looks_at(patch, dest.resolve() / STAGING_NAME / "sub", fail_at=n)
            with pytest.raises(OSError) as exc:
                unpack(archive, dest)
        assert exc.value.errno == errno.EIO, looks[n - 1]
        assert _tree(dest) == before, looks[n - 1]


def test_file_over_a_directory_is_refused_whichever_look_at_it_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """All platforms: where the archive has a file and dest a directory of the
    same name, a failure of any look unpack takes at that directory fails
    the call and leaves dest as it was. Path.is_dir() on Python 3.14 returns
    False on such an error, which skipped the refusal: the directory was
    moved aside and deleted, and the unpack reported success."""
    archive, dest, _ = _dir_in_dest(tmp_path / "clean", "file")
    with monkeypatch.context() as patch:
        looks = _looks_at(patch, dest.resolve() / "sub")
        with pytest.raises(FileExistsError, match="file over existing directory"):
            unpack(archive, dest)
    assert looks

    for n in range(1, len(looks) + 1):
        archive, dest, before = _dir_in_dest(tmp_path / str(n), "file")
        with monkeypatch.context() as patch:
            _looks_at(patch, dest.resolve() / "sub", fail_at=n)
            with pytest.raises(OSError):
                unpack(archive, dest)
        assert _tree(dest) == before, looks[n - 1]


@pytest.mark.parametrize("order", ["a-first", "z-first"])
@pytest.mark.parametrize("changed", ["file-in-dest", "staged-file"])
def test_merge_moves_only_what_is_a_regular_file_right_before_the_move(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, changed: str, order: str
) -> None:
    """All platforms: each entry's type is read again right before it moves.
    A file in dest that became a directory after the check before any move
    (another process at work, say) is not moved aside, and a staged file
    that is no longer a regular file is not moved in: the call fails and is
    undone, and the directory is left alone. The change lands just as the
    merge takes that last look at z.md, whichever of a.md and z.md the
    staging directory lists first (both orders are run)."""
    import secrets

    monkeypatch.setattr(secrets, "token_hex", lambda nbytes: "00" * nbytes)
    archive, dest, before = _merge_archive(tmp_path)
    staging = dest.resolve() / STAGING_NAME
    entry = dest.resolve() / "z.md" if changed == "file-in-dest" else staging / "z.md"
    changes: list[str] = []
    real_lstat, real_scandir = os.lstat, os.scandir

    def moving() -> bool:
        frame = sys._getframe(2)
        while frame is not None and frame.f_code.co_name != "put_file":
            frame = frame.f_back
        return frame is not None

    def lstat(path: str, *args: object, **kwargs: object) -> os.stat_result:
        if not changes and Path(os.fspath(path)) == entry and moving():
            changes.append(os.fspath(path))
            entry.unlink()
            entry.mkdir()
            (entry / "precious.md").write_bytes(b"precious")
        return real_lstat(path, *args, **kwargs)

    def scandir(path: object = ".") -> object:
        if (
            not isinstance(path, (str, os.PathLike))
            or Path(os.fspath(path)) != staging
            or not _from_aphelion()
        ):
            return real_scandir(path)
        with real_scandir(path) as listing:
            entries = sorted(listing, key=lambda e: e.name, reverse=order == "z-first")
        return contextlib.nullcontext(entries)

    monkeypatch.setattr(os, "lstat", lstat)
    monkeypatch.setattr(os, "scandir", scandir)

    with pytest.raises(OSError) as exc:
        unpack(archive, dest)
    monkeypatch.undo()

    assert changes
    if changed == "file-in-dest":
        assert "file over existing directory" in str(exc.value)
        del before["z.md"]
        assert _tree(dest) == {**before, "z.md": None, "z.md/precious.md": b"precious"}
    else:
        assert "not a regular file" in str(exc.value)
        assert _tree(dest) == before


def _not_found(path: object, winerror: int | None = 2) -> OSError:
    """The error an os call raises for ``path`` when it finds nothing there:
    ENOENT. On Windows ``winerror`` says what the call reported (2: no such
    file; 53 and 67: a network path or share that cannot be reached, which
    Windows also raises as FileNotFoundError), and sets type and errno as it
    does for a real one; None leaves it out. Elsewhere it is ignored."""
    if winerror is None:
        return OSError(errno.ENOENT, "simulated: not found", os.fspath(path))
    return OSError(errno.ENOENT, "simulated: not found", os.fspath(path), winerror)


@pytest.mark.parametrize("winerror", [2, pytest.param(53, marks=WINDOWS_ONLY)])
@pytest.mark.parametrize("found_absent", ["file", "directory", "new-dest-over-a-file"])
def test_entry_wrongly_found_absent_is_never_replaced(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, found_absent: str, winerror: int
) -> None:
    """All platforms: the lstat that finds an entry absent can be wrong
    (another process at work, say). What it found absent is put in place by
    a step that fails if anything is there (an exclusive create, an
    exclusive mkdir, a rename that replaces no file), so the unpack fails
    and dest keeps what it had, instead of a rename replacing a file nothing
    backed up. Windows also: a network error Windows reports as "not found"
    (winerror 53) is no "not found" at all, and fails the call."""
    archive, dest, _ = _merge_archive(tmp_path)
    if found_absent == "file":
        entry = dest / "z.md"  # after a.md was replaced, so that is undone too
    elif found_absent == "directory":
        entry = dest / "new"
        entry.mkdir()
        (entry / "old.md").write_bytes(b"old")
    else:
        shutil.rmtree(dest)
        dest.write_bytes(b"a file of the user's")
        entry = dest
    before = dest.read_bytes() if dest.is_file() else _tree(dest)
    want = os.path.normcase(os.path.abspath(entry.resolve()))
    real_lstat = os.lstat

    def lstat(path: str, *args: object, **kwargs: object) -> os.stat_result:
        name = os.path.normcase(os.path.abspath(os.fspath(path)))
        if not kwargs.get("dir_fd") and name == want and _from_aphelion():
            raise _not_found(path, winerror)
        return real_lstat(path, *args, **kwargs)

    monkeypatch.setattr(os, "lstat", lstat)
    with pytest.raises(OSError):
        unpack(archive, dest)
    monkeypatch.undo()

    assert (dest.read_bytes() if dest.is_file() else _tree(dest)) == before
    assert sorted(p.name for p in tmp_path.iterdir()) == ["a.tar", "dest"]


# Every place unpack and migrate take an error to mean "there is no such entry".
ABSENT_SITES = ["lstat", "stat", "samefile", "rmdir-backup", "migrate-samefile"]


def _taken_as_absent(
    site: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, err: OSError
) -> bool:
    """Run one of ``ABSENT_SITES`` with ``err`` raised by the os call it makes,
    on an entry that is there all along; whether it took ``err`` to mean that
    there is no such entry, or raised it on (the backup: kept, not gone)."""
    from aphelion import migrate, unpacker

    entry = tmp_path / "entry"
    entry.mkdir()

    def fail(*args: object, **kwargs: object) -> object:
        raise err

    with monkeypatch.context() as patch:
        try:
            if site in ("lstat", "stat"):
                patch.setattr(os, site, fail)
                return unpacker._lstat(entry, follow_symlinks=site == "stat") is None
            if site == "rmdir-backup":
                patch.setattr(os, "rmdir", fail)
                # Its error already names the backup, so nothing more is reported.
                return unpacker._discard_backup(entry, OSError(f"kept {entry}"))
            patch.setattr(os.path, "samefile", fail)
            same_entry = migrate._same_entry if site.startswith("migrate") else unpacker._same_entry
            return same_entry(entry, tmp_path / "other") is False
        except OSError as raised:
            assert raised is err
            return False


@WINDOWS_ONLY
@pytest.mark.parametrize(
    "winerror, absent",
    [(2, True), (3, True), (53, False), (67, False), (267, False), (None, False)],
)
@pytest.mark.parametrize("site", ABSENT_SITES)
def test_on_windows_only_no_such_file_or_path_means_absent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    site: str,
    winerror: int | None,
    absent: bool,
) -> None:
    """Windows only: an entry counts as absent only where Windows reported
    ERROR_FILE_NOT_FOUND (2) or ERROR_PATH_NOT_FOUND (3). A network path or
    share that cannot be reached (53, 67) is raised as FileNotFoundError
    too, ERROR_DIRECTORY (267) as NotADirectoryError, and Windows' own calls
    never raise one without a winerror: the entry may be there, so the
    error is raised on (or the backup kept) and fails the call."""
    err = _not_found(tmp_path / "entry", winerror)
    assert _taken_as_absent(site, tmp_path, monkeypatch, err) is absent


@pytest.mark.skipif(sys.platform == "win32", reason="Windows tells them apart by winerror")
@pytest.mark.parametrize("code", [errno.ENOENT, errno.ENOTDIR])
@pytest.mark.parametrize("site", ABSENT_SITES)
def test_elsewhere_enoent_and_enotdir_still_mean_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, site: str, code: int
) -> None:
    """POSIX: ENOENT and ENOTDIR still mean that there is no such entry;
    except from rmdir, where ENOTDIR can mean that something other than a
    directory is there, so the backup is kept, as before."""
    err = OSError(code, os.strerror(code), str(tmp_path / "entry"))
    absent = not (site == "rmdir-backup" and code == errno.ENOTDIR)
    assert _taken_as_absent(site, tmp_path, monkeypatch, err) is absent


@pytest.mark.parametrize("winerror", [2, pytest.param(53, marks=WINDOWS_ONLY)])
def test_undo_never_moves_an_original_over_its_staged_copy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, winerror: int
) -> None:
    """All platforms: moving z.md aside fails (a sharing violation, a network
    hiccup), so the undo finds the original still in dest. Where the look
    at its staged copy wrongly finds nothing (another process at work, say;
    on Windows also a network error raised as "not found"), the undo still
    cannot move the original over that copy, into staging and away with it:
    it moves back only by a step that fails if anything is there."""
    archive, dest, before = _merge_archive(tmp_path)
    z_in_dest = dest.resolve() / "z.md"
    undoing: list[str] = []
    real_replace, real_lstat = os.replace, os.lstat

    def replace(src: str, dst: str, **kwargs: object) -> None:
        if Path(os.fspath(src)) == z_in_dest and ".backup-" in os.fspath(dst):
            undoing.append(os.fspath(src))
            raise OSError(errno.EIO, "simulated I/O error", os.fspath(src))
        real_replace(src, dst, **kwargs)

    def lstat(path: str, *args: object, **kwargs: object) -> os.stat_result:
        staged = Path(os.fspath(path))
        if (
            undoing
            and staged.name == "z.md"
            and staged.parent.name.startswith(".unpacking-")
            and _from_aphelion()
        ):
            raise _not_found(path, winerror)
        return real_lstat(path, *args, **kwargs)

    monkeypatch.setattr(os, "replace", replace)
    monkeypatch.setattr(os, "lstat", lstat)
    with pytest.raises(OSError) as exc:
        unpack(archive, dest)
    monkeypatch.undo()

    assert "simulated I/O error" in str(exc.value)
    assert _tree(dest) == before
    assert sorted(p.name for p in tmp_path.iterdir()) == ["a.tar", "dest"]


def test_undo_leaves_a_directory_its_failed_mkdir_did_not_make(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """All platforms: dest/sub is there and empty, and the archive has
    sub/new.md. Where the look at sub wrongly finds nothing and making it
    then fails with an error other than "exists" (Windows raises a network
    error as "not found" for both), nothing was made, so the undo leaves
    sub alone instead of removing the user's directory."""
    archive = _write_tar(tmp_path / "a.tar", [(_dir("sub"), None), (_reg("sub/new.md"), b"new")])
    dest = tmp_path / "dest"
    (dest / "sub").mkdir(parents=True)
    before = _tree(dest)
    sub = dest.resolve() / "sub"
    failed: list[Path] = []
    real_lstat, real_mkdir = os.lstat, Path.mkdir

    def lstat(path: str, *args: object, **kwargs: object) -> os.stat_result:
        if not failed and Path(os.fspath(path)) == sub and _from_aphelion():
            raise _not_found(path)
        return real_lstat(path, *args, **kwargs)

    def mkdir(self: Path, *args: object, **kwargs: object) -> None:
        if self == sub:
            failed.append(self)
            raise _not_found(self, 53)
        real_mkdir(self, *args, **kwargs)

    monkeypatch.setattr(os, "lstat", lstat)
    monkeypatch.setattr(Path, "mkdir", mkdir)
    with pytest.raises(FileNotFoundError):
        unpack(archive, dest)
    monkeypatch.undo()

    assert failed
    assert _tree(dest) == before
    assert sorted(p.name for p in tmp_path.iterdir()) == ["a.tar", "dest"]


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
    """All platforms that can create symlinks, and Windows for junctions: a dest
    that is a dangling link is refused, and nothing is made where it points."""
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
    """All platforms that can create symlinks, and Windows for junctions: a dest
    that is a link to a directory is refused, and the directory stays empty."""
    archive = _write_tar(tmp_path / "a.tar", [(_reg("a.md"), b"a")])
    target = tmp_path / "target"
    target.mkdir()
    dest = tmp_path / "dest"
    _link_or_skip(dest, target, kind)

    with pytest.raises(FileExistsError) as exc:
        unpack(archive, dest)

    assert "symlink or junction" in str(exc.value)
    assert list(target.iterdir()) == []


@pytest.mark.parametrize("kind", LINK_KINDS)
def test_unpack_refuses_a_link_dest_wrongly_resolved_to_itself(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    """All platforms that can create symlinks, and Windows for junctions: a
    dest that is a link, which resolving wrongly leaves where it is (as if
    it were no link), is refused by the lstat, and the directory it points
    to is left as it was."""
    archive = _write_tar(tmp_path / "a.tar", [(_reg("a.md"), b"new a")])
    target = tmp_path / "real"
    target.mkdir()
    (target / "a.md").write_bytes(b"old a")
    dest = tmp_path / "dest"
    _link_or_skip(dest, target, kind)
    want = os.path.normcase(str(dest.parent.resolve() / dest.name))
    real_resolve = Path.resolve

    def resolve(self: Path, *args: object, **kwargs: object) -> Path:
        if os.path.normcase(os.path.abspath(self)) == want:
            return Path(os.path.abspath(self))
        return real_resolve(self, *args, **kwargs)

    monkeypatch.setattr(Path, "resolve", resolve)
    with pytest.raises(FileExistsError) as exc:
        unpack(archive, dest)
    monkeypatch.undo()

    assert "symlink or junction" in str(exc.value)
    assert _tree(target) == {"a.md": b"old a"}
    assert sorted(p.name for p in tmp_path.iterdir()) == ["a.tar", "dest", "real"]


SPELLED_NAME = "aLongDirectoryName"  # long enough to get an 8.3 short name
DEST_SPELLINGS = [
    "dot",
    "dotdot",
    "absolute-dotdot",
    "trailing-slash",
    pytest.param(
        "trailing-backslash",
        marks=pytest.mark.skipif(
            sys.platform != "win32", reason="a backslash separates only on Windows"
        ),
    ),
    pytest.param("short-name", marks=WINDOWS_83),
    pytest.param(
        "mixed-case",
        marks=pytest.mark.skipif(
            sys.platform != "win32", reason="names differing in case are one only on Windows"
        ),
    ),
    pytest.param(
        "index-stream",
        marks=pytest.mark.skipif(
            sys.platform != "win32", reason="NTFS stream names exist only on Windows"
        ),
    ),
]


def _spell_dest(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, spelling: str) -> str:
    """A spelling of tmp_path/SPELLED_NAME (which has a ``sub`` directory) as
    dest, changing the cwd where the spelling needs one."""
    entry = tmp_path / SPELLED_NAME
    if spelling == "dot":
        monkeypatch.chdir(entry)
        return "."
    if spelling == "dotdot":
        monkeypatch.chdir(entry / "sub")
        return ".."
    if spelling == "absolute-dotdot":
        return f"{entry}/sub/.."
    monkeypatch.chdir(tmp_path)
    if spelling == "trailing-slash":
        return SPELLED_NAME + "/"
    if spelling == "trailing-backslash":
        return SPELLED_NAME + "\\"
    if spelling == "mixed-case":
        return SPELLED_NAME.swapcase()
    if spelling == "index-stream":  # the directory's index, which Win32 opens as the directory
        return SPELLED_NAME + "::$INDEX_ALLOCATION"
    short = _short_name(entry)
    if short is None:
        pytest.skip("this volume does not generate 8.3 short names")
    return short


@pytest.mark.skipif(
    sys.platform != "win32", reason="elsewhere '..' is resolved physically: see the next test"
)
@pytest.mark.parametrize("spelling", DEST_SPELLINGS)
@pytest.mark.parametrize("kind", LINK_KINDS)
def test_unpack_refuses_a_link_dest_however_it_is_spelled(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str, spelling: str
) -> None:
    """Windows only: Win32 collapses "." and ".." against the full path
    before it looks at any link, so "." with the cwd a link, ".." from a
    directory in it, "link/sub/..", and the link's short name, a case
    variant, a trailing separator or its index stream all name the link
    itself, which the look at dest as spelled reports. Each is refused,
    and the directory it points to is left as it was."""
    archive = _write_tar(tmp_path / "a.tar", [(_reg("a.md"), b"new a")])
    target = tmp_path / "real"
    (target / "sub").mkdir(parents=True)
    (target / "a.md").write_bytes(b"old a")
    _link_or_skip(tmp_path / SPELLED_NAME, target, kind)
    dest = _spell_dest(tmp_path, monkeypatch, spelling)

    with pytest.raises(FileExistsError) as exc:
        unpack(archive, dest)

    assert "symlink or junction" in str(exc.value)
    assert _tree(target) == {"a.md": b"old a", "sub": None}
    assert sorted(p.name for p in tmp_path.iterdir()) == sorted(["a.tar", "real", SPELLED_NAME])


@pytest.mark.skipif(sys.platform == "win32", reason="Windows collapses '..' first: see above")
@pytest.mark.parametrize("spelling", ["dot", "dotdot", "absolute-dotdot", "trailing-slash"])
def test_elsewhere_dot_and_dotdot_by_way_of_a_link_dest_end_at_its_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, spelling: str
) -> None:
    """Elsewhere than Windows the cwd is a physical path and ".." is resolved
    physically, so "." with the cwd entered by way of a symlink, ".." from a
    directory in it and "link/sub/.." end at the directory it points to, a
    real directory, which is unpacked into. "link/" names the link itself
    and is refused."""
    archive = _write_tar(tmp_path / "a.tar", [(_reg("a.md"), b"new a")])
    target = tmp_path / "real"
    (target / "sub").mkdir(parents=True)
    (target / "a.md").write_bytes(b"old a")
    _link_or_skip(tmp_path / SPELLED_NAME, target, "symlink")
    dest = _spell_dest(tmp_path, monkeypatch, spelling)

    if spelling == "trailing-slash":
        with pytest.raises(FileExistsError) as exc:
            unpack(archive, dest)
        assert "symlink or junction" in str(exc.value)
        assert _tree(target) == {"a.md": b"old a", "sub": None}
    else:
        unpack(archive, dest)
        assert _tree(target) == {"a.md": b"new a", "sub": None}
    assert sorted(p.name for p in tmp_path.iterdir()) == sorted(["a.tar", "real", SPELLED_NAME])


@pytest.mark.parametrize("spelling", DEST_SPELLINGS)
def test_unpack_into_a_real_directory_however_it_is_spelled(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, spelling: str
) -> None:
    """All platforms (Windows also for a backslash, a short name, a case
    variant and the index stream): the same spellings of a real directory
    are unpacked into."""
    archive = _write_tar(tmp_path / "a.tar", [(_reg("a.md"), b"new a")])
    target = tmp_path / SPELLED_NAME
    (target / "sub").mkdir(parents=True)
    (target / "a.md").write_bytes(b"old a")
    dest = _spell_dest(tmp_path, monkeypatch, spelling)

    unpack(archive, dest)

    assert _tree(target) == {"a.md": b"new a", "sub": None}
    assert sorted(p.name for p in tmp_path.iterdir()) == sorted(["a.tar", SPELLED_NAME])


@pytest.mark.parametrize("dest_exists", [False, True], ids=["new-dest", "existing-dest"])
@pytest.mark.parametrize("kind", LINK_KINDS)
def test_unpack_into_a_dest_whose_parent_is_a_link(
    tmp_path: Path, kind: str, dest_exists: bool
) -> None:
    """All platforms that can create symlinks, and Windows for junctions: a
    link above dest is followed, as any parent is; only dest itself must
    not be one."""
    archive = _write_tar(tmp_path / "a.tar", [(_reg("a.md"), b"new a")])
    real_parent = tmp_path / "real"
    real_parent.mkdir()
    if dest_exists:
        (real_parent / "dest").mkdir()
    _link_or_skip(tmp_path / "parent", real_parent, kind)

    unpack(archive, tmp_path / "parent" / "dest")

    assert _tree(real_parent) == {"dest": None, "dest/a.md": b"new a"}
    assert sorted(p.name for p in tmp_path.iterdir()) == ["a.tar", "parent", "real"]


@contextlib.contextmanager
def _drive_mapped_to(target: Path) -> Iterator[str]:
    """A free drive letter mapped onto ``target`` while the block runs, as
    subst maps one (without telling other windows); the mapping is always
    removed. Skips where no letter is free or none can be mapped."""
    import ctypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    no_broadcast, remove = 0x8, 0x2  # DDD_NO_BROADCAST_SYSTEM, DDD_REMOVE_DEFINITION
    used = kernel32.GetLogicalDrives()
    free = [c for c in "ZYXWVUTSRQPONMLKJIHG" if not used & (1 << (ord(c) - ord("A")))]
    if not free:
        pytest.skip("no free drive letter to map")
    drive = f"{free[0]}:"
    if not kernel32.DefineDosDeviceW(no_broadcast, drive, str(target)):
        pytest.skip(f"cannot map a drive letter here: {ctypes.WinError(ctypes.get_last_error())}")
    try:
        yield drive
    finally:
        kernel32.DefineDosDeviceW(remove | no_broadcast, drive, None)


@pytest.mark.skipif(sys.platform != "win32", reason="drive letters exist only on Windows")
@pytest.mark.parametrize("spelling", ["root", "root-slash", "drive", "dot-at-root"])
@pytest.mark.parametrize("kind", ["junction", "symlink", "real-directory"])
def test_unpack_into_a_drive_root_mapped_onto_a_link_is_refused(
    tmp_path: Path, kind: str, spelling: str
) -> None:
    """Windows only: a drive letter mapped (as subst does) onto a junction or
    a directory symlink names that link, so its root, spelled "X:\\", "X:/",
    "X:" or "." with the cwd there, is refused, and the directory the link
    points to is left as it was. Mapped onto a real directory, each of these
    spellings is unpacked into."""
    archive = _write_tar(tmp_path / "a.tar", [(_reg("a.md"), b"new a")])
    target = tmp_path / "real"
    target.mkdir()
    (target / "a.md").write_bytes(b"old a")
    mapped = target
    if kind != "real-directory":
        mapped = tmp_path / "link"
        _link_or_skip(mapped, target, kind)

    cwd = os.getcwd()
    with _drive_mapped_to(mapped) as drive:
        dest = {"root": drive + "\\", "root-slash": drive + "/", "drive": drive}.get(spelling, ".")
        try:
            if spelling == "dot-at-root":
                os.chdir(drive + "\\")
            if kind == "real-directory":
                unpack(archive, dest)
            else:
                with pytest.raises(FileExistsError) as exc:
                    unpack(archive, dest)
                assert "symlink or junction" in str(exc.value)
        finally:
            os.chdir(cwd)

    assert _tree(target) == {"a.md": b"new a" if kind == "real-directory" else b"old a"}


@pytest.mark.parametrize("appears", ["before-staging", "before-rename"])
@pytest.mark.parametrize("kind", LINK_KINDS)
def test_unpack_refuses_a_link_that_appears_at_a_new_dest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str, appears: str
) -> None:
    """All platforms that can create symlinks, and Windows for junctions: a
    new dest, where a link to a directory appears after the first look
    (another process at work) and before staging is placed or the staged
    tree is renamed into place, is refused by that later look. The
    directory it points to is left as it was, and nothing is left over."""
    import aphelion.unpacker as unpacker

    archive = _write_tar(tmp_path / "a.tar", [(_reg("a.md"), b"new a")])
    target = tmp_path / "real"
    target.mkdir()
    (target / "a.md").write_bytes(b"old a")
    dest = tmp_path / "dest"
    step = "_make_parents" if appears == "before-staging" else "_extract"
    real_step = getattr(unpacker, step)

    def step_then_link(*args: object) -> None:
        real_step(*args)
        _link_or_skip(dest, target, kind)

    monkeypatch.setattr(unpacker, step, step_then_link)
    with pytest.raises(FileExistsError) as exc:
        unpack(archive, dest)
    monkeypatch.undo()

    assert "symlink or junction" in str(exc.value)
    assert _tree(target) == {"a.md": b"old a"}
    assert sorted(p.name for p in tmp_path.iterdir()) == ["a.tar", "dest", "real"]


@WINDOWS_83
def test_unpack_into_a_real_directory_by_its_short_name_where_its_parent_cannot_be_listed(
    tmp_path: Path,
) -> None:
    """Windows only: a real directory given by its 8.3 short name, in a
    directory the user may not list, is unpacked into: looking at it needs
    no listing of its parent."""
    archive = _write_tar(tmp_path / "a.tar", [(_reg("a.md"), b"new a")])
    locked = tmp_path / "locked"
    target = locked / SPELLED_NAME
    target.mkdir(parents=True)
    (target / "a.md").write_bytes(b"old a")
    short = _short_name(target)
    if short is None:
        pytest.skip("this volume does not generate 8.3 short names")
    everyone = "*S-1-1-0"
    deny = subprocess.run(
        ["icacls", str(locked), "/deny", f"{everyone}:(RD)"], capture_output=True
    )
    try:
        if deny.returncode != 0:
            pytest.skip("cannot deny listing a directory here")
        try:
            os.listdir(locked)
        except PermissionError:
            pass
        else:
            pytest.skip("listing a directory cannot be denied to this user")

        unpack(archive, locked / short)
    finally:
        subprocess.run(["icacls", str(locked), "/remove:d", everyone], capture_output=True)

    assert _tree(target) == {"a.md": b"new a"}
    assert os.listdir(locked) == [SPELLED_NAME]


@WINDOWS_ONLY
@pytest.mark.parametrize("winerror", [1, 50])
@pytest.mark.parametrize("spelling", ["long-name", "short-name"])
def test_unpack_into_a_real_dest_where_no_final_path_is_reported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, spelling: str, winerror: int
) -> None:
    """Windows only (simulated): on a volume whose driver cannot answer the
    final-path query, resolving dest falls back as the standard library
    does, and a real directory, by its long or its short name, is unpacked
    into."""
    archive = _write_tar(tmp_path / "a.tar", [(_reg("a.md"), b"new a")])
    target = tmp_path / SPELLED_NAME
    target.mkdir()
    (target / "a.md").write_bytes(b"old a")
    dest = target
    if spelling == "short-name":
        short = _short_name(dest)
        if short is None:
            pytest.skip("this volume does not generate 8.3 short names")
        dest = tmp_path / short
    _no_final_path(monkeypatch, tmp_path.resolve(), winerror)

    unpack(archive, dest)
    monkeypatch.undo()

    assert _tree(target) == {"a.md": b"new a"}
    assert sorted(p.name for p in tmp_path.iterdir()) == ["a.tar", SPELLED_NAME]


@pytest.mark.skipif(sys.platform != "win32", reason="junctions exist only on Windows")
def test_unpack_refuses_a_junction_to_a_drive_root_as_destination(tmp_path: Path) -> None:
    """Windows only: a junction to the root of a volume is refused like any
    other junction, though it looks much like a mounted folder."""
    name = f"{tmp_path.name}.md"  # unique, so nothing else makes it at the root
    archive = _write_tar(tmp_path / "a.tar", [(_reg(name), b"a")])
    root = Path(tmp_path.anchor)
    dest = tmp_path / "dest"
    _link_or_skip(dest, root, "junction")
    try:
        with pytest.raises(FileExistsError) as exc:
            unpack(archive, dest)
    finally:
        os.rmdir(dest)  # the junction only, never its target

    assert "symlink or junction" in str(exc.value)
    assert not (root / name).exists()
    assert not [n for n in os.listdir(root) if ".unpacking-" in n]


# ---------- member names must be portable ----------


NON_PORTABLE_NAMES = [
    "old.txt:stream",  # NTFS alternate data stream
    "a<b", "a>b", 'a"b', "a|b", "a?b", "a*b",
    "a\x01b", "a\x1fb",
    "CON", "con.txt", "Nul.tar.gz", "AUX", "PRN", "COM1", "com9.md", "LPT1", "lpt9",
    "COM¹", "CON .txt",
    "dir./f.md", "dir /f.md", "f.md.", "f.md ",
    "claims/NUL",
]
NEAR_DEVICE_NAMES = ["CONSOLE.md", "con-x.md", "COM10", "LPT0", "a.b.c", "nul_file"]
ONLY_WINDOWS_REFUSES = pytest.mark.skipif(
    sys.platform != "win32", reason="only Windows refuses names Win32 cannot create as files"
)


@ONLY_WINDOWS_REFUSES
@pytest.mark.parametrize("name", NON_PORTABLE_NAMES)
def test_non_portable_member_name_is_refused(tmp_path: Path, name: str) -> None:
    """Windows only: a member name Win32 cannot create as a file (a stream name,
    a reserved character, a device name, a trailing dot or space) is refused
    before anything is written."""
    archive = _write_tar(tmp_path / "a.tar", [(_reg(name), b"x")])
    dest = tmp_path / "dest"

    with pytest.raises(SecurityError) as exc:
        unpack(archive, dest)

    assert exc.value.code == ErrorCode.PATH_TRAVERSAL
    assert "not a portable file name" in str(exc.value)
    assert not dest.exists()


@pytest.mark.parametrize("name", NEAR_DEVICE_NAMES)
def test_portable_names_near_device_names_are_accepted(tmp_path: Path, name: str) -> None:
    """All platforms: names that only look like device names are unpacked."""
    archive = _write_tar(tmp_path / "a.tar", [(_reg(name), b"x")])
    unpack(archive, tmp_path / "dest")
    assert (tmp_path / "dest" / name).read_bytes() == b"x"


@pytest.mark.parametrize("name", [*NON_PORTABLE_NAMES, *NEAR_DEVICE_NAMES, "a:b.md"])
def test_pack_refuses_exactly_the_names_unpack_refuses(tmp_path: Path, name: str) -> None:
    """All platforms: whatever this platform's unpack refuses, pack refuses
    too, with the same code, and unpack refuses whatever pack refuses."""
    from aphelion.canonical_tar import TarMember, pack
    from aphelion.errors import SchemaError

    try:
        pack([TarMember(path=name, data=b"x")])
        packed = None
    except SchemaError as exc:
        packed = exc.code
    archive = _write_tar(tmp_path / "a.tar", [(_reg(name), b"x")])
    try:
        unpack(archive, tmp_path / "dest")
        unpacked = None
    except SecurityError as exc:
        unpacked = exc.code

    assert packed == unpacked
    if name == "a:b.md":  # a drive prefix: unpack always refused it everywhere; now pack too
        assert packed == ErrorCode.WINDOWS_DRIVE
    else:
        refused = sys.platform == "win32" and name in NON_PORTABLE_NAMES
        assert packed == (ErrorCode.PATH_TRAVERSAL if refused else None)


@pytest.mark.skipif(
    sys.platform == "win32", reason="Win32 cannot create these names; Windows refuses them"
)
@pytest.mark.parametrize(
    "name", ["schemas/con.json", "signers/aux.json", "claims/a:b.md", "trail.", *NON_PORTABLE_NAMES]
)
def test_names_only_windows_refuses_work_elsewhere(tmp_path: Path, name: str) -> None:
    """POSIX only: a name Win32 cannot create as a file is an ordinary name
    here, and is packed, validated and unpacked as before."""
    from aphelion.canonical_tar import TarMember, pack
    from aphelion.unpacker import check_member_names

    archive = tmp_path / "a.tar"
    archive.write_bytes(pack([TarMember(path=name, data=b"x")]))
    check_member_names(archive)
    unpack(archive, tmp_path / "dest")
    assert (tmp_path / "dest" / name).read_bytes() == b"x"


@pytest.mark.skipif(
    sys.platform == "win32", reason="Win32 drops trailing dots and spaces; Windows refuses these"
)
@pytest.mark.parametrize("first, second", [("trail", "trail."), ("x/a:b", "x/a:b ")])
def test_names_differing_by_a_trailing_dot_or_space_are_two_files_elsewhere(
    tmp_path: Path, first: str, second: str
) -> None:
    """POSIX only: names that differ only by a trailing dot or space are two
    files here, so pack, validate and unpack accept both."""
    from aphelion.canonical_tar import TarMember, pack
    from aphelion.unpacker import check_member_names

    archive = tmp_path / "a.tar"
    archive.write_bytes(
        pack([TarMember(path=first, data=b"1"), TarMember(path=second, data=b"2")])
    )
    check_member_names(archive)
    unpack(archive, tmp_path / "dest")
    assert (tmp_path / "dest" / first).read_bytes() == b"1"
    assert (tmp_path / "dest" / second).read_bytes() == b"2"


@ONLY_WINDOWS_REFUSES
def test_stream_name_does_not_replace_an_existing_file(tmp_path: Path) -> None:
    """Windows only: a member named like a stream of an existing file is
    refused, and the file keeps its content."""
    archive = _write_tar(tmp_path / "a.tar", [(_reg("old.txt:stream"), b"x")])
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
    """All platforms: a parent of dest that another process created meanwhile is
    not removed by the failed unpack, nor is anything in it."""
    archive, policy = _fails_after_first_member(tmp_path, monkeypatch)
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

    assert exc.value.code == ErrorCode.ARCHIVE_BOMB
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


@pytest.mark.parametrize(
    "kind",
    [
        pytest.param(KeyboardInterrupt, id="interrupt-after-step"),
        pytest.param(OSError, id="oserror-after-step"),
    ],
)
def test_parent_made_right_before_a_failure_is_removed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: type[BaseException]
) -> None:
    """All platforms: a parent of dest is on record before it is made, so a
    failure or interrupt right after its creation returns still removes it
    (and the ones made before it)."""
    work = tmp_path / "clean"
    archive = _write_tar(work / "a.tar", [(_reg("a.md"), b"a")])
    call = functools.partial(unpack, archive, work / "p1" / "p2" / "dest")
    steps, exc, _ = _run_steps(monkeypatch, call, {})
    assert exc is None
    parents = [
        n
        for n, line in enumerate(steps, 1)
        if line.startswith("mkdir ") and Path(line[len("mkdir ") :]).name in ("p1", "p2")
    ]
    assert len(parents) == 2

    for n in parents:
        work = tmp_path / str(n)
        archive = _write_tar(work / "a.tar", [(_reg("a.md"), b"a")])
        error = _error(kind)
        call = functools.partial(unpack, archive, work / "p1" / "p2" / "dest")
        _, exc, _ = _run_steps(monkeypatch, call, {n: (error, True)})
        assert exc is error, steps[n - 1]
        assert sorted(os.listdir(work)) == ["a.tar"], steps[n - 1]


def test_interrupt_at_any_line_of_the_extraction_leaves_nothing_behind(tmp_path: Path) -> None:
    """All platforms (guards Windows, where a file left open cannot be
    deleted): an interrupt at any line of the extraction into staging
    leaves neither staging nor the parents made for dest behind. A file was
    once opened on one line and taken into its with statement on the next,
    and an interrupt between the two left it open and staging undeletable."""
    import aphelion.unpacker as unpacker

    def run(work: Path, stop_at: int | None) -> int:
        archive = _write_tar(work / "a.tar", [(_reg("a.md"), b"a"), (_reg("sub/b.md"), b"b")])
        lines = 0

        def local(frame: object, event: str, arg: object) -> object:
            nonlocal lines
            if event == "line":
                lines += 1
                if lines == stop_at:
                    raise KeyboardInterrupt
            return local

        def calls(frame: object, event: str, arg: object) -> object:
            return local if frame.f_code is unpacker._extract.__code__ else None  # type: ignore[attr-defined]

        previous = sys.gettrace()
        sys.settrace(calls)
        try:
            unpack(archive, work / "p1" / "dest")
        except KeyboardInterrupt:
            assert stop_at is not None and lines >= stop_at
        finally:
            sys.settrace(previous)
        return lines

    total = run(tmp_path / "clean", None)
    assert total > 20
    for n in range(1, total + 1):
        work = tmp_path / str(n)
        run(work, n)
        assert sorted(os.listdir(work)) == ["a.tar"], n
