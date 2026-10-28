"""Safe streaming tar extractor for Aphelion archives.

Every known tar-extraction attack is rejected with a SecurityError and a
distinct PX_E_6NNN code (see :mod:`aphelion.error_codes`):
  * path traversal ('..' / absolute / Windows drive / backslash)
  * member names that collide once normalized the way any supported
    filesystem would see them (leading ``./``, repeated or ``.`` separators,
    Unicode NFC, case folding, and on Windows trailing dots/spaces), or that
    reach one entry on disk under different names (8.3 short names)
  * disallowed member types (symlink, hardlink, device, fifo, sparse)
  * zip-bomb (enforced streaming, per-file and per-total budgets, and a
    limit on every byte read or decompressed, whatever the headers say)
  * too many files, overly long paths
"""

from __future__ import annotations

import errno
import io
import os
import re
import secrets
import shutil
import stat
import struct
import sys
import tarfile
import unicodedata
import warnings
import zlib
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, BinaryIO, Callable, Generator, Iterator, Mapping, NamedTuple, NoReturn

from aphelion.error_codes import ErrorCode
from aphelion.errors import SecurityError


WINDOWS_DRIVE_RE = re.compile(r"^[A-Za-z]:")
# Names Win32 cannot create as a plain file: reserved characters (':' would
# address an NTFS alternate data stream of another file), device names with or
# without an extension, and a trailing dot or space, which Win32 drops.
WINDOWS_RESERVED_CHARS = frozenset('<>:"|?*') | frozenset(map(chr, range(32)))
# With an extension too (con.txt): Windows 10 and earlier open the device; conservative.
WINDOWS_DEVICE_RE = re.compile(
    r"^(CON|PRN|AUX|NUL|COM[1-9\u00b9\u00b2\u00b3]|LPT[1-9\u00b9\u00b2\u00b3]) *(\..*)?$",
    re.IGNORECASE,
)

# Hard ceiling on uncompressed archive size (v0.3.0, spec/packaging.md §3).
# 100 MiB = 104_857_600 bytes. MUST equal ExtractPolicy.max_total_bytes.
PACKAGE_TOTAL_BYTES_LIMIT: int = 104_857_600
# Per-file hard ceiling. Spec allows up to 50 MiB; reference implementation
# is tighter (25 MiB) for belt-and-braces.
PACKAGE_SINGLE_FILE_BYTES_LIMIT: int = 25 * 1024 * 1024


@dataclass(frozen=True)
class ExtractPolicy:
    max_files: int = 10_000
    max_total_bytes: int = PACKAGE_TOTAL_BYTES_LIMIT  # 100 MiB
    max_file_bytes: int = PACKAGE_SINGLE_FILE_BYTES_LIMIT  # 25 MiB
    max_compression_ratio: int = 100
    max_path_length: int = 512

    @classmethod
    def default(cls) -> "ExtractPolicy":
        return cls()


def _check_path(raw_name: str, policy: ExtractPolicy) -> str:
    """Normalize and reject dangerous paths. Returns NFC-normalized POSIX path.

    Length is enforced on the normalized form — that is the form that ends up
    on disk, and NFC can expand some decomposed sequences.
    """
    if not raw_name:
        raise SecurityError(code=ErrorCode.EMPTY_MEMBER_NAME, msg="empty archive member name")
    if "\\" in raw_name:
        raise SecurityError(
            code=ErrorCode.WINDOWS_BACKSLASH,
            msg=f"backslash in member path: {raw_name!r}",
            path=raw_name,
        )
    if raw_name.startswith("/"):
        raise SecurityError(
            code=ErrorCode.ABSOLUTE_PATH,
            msg=f"absolute path in archive: {raw_name!r}",
            path=raw_name,
        )
    if WINDOWS_DRIVE_RE.match(raw_name):
        raise SecurityError(
            code=ErrorCode.WINDOWS_DRIVE,
            msg=f"Windows drive path in archive: {raw_name!r}",
            path=raw_name,
        )
    normalized = unicodedata.normalize("NFC", raw_name)
    if len(normalized) > policy.max_path_length:
        raise SecurityError(
            code=ErrorCode.PATH_TOO_LONG,
            msg=f"member path exceeds {policy.max_path_length} bytes: {raw_name!r}",
            path=raw_name,
        )
    for part in normalized.split("/"):
        if part == "..":
            raise SecurityError(
                code=ErrorCode.PATH_TRAVERSAL,
                msg=f"'..' segment in member path: {raw_name!r}",
                path=raw_name,
            )
    return normalized


def non_portable_component(parts: list[str]) -> str | None:
    """The first component Win32 cannot create as the plain file it names.

    On Windows such a component names a device, a stream of another file, or
    a different file than the archive says, so it is returned there. On other
    platforms these are ordinary names and None is returned. Shared by
    :func:`unpack` (and :func:`check_member_names`) and
    :func:`aphelion.canonical_tar.pack`, so on each platform the writer
    refuses exactly the names the reader would.
    """
    if sys.platform != "win32":
        return None
    for part in parts:
        if (
            not WINDOWS_RESERVED_CHARS.isdisjoint(part)
            or part[-1] in " ."
            or WINDOWS_DEVICE_RE.match(part)
        ):
            return part
    return None


def path_parts(normalized: str) -> list[str]:
    """Split a checked member path into its real components.

    Empty and ``.`` segments name no directory level (``./a``, ``a//b`` and
    ``a/./b`` are ``a`` and ``a/b`` on every filesystem), so they are dropped.
    """
    return [part for part in normalized.split("/") if part not in ("", ".")]


def member_path_key(parts: list[str]) -> str:
    """Collision key for a member path, as a case-insensitive filesystem sees it.

    Two members with the same key land on the same file on at least one
    supported platform: NTFS and APFS compare names case-insensitively, and
    APFS is also normalization-insensitive. On Windows, where Win32 drops
    trailing dots and spaces from each component, those are dropped too;
    elsewhere ``trail.`` and ``trail`` are two files.
    """
    folded = []
    for part in parts:
        if sys.platform == "win32":
            part = part.rstrip(" .") or part
        folded.append(
            unicodedata.normalize("NFC", unicodedata.normalize("NFC", part).casefold())
        )
    return "/".join(folded)


class MemberNames:
    """Tracks member paths and reports the first collision.

    ``add`` returns ``None`` when the path is new, or the earlier spelling it
    collides with: the same file twice, two spellings of one directory, or a
    file and a directory under one key. Shared by :func:`unpack` and
    :func:`aphelion.canonical_tar.pack`, so the writer refuses exactly the
    names the reader would.
    """

    def __init__(self) -> None:
        # key -> spelling, so two spellings of one directory are caught as
        # well as two members for one file.
        self._dirs: dict[str, str] = {}
        self._explicit_dirs: set[str] = set()
        self._files: dict[str, str] = {}

    def _claim_dir(self, spelling: str, key: str) -> str | None:
        if key in self._files:
            return self._files[key]
        known = self._dirs.setdefault(key, spelling)
        return known if known != spelling else None

    def add(self, parts: list[str], *, is_dir: bool) -> str | None:
        for depth in range(1, len(parts)):
            other = self._claim_dir("/".join(parts[:depth]), member_path_key(parts[:depth]))
            if other is not None:
                return other
        rel = "/".join(parts)
        key = member_path_key(parts)
        if is_dir:
            if not parts:
                return None  # the archive root itself (``.``)
            if key in self._explicit_dirs:
                return self._dirs.get(key, rel)
            other = self._claim_dir(rel, key)
            if other is not None:
                return other
            self._explicit_dirs.add(key)
            return None
        other = self._files.get(key, self._dirs.get(key))
        if other is not None:
            return other
        self._files[key] = rel
        return None


# What one pass over an archive may hand to tarfile (see :func:`_members`).
# Every member may take at least this many bytes of header blocks (its ustar
# header and any pax or GNU long-name headers before it; see _header_bytes) ...
_HEADER_BYTES = 4096
# ... and the first one this many more, for a global pax header before it.
_GLOBAL_HEADER_BYTES = 1024
# Header types (typeflag bytes) tarfile reads as extensions of the member
# header after them.
_EXTENSION_TYPES = b"xgXLK"
# The member types read here: regular files (tarfile.REGULAR_TYPES, of which
# GNU sparse files are refused as sparse) and directories; and each typeflag
# byte as tarfile gives it.
_MEMBER_TYPES = frozenset((*tarfile.REGULAR_TYPES, tarfile.DIRTYPE))
_TYPEFLAGS = tuple(bytes((flag,)) for flag in range(256))
# The keys tarfile takes as a member's size.
_PAX_SIZE_KEYS = (b"size", b"GNU.sparse.size", b"GNU.sparse.realsize")
# What tarfile before Python 3.10.15, 3.11.10 and 3.12.6 also reads from
# anywhere in a pax header's data: the encoding of the names in it, and the
# offsets and sizes of a GNU sparse 0.0 member.
_PAX_CHARSET_BEFORE = re.compile(rb"\d+ hdrcharset=([^\n]+)\n")
_PAX_SPARSE_BEFORE = re.compile(rb"\d+ GNU.sparse.(?:offset|numbytes)=(\d+)\n")
# How many reads may find the end of the archive; the next one fails.
_MAX_EOF_READS = 8
_READ_CHUNK = 64 * 1024
# The most memory the xz and LZMA decoder may use: 1.5 times what the largest
# xz preset (-9 and -9e, a 64 MiB dictionary) needs, about 67.2 MB (the exact
# figure depends on the liblzma build).
_XZ_MEMLIMIT = 100_762_596


def _header_bytes(policy: ExtractPolicy) -> int:
    """How many bytes of header blocks a member may take: room for a pax
    header with a path of ``max_path_length`` four-byte UTF-8 characters and
    about 1 KiB of other records, and the member's own header; at least
    ``_HEADER_BYTES`` (exactly that at the default ``max_path_length``, 512)."""
    records = 4 * policy.max_path_length + 1024
    return max(_HEADER_BYTES, 1024 + -(-records // 512) * 512)


def _archive_bomb(msg: str) -> SecurityError:
    return SecurityError(code=ErrorCode.ARCHIVE_BOMB, msg=msg)


class _ForwardReader:
    """What tarfile reads an archive through: its bytes, decompressed if it
    is compressed, in order, each handed out once.

    It has ``read`` only, no ``seek`` or ``tell``: tarfile's stream mode
    (``r|``) never seeks the file it reads. ``limit`` is how far tarfile may
    read; a read at ``limit`` fails with ARCHIVE_BOMB without handing out
    anything, and so does a read after ``_MAX_EOF_READS`` have found the end
    of the archive. ``handed`` counts the bytes handed out. ``kept`` holds
    those from ``mark`` on, at most ``window`` of them: the header blocks
    after the member before, which the checks read again themselves. An
    error of the decompressor for damaged or cut-short data (one of
    ``errors``, other than an operating-system error with an errno) fails
    with ``tarfile.ReadError``.
    """

    def __init__(
        self,
        source: BinaryIO,
        window: int,
        errors: tuple[type[Exception], ...] = (),
        kind: str = "tar",
    ) -> None:
        self._source = source
        self.limit = window
        self.window = window
        self.handed = 0
        self.mark = 0
        self.kept = bytearray()
        self._eof_reads = 0
        self._errors = errors
        self._kind = kind

    def advance(self, end: int, limit: int) -> None:
        """Keep the bytes from ``end`` on, and let tarfile read up to ``limit``."""
        if end <= self.handed:
            del self.kept[: end - self.mark]
        else:
            self.kept.clear()
        self.mark = end
        self.limit = limit

    def read(self, size: int | None = -1) -> bytes:
        if size == 0:
            return b""
        if self.handed >= self.limit:
            raise _archive_bomb(
                f"reading the archive goes past byte {self.limit}: a member's headers "
                f"take more than they may, or the archive goes on where its headers "
                f"say it ends"
            )
        want = self.limit - self.handed
        if size is not None and size > 0:
            want = min(want, size)
        try:
            data = self._source.read(min(want, _READ_CHUNK))
        except self._errors as exc:
            if isinstance(exc, OSError) and exc.errno is not None:
                raise  # reading the file failed, not the data
            if not self.handed:
                raise tarfile.ReadError(f"not a {self._kind} file") from exc
            raise tarfile.ReadError(
                f"the {self._kind} data is damaged or cut short: {exc}"
            ) from exc
        if not data:
            self._eof_reads += 1
            if self._eof_reads > _MAX_EOF_READS:
                raise _archive_bomb(
                    "the archive ends before the data its headers declare"
                )
            return b""
        start = self.handed
        self.handed += len(data)
        low = max(start, self.mark)
        high = min(self.handed, self.mark + self.window)
        if low < high:
            self.kept += data[low - start : high - start]
        return data


class _LZMAReader:
    """An xz or LZMA-alone stream, decompressed with at most
    ``_XZ_MEMLIMIT`` bytes of decoder memory (``lzma.LZMAFile`` sets no
    limit). Read as ``LZMAFile`` reads it: concatenated streams one after
    another, and after the last one anything that is not a stream is
    ignored. A stream that needs more memory fails with ARCHIVE_BOMB."""

    def __init__(self, raw: BinaryIO, format: int) -> None:
        import lzma

        self._lzma = lzma
        self._raw = raw
        self._format = format
        self._decompressor = self._new()
        self._done = False

    def _new(self) -> Any:
        return self._lzma.LZMADecompressor(format=self._format, memlimit=_XZ_MEMLIMIT)

    def _decompress(self, block: bytes, size: int) -> bytes:
        try:
            return self._decompressor.decompress(block, size)
        except self._lzma.LZMAError as exc:
            if "memory usage limit" in str(exc).lower():
                raise _archive_bomb(
                    f"decompressing the archive needs more than {_XZ_MEMLIMIT} bytes "
                    f"of memory"
                ) from None
            raise

    def read(self, size: int = -1) -> bytes:
        if self._done or size == 0:
            return b""
        if size < 0:
            size = _READ_CHUNK
        while True:
            if self._decompressor.eof:
                block = self._decompressor.unused_data or self._raw.read(_READ_CHUNK)
                if not block:
                    self._done = True
                    return b""
                self._decompressor = self._new()
                try:
                    data = self._decompress(block, size)
                except self._lzma.LZMAError:
                    self._done = True  # not another stream
                    return b""
            else:
                block = b""
                if self._decompressor.needs_input:
                    block = self._raw.read(_READ_CHUNK)
                    if not block:
                        raise EOFError(
                            "Compressed file ended before the end-of-stream marker was reached"
                        )
                data = self._decompress(block, size)
            if data:
                return data

    def close(self) -> None:
        pass


def _compression(
    head: bytes,
) -> tuple[str, Callable[[BinaryIO], BinaryIO], tuple[type[Exception], ...]]:
    """The compression an archive's leading bytes name (the test tarfile's
    stream mode uses), how to read such a file, and the errors its
    decompressor raises for data that is not of that kind, damaged or cut
    short (as in tarfile's ``gzopen``, ``bz2open``, ``xzopen`` and
    ``zstopen``). LZMA-alone is recognised only by a header starting
    ``5d 00 00 80`` (the default properties, and a dictionary of 8 MiB or
    8 MiB plus a multiple of 16 MiB), and zstd only from a data frame (not a
    skippable one) on Python 3.14 and later; anything else is read as an
    uncompressed tar."""
    try:
        if head.startswith(b"\x1f\x8b\x08"):
            import gzip

            return (
                "gzip",
                lambda raw: gzip.GzipFile(fileobj=raw, mode="rb"),
                (gzip.BadGzipFile, EOFError, zlib.error),
            )
        if head[:3] == b"BZh" and head[4:10] == b"1AY&SY":
            import bz2

            # The bz2 module reports damaged data as an OSError without an
            # errno; one with an errno comes from reading the file.
            return "bzip2", bz2.BZ2File, (OSError, EOFError)
        if head.startswith((b"\x5d\x00\x00\x80", b"\xfd7zXZ")):
            import lzma

            fmt = lzma.FORMAT_XZ if head.startswith(b"\xfd7zXZ") else lzma.FORMAT_ALONE
            return "lzma", lambda raw: _LZMAReader(raw, fmt), (lzma.LZMAError, EOFError)
        if head.startswith(b"\x28\xb5\x2f\xfd"):
            from compression import zstd  # type: ignore[import-not-found]  # Python 3.14+

            return "zstd", zstd.ZstdFile, (zstd.ZstdError, EOFError)
    except ImportError as exc:
        raise tarfile.ReadError(f"cannot read this compressed archive: {exc}") from None
    return "tar", lambda raw: raw, ()


class _Member(NamedTuple):
    """A member as one pass saw it. ``path`` is its checked relative path
    (``./`` and empty segments dropped; ``""`` for the archive root), set
    only by a pass that checks names."""

    name: str
    type: bytes
    size: int
    offset: int
    path: str


def _members(
    archive: Path, policy: ExtractPolicy, *, check_names: bool
) -> Iterator[tuple[tarfile.TarFile, tarfile.TarInfo, _Member]]:
    """One pass over ``archive``: check every member header, and yield
    ``(tar, member, seen)`` for each member that passes. Before asking for
    the next one, the caller may read the member's data with
    ``tar.extractfile(member)``; no earlier member's can be read.

    tarfile reads the archive in stream mode through a
    :class:`_ForwardReader`, so it moves forwards only and never reads a
    byte twice. Before it reads on from member k, it may read up to
    ``E_k + H``, where ``E_k`` is where member k's data ends (``offset_data``
    plus its size padded to a multiple of 512 bytes, as the member's own
    header gives them; any other member type has no data) and ``H`` is
    :func:`_header_bytes` (4,096 at the default policy); before the first
    member, ``H + _GLOBAL_HEADER_BYTES``. So one
    pass hands tarfile at most ``max_total_bytes + max_files * (H + 511) +
    H + _GLOBAL_HEADER_BYTES`` bytes (150,932,720 at the default policy); a
    decompressing file object may decompress up to
    ``io.DEFAULT_BUFFER_SIZE`` more ahead of what it hands out. tarfile
    keeps no list of the members it has read.

    Refused, before the scan moves past the member, in this order: a
    negative size (in the member's header, a header before it or a pax
    record), then a pax header before it that Python releases do not read
    alike (``tarfile.ReadError``; see :func:`_header_chain`); a member type
    other than a regular file or a directory (read from the member's own
    header), a regular-file header (NUL typeflag) whose name field ends in
    '/' after a pax or GNU long-name header, which releases read as
    different types, or with a size other than 0 (with no such header
    before it, a directory, which tar programs read with and without that
    many bytes of data after it), a sparse member or a ``GNU.sparse.*``
    key tarfile can parse, a size in a pax header (local or global),
    header blocks that do not lead, size by size, from where the member
    before ends to the member's own header, a member that tarfile reports
    with another type or size than its own header gives (ARCHIVE_BOMB),
    and header blocks longer than ``H`` (the first member's may take up to
    ``_GLOBAL_HEADER_BYTES`` more for global pax headers before it); with
    ``check_names``, the names :func:`unpack` refuses; a declared size over
    ``max_file_bytes``, a total over ``max_total_bytes``, and a declared
    total over ``max_compression_ratio`` times the archive size (for an
    archive that is a regular file; for another kind of file the size is
    not known and the ratio is not checked). Reading past what tarfile may
    read (ARCHIVE_BOMB) comes after a negative size in the header blocks
    read up to there, and is ``tarfile.ReadError`` after a pax header there
    that a release stops at; it comes before the other checks of the member
    it reads towards. A member past ``max_files`` is refused as a release
    that stops at its headers reports it (a negative size, then such a pax
    header), else as one too many. The ratio counts declared member data
    only; header bytes are bounded by the per-member allowance above. A
    directory's size, if not negative, is ignored, as tarfile ignores it
    (an old-form one's must be 0). After the
    last member (or from the start, if there is none), the ``H`` bytes
    past its end must be zeros, else ``tarfile.ReadError`` is raised;
    nothing further on is looked at. Anything else tarfile raises while it
    parses a header (other than an operating-system or out-of-memory
    error), and the decompressor's errors for data that is damaged or cut
    short, are ``tarfile.ReadError`` too; an operating-system error reading
    the archive file passes through unchanged, and a refusal of these
    checks raised while tarfile reads keeps its code.

    The archive must be a seekable file: its first bytes are read to tell
    its compression, and then it is read from the start.
    """
    header_bytes = _header_bytes(policy)
    with open(archive, "rb") as raw:
        st = os.fstat(raw.fileno())
        compressed = st.st_size if stat.S_ISREG(st.st_mode) else 0
        kind, open_source, errors = _compression(raw.read(10))
        raw.seek(0)
        with closing(open_source(raw)) as source:
            reader = _ForwardReader(source, header_bytes + _GLOBAL_HEADER_BYTES, errors, kind)
            # tarfile asks for up to _READ_CHUNK bytes at a time; the reader
            # still hands out nothing past its limit. Stream mode keeps no
            # list of the members it has read (from Python 3.13 by asking it
            # not to; before, the list is emptied after each member).
            options = {"stream": True} if sys.version_info >= (3, 13) else {}
            tar = _parsing(
                reader,
                lambda: tarfile.open(fileobj=reader, mode="r|", bufsize=_READ_CHUNK, **options),
            )
            found: list[_Member] = []
            with tar:
                try:
                    end = yield from _checked_members(
                        tar, reader, policy, header_bytes, compressed, check_names, found
                    )
                except tarfile.StreamError:
                    # Python 3.10 reads past an archive of zero blocks only
                    # by seeking back before its start: no members, and what
                    # follows them is checked below as on later releases.
                    if found or not reader.handed:
                        raise
                    end = 0
            stop = end + header_bytes

            def drain() -> None:
                while reader.handed < stop and reader.read(stop - reader.handed):
                    pass

            _parsing(reader, drain)
            if reader.kept[:header_bytes].rstrip(b"\0"):
                _refuse_negative_size(reader)
                raise tarfile.ReadError("data after the end of the archive")


def _parsing(reader: _ForwardReader, call: Callable[[], Any]) -> Any:
    """Run a call that reads member headers (a tarfile call, or the read of
    the bytes after the last member). A refusal of ours passes through, and
    anything else tarfile raises while it parses a header (other than an
    operating-system or out-of-memory error) is ``tarfile.ReadError``. If
    the header blocks after the last member declare a negative size, which
    tarfile, depending on the release, stops at, reads wrongly or reports,
    the refusal is FILE_BYTES_EXCEEDED on every release. A read past what
    tarfile may read (ARCHIVE_BOMB) after a pax header there that some
    release stops reading the archive at (see :func:`_header_chain`) is
    ``tarfile.ReadError``, as on that release."""
    try:
        return call()
    except SecurityError as exc:
        if exc.code == ErrorCode.ARCHIVE_BOMB:
            unread = _refuse_negative_size(reader)
            if unread is not None and unread[1]:
                raise _unread(reader.mark, unread) from exc
        raise
    except tarfile.TarError:
        _refuse_negative_size(reader)
        raise
    except (OSError, MemoryError):
        raise
    except Exception as exc:
        _refuse_negative_size(reader)
        raise tarfile.ReadError(
            f"cannot read a member header: {type(exc).__name__}: {exc}"
        ) from exc


def _number(field: bytes) -> int | None:
    """A numeric header field as tarfile reads it (octal, or base-256 after
    a 0x80 or 0xff byte); None if it is not a number."""
    if field[0] in (0x80, 0xFF):
        value = int.from_bytes(field[1:], "big")
        return value - (1 << (8 * len(field) - 8)) if field[0] == 0xFF else value
    try:
        return int(field.split(b"\0", 1)[0].decode("ascii").strip() or "0", 8)
    except ValueError:
        return None


def _size_field(block: bytes | bytearray) -> int | None:
    """A header block's size, if its checksum is right, as tarfile reads them
    (the sum of the block's bytes with the checksum field as spaces, taken
    as unsigned or, failing that, signed bytes)."""
    stored = _number(block[148:156])
    # An Adler-32 started at 0 holds in its low 16 bits the sum of the bytes
    # modulo 65,521: the sum itself for 256 bytes, which is at most 65,280.
    total = (zlib.adler32(block[:256], 0) & 0xFFFF) + (zlib.adler32(block[256:512], 0) & 0xFFFF)
    unsigned = 256 + total - sum(block[148:156])
    if stored != unsigned and stored != 256 + sum(struct.unpack_from("148b8x356b", block)):
        return None
    return _number(block[124:136])


def _pax_records(
    blocks: bytes | bytearray, pos: int, stop: int
) -> tuple[list[tuple[bytes | bytearray, bytes | bytearray]], bool]:
    """The records of a pax header whose data, padded to whole blocks, is
    ``blocks[pos:stop]``, read up to the first NUL byte as tarfile reads
    them: those whose key starts with ``s``, ``G`` or ``h`` (``size``,
    ``GNU.sparse.*`` and ``hdrcharset`` are read here), as (key, value),
    up to the first record that is not whole; and whether every record is
    whole. A whole record has a length of 1 to 20 digits and a space, of
    at least 5 bytes and within the data, a key that is not empty followed
    by '=', and a newline as its last byte."""
    records = []
    while pos < stop and blocks[pos]:
        space = blocks.find(b" ", pos, min(pos + 21, stop))
        digits = blocks[pos:space]
        if space < 0 or not digits.isdigit():
            return records, False
        length = int(digits)
        last = pos + length - 1
        key = space + 1
        equals = blocks.find(b"=", key, last)
        if length < 5 or last >= stop or blocks[last] != 0x0A or equals <= key:
            return records, False
        if blocks[key] in b"sGh":
            records.append((blocks[key:equals], blocks[equals + 1 : last]))
        pos += length
    return records, True


def _pax_read_alike(
    blocks: bytes | bytearray,
    pos: int,
    stop: int,
    records: list[tuple[bytes | bytearray, bytes | bytearray]],
    typeflag: int,
    global_keys: set[bytes],
) -> bool | None:
    """Whether Python releases read a pax header alike, given its data
    ``blocks[pos:stop]`` (its records whole, ``records`` as
    :func:`_pax_records` gives them) and the ``size`` and ``GNU.sparse.*``
    keys of the global headers before it in the same run of headers
    (``global_keys``; tarfile holds those and the header's own). None if
    they do. tarfile before Python 3.10.15, 3.11.10 and 3.12.6 takes the
    encoding of the names in it from the first ``<digits>
    hdrcharset=<value>`` line found anywhere in its data or, if there is
    none, from a global header's; from those releases on, from its first
    ``hdrcharset`` record. True if a release stops reading the archive at
    it: the earlier ones fail if that value is not UTF-8. False if
    releases read it differently: they take different encodings, or it is
    a global header with a ``hdrcharset`` (which the earlier ones apply to
    the headers after it); or, for a GNU sparse 0.0 member, tarfile from
    those releases on fails on an ``offset`` or ``numbytes`` record whose
    value int() cannot read, while the earlier ones read the offsets and
    sizes as digits found anywhere in the data (failing only on a number
    int() cannot read)."""
    if blocks.find(b"hdrcharset", pos, stop) >= 0:
        match = _PAX_CHARSET_BEFORE.search(blocks, pos, stop)
        if match is not None:
            try:
                match.group(1).decode("utf-8")
            except UnicodeDecodeError:
                return True
        first = next((value for key, value in records if key == b"hdrcharset"), None)
        if typeflag == ord("g") and (match is not None or first is not None):
            return False
        if (match is not None and match.group(1) == b"BINARY") != (first == b"BINARY"):
            return False
    keys = global_keys.union(bytes(key) for key, _ in records)
    if b"GNU.sparse.size" in keys and b"GNU.sparse.map" not in keys:
        try:
            for key, value in records:
                if key in (b"GNU.sparse.offset", b"GNU.sparse.numbytes"):
                    int(value.decode())
            for match in _PAX_SPARSE_BEFORE.finditer(blocks, pos, stop):
                int(match.group(1))
        except ValueError:
            return False
    return None


def _header_chain(
    blocks: bytes | bytearray, start: int, *, stop: int | None = None
) -> tuple[int, int, set[bytes], int | None, tuple[int, bool] | None]:
    """Walk the pax and GNU long-name headers at the start of ``blocks``
    (bytes read from archive offset ``start``; only the first ``stop`` of
    them, if given), each followed by its data as its size says, up to the
    first block that is not such a header. Every block on the way, that
    last one included, is read here from the bytes: its checksum (summed
    as unsigned bytes, then, if that does not match, as signed ones), its
    size field and, for a pax header (local or global), its records, as
    tarfile reads them; nothing is taken from what tarfile made of them.
    Returns where the last block starts, how many bytes the global pax
    headers on the way take, the ``size`` and ``GNU.sparse.*`` keys the
    pax records on the way hold, the last block's size (None if the walk
    does not end on a header with a right checksum and a numeric size),
    and the first pax header on the way that Python releases do not read
    alike, as (where it starts, whether a release stops reading the
    archive at it), the first one a release stops at if there is one, or
    None. A release stops at a pax header with a record that is not whole
    (see :func:`_pax_records`; tarfile from Python 3.10.15, 3.11.10 and
    3.12.6 on fails there, and before stops reading the header's records
    or reads them differently) and at one :func:`_pax_read_alike` says it
    stops at; that function also says which ones releases read
    differently. A pax header whose data ``blocks`` does not hold whole is
    not looked at for this. Where this release's tarfile fails on a record
    that is not whole (``_PAX_READ_ON`` is false), it reports no member and
    reads on past no header with one, so only the pax headers whose data
    holds ``size=``, ``GNU.sparse.`` or ``hdrcharset``, or that follow a
    global header with a ``size`` or ``GNU.sparse.*`` key, have their
    records read. A negative size on the way, in a header's size
    field or in a whole pax record before the first that is not, is
    refused (FILE_BYTES_EXCEEDED): tarfile, depending on the release,
    stops at it, skips the member, reads past it wrongly, or reports it."""
    end = len(blocks) if stop is None else min(stop, len(blocks))
    pos = 0
    global_bytes = 0
    keys: set[bytes] = set()
    global_keys: set[bytes] = set()
    unread: tuple[int, bool] | None = None
    while pos + 512 <= end:
        size = _size_field(blocks[pos : pos + 512])
        if size is None:
            break
        typeflag = blocks[pos + 156]
        step = 512 + -(-size // 512) * 512
        declared = size
        if size > 0 and typeflag in b"xXg":
            held = pos + step <= end
            data_end = pos + step if held else end
            # Where this release's tarfile fails on a record that is not
            # whole, it has read every header here as whole: only one with
            # a key read below, or after a global header with one, is read.
            if (
                _PAX_READ_ON
                or global_keys
                or blocks.find(b"size=", pos + 512, data_end) >= 0
                or blocks.find(b"GNU.sparse.", pos + 512, data_end) >= 0
                or blocks.find(b"hdrcharset", pos + 512, data_end) >= 0
            ):
                records, whole = _pax_records(blocks, pos + 512, data_end)
                if held and (unread is None or not unread[1]):
                    stops = (
                        _pax_read_alike(
                            blocks, pos + 512, data_end, records, typeflag, global_keys
                        )
                        if whole
                        else True
                    )
                    if stops or (stops is not None and unread is None):
                        unread = (pos, stops)
                for key, value in records:
                    if key == b"size" or key.startswith(b"GNU.sparse."):
                        keys.add(bytes(key))
                        if typeflag == ord("g"):
                            global_keys.add(bytes(key))
                        if key in _PAX_SIZE_KEYS:
                            try:
                                declared = min(
                                    declared, int(value.decode("utf-8", "surrogateescape"))
                                )
                            except ValueError:
                                pass
        if declared < 0:
            raise SecurityError(
                code=ErrorCode.FILE_BYTES_EXCEEDED,
                msg=f"a header at byte {start + pos} declares a negative size {declared}",
            )
        if typeflag not in _EXTENSION_TYPES:
            break
        if typeflag == ord("g"):
            global_bytes += step
        pos += step
    else:
        size = None
    return pos, global_bytes, keys, size, unread


def _reads_on_past_broken_records() -> bool:
    """Whether this release's tarfile reads on past a pax record that is
    not whole (see :func:`_pax_records`), as tarfile before Python 3.10.15,
    3.11.10 and 3.12.6 does, rather than failing there: found by reading a
    pax header whose one record has no newline at its end. If that fails
    other than with ``tarfile.ReadError``, True: every pax header's
    records are then read."""
    try:
        info = tarfile.TarInfo("a")
        info.pax_headers = {"comment": "c"}
        raw = info.tobuf(tarfile.PAX_FORMAT, "utf-8", "surrogateescape")
        raw = raw.replace(b"13 comment=c\n", b"13 comment=cc") + bytes(1024)
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as tar:
            tar.next()
    except tarfile.ReadError:
        return False
    except Exception:  # another tarfile error, ValueError, ...: read every record
        return True
    return True


_PAX_READ_ON = _reads_on_past_broken_records()


def _refuse_negative_size(reader: _ForwardReader) -> tuple[int, bool] | None:
    """Refuse (FILE_BYTES_EXCEEDED) if the header blocks tarfile reads from
    where the last member ends declare a negative size; else return the
    first pax header there that releases do not read alike (see
    :func:`_header_chain`)."""
    return _header_chain(bytes(reader.kept), reader.mark)[4]


def _unread(start: int, unread: tuple[int, bool]) -> tarfile.ReadError:
    return tarfile.ReadError(
        f"the pax header at byte {start + unread[0]} has records that Python releases "
        "read differently"
    )


def _scan(
    archive: Path,
    policy: ExtractPolicy,
    *,
    check_names: bool,
    on_member: Callable[[tarfile.TarFile, tarfile.TarInfo, _Member], None] | None = None,
) -> list[_Member]:
    """A whole pass of :func:`_members`, handing each member to
    ``on_member``; returns the members seen."""
    seen: list[_Member] = []
    with closing(_members(archive, policy, check_names=check_names)) as members:
        for tar, member, record in members:
            seen.append(record)
            if on_member is not None:
                on_member(tar, member, record)
    return seen


def _checked_members(
    tar: tarfile.TarFile,
    reader: _ForwardReader,
    policy: ExtractPolicy,
    header_bytes: int,
    compressed: int,
    check_names: bool,
    members: list[_Member],
) -> Generator[tuple[tarfile.TarFile, tarfile.TarInfo, _Member], None, int]:
    """The member loop of :func:`_members`; returns where the last member ends."""
    names = MemberNames()
    declared = 0
    end = 0
    while True:
        if isinstance(getattr(tar, "members", None), list):
            tar.members.clear()  # stream mode never looks a member up again
        member = _parsing(reader, tar.next)
        if member is None:
            return end
        if len(members) >= policy.max_files:
            # As where tarfile stops at this member's headers.
            stop = max(member.offset_data - end, 0)
            unread = _header_chain(reader.kept, end, stop=stop)[4]
            if member.size < 0 or unread is not None:
                _refuse_stopped(member, end, reader.kept, unread)
            raise SecurityError(
                code=ErrorCode.FILE_COUNT_EXCEEDED,
                msg=f"archive exceeds {policy.max_files} files",
            )
        regular, size = _check_extent(member, end, reader.kept, header_bytes, first=not members)
        rel = _check_name(member, policy, names) if check_names else ""
        if regular:
            label = rel if check_names else member.name
            if size > policy.max_file_bytes:
                raise SecurityError(
                    code=ErrorCode.FILE_BYTES_EXCEEDED,
                    msg=(
                        f"member {label!r} declares size {size} "
                        f"> max-file-bytes {policy.max_file_bytes}"
                    ),
                    path=label,
                )
            if declared + size > policy.max_total_bytes:
                raise SecurityError(
                    code=ErrorCode.TOTAL_BYTES_EXCEEDED,
                    msg=f"total uncompressed size would exceed {policy.max_total_bytes} bytes",
                )
            declared += size
            if compressed > 0 and declared > compressed * policy.max_compression_ratio:
                raise SecurityError(
                    code=ErrorCode.COMPRESSION_RATIO_EXCEEDED,
                    msg=(
                        f"uncompressed size {declared} exceeds "
                        f"archive size {compressed} * ratio "
                        f"{policy.max_compression_ratio}"
                    ),
                )
        stored = -(-size // tarfile.BLOCKSIZE) * tarfile.BLOCKSIZE if regular else 0
        end = member.offset_data + stored
        reader.advance(end, end + header_bytes)
        record = _Member(member.name, member.type, member.size, member.offset, rel)
        members.append(record)
        yield tar, member, record


def _refuse_stopped(
    member: tarfile.TarInfo, end: int, kept: bytearray, unread: tuple[int, bool] | None
) -> NoReturn:
    """Refuse ``member``, which has a negative size or (``unread``, see
    :func:`_header_chain`) a pax header before it that releases do not
    read alike, as a release that stops reading the archive at its header
    blocks reports it, whether this one did or read on: a negative size in
    the header blocks from where the member before it ends (``end``;
    ``kept`` holds the bytes from there on) first (FILE_BYTES_EXCEEDED),
    then that pax header (``tarfile.ReadError``)."""
    _header_chain(kept, end)
    if unread is not None:
        raise _unread(end, unread)
    raise SecurityError(
        code=ErrorCode.FILE_BYTES_EXCEEDED,
        msg=f"member {member.name!r} declares a negative size {member.size}",
        path=member.name,
    )


def _check_extent(
    member: tarfile.TarInfo,
    end: int,
    kept: bytearray,
    header_bytes: int,
    *,
    first: bool,
) -> tuple[bool, int]:
    """Refuse a member whose extent in the archive tarfile might see
    differently from its header, or whose header blocks do not follow on
    from where the member before it ends (``end``). ``kept`` holds the bytes
    from ``end`` on, so the header blocks, every pax record and the
    member's own header, with its type and size, are read again here,
    whatever the tarfile release made of them. Taken from tarfile: where
    the member's data begins (``offset_data``) and its headers begin
    (``offset``), its name (with a pax path or GNU long name applied), and
    whether it is sparse (``issparse``, a further refusal); its type and
    size, which must be what its own header gives (else it is refused), and
    a negative size of its that the header blocks do not show (refused);
    and, where the header blocks do not lead to its own header (it is then
    refused), its type, which only picks the code. Returns whether the
    member is a regular file and its size, as its own header gives them."""
    headers = member.offset_data - end
    # The header blocks from ``end`` up to the member's data are walked from
    # the bytes, the member's own header included, whatever tarfile (whose
    # view of a negative size or of a pax record differs between releases)
    # made of them.
    found, global_bytes, keys, size, unread = _header_chain(kept, end, stop=max(headers, 0))
    if member.size < 0 or unread is not None:
        _refuse_stopped(member, end, kept, unread)
    # They must lead, size by size, to the member's own header, so every
    # release reads them as they are. If they do not, tarfile may have
    # skipped a member.
    leads = (
        member.offset >= end and headers <= len(kept) and found == headers - 512
        and size is not None
    )
    own_type = member.type
    if leads:
        # The member's type is its own header's typeflag. A NUL typeflag is a
        # regular file in the old form, or a directory if the name field ends
        # in '/': every release reads it so when it is the member's first
        # header (refused if its size is not 0, as some tar programs read
        # that many bytes of data after it). After a pax or GNU long-name
        # header, some releases read it as a directory and others as a
        # regular file followed by its data, so it is refused.
        typeflag = kept[found + 156]
        if typeflag == 0:
            name_end = kept.find(b"\0", found, found + 100)
            name_end = found + 100 if name_end < 0 else name_end
            if name_end > found and kept[name_end - 1] == 0x2F:
                field = bytes(kept[found:name_end]).decode("utf-8", "surrogateescape")
                if found:
                    raise SecurityError(
                        code=ErrorCode.DISALLOWED_MEMBER_TYPE,
                        msg=(
                            f"the header at byte {end + found} has a NUL typeflag and a "
                            f"name field ending in '/' ({field!r}) after a pax or GNU "
                            "long-name header, which Python releases read as different types"
                        ),
                    )
                if size:
                    raise SecurityError(
                        code=ErrorCode.DISALLOWED_MEMBER_TYPE,
                        msg=(
                            f"the header at byte {end + found} has a NUL typeflag, a name "
                            f"field ending in '/' ({field!r}) and a size of {size}, which tar "
                            "programs read as a directory with and without data"
                        ),
                    )
                typeflag = 0x35  # a directory
        own_type = _TYPEFLAGS[typeflag]
    # Where the header blocks do not lead to the member's own header, the
    # member is refused below (PX_E_6013) and tarfile's type only picks the
    # code: releases read a type differently only as a regular file or a
    # directory (above), both allowed here.
    # Reject disallowed member types BEFORE path checks to catch hardlinks
    # whose link target points outside dest (member.isfile() would NOT catch these).
    if own_type not in _MEMBER_TYPES:
        raise SecurityError(
            code=ErrorCode.DISALLOWED_MEMBER_TYPE,
            msg=(
                f"disallowed member type for {member.name!r}: "
                f"type={own_type!r} (symlink/hardlink/device/fifo forbidden)"
            ),
            path=member.name,
        )
    # Sparse data (and the sparse map blocks after the header) is not part of
    # the format. The keys are those of every pax header before the member,
    # local or global, read from the bytes (tarfile's pax_headers holds only
    # the first local header's keys and the global keys before it). A global
    # header's keys apply to the later members too; the first is refused here.
    if (
        own_type == tarfile.GNUTYPE_SPARSE
        or member.issparse()
        or (keys and any(k.startswith(b"GNU.sparse.") for k in keys))
    ):
        raise SecurityError(
            code=ErrorCode.DISALLOWED_MEMBER_TYPE,
            msg=f"sparse member {member.name!r} (sparse files are not part of the format)",
            path=member.name,
        )
    if b"size" in keys:
        raise SecurityError(
            code=ErrorCode.FILE_BYTES_EXCEEDED,
            msg=f"member {member.name!r} has its size in a pax header",
            path=member.name,
        )
    if not leads or size is None:
        raise _archive_bomb(
            f"the header blocks from byte {end} do not lead to the header of "
            f"member {member.name!r}"
        )
    # What tarfile reports must be what the bytes give, as every release
    # reads them; the reads and checks after this use either.
    if member.type != own_type or member.size != size:
        raise _archive_bomb(
            f"tarfile read the header of member {member.name!r} as type "
            f"{member.type!r} and size {member.size}; its bytes give {own_type!r} and {size}"
        )
    allowance = header_bytes + (min(global_bytes, _GLOBAL_HEADER_BYTES) if first else 0)
    if headers > allowance:
        raise _archive_bomb(
            f"the headers of member {member.name!r} take {headers} bytes, more than "
            f"{allowance}"
        )
    return own_type != tarfile.DIRTYPE, size


def _check_name(member: tarfile.TarInfo, policy: ExtractPolicy, names: MemberNames) -> str:
    """Check a member's name as :func:`unpack` does; returns its relative path."""
    parts = path_parts(_check_path(member.name, policy))
    if not parts and not member.isdir():
        raise SecurityError(
            code=ErrorCode.EMPTY_MEMBER_NAME,
            msg=f"regular file member has no name: {member.name!r}",
            path=member.name,
        )
    rel = "/".join(parts)
    other = names.add(parts, is_dir=member.isdir())
    if other is not None:
        raise SecurityError(
            code=ErrorCode.DUPLICATE_MEMBER_PATH,
            msg=f"member path {rel!r} collides with {other!r} after normalization",
            path=rel,
        )
    bad = non_portable_component(parts)
    if bad is not None:
        raise SecurityError(
            code=ErrorCode.PATH_TRAVERSAL,
            msg=(
                f"member path component {bad!r} is not a portable file name "
                f"(Windows-reserved character or device name, or trailing dot "
                f"or space): {member.name!r}"
            ),
            path=member.name,
        )
    return rel


def check_member_names(
    archive_path: Path | str, policy: ExtractPolicy | None = None
) -> None:
    """Run the header checks of :func:`unpack` (member types, extents,
    names and declared sizes) without extracting anything, in one pass
    over the archive (see :func:`_members`).

    Anything that reads an archive by member name (signature validation,
    signer-manifest lookup) must check this first: once no two members collide,
    a name lookup and an extraction can no longer see different files.
    """
    _scan(Path(archive_path), policy or ExtractPolicy.default(), check_names=True)


def unpack(
    archive_path: Path | str,
    dest_dir: Path | str,
    policy: ExtractPolicy | None = None,
) -> Path:
    """Safely extract a canonical .aphelion.tar into dest_dir.

    Uses a streaming tarfile.next() loop - NEVER tar.extractall(), because
    extractall won't catch zip-bomb-class expansion until it's already disk-bound.
    Reads the archive twice, front to back: the first pass checks every
    member header, the second compares each header with what the first saw
    and writes the member, refusing with ARCHIVE_BOMB, before writing it,
    a member that differs (and an archive with more or fewer members).
    Whatever the member headers say, each pass hands
    tarfile at most ``max_total_bytes`` plus 4,607 bytes per ``max_files``
    member plus 5,120 bytes (150,932,720 bytes at the default policy; see
    :func:`_members` for what each pass refuses), and a decompressing file
    object may decompress up to ``io.DEFAULT_BUFFER_SIZE`` (8 KiB, or
    128 KiB from Python 3.14) more ahead of that.

    All-or-nothing: members are extracted into a staging directory and moved
    into place only once every member has passed every check. For an existing
    ``dest_dir`` the staging directory is a hidden ``.unpacking-*`` directory
    inside it, visible there while the unpack runs; otherwise it sits next to
    ``dest_dir`` and is renamed to it. Files an existing ``dest_dir`` already
    has are moved aside into the staging directory before being replaced, so
    an error while moving puts them back (see :class:`_Replacement`). Only
    regular files are ever moved aside: where the archive has a file and
    ``dest_dir`` a directory, a link or anything else, or the archive a
    directory and ``dest_dir`` anything but a real directory, the unpack is
    refused before anything moves, and again if that changes meanwhile. An
    entry found absent is put in place by a step that fails if anything is
    there by then (an exclusive create, or a rename that replaces nothing),
    so a wrong "not found" fails the unpack instead of replacing a file
    nothing backed up.
    Two members that reach one entry already in ``dest_dir`` (by its 8.3
    short name, say) are refused before anything moves; two hard links of
    one file are two entries, each replaced on its own. An alias the merge
    itself creates (Windows gives a new file or directory a short name
    another member spells) is found during the merge, which is then undone.
    Where the filesystem reports no file identity (inode number 0) that
    check cannot run, so an entry the archive would replace or merge into
    is refused.

    Until every entry is in place, any exception, an interrupt such as
    KeyboardInterrupt included, leaves the contents of ``dest_dir`` as they
    were (its own timestamps may change), or the error names the directory
    that still holds the original files: on failure that directory is
    deleted only once it is empty. Parent directories this call created are
    removed again. Once every entry is in place the unpack has succeeded,
    and an interrupt while the replaced files are deleted propagates with a
    note saying so and naming what is left over. Leftovers are named, on
    Python 3.11+, in a note on the raised error and in a RuntimeWarning;
    where no note can carry the name (Python 3.10, or a call that
    succeeded), the RuntimeWarning is shown even where warnings are
    ignored or turned into errors. ``dest_dir``
    itself must not be a symlink or junction. Nor can it be a Windows
    mounted folder, which is the same kind of reparse point as a junction:
    unpack into a directory inside it instead.

    Known limits: there is no journal, so a killed process or a power loss
    can leave a ``.unpacking-*`` directory (with replaced files in it) behind,
    and an interrupt in the instant after it is created, an empty one;
    a file Windows holds open without delete sharing can stop both the move
    and the undo; staging is always on ``dest_dir``'s own filesystem, so a
    separate mount inside ``dest_dir`` makes the move fail (and be undone).
    Every check goes by path: a process that can replace ``dest_dir``, one
    of its parents or an entry in it while unpack runs can still redirect
    the writes, a window that path-based checks cannot close. Likewise the
    one look at ``dest_dir`` as spelled is taken as the OS gives it: where
    the OS wrongly reports a link there as absent or as a plain directory,
    resolving ``dest_dir`` follows the link. Resolving
    ``dest_dir`` and each member's path (``Path.resolve``) keeps its
    standard-library behaviour, which can take a component it cannot look
    at for one that is not a link; the merge's strict check of every entry
    in ``dest_dir`` is what refuses a link there. On a filesystem other
    than Windows', a new ``dest_dir`` renamed into place can replace an
    empty directory that appeared there meanwhile.
    On success, archive files replace same-named files in an existing
    ``dest_dir``; other files there are kept.
    """
    return _unpack(archive_path, dest_dir, policy, None)


def _unpack(
    archive_path: Path | str,
    dest_dir: Path | str,
    policy: ExtractPolicy | None,
    collect: _SignatureMembers | None,
) -> Path:
    """:func:`unpack`; with ``collect``, the members signature validation
    reads are collected while they are written."""
    policy = policy or ExtractPolicy.default()
    archive = Path(archive_path)
    dest = Path(dest_dir)
    # One strict look at dest as spelled, so the OS resolves the spelling
    # ("." or "x/.." on Windows, a drive root a subst maps elsewhere) and
    # reports a link there; then dest is resolved whole.
    _dest_exists(dest)
    dest_resolved = dest.resolve()
    made: list[Path] = []  # parents this call created, each on record before its mkdir
    staging = backup = replacement = None
    renaming = False
    try:
        _make_parents(dest_resolved.parent, made)
        staging = _make_staging_dir(dest_resolved)
        if staging.parent == dest_resolved:
            backup = _make_unique_dir(staging, ".backup-")
        _extract(archive, staging, dest_resolved, policy, backup, collect)
        if backup is None and _dest_exists(dest_resolved):  # dest appeared beside staging
            backup = _make_unique_dir(staging, ".backup-")
        if backup is None:
            renaming = True  # on record before the rename, as _Replacement logs its steps
            # Not os.replace, which on Windows replaces a file there by now.
            os.rename(staging, dest_resolved)
        else:
            replacement = _Replacement(backup)
            _merge(staging, dest_resolved, replacement)
            # Every entry is in place; what follows only deletes what was replaced.
            replacement.commit()
            _remove_or_warn(staging)
    except BaseException as exc:
        if (replacement is not None and replacement.complete) or (
            renaming and not _maybe_present(staging)
        ):
            # The unpack succeeded; only the cleanup after it was cut short.
            left = ""
            if staging is not None and _maybe_present(staging):
                left = f"; {staging} is left over and holds only replaced files, so it can go"
            _report(f"the unpack completed and {dest} is updated{left}", exc)
            raise
        # The backup holds what a merge moved aside, and staging holds the
        # backup: staging goes only once the backup is gone.
        if staging is not None and (backup is None or _discard_backup(backup, exc)):
            _remove_or_warn(staging, exc)
        _remove_made(made)
        raise
    return dest


def _dest_exists(dest: Path) -> bool:
    """Whether the unpack destination is there, by a strict lstat; a link or
    anything but a directory there is refused. Asked of dest as spelled
    first, then of the resolved dest where staging is placed and before a
    new dest is renamed into place, so a link that appeared there meanwhile
    is refused too."""
    st = _lstat(dest)
    if st is None:
        return False
    if _is_link(st):
        # resolve() would follow it, also when dangling, and unpack elsewhere.
        raise FileExistsError(f"unpack destination is a symlink or junction: {dest}")
    if not stat.S_ISDIR(st.st_mode):
        raise FileExistsError(f"unpack destination is not a directory: {dest}")
    return True


def _is_link(st: os.stat_result) -> bool:
    # A Windows junction is a reparse point but not S_ISLNK on Python < 3.12.
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return stat.S_ISLNK(st.st_mode) or bool(getattr(st, "st_file_attributes", 0) & reparse)


def _same_entry(a: Path, b: Path) -> bool:
    # Only "no such entry" means "not the same": any other error fails the
    # call, since an identity check that cannot run must not pass.
    try:
        return os.path.samefile(a, b)
    except (FileNotFoundError, NotADirectoryError) as err:
        if _absent(err):
            return False
        raise


def _make_parents(path: Path, made: list[Path]) -> None:
    """Create ``path`` and its missing parents, adding each to ``made``.

    Each level is created on its own and put on record before its mkdir, so
    an interrupt right after the mkdir returns still finds it. A directory
    another process creates meanwhile is taken off the record again, so it
    is never removed on failure.
    """
    missing = []
    for candidate in (path, *path.parents):
        if _lstat(candidate) is not None:
            break
        missing.append(candidate)
    for directory in reversed(missing):
        made.append(directory)
        try:
            directory.mkdir()
        except FileExistsError:
            made.pop()
            st = _lstat(directory, follow_symlinks=True)
            if st is None or not stat.S_ISDIR(st.st_mode):
                raise


def _remove_made(made: list[Path]) -> None:
    # rmdir, not rmtree: anything another process put there stays.
    for directory in reversed(made):
        try:
            os.rmdir(directory)
        except OSError:
            pass


class _RestoreError(OSError):
    """An undo did not finish; the message names what is left and where."""


class _Replacement:
    """Put entries in place by rename, so that a failure can be undone.

    An entry about to be replaced is first renamed into ``backup``, a
    directory on the same filesystem. Each step is logged before it runs, so
    an interrupt that lands right after a rename returns is still on record;
    ``rollback`` checks which renames happened and reverses them. ``commit``
    deletes ``backup`` after success, warning instead of raising if it
    cannot. On a failure path ``backup`` is deleted only once it is empty
    (see :func:`_discard_backup`). Shared by unpack, whose merge uses
    ``mkdir`` and ``put_file`` and so moves aside regular files only, and
    migrate, whose ``replace_entry`` replaces the whole destination. An
    entry found absent is placed by a step that fails if anything is there
    by then: a file over an empty placeholder made by an exclusive create
    (removed again by ``rollback``), a directory by a rename that replaces
    nothing on Windows and only an empty directory elsewhere. ``rollback``
    moves an entry back the same way, so it never replaces what it moves to.

    Known limits: the log is in memory only (no recovery after a kill or a
    power loss; ``backup`` then still holds the replaced entries), an undo
    step fails if Windows holds the file open without delete sharing, every
    rename must stay on one filesystem, and an interrupt while ``commit``
    deletes ``backup`` (every entry is in place by then) leaves part of it.
    Every check goes by path: a process that can replace a target or one of
    its parents between the check and the rename can still redirect it, a
    window that path-based checks cannot close.
    """

    def __init__(self, backup: Path) -> None:
        self.backup = backup
        # Set by the caller once every step is done; from then on the call
        # has succeeded, and only deleting the replaced entries is left.
        self.complete = False
        # (src, target, saved): target was renamed to saved (if it existed),
        # then src onto target. src None: target is a directory this call made.
        self._log: list[tuple[Path | None, Path, Path | None]] = []
        self._placed: dict[tuple[int, int], Path] = {}  # (st_dev, st_ino) -> target
        self._claims: dict[Path, tuple[int, int]] = {}  # placeholder -> (st_dev, st_ino)

    def mkdir(self, target: Path) -> None:
        """Unpack's merge: make ``target`` for a staged directory, or merge
        into the real directory already there; anything else fails."""
        st = _lstat(target)
        if st is not None:
            _check_replaceable(st, target, is_dir=True)
            self._refuse_placed(st, target)
            # Merged into, so a later member must not reach it by another name.
            self._placed[_identity(st, target)] = target
            return
        self._log.append((None, target, None))
        try:
            target.mkdir()
        except OSError:  # nothing was made; what is there, if anything, is not this call's
            self._log.pop()
            raise
        self._remember(target)

    def put_file(self, src: Path, target: Path) -> None:
        """Unpack's merge: move the staged regular file ``src`` to ``target``.

        Whether something is there, and that it is a regular file that may
        be moved aside, is read by a strict lstat right before the rename: a
        directory, a link or an entry that cannot be looked at fails the
        call instead, so the merge never moves aside or replaces anything
        else in dest.
        """
        src_st = _lstat(src)
        if src_st is None or not stat.S_ISREG(src_st.st_mode):
            raise OSError(f"staged entry is not a regular file any more: {src}")
        st = _lstat(target)
        if st is not None:
            _check_replaceable(st, target, is_dir=False)
            self._refuse_placed(st, target)
        self._swap(src, target, present=st is not None)
        self._remember(target)

    def replace_entry(self, src: Path, target: Path) -> None:
        """migrate --force: put the directory ``src`` at ``target``, moving
        aside whatever is there, by design: the whole old destination, or the
        link it is."""
        self._swap(src, target, present=_lstat(target) is not None, directory=True)

    def _swap(self, src: Path, target: Path, *, present: bool, directory: bool = False) -> None:
        saved = self.backup / str(len(self._log)) if present else None
        self._log.append((src, target, saved))
        if saved is not None:
            os.replace(target, saved)
            os.replace(src, target)
            return
        # Found absent, and nothing backed up what a rename would replace,
        # while the strict lstat can still be wrong (on Windows a network
        # error is reported as "not found"): placed by a step that fails if
        # anything is there by now. A directory by a rename, which replaces
        # nothing on Windows and elsewhere only an empty directory; a file
        # over an empty placeholder made by an exclusive create.
        try:
            if directory:
                os.rename(src, target)
                return
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except OSError:  # nothing was made; what is there, if anything, is not this call's
            self._log.pop()
            raise
        try:
            st = os.fstat(fd)
            self._claims[target] = (st.st_dev, st.st_ino)  # how rollback knows it
        finally:
            os.close(fd)
        os.replace(src, target)

    def _unclaim(self, target: Path) -> None:
        # The placeholder of a move that did not happen goes; anything else
        # at target (the moved file, if it could not be moved back) stays.
        _remove_placeholder(target, self._claims[target])

    def _refuse_placed(self, st: os.stat_result, target: Path) -> None:
        # Two entries distinct in staging can still name one entry here: the
        # 8.3 short name Windows gives the first may be the second's name.
        # Found by identity, whatever the names look like.
        other = self._placed.get(_identity(st, target))
        if other is not None:
            raise SecurityError(
                code=ErrorCode.DUPLICATE_MEMBER_PATH,
                msg=(
                    f"{target} reaches {other}, which this call already put in place "
                    f"(an 8.3 short name or other filesystem alias)"
                ),
                path=str(target),
            )

    def _remember(self, target: Path) -> None:
        st = os.lstat(target)
        if st.st_ino:
            self._placed[(st.st_dev, st.st_ino)] = target

    def rollback(self, exc: BaseException) -> None:
        """Undo every logged step; if all is back, return for ``exc`` to propagate.

        Every step is tried, even after one fails or is interrupted. What
        could not be put back is reported: after an interrupt (a
        BaseException that is not an Exception, from ``exc`` or from an undo
        step) in a note on it (Python 3.11+), and the interrupt propagates as
        itself; otherwise by a :class:`_RestoreError` raised from ``exc``.
        Nothing is deleted here.
        """
        self.complete = False
        errors: list[BaseException] = []
        for src, target, saved in reversed(self._log):
            if src is None:
                _attempt(errors, _rmdir_if_present, target)
                continue
            _attempt(errors, _move_back, target, src)
            if saved is not None:
                _attempt(errors, _restore, saved, target, src)
            elif target in self._claims:
                _attempt(errors, self._unclaim, target)
        kept = [
            f"{target} as {saved.name}"
            for _src, target, saved in self._log
            if saved is not None and _maybe_present(saved)
        ]
        added = [
            str(target)
            for _src, target, saved in self._log
            if saved is None and _maybe_present(target)
        ]
        self._log.clear()
        self._claims.clear()
        interrupt = next((e for e in (exc, *errors) if not isinstance(e, Exception)), None)
        left = []
        if kept:
            left.append(f"the original entries are kept in {self.backup}: {', '.join(kept)}")
        if added:
            left.append(f"entries this call added are still in place: {', '.join(added)}")
        if left and interrupt is None:
            raise _RestoreError(
                f"could not undo after {exc!r}: {'; '.join(left)} "
                f"({'; '.join(map(str, errors))})"
            ) from exc
        if left and hasattr(interrupt, "add_note"):
            interrupt.add_note(f"could not undo: {'; '.join(left)}")
        if interrupt is not None and interrupt is not exc:
            raise interrupt

    def commit(self) -> None:
        _remove_or_warn(self.backup)


def _attempt(errors: list[BaseException], step: Callable[..., object], *args: Path) -> None:
    try:
        step(*args)
    except BaseException as err:  # finish the undo first; the caller decides what to raise
        errors.append(err)


def _lstat(path: Path, *, follow_symlinks: bool = False) -> os.stat_result | None:
    """``os.lstat`` (``os.stat`` with ``follow_symlinks``), or None if there
    is no such entry.

    Any other error is raised: an entry that cannot be looked at may still
    be there, so it must not be taken as absent. The type and existence
    checks unpack and migrate make themselves go through here, never through
    pathlib or os.path predicates, which return False on errors. Path
    resolution (``Path.resolve``) and ``Path.mkdir(exist_ok=True)`` keep their
    standard-library behaviour; the strict checks of the entries that are
    moved are their backstop. Only the OS saying there is no such entry
    counts as absent (see :func:`_absent`); as even that can be wrong, what
    is found absent is placed by a step that fails if anything is there.
    """
    try:
        return os.stat(path) if follow_symlinks else os.lstat(path)
    except (FileNotFoundError, NotADirectoryError) as err:
        if _absent(err):
            return None
        raise


def _absent(err: OSError) -> bool:
    """Whether ``err`` is the OS saying that there is no such entry.

    Windows also raises FileNotFoundError for some network errors (a
    network path or share that cannot be reached: winerror 53 and 67), and
    an entry behind those may well be there, so on Windows only
    ERROR_FILE_NOT_FOUND and ERROR_PATH_NOT_FOUND count; elsewhere ENOENT
    and ENOTDIR. Every place that takes an error to mean "absent" asks this.
    """
    if sys.platform == "win32":
        return getattr(err, "winerror", None) in (2, 3)
    return err.errno in (errno.ENOENT, errno.ENOTDIR)


def _is_dir(st: os.stat_result) -> bool:
    # A real directory: a junction is S_ISDIR too, but leads elsewhere.
    return stat.S_ISDIR(st.st_mode) and not _is_link(st)


def _maybe_present(path: Path) -> bool:
    try:
        return _lstat(path) is not None
    except OSError:  # cannot tell: report it rather than lose track of it
        return True


def _move_back(path: Path, back: Path) -> None:
    # Only a rename that happened is reversed, by a step that fails if
    # anything is at back by then, as the look that found it free can be
    # wrong: a directory by a rename (which replaces nothing on Windows and
    # elsewhere only an empty directory), anything else over an empty
    # placeholder made by an exclusive create, removed again if the move fails.
    st = _lstat(path)
    if st is None or _lstat(back) is not None:
        return
    if stat.S_ISDIR(st.st_mode):
        os.rename(path, back)
        return
    fd = os.open(back, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        claim = os.fstat(fd)
    finally:
        os.close(fd)
    try:
        os.replace(path, back)
    except BaseException:
        _remove_placeholder(back, (claim.st_dev, claim.st_ino))
        raise


def _remove_placeholder(path: Path, claim: tuple[int, int]) -> None:
    # The empty file this call made at path goes; anything else there stays.
    st = _lstat(path)
    if (
        st is not None
        and st.st_ino
        and stat.S_ISREG(st.st_mode)
        and (st.st_dev, st.st_ino) == claim
    ):
        os.unlink(path)


def _restore(saved: Path, target: Path, src: Path) -> None:
    # target is free, or still holds the new entry (src is gone because it
    # could not be moved back): the original may replace that, nothing else.
    if _lstat(saved) is not None and (_lstat(target) is None or _lstat(src) is None):
        os.replace(saved, target)


def _rmdir_if_present(path: Path) -> None:
    if _lstat(path) is not None:
        os.rmdir(path)


def _discard_backup(backup: Path, exc: BaseException) -> bool:
    """On a failure path, remove ``backup`` only if it is empty.

    Never rmtree: whatever is still in it was moved aside and not put back.
    Such a backup is kept and, unless ``exc`` already names it, named in a
    RuntimeWarning and, on Python 3.11+, in a note on ``exc``. Returns
    whether ``backup`` is gone.
    """
    try:
        os.rmdir(backup)  # refuses a directory that is not empty
    except OSError as err:
        # From rmdir, ENOTDIR can mean that something other than a
        # directory is there: only "not found" means it is gone.
        if isinstance(err, FileNotFoundError) and _absent(err):
            return True
        if not any(str(backup) in text for text in (str(exc), *getattr(exc, "__notes__", ()))):
            _report(
                f"kept {backup}: it may hold entries this call moved aside and could "
                f"not put back",
                exc,
            )
        return False
    return True


def _remove_or_warn(path: Path, exc: BaseException | None = None) -> None:
    """Remove a directory tree this process made; never raises.

    rmtree unlinks links inside the tree instead of following them; where
    ``shutil.rmtree.avoids_symlink_attacks`` is true it also refuses a
    directory replaced by a link while it runs. Where it is false (Windows)
    that race remains, and only symlink and junction reparse points count as
    links. On Windows a read-only entry (the attribute blocks deletion) is
    made writable and retried. Whatever is still left is named as
    :func:`_report` does, so the caller's error is never replaced.
    """

    def retry_writable(func: Callable[[str], object], entry: str, _exc: object) -> None:
        # POSIX has no read-only attribute to clear: a failed removal stays
        # failed and is reported below.
        if sys.platform != "win32" or func not in (os.unlink, os.rmdir, os.remove):
            return
        try:
            st = os.lstat(entry)
            # Never chmod through a link: that would change its target, which
            # may lie outside the tree. Where chmod cannot be told not to
            # follow links, the lstat above is the only guard.
            if not _is_link(st):
                if os.chmod in os.supports_follow_symlinks:
                    os.chmod(
                        entry, stat.S_IMODE(st.st_mode) | stat.S_IWRITE, follow_symlinks=False
                    )
                else:
                    os.chmod(entry, stat.S_IMODE(st.st_mode) | stat.S_IWRITE)
            func(entry)
        except OSError:
            pass

    if sys.version_info >= (3, 12):
        shutil.rmtree(path, onexc=retry_writable)
    else:
        shutil.rmtree(path, onerror=retry_writable)
    if _maybe_present(path):
        _report(f"could not remove {path}; delete it by hand", exc)


def _report(note: str, exc: BaseException | None) -> None:
    """Name a leftover so that it reaches the user; never replaces ``exc``.

    On Python 3.11+ with an error to carry it, a note on ``exc`` names it,
    and so does a RuntimeWarning, subject to the warnings filters. Otherwise
    (Python 3.10, or a call that succeeded) the RuntimeWarning is all there
    is, so it goes straight to :func:`warnings.showwarning`, past the
    filters: shown once, like any warning, even where RuntimeWarnings are
    ignored or turned into errors. Where ``showwarning`` has been replaced
    (``logging.captureWarnings``, say, which with no handler shows nothing)
    the line is also written to stderr.
    """
    if exc is not None and hasattr(exc, "add_note"):
        exc.add_note(note)
        try:
            warnings.warn(note, RuntimeWarning, stacklevel=4)
        except Exception:  # a filter set to "error" must not mask exc; the note names it
            pass
        return
    try:
        frame = sys._getframe(3)  # where warnings.warn(stacklevel=4) would point
        filename, lineno = frame.f_code.co_filename, frame.f_lineno
    except ValueError:
        filename, lineno = __file__, 0
    # Not the standard library's: it may show nothing, so stderr too.
    replaced = warnings.showwarning is not getattr(warnings, "_showwarning_orig", None)
    try:
        warnings.showwarning(RuntimeWarning(note), RuntimeWarning, filename, lineno)
    except Exception:  # a replaced showwarning that fails: stderr is what is left
        replaced = True
    if replaced and sys.stderr is not None:
        try:
            sys.stderr.write(f"RuntimeWarning: {note}\n")
        except (OSError, ValueError):  # stderr closed: nowhere left to say it
            pass


def _make_staging_dir(dest: Path) -> Path:
    # On dest's filesystem, so every move into place is a rename. An existing
    # dest gets the staging dir inside it: dest may be a mount point, or sit
    # in a directory the caller cannot write to. A new dest gets a sibling,
    # which becomes dest by one rename; Path.mkdir (not tempfile.mkdtemp)
    # keeps the umask-derived mode that dest would have had.
    if _dest_exists(dest):
        return _make_unique_dir(dest, ".unpacking-")
    return _make_unique_dir(dest.parent, f".{dest.name}.unpacking-")


def _make_unique_dir(parent: Path, prefix: str) -> Path:
    while True:
        path = parent / f"{prefix}{secrets.token_hex(8)}"
        try:
            path.mkdir()
        except FileExistsError:  # pragma: no cover - 64-bit random collision
            continue
        return path


def _merge(staging: Path, dest: Path, replacement: _Replacement) -> None:
    """Merge a fully extracted staging tree into the existing ``dest``.

    Every move goes through ``replacement``, whose backup directory sits in
    staging, so an error midway is undone. ``replacement.complete`` is set
    once every entry is in place.
    """
    entries = _staged(staging, replacement.backup)
    # Check every target first so a conflict cannot leave a half-moved tree.
    existing: dict[tuple[int, int, str | None], Path] = {}
    for rel, is_dir in entries:
        target = dest / rel
        # Staging sits inside dest. Compared by identity, not by name: on
        # Windows a case variant or the 8.3 short name also reaches it,
        # and so can a directory link already in dest.
        if _same_entry(target, staging):
            raise FileExistsError(f"cannot unpack over the staging directory: {target}")
        st = _lstat(target)
        if st is not None:
            _check_replaceable(st, target, is_dir=is_dir)
            # Two members distinct in staging can name one entry already in
            # dest (the 8.3 short name of a file or directory there).
            entry = (*_identity(st, target), _entry_name(st, target, is_dir=is_dir))
            other = existing.setdefault(entry, target)
            if other != target:
                raise SecurityError(
                    code=ErrorCode.DUPLICATE_MEMBER_PATH,
                    msg=(
                        f"{target} and {other} are one entry in dest "
                        f"(an 8.3 short name or other filesystem alias)"
                    ),
                    path=str(target),
                )
    try:
        for rel, is_dir in entries:
            if is_dir:
                replacement.mkdir(dest / rel)
            else:
                replacement.put_file(staging / rel, dest / rel)
        replacement.complete = True  # last: anything raised before it is undone
    except BaseException as exc:
        replacement.rollback(exc)
        raise


def _staged(staging: Path, backup: Path) -> list[tuple[Path, bool]]:
    """Every staged entry except ``backup``, as ``(path relative to staging,
    is a directory)``, each directory before the entries in it.

    The type of each entry comes from a strict lstat of it, never from the
    directory listing: os.walk takes an entry whose type it cannot read for
    a file. Staging holds only what this call extracted, so an entry that
    is neither a regular file nor a directory fails the call.
    """
    entries: list[tuple[Path, bool]] = []
    pending = [Path()]
    while pending:
        rel_dir = pending.pop(0)
        with os.scandir(staging / rel_dir) as listing:
            names = [entry.name for entry in listing]
        dirs: list[Path] = []
        files: list[Path] = []
        for name in names:
            if not rel_dir.parts and name == backup.name:
                continue  # listed under its own name; members cannot reach it (see _extract)
            rel = rel_dir / name
            st = _lstat(staging / rel)
            if st is not None and _is_dir(st):
                dirs.append(rel)
            elif st is not None and stat.S_ISREG(st.st_mode):
                files.append(rel)
            else:
                raise OSError(f"staged entry is gone or not a file or directory: {staging / rel}")
        entries += [(rel, True) for rel in dirs] + [(rel, False) for rel in files]
        pending += dirs
    return entries


def _identity(st: os.stat_result, target: Path) -> tuple[int, int]:
    """``(st_dev, st_ino)`` of an existing entry the merge would use.

    An inode number of 0 means the filesystem reports no identity, so
    whether another member reaches the same entry cannot be checked: the
    merge fails closed instead of skipping the check.
    """
    if not st.st_ino:
        raise SecurityError(
            code=ErrorCode.DUPLICATE_MEMBER_PATH,
            msg=(
                f"cannot tell whether another member also reaches {target}: "
                f"the filesystem reports no file identity there"
            ),
            path=str(target),
        )
    return st.st_dev, st.st_ino


def _entry_name(st: os.stat_result, target: Path, *, is_dir: bool) -> str | None:
    """Which directory entry ``target`` is, where its identity cannot tell.

    None where the entry is the only one (a directory, or a file with one
    link), so every name that reaches it is an alias. A file with hard links
    has several entries: the name the filesystem stores (resolving spells
    an 8.3 short name or a case variant out) tells them apart, so two hard
    links are two entries, each replaced on its own.
    """
    if is_dir or st.st_nlink <= 1:
        return None
    return os.path.normcase(str(_resolve_existing(target)))


def _resolve_existing(path: Path) -> Path:
    """``path.resolve(strict=True)``, for a path a strict lstat has found.

    Where the volume's driver cannot answer the final-path query that
    Windows resolves with (ERROR_INVALID_FUNCTION 1 or ERROR_NOT_SUPPORTED
    50: some RAM disks and mapped drives), the non-strict resolve, which
    then falls back as the standard library does; the caller's lstat has
    shown that the path exists. Any other error is raised.
    """
    try:
        return path.resolve(strict=True)
    except OSError as err:
        if getattr(err, "winerror", None) not in (1, 50):
            raise
        return path.resolve()


def _check_replaceable(st: os.stat_result, target: Path, *, is_dir: bool) -> None:
    """Refuse an entry in dest the merge may not touch.

    A staged directory merges only into a real directory; a staged file
    replaces only a regular file. Anything else there (a directory where
    the archive has a file, a link, a junction, a device) is refused, so it
    is never moved aside, replaced or deleted.
    """
    if is_dir:
        if not _is_dir(st):
            raise FileExistsError(f"cannot unpack directory over existing non-directory: {target}")
    elif stat.S_ISDIR(st.st_mode):
        raise FileExistsError(f"cannot unpack file over existing directory: {target}")
    elif not stat.S_ISREG(st.st_mode):
        raise FileExistsError(f"cannot unpack file over existing non-file: {target}")


def _extract(
    archive: Path,
    staging: Path,
    dest_resolved: Path,
    policy: ExtractPolicy,
    backup: Path | None = None,
    collect: _SignatureMembers | None = None,
) -> None:
    total_bytes = 0
    archive_size = archive.stat().st_size
    made: set[str] = set()  # directories this call created in staging

    # Every header is checked before the first byte is written, so a
    # colliding or forbidden member late in the archive cannot ride on
    # members that were already extracted. The second pass must see the
    # same members, else nothing more is written.
    checked = _scan(archive, policy, check_names=True)
    count = 0
    with closing(_members(archive, policy, check_names=False)) as members:
        for tar, member, seen in members:
            if count >= len(checked) or checked[count][:4] != seen[:4]:
                raise _changed(archive)
            normalized = checked[count].path
            count += 1
            keep: list[bytes] | None = [] if collect is not None and collect.wants(member) else None
            # Checked against the real destination: a symlink already inside
            # dest must not carry a member outside it once moved into place.
            final = (dest_resolved / normalized).resolve()
            if dest_resolved not in final.parents and final != dest_resolved:
                raise SecurityError(
                    code=ErrorCode.PATH_TRAVERSAL,
                    msg=f"resolved path escapes dest: {normalized!r}",
                    path=normalized,
                )
            # The backup directory sits in staging; like staging itself it is
            # recognised by identity, so no alias of its name can reach it.
            if backup is not None and normalized:
                first = staging / normalized.split("/", 1)[0]
                if _same_entry(first, backup):
                    raise FileExistsError(f"cannot unpack over the backup directory: {first}")
            target = staging / normalized
            # Staging starts empty, so every entry is created exclusively, a
            # directory again only under the exact path this call made it: a
            # member that reaches an earlier one under another spelling (an
            # 8.3 short name, case folding, any filesystem alias) then fails
            # instead of overwriting it or merging into it.
            parts = normalized.split("/") if normalized else []
            for depth in range(1, len(parts) + (1 if member.isdir() else 0)):
                rel = "/".join(parts[:depth])
                if rel not in made:
                    try:
                        (staging / rel).mkdir()
                    except FileExistsError:
                        raise _aliased(normalized, rel) from None
                    made.add(rel)
            if member.isdir():
                if collect is not None and keep is not None:
                    collect.add(member, None)
                continue

            # Fast-fail on header-declared sizes. A malicious header can lie
            # (declare 0 then stream 30 MiB), so these guards are NOT
            # authoritative — the chunked read loop below is.
            if member.size > policy.max_file_bytes:
                raise SecurityError(
                    code=ErrorCode.FILE_BYTES_EXCEEDED,
                    msg=(
                        f"member {normalized!r} declares size {member.size} "
                        f"> max-file-bytes {policy.max_file_bytes}"
                    ),
                    path=normalized,
                )
            if total_bytes + member.size > policy.max_total_bytes:
                raise SecurityError(
                    code=ErrorCode.TOTAL_BYTES_EXCEEDED,
                    msg=(
                        f"total uncompressed size would exceed {policy.max_total_bytes} bytes"
                    ),
                )
            src = tar.extractfile(member)
            if src is None:
                raise SecurityError(
                    code=ErrorCode.DISALLOWED_MEMBER_TYPE,
                    msg=f"could not open stream for regular file {normalized!r}",
                    path=normalized,
                )
            written = 0
            chunk_size = 64 * 1024
            # Authoritative budget enforcement happens inside the read loop.
            # A failure here discards the whole staging tree (see unpack).
            out = None
            try:
                # Created by the with statement itself, so no interrupt can
                # land between the two and leave the file open (Windows could
                # not delete it); closed again below for one landing just as
                # the with statement exits.
                with _create_exclusive(target, normalized) as out:
                    while True:
                        chunk = src.read(chunk_size)
                        if not chunk:
                            break
                        written += len(chunk)
                        if written > policy.max_file_bytes:
                            raise SecurityError(
                                code=ErrorCode.ARCHIVE_BOMB,
                                msg=(
                                    f"member {normalized!r} streamed past "
                                    f"max-file-bytes {policy.max_file_bytes} "
                                    f"(bomb / oversize)"
                                ),
                                path=normalized,
                            )
                        if total_bytes + written > policy.max_total_bytes:
                            raise SecurityError(
                                code=ErrorCode.ARCHIVE_BOMB,
                                msg=(
                                    f"archive streaming expansion exceeded "
                                    f"max-total-bytes {policy.max_total_bytes}"
                                ),
                            )
                        out.write(chunk)
                        if keep is not None:
                            keep.append(chunk)
            finally:
                src.close()
                if out is not None:
                    out.close()
            total_bytes += written
            if collect is not None and keep is not None:
                collect.add(member, b"".join(keep))
            # compression-ratio enforcement (uncompressed total / archive size)
            if (
                archive_size > 0
                and total_bytes > archive_size * policy.max_compression_ratio
            ):
                raise SecurityError(
                    code=ErrorCode.COMPRESSION_RATIO_EXCEEDED,
                    msg=(
                        f"uncompressed size {total_bytes} exceeds "
                        f"archive size {archive_size} * ratio "
                        f"{policy.max_compression_ratio}"
                    ),
                )
    if count != len(checked):
        raise _changed(archive)


def _changed(archive: Path) -> SecurityError:
    return _archive_bomb(f"the archive changed while it was read: {archive}")


def _create_exclusive(target: Path, member: str) -> BinaryIO:
    # Exclusive, as staging starts empty: a file already there was made by an
    # earlier member under another name.
    try:
        return open(target, "xb")
    except FileExistsError:
        raise _aliased(member, member) from None


def _aliased(member: str, rel: str) -> SecurityError:
    return SecurityError(
        code=ErrorCode.DUPLICATE_MEMBER_PATH,
        msg=(
            f"member path {member!r}: {rel!r} reaches an entry an earlier member "
            f"created under another name (an 8.3 short name or other filesystem alias)"
        ),
        path=member,
    )


class _SignatureMembers:
    """The members signature validation reads, collected during a pass.

    Each is found by its exact member name, as ``TarFile.getmember`` finds
    one: when names repeat, the last member counts. ``signatures`` is the
    content of ``signatures.jsonl``, or None if it is absent or not a
    regular file; ``signers`` maps each signer id to the content of the
    regular file ``signers/<signer_id>.json``; ``manifest`` is the type and
    content (None if not a regular file) of ``manifest.json``, or None if
    it is absent. ``kinds`` limits what is collected.
    """

    def __init__(self, kinds: tuple[str, ...] = ("signatures", "signer", "manifest")) -> None:
        self.kinds = kinds
        self.signatures: bytes | None = None
        self.signers: dict[str, bytes] = {}
        self.manifest: tuple[bytes, bytes | None] | None = None

    @staticmethod
    def _kind(member: tarfile.TarInfo) -> str | None:
        name = member.name
        if name == "signatures.jsonl":
            return "signatures"
        if name == "manifest.json":
            return "manifest"
        # signer_id is the stem: signers/<signer_id>.json
        if member.isreg() and name.startswith("signers/") and name.endswith(".json"):
            if name[len("signers/"):-len(".json")]:
                return "signer"
        return None

    def wants(self, member: tarfile.TarInfo) -> bool:
        return self._kind(member) in self.kinds

    def add(self, member: tarfile.TarInfo, data: bytes | None) -> None:
        kind = self._kind(member)
        if kind == "signatures":
            self.signatures = data
        elif kind == "manifest":
            self.manifest = (member.type, data)
        elif kind == "signer" and data is not None:
            self.signers[member.name[len("signers/"):-len(".json")]] = data

    def __call__(self, tar: tarfile.TarFile, member: tarfile.TarInfo, _seen: _Member) -> None:
        """Collect ``member`` if it is wanted (a :func:`_scan` callback)."""
        if not self.wants(member):
            return
        data = None
        src = tar.extractfile(member) if member.isreg() else None
        if src is not None:
            with src:
                data = src.read()
        self.add(member, data)


def _read_signature_members(tar_path: Path | str) -> _SignatureMembers:
    """One pass over the archive: the checks of :func:`check_member_names`
    at the default policy, collecting the members signature validation
    reads."""
    members = _SignatureMembers()
    _scan(Path(tar_path), ExtractPolicy.default(), check_names=True, on_member=members)
    return members


def _unpack_reading_signature_members(
    archive_path: Path | str, dest_dir: Path | str
) -> tuple[Path, _SignatureMembers]:
    """:func:`unpack` at the default policy, collecting the members signature
    validation reads from the pass that writes them."""
    members = _SignatureMembers()
    return _unpack(archive_path, dest_dir, None, members), members


def extract_signatures_jsonl(tar_path: Path | str) -> bytes | None:
    """Return raw bytes of ``signatures.jsonl`` at archive root, or ``None`` if absent.

    Spec §5: presence of signatures.jsonl opts the package into v0.5 verification.
    This is a read-only accessor that does NOT run the name checks of
    :func:`unpack` — it is only used after a package has already been
    trust-verified at the tar level. It makes one pass over the archive with
    the other header checks of :func:`unpack` at the default policy (see
    :func:`_members`). When several members have the name, the last one counts;
    if that is a directory, the result is ``None``.
    """
    members = _SignatureMembers(("signatures",))
    _scan(Path(tar_path), ExtractPolicy.default(), check_names=False, on_member=members)
    return members.signatures


def extract_signer_manifests(tar_path: Path | str) -> Mapping[str, bytes]:
    """Return a frozen mapping of ``signer_id`` → raw JSON bytes for each
    ``signers/<signer_id>.json`` file present in the archive.

    Returns an empty ``MappingProxyType`` if no ``signers/`` directory exists.
    Spec §5: used during signature verification to locate signer manifests.
    It makes one pass over the archive with the header checks of
    :func:`unpack` other than the name checks, at the default policy (see
    :func:`_members`). When several regular files have the name, the last one
    counts.
    """
    members = _SignatureMembers(("signer",))
    _scan(Path(tar_path), ExtractPolicy.default(), check_names=False, on_member=members)
    return MappingProxyType(members.signers)
