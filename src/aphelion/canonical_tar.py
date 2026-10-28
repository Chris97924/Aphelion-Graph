"""Canonical uncompressed tar writer for Aphelion.

POSIX ustar format, with every source of non-determinism nailed down:
  * mtime=0, uid=0, gid=0, uname='', gname=''
  * regular files -> mode 0o644, directories -> mode 0o755
  * members sorted by NFC-normalized POSIX path (codepoint ascending)
  * only regular files and directories allowed; symlink/hardlink/device/fifo rejected
  * uncompressed .tar (.tar.gz left for v0.2.1 with fixed-params compressor)
"""

from __future__ import annotations

import io
import tarfile
import unicodedata
from dataclasses import dataclass

from aphelion.error_codes import ErrorCode
from aphelion.errors import SchemaError
from aphelion.unpacker import WINDOWS_DRIVE_RE, MemberNames, non_portable_component, path_parts


MODE_FILE = 0o644
MODE_DIR = 0o755


@dataclass(frozen=True)
class TarMember:
    """A single canonical tar member.

    path: POSIX path, will be NFC-normalized on write.
    data: file bytes (must be None for directories).
    is_dir: True for directories, False for regular files.
    """

    path: str
    data: bytes | None = None
    is_dir: bool = False

    def normalized_path(self) -> str:
        return unicodedata.normalize("NFC", self.path)


def _check_member_path(path: str) -> str:
    """Reject a member path that names something outside the archive root."""
    if not path:
        raise SchemaError(code=ErrorCode.EMPTY_MEMBER_NAME, msg="empty archive member path")
    if "\\" in path:
        raise SchemaError(
            code=ErrorCode.WINDOWS_BACKSLASH,
            msg=f"backslash in archive member path: {path!r}",
        )
    if path.startswith("/"):
        raise SchemaError(
            code=ErrorCode.ABSOLUTE_PATH,
            msg=f"absolute archive member path: {path!r}",
        )
    if WINDOWS_DRIVE_RE.match(path):
        raise SchemaError(
            code=ErrorCode.WINDOWS_DRIVE,
            msg=f"Windows drive prefix in archive member path: {path!r}",
        )
    if ".." in path.split("/"):
        raise SchemaError(
            code=ErrorCode.PATH_TRAVERSAL,
            msg=f"'..' segment in archive member path: {path!r}",
        )
    return path


def pack(members: list[TarMember]) -> bytes:
    """Pack members into a canonical uncompressed .tar byte string.

    Raises SchemaError on any member type violation or inconsistency, on a
    path the unpacker would refuse (absolute, drive-prefixed, backslash,
    ``..``, and on Windows a name Win32 cannot create; see
    :func:`aphelion.unpacker.non_portable_component`), and on two paths that
    collide once normalized (see :class:`aphelion.unpacker.MemberNames`).
    pack does not see filesystem aliases such as Windows 8.3 short names;
    unpack refuses an archive whose members reach one entry on the target
    filesystem.
    """
    names = MemberNames()
    for member in members:
        norm = member.normalized_path()
        parts = path_parts(_check_member_path(norm))
        if not parts and not member.is_dir:
            raise SchemaError(
                code=ErrorCode.EMPTY_MEMBER_NAME,
                msg=f"regular-file member has no name: {norm!r}",
            )
        other = names.add(parts, is_dir=member.is_dir)
        if other is not None:
            raise SchemaError(
                code=ErrorCode.DUPLICATE_MEMBER_PATH,
                msg=f"archive member path {norm!r} collides with {other!r} after normalization",
            )
        bad = non_portable_component(parts)
        if bad is not None:
            raise SchemaError(
                code=ErrorCode.PATH_TRAVERSAL,
                msg=f"archive member path component {bad!r} is not a portable file name: {norm!r}",
            )
        if member.is_dir and member.data is not None:
            raise SchemaError(
                code=ErrorCode.DISALLOWED_MEMBER_TYPE,
                msg=f"directory member must not carry data: {norm!r}",
            )
        if not member.is_dir and member.data is None:
            raise SchemaError(
                code=ErrorCode.DISALLOWED_MEMBER_TYPE,
                msg=f"regular-file member must carry data (got None): {norm!r}",
            )

    sorted_members = sorted(members, key=lambda m: m.normalized_path())

    buf = io.BytesIO()
    # format=USTAR_FORMAT gives us fixed POSIX ustar headers
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        for member in sorted_members:
            info = tarfile.TarInfo(name=member.normalized_path())
            info.mtime = 0
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            info.devmajor = 0
            info.devminor = 0
            if member.is_dir:
                info.type = tarfile.DIRTYPE
                info.mode = MODE_DIR
                info.size = 0
                tar.addfile(info)
            else:
                # Pre-loop validation above guarantees member.data is not None here.
                data = member.data
                assert data is not None
                info.type = tarfile.REGTYPE
                info.mode = MODE_FILE
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))

    return buf.getvalue()


def read_members(raw: bytes) -> list[TarMember]:
    """Read a tar byte string back into TarMembers (used by unpacker / round-trip)."""
    out: list[TarMember] = []
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r") as tar:
        for info in tar:
            if info.issym() or info.islnk() or info.ischr() or info.isblk() or info.isfifo():
                raise SchemaError(
                    code=ErrorCode.DISALLOWED_MEMBER_TYPE,
                    msg=f"disallowed member type for {info.name!r}: {info.type!r}",
                )
            if info.isdir():
                out.append(TarMember(path=info.name, data=None, is_dir=True))
            elif info.isreg():
                extracted = tar.extractfile(info)
                blob = extracted.read() if extracted else b""
                out.append(TarMember(path=info.name, data=blob, is_dir=False))
            else:
                raise SchemaError(
                    code=ErrorCode.DISALLOWED_MEMBER_TYPE,
                    msg=f"unknown member type for {info.name!r}",
                )
    return out
