"""Canonical uncompressed tar writer for DPKG.

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

from dpkg.error_codes import ErrorCode
from dpkg.errors import SchemaError


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


def pack(members: list[TarMember]) -> bytes:
    """Pack members into a canonical uncompressed .tar byte string.

    Raises SchemaError on any member type violation or inconsistency.
    """
    seen: set[str] = set()
    for member in members:
        norm = member.normalized_path()
        if norm in seen:
            raise SchemaError(
                code=ErrorCode.DUPLICATE_MEMBER_PATH,
                msg=f"duplicate archive member path after NFC: {norm!r}",
            )
        seen.add(norm)
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
