"""Safe streaming tar extractor for DPKG archives.

Every known tar-extraction attack is rejected with a SecurityError and a
distinct PX_E_6NNN code (see :mod:`dpkg.error_codes`):
  * path traversal ('..' / absolute / Windows drive / backslash)
  * duplicate normalized paths
  * disallowed member types (symlink, hardlink, device, fifo)
  * zip-bomb (enforced streaming, per-file and per-total budgets)
  * too many files, overly long paths
"""

from __future__ import annotations

import re
import tarfile
import unicodedata
from dataclasses import dataclass
from pathlib import Path

from dpkg.error_codes import ErrorCode
from dpkg.errors import SecurityError


WINDOWS_DRIVE_RE = re.compile(r"^[A-Za-z]:")

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


def unpack(
    archive_path: Path | str,
    dest_dir: Path | str,
    policy: ExtractPolicy | None = None,
) -> Path:
    """Safely extract a canonical .dpkg.tar into dest_dir.

    Uses a streaming tarfile.next() loop - NEVER tar.extractall(), because
    extractall won't catch zip-bomb-class expansion until it's already disk-bound.
    """
    policy = policy or ExtractPolicy.default()
    archive = Path(archive_path)
    dest = Path(dest_dir)
    dest.mkdir(parents=True, exist_ok=True)
    dest_resolved = dest.resolve()

    file_count = 0
    total_bytes = 0
    seen_paths: set[str] = set()
    archive_size = archive.stat().st_size

    with tarfile.open(archive, mode="r") as tar:
        while True:
            member = tar.next()
            if member is None:
                break
            file_count += 1
            if file_count > policy.max_files:
                raise SecurityError(
                    code=ErrorCode.FILE_COUNT_EXCEEDED,
                    msg=f"archive exceeds {policy.max_files} files",
                )
            # Reject disallowed member types BEFORE path checks to catch hardlinks
            # whose link target points outside dest (member.isfile() would NOT catch these).
            if not (member.isreg() or member.isdir()):
                raise SecurityError(
                    code=ErrorCode.DISALLOWED_MEMBER_TYPE,
                    msg=(
                        f"disallowed member type for {member.name!r}: "
                        f"type={member.type!r} (symlink/hardlink/device/fifo forbidden)"
                    ),
                    path=member.name,
                )
            normalized = _check_path(member.name, policy)
            if normalized in seen_paths:
                raise SecurityError(
                    code=ErrorCode.DUPLICATE_MEMBER_PATH,
                    msg=f"duplicate member path: {normalized!r}",
                    path=normalized,
                )
            seen_paths.add(normalized)

            target = (dest / normalized).resolve()
            if dest_resolved not in target.parents and target != dest_resolved:
                raise SecurityError(
                    code=ErrorCode.PATH_TRAVERSAL,
                    msg=f"resolved path escapes dest: {normalized!r}",
                    path=normalized,
                )

            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
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
            target.parent.mkdir(parents=True, exist_ok=True)
            written = 0
            chunk_size = 64 * 1024
            # Authoritative budget enforcement happens inside the read loop.
            # On any SecurityError mid-stream, unlink the partial file so
            # callers do not see a truncated output.
            try:
                with open(target, "wb") as out:
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
            except BaseException:
                target.unlink(missing_ok=True)
                raise
            finally:
                src.close()
            total_bytes += written
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
    return dest
