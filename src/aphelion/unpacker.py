"""Safe streaming tar extractor for Aphelion archives.

Every known tar-extraction attack is rejected with a SecurityError and a
distinct PX_E_6NNN code (see :mod:`aphelion.error_codes`):
  * path traversal ('..' / absolute / Windows drive / backslash)
  * member names that collide once normalized the way any supported
    filesystem would see them (leading ``./``, repeated or ``.`` separators,
    Unicode NFC, case folding, Windows trailing dots/spaces)
  * disallowed member types (symlink, hardlink, device, fifo)
  * zip-bomb (enforced streaming, per-file and per-total budgets)
  * too many files, overly long paths
"""

from __future__ import annotations

import os
import re
import secrets
import shutil
import tarfile
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Mapping

from aphelion.error_codes import ErrorCode
from aphelion.errors import SecurityError


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


def path_parts(normalized: str) -> list[str]:
    """Split a checked member path into its real components.

    Empty and ``.`` segments name no directory level (``./a``, ``a//b`` and
    ``a/./b`` are ``a`` and ``a/b`` on every filesystem), so they are dropped.
    """
    return [part for part in normalized.split("/") if part not in ("", ".")]


def member_path_key(parts: list[str]) -> str:
    """Collision key for a member path, as a case-insensitive filesystem sees it.

    Two members with the same key land on the same file on at least one
    supported platform: NTFS and APFS compare names case-insensitively, APFS
    is also normalization-insensitive, and Win32 drops trailing dots and
    spaces from each component.
    """
    folded = []
    for part in parts:
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


def _scan_members(
    tar: tarfile.TarFile, policy: ExtractPolicy
) -> list[tuple[tarfile.TarInfo, str]]:
    """Check every member header before anything is read or written.

    Returns ``(member, relative_path)`` pairs, where ``relative_path`` drops
    ``./`` and empty segments. ``relative_path`` is ``""`` only for a
    directory entry naming the archive root itself (``.``).
    """
    scanned: list[tuple[tarfile.TarInfo, str]] = []
    names = MemberNames()

    while True:
        member = tar.next()
        if member is None:
            break
        if len(scanned) >= policy.max_files:
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
        scanned.append((member, rel))
    return scanned


def check_member_names(
    archive_path: Path | str, policy: ExtractPolicy | None = None
) -> None:
    """Run the header checks of :func:`unpack` without extracting anything.

    Anything that reads an archive by member name (signature validation,
    signer-manifest lookup) must call this first: once no two members collide,
    a name lookup and an extraction can no longer see different files.
    """
    with tarfile.open(Path(archive_path), mode="r") as tar:
        _scan_members(tar, policy or ExtractPolicy.default())


def unpack(
    archive_path: Path | str,
    dest_dir: Path | str,
    policy: ExtractPolicy | None = None,
) -> Path:
    """Safely extract a canonical .aphelion.tar into dest_dir.

    Uses a streaming tarfile.next() loop - NEVER tar.extractall(), because
    extractall won't catch zip-bomb-class expansion until it's already disk-bound.

    All-or-nothing: members are extracted into a staging directory (inside
    ``dest_dir`` if it exists, next to it otherwise) and moved into place only
    once every member has passed every check. A failed unpack leaves
    ``dest_dir`` as it was, including no staging directory, and removes any
    parent directories it had to create. On success, archive files replace
    same-named files in an existing ``dest_dir``; other files there are kept.
    """
    policy = policy or ExtractPolicy.default()
    archive = Path(archive_path)
    dest = Path(dest_dir)
    if dest.exists() and not dest.is_dir():
        raise FileExistsError(f"unpack destination is not a directory: {dest}")
    dest_resolved = dest.resolve()
    created = _first_missing_ancestor(dest_resolved)
    dest_resolved.parent.mkdir(parents=True, exist_ok=True)
    staging = _make_staging_dir(dest_resolved)
    try:
        _extract(archive, staging, dest_resolved, policy)
        _move_into_place(staging, dest_resolved)
    except BaseException:
        # rmtree does not follow symlinks; staging and `created` only hold
        # directories and files this call made.
        shutil.rmtree(staging, ignore_errors=True)
        if created is not None:
            shutil.rmtree(created, ignore_errors=True)
        raise
    return dest


def _first_missing_ancestor(path: Path) -> Path | None:
    """The outermost of ``path`` and its parents that does not exist yet."""
    missing = None
    for candidate in (path, *path.parents):
        if candidate.exists() or candidate.is_symlink():
            break
        missing = candidate
    return missing


def _make_staging_dir(dest: Path) -> Path:
    # On dest's filesystem, so every move into place is a rename. An existing
    # dest gets the staging dir inside it: dest may be a mount point, or sit
    # in a directory the caller cannot write to. A new dest gets a sibling,
    # which becomes dest by one rename; Path.mkdir (not tempfile.mkdtemp)
    # keeps the umask-derived mode that dest would have had.
    if dest.is_dir():
        parent, prefix = dest, ".unpacking-"
    else:
        parent, prefix = dest.parent, f".{dest.name}.unpacking-"
    while True:
        staging = parent / f"{prefix}{secrets.token_hex(8)}"
        try:
            staging.mkdir()
        except FileExistsError:  # pragma: no cover - 64-bit random collision
            continue
        return staging


def _move_into_place(staging: Path, dest: Path) -> None:
    """Move a fully extracted staging tree into ``dest``."""
    if not dest.exists():
        os.replace(staging, dest)
        return
    # Existing destination: merge. Check every target first so a conflict
    # cannot leave a half-moved tree behind.

    def is_staging(target: Path) -> bool:
        # Staging may sit inside dest. Compared by identity, not by name: on
        # Windows a case variant, a trailing dot or space, or the 8.3 short
        # name also reaches it, and so can a directory link already in dest.
        try:
            return os.path.lexists(target) and os.path.samefile(target, staging)
        except OSError:
            return False

    for root, dirnames, filenames in os.walk(staging):
        rel_root = Path(root).relative_to(staging)
        for name in (*dirnames, *filenames):
            target = dest / rel_root / name
            if is_staging(target):
                raise FileExistsError(
                    f"cannot unpack over the staging directory: {target}"
                )
        for name in dirnames:
            target = dest / rel_root / name
            if target.is_symlink() or (target.exists() and not target.is_dir()):
                raise FileExistsError(
                    f"cannot unpack directory over existing non-directory: {target}"
                )
        for name in filenames:
            target = dest / rel_root / name
            if target.is_dir() and not target.is_symlink():
                raise FileExistsError(
                    f"cannot unpack file over existing directory: {target}"
                )
    for root, dirnames, filenames in os.walk(staging):
        rel_root = Path(root).relative_to(staging)
        for name in dirnames:
            (dest / rel_root / name).mkdir(exist_ok=True)
        for name in filenames:
            os.replace(Path(root) / name, dest / rel_root / name)
    shutil.rmtree(staging)


def _extract(
    archive: Path, staging: Path, dest_resolved: Path, policy: ExtractPolicy
) -> None:
    total_bytes = 0
    archive_size = archive.stat().st_size

    with tarfile.open(archive, mode="r") as tar:
        # Every header is checked before the first byte is written, so a
        # colliding or forbidden member late in the archive cannot ride on
        # members that were already extracted.
        for member, normalized in _scan_members(tar, policy):
            # Checked against the real destination: a symlink already inside
            # dest must not carry a member outside it once moved into place.
            final = (dest_resolved / normalized).resolve()
            if dest_resolved not in final.parents and final != dest_resolved:
                raise SecurityError(
                    code=ErrorCode.PATH_TRAVERSAL,
                    msg=f"resolved path escapes dest: {normalized!r}",
                    path=normalized,
                )
            target = staging / normalized
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
            # A failure here discards the whole staging tree (see unpack).
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


def extract_signatures_jsonl(tar_path: Path | str) -> bytes | None:
    """Return raw bytes of ``signatures.jsonl`` at archive root, or ``None`` if absent.

    Spec §5: presence of signatures.jsonl opts the package into v0.5 verification.
    This is a read-only accessor that does NOT run security checks — it is only
    used after a package has already been trust-verified at the tar level.
    """
    archive = Path(tar_path)
    with tarfile.open(archive, mode="r") as tar:
        try:
            member = tar.getmember("signatures.jsonl")
        except KeyError:
            return None
        src = tar.extractfile(member)
        if src is None:
            return None
        try:
            return src.read()
        finally:
            src.close()


def extract_signer_manifests(tar_path: Path | str) -> Mapping[str, bytes]:
    """Return a frozen mapping of ``signer_id`` → raw JSON bytes for each
    ``signers/<signer_id>.json`` file present in the archive.

    Returns an empty ``MappingProxyType`` if no ``signers/`` directory exists.
    Spec §5: used during signature verification to locate signer manifests.
    """
    archive = Path(tar_path)
    result: dict[str, bytes] = {}
    with tarfile.open(archive, mode="r") as tar:
        for member in tar.getmembers():
            name = member.name
            if name.startswith("signers/") and name.endswith(".json") and member.isreg():
                # signer_id is the stem: signers/<signer_id>.json
                signer_id = name[len("signers/"):-len(".json")]
                if not signer_id:
                    continue
                src = tar.extractfile(member)
                if src is None:
                    continue
                try:
                    result[signer_id] = src.read()
                finally:
                    src.close()
    return MappingProxyType(result)
