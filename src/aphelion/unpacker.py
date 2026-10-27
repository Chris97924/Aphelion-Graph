"""Safe streaming tar extractor for Aphelion archives.

Every known tar-extraction attack is rejected with a SecurityError and a
distinct PX_E_6NNN code (see :mod:`aphelion.error_codes`):
  * path traversal ('..' / absolute / Windows drive / backslash)
  * member names that collide once normalized the way any supported
    filesystem would see them (leading ``./``, repeated or ``.`` separators,
    Unicode NFC, case folding, and on Windows trailing dots/spaces), or that
    reach one entry on disk under different names (8.3 short names)
  * disallowed member types (symlink, hardlink, device, fifo)
  * zip-bomb (enforced streaming, per-file and per-total budgets)
  * too many files, overly long paths
"""

from __future__ import annotations

import errno
import os
import re
import secrets
import shutil
import stat
import sys
import tarfile
import unicodedata
import warnings
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import BinaryIO, Callable, Mapping

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
    the writes, a window that path-based checks cannot close. Resolving
    ``dest_dir`` and each member's path (``Path.resolve``) keeps its
    standard-library behaviour, which can take a component it cannot look
    at for one that is not a link; the merge's strict check of every entry
    in ``dest_dir`` is what refuses a link there. On a filesystem other
    than Windows', a new ``dest_dir`` renamed into place can replace an
    empty directory that appeared there meanwhile.
    On success, archive files replace same-named files in an existing
    ``dest_dir``; other files there are kept.
    """
    policy = policy or ExtractPolicy.default()
    archive = Path(archive_path)
    dest = Path(dest_dir)
    st = _lstat(dest)
    if st is not None and _is_link(st):
        # resolve() would follow it, also when dangling, and unpack elsewhere.
        raise FileExistsError(f"unpack destination is a symlink or junction: {dest}")
    if st is not None and not stat.S_ISDIR(st.st_mode):
        raise FileExistsError(f"unpack destination is not a directory: {dest}")
    dest_resolved = dest.resolve()
    made: list[Path] = []  # parents this call created, each on record before its mkdir
    staging = backup = replacement = None
    renaming = False
    try:
        _make_parents(dest_resolved.parent, made)
        staging = _make_staging_dir(dest_resolved)
        if staging.parent == dest_resolved:
            backup = _make_unique_dir(staging, ".backup-")
        _extract(archive, staging, dest_resolved, policy, backup)
        if backup is None and _lstat(dest_resolved) is not None:  # dest appeared beside staging
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
        if _absent(err):
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
    ignored or turned into errors.
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
    try:
        warnings.showwarning(RuntimeWarning(note), RuntimeWarning, filename, lineno)
    except Exception:  # a replaced showwarning that fails: stderr is what is left
        if sys.stderr is not None:
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
    if _lstat(dest) is not None:
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
    has several entries: the name the filesystem stores (``realpath`` spells
    an 8.3 short name or a case variant out) tells them apart, so two hard
    links are two entries, each replaced on its own.
    """
    if is_dir or st.st_nlink <= 1:
        return None
    return os.path.normcase(os.path.realpath(target, strict=True))


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
) -> None:
    total_bytes = 0
    archive_size = archive.stat().st_size
    made: set[str] = set()  # directories this call created in staging

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
            finally:
                src.close()
                if out is not None:
                    out.close()
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
