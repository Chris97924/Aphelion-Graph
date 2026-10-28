"""Unit tests for aphelion.canonical_tar."""

from __future__ import annotations

import hashlib

import pytest

from aphelion.canonical_tar import MODE_DIR, MODE_FILE, TarMember, pack, read_members
from aphelion.error_codes import ErrorCode
from aphelion.errors import SchemaError


def test_deterministic_same_input_same_bytes() -> None:
    members = [
        TarMember(path="b.txt", data=b"B\n", is_dir=False),
        TarMember(path="a.txt", data=b"A\n", is_dir=False),
    ]
    b1 = pack(members)
    b2 = pack(list(reversed(members)))
    assert b1 == b2
    assert hashlib.sha256(b1).hexdigest() == hashlib.sha256(b2).hexdigest()


def test_members_sorted_by_path() -> None:
    out = pack(
        [
            TarMember(path="z.txt", data=b"z", is_dir=False),
            TarMember(path="a.txt", data=b"a", is_dir=False),
        ]
    )
    back = read_members(out)
    assert [m.path for m in back] == ["a.txt", "z.txt"]


def test_mode_enforced() -> None:
    import io
    import tarfile

    out = pack(
        [
            TarMember(path="dir", data=None, is_dir=True),
            TarMember(path="f.txt", data=b"x", is_dir=False),
        ]
    )
    with tarfile.open(fileobj=io.BytesIO(out), mode="r") as tar:
        infos = {info.name: info for info in tar}
    assert infos["dir"].mode == MODE_DIR
    assert infos["f.txt"].mode == MODE_FILE


def test_zero_metadata() -> None:
    import io
    import tarfile

    out = pack([TarMember(path="x", data=b"y", is_dir=False)])
    with tarfile.open(fileobj=io.BytesIO(out), mode="r") as tar:
        info = tar.next()
    assert info.mtime == 0
    assert info.uid == 0 and info.gid == 0
    assert info.uname == "" and info.gname == ""


def test_duplicate_path_rejected() -> None:
    with pytest.raises(SchemaError) as exc:
        pack(
            [
                TarMember(path="x", data=b"a", is_dir=False),
                TarMember(path="x", data=b"b", is_dir=False),
            ]
        )
    assert exc.value.code == "PX_E_6007"


def test_dir_with_data_rejected() -> None:
    with pytest.raises(SchemaError):
        pack([TarMember(path="d", data=b"x", is_dir=True)])


def test_regular_without_data_rejected() -> None:
    with pytest.raises(SchemaError):
        pack([TarMember(path="f", data=None, is_dir=False)])


def test_roundtrip_preserves_bytes() -> None:
    members = [
        TarMember(path="a.txt", data=b"alpha", is_dir=False),
        TarMember(path="b.txt", data=b"bravo", is_dir=False),
    ]
    b1 = pack(members)
    back = read_members(b1)
    b2 = pack(back)
    assert b1 == b2


# ---------- member paths may not escape the archive root ----------


@pytest.mark.parametrize(
    "path, code",
    [
        ("../x.json", ErrorCode.PATH_TRAVERSAL),
        ("signers/../x.json", ErrorCode.PATH_TRAVERSAL),
        ("signers/../../x.json", ErrorCode.PATH_TRAVERSAL),
        ("..", ErrorCode.PATH_TRAVERSAL),
        ("/etc/x.json", ErrorCode.ABSOLUTE_PATH),
        ("C:/x.json", ErrorCode.WINDOWS_DRIVE),
        ("c:x.json", ErrorCode.WINDOWS_DRIVE),
        ("signers\\..\\x.json", ErrorCode.WINDOWS_BACKSLASH),
        ("", ErrorCode.EMPTY_MEMBER_NAME),
    ],
)
def test_pack_rejects_member_paths_that_escape(path: str, code: ErrorCode) -> None:
    """All platforms: pack refuses a member path that names something outside
    the archive root, with the code unpack would use."""
    with pytest.raises(SchemaError) as exc:
        pack([TarMember(path=path, data=b"x", is_dir=False)])
    assert exc.value.code == code


def test_pack_rejects_directory_member_that_escapes() -> None:
    """All platforms: the same holds for a directory member."""
    with pytest.raises(SchemaError) as exc:
        pack([TarMember(path="a/../..", data=None, is_dir=True)])
    assert exc.value.code == ErrorCode.PATH_TRAVERSAL


@pytest.mark.parametrize(
    "first, second",
    [("signers/A.json", "signers/a.json"), ("x.json", "./x.json"), ("a/b", "a//b")],
)
def test_pack_rejects_paths_that_unpack_would_reject_as_colliding(
    first: str, second: str
) -> None:
    """All platforms: pack refuses two paths that collide once normalized,
    as unpack does."""
    with pytest.raises(SchemaError) as exc:
        pack([
            TarMember(path=first, data=b"1", is_dir=False),
            TarMember(path=second, data=b"2", is_dir=False),
        ])
    assert exc.value.code == ErrorCode.DUPLICATE_MEMBER_PATH
