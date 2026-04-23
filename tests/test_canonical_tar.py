"""Unit tests for dpkg.canonical_tar."""

from __future__ import annotations

import hashlib

import pytest

from dpkg.canonical_tar import MODE_DIR, MODE_FILE, TarMember, pack, read_members
from dpkg.errors import SchemaError


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
