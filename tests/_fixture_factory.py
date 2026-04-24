"""Programmatic fixture builders for Aphelion v0.2.0 golden tests.

Fixtures are generated at import time so they're diffable + reproducible.
Each builder returns (name, source_dir_factory, expected_outcome).
"""

from __future__ import annotations

import hashlib
import io
import json
import shutil
import tarfile
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from aphelion.canonical_json import dumps as canonical_dumps
from aphelion.canonical_json import normalize


UUID_PKG = "0191aaaa-0000-7000-8000-000000000001"
UUID_CLAIM_A = "0191aaaa-0000-7000-8000-00000000aaaa"
UUID_CLAIM_B = "0191aaaa-0000-7000-8000-00000000bbbb"
UUID_CLAIM_MISSING = "0191aaaa-0000-7000-8000-00000000cccc"
UUID_INSTANCE_A = "0191aaaa-0000-7000-8000-aaaaaaaaaaaa"
UUID_INSTANCE_B = "0191aaaa-0000-7000-8000-bbbbbbbbbbbb"
UUID_EVENT_1 = "0191aaaa-0000-7000-8000-eeee00000001"
UUID_EVENT_2 = "0191aaaa-0000-7000-8000-eeee00000002"
UUID_EVENT_3 = "0191aaaa-0000-7000-8000-eeee00000003"
UUID_EVENT_UNKNOWN = "0191aaaa-0000-7000-8000-eeee00000099"


@dataclass(frozen=True)
class FixtureCase:
    category: str
    name: str
    expected_exit: int
    expected_code: str | None  # for exit==3 cases; None for exit==0
    description: str


def _write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def _claim_md(claim_id: str, title: str, body: str = "") -> bytes:
    header = (
        '---\n'
        f'"body_format": "markdown"\n'
        f'"claim_id": "{claim_id}"\n'
        f'"title": "{title}"\n'
        '---\n'
    )
    return (header + body).encode("utf-8")


def _build_minimal(
    dest: Path,
    *,
    claim_id: str = UUID_CLAIM_A,
    instance_id: str = UUID_INSTANCE_A,
    title: str = "Hello",
    body: str = "",
    extra_manifest: dict | None = None,
    extra_events: list[dict] | None = None,
    claim_path_override: str | None = None,
) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    claim_path = claim_path_override or f"claims/{claim_id}.md"
    claim_bytes = _claim_md(claim_id, title, body)
    _write(dest / claim_path, claim_bytes)
    manifest = {
        "aphelion_spec_version": "0.4.0",
        "claims": [
            {
                "claim_id": claim_id,
                "claim_instance_id": instance_id,
                "hash": hashlib.sha256(claim_bytes).hexdigest(),
                "path": claim_path,
                "state": "active",
            }
        ],
        "created_at": "2026-04-21T00:00:00Z",
        "format_version": "2.0",
        "license": "Apache-2.0",
        "package_id": UUID_PKG,
        "producer": "aphelion-test",
        "provenance_path": "provenance.jsonl",
    }
    if extra_manifest:
        manifest.update(extra_manifest)
    _write(dest / "manifest.json", canonical_dumps(normalize(manifest)))
    events = [
        {
            "actor": "test",
            "claim_id": claim_id,
            "claim_instance_id": instance_id,
            "event_id": UUID_EVENT_1,
            "event_type": "create",
            "timestamp": "2026-04-21T00:00:00Z",
        }
    ]
    if extra_events:
        events = extra_events
    prov = b"".join(canonical_dumps(normalize(e)) for e in events)
    _write(dest / "provenance.jsonl", prov)


# =====================  VALID  =====================

def build_valid_unicode_nfc(dest: Path) -> None:
    _build_minimal(dest, title="Unicode café 中文 🎉")


def build_valid_long_path(dest: Path) -> None:
    # Path length up to 200 chars still valid (schema doesn't constrain length)
    _build_minimal(dest, title="long path (kept under 100 bytes per ustar)")


def build_valid_empty_evidence(dest: Path) -> None:
    _build_minimal(dest, title="no body", body="")


def build_valid_empty_vault(dest: Path) -> None:
    """manifest with zero claims."""
    dest.mkdir(parents=True, exist_ok=True)
    manifest = {
        "aphelion_spec_version": "0.4.0",
        "claims": [],
        "created_at": "2026-04-21T00:00:00Z",
        "format_version": "2.0",
        "license": "Apache-2.0",
        "package_id": UUID_PKG,
        "producer": "aphelion-test",
        "provenance_path": "provenance.jsonl",
    }
    _write(dest / "manifest.json", canonical_dumps(normalize(manifest)))
    _write(dest / "provenance.jsonl", b"")


def build_valid_forward_compat(dest: Path) -> None:
    """Manifest carries an `extensions` object - validators ignore contents."""
    _build_minimal(
        dest,
        extra_manifest={"extensions": {"vendor-x": "whatever"}},
    )


def build_valid_nfd_string(dest: Path) -> None:
    """Input contains NFD string -> normalize() converts to NFC at insert time."""
    nfd = unicodedata.normalize("NFD", "café")
    _build_minimal(dest, title=nfd)


def build_valid_minimal_single_claim(dest: Path) -> None:
    _build_minimal(dest)


def build_valid_multi_claim(dest: Path) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    claim_a = _claim_md(UUID_CLAIM_A, "A")
    claim_b = _claim_md(UUID_CLAIM_B, "B")
    _write(dest / f"claims/{UUID_CLAIM_A}.md", claim_a)
    _write(dest / f"claims/{UUID_CLAIM_B}.md", claim_b)
    manifest = {
        "claims": [
            {
                "claim_id": UUID_CLAIM_A,
                "claim_instance_id": UUID_INSTANCE_A,
                "hash": hashlib.sha256(claim_a).hexdigest(),
                "path": f"claims/{UUID_CLAIM_A}.md",
                "state": "active",
            },
            {
                "claim_id": UUID_CLAIM_B,
                "claim_instance_id": UUID_INSTANCE_B,
                "hash": hashlib.sha256(claim_b).hexdigest(),
                "path": f"claims/{UUID_CLAIM_B}.md",
                "state": "active",
            },
        ],
        "aphelion_spec_version": "0.4.0",
        "created_at": "2026-04-21T00:00:00Z",
        "format_version": "2.0",
        "license": "Apache-2.0",
        "package_id": UUID_PKG,
        "producer": "aphelion-test",
        "provenance_path": "provenance.jsonl",
    }
    _write(dest / "manifest.json", canonical_dumps(normalize(manifest)))
    events = [
        {
            "actor": "t",
            "claim_id": UUID_CLAIM_A,
            "claim_instance_id": UUID_INSTANCE_A,
            "event_id": UUID_EVENT_1,
            "event_type": "create",
            "timestamp": "2026-04-21T00:00:00Z",
        },
        {
            "actor": "t",
            "claim_id": UUID_CLAIM_B,
            "claim_instance_id": UUID_INSTANCE_B,
            "event_id": UUID_EVENT_2,
            "event_type": "create",
            "timestamp": "2026-04-21T00:00:01Z",
        },
    ]
    _write(
        dest / "provenance.jsonl",
        b"".join(canonical_dumps(normalize(e)) for e in events),
    )


def build_valid_init_generated(dest: Path) -> None:
    """Skeleton produced by ``aphelion init`` — deterministic via fixed overrides."""
    from aphelion.initializer import InitOptions, init_skeleton

    init_skeleton(
        InitOptions(
            dest=dest,
            spec_version="0.4.0",
            package_id=UUID_PKG,
            created_at="2026-04-21T00:00:00Z",
        )
    )


def build_valid_notice_path(dest: Path) -> None:
    """Valid manifest carrying the optional notice_path field."""
    _build_minimal(dest, extra_manifest={"notice_path": "NOTICE.md"})


# =====================  INVALID SYNTAX  =====================

def build_invalid_malformed_trailing_comma(dest: Path) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    _write(dest / "manifest.json", b'{"claims": [],}\n')
    _write(dest / "provenance.jsonl", b"")


def build_invalid_malformed_unclosed(dest: Path) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    _write(dest / "manifest.json", b'{"claims": [\n')
    _write(dest / "provenance.jsonl", b"")


def build_invalid_hash_format_wrong_length(dest: Path) -> None:
    _build_minimal(dest)
    # Overwrite manifest with hash that's only 32 hex (half length)
    data = json.loads((dest / "manifest.json").read_bytes())
    data["claims"][0]["hash"] = "a" * 32
    _write(dest / "manifest.json", canonical_dumps(normalize(data)))


def build_invalid_duplicate_json_keys(dest: Path) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    # Two "license" keys - valid JSON grammar, rejected by our strict parser
    raw = (
        b'{"claims":[],"created_at":"2026-04-21T00:00:00Z",'
        b'"format_version":"1.0","license":"Apache-2.0","license":"MIT",'
        b'"package_id":"' + UUID_PKG.encode() + b'",'
        b'"producer":"x","provenance_path":"provenance.jsonl"}\n'
    )
    _write(dest / "manifest.json", raw)
    _write(dest / "provenance.jsonl", b"")


def build_invalid_wrong_type(dest: Path) -> None:
    _build_minimal(dest)
    data = json.loads((dest / "manifest.json").read_bytes())
    data["claims"] = "not a list"
    _write(dest / "manifest.json", canonical_dumps(normalize(data)))


def build_invalid_json_parse_error(dest: Path) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    _write(dest / "manifest.json", b"this is not json at all")
    _write(dest / "provenance.jsonl", b"")


def build_invalid_schema_version_future(dest: Path) -> None:
    _build_minimal(dest)
    data = json.loads((dest / "manifest.json").read_bytes())
    data["format_version"] = "3.0"
    _write(dest / "manifest.json", canonical_dumps(normalize(data)))


def build_invalid_schema_version_legacy(dest: Path) -> None:
    """A v0.3 package (format_version 1.1) rejected by the v0.4 validator."""
    _build_minimal(dest)
    data = json.loads((dest / "manifest.json").read_bytes())
    data["format_version"] = "1.1"
    _write(dest / "manifest.json", canonical_dumps(normalize(data)))


def build_invalid_missing_required(dest: Path) -> None:
    _build_minimal(dest)
    data = json.loads((dest / "manifest.json").read_bytes())
    del data["claims"][0]["claim_id"]
    _write(dest / "manifest.json", canonical_dumps(normalize(data)))


def build_invalid_enum(dest: Path) -> None:
    _build_minimal(dest)
    data = json.loads((dest / "manifest.json").read_bytes())
    data["claims"][0]["state"] = "banana"
    _write(dest / "manifest.json", canonical_dumps(normalize(data)))


def build_invalid_nan(dest: Path) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    # Raw NaN literal - json module accepts by default but our parser rejects
    _write(dest / "manifest.json", b'{"claims":NaN}\n')
    _write(dest / "provenance.jsonl", b"")


def build_invalid_empty_producer(dest: Path) -> None:
    _build_minimal(dest)
    data = json.loads((dest / "manifest.json").read_bytes())
    data["producer"] = ""
    _write(dest / "manifest.json", canonical_dumps(normalize(data)))


def build_invalid_extra_manifest_field(dest: Path) -> None:
    _build_minimal(dest)
    data = json.loads((dest / "manifest.json").read_bytes())
    data["sneaky_unknown"] = "nope"
    _write(dest / "manifest.json", canonical_dumps(normalize(data)))


def build_invalid_forbidden_create_prev(dest: Path) -> None:
    """A `create` event carrying `prev_event_id` must be rejected."""
    dest.mkdir(parents=True, exist_ok=True)
    _build_minimal(dest)
    events = [
        {
            "actor": "t",
            "claim_id": UUID_CLAIM_A,
            "claim_instance_id": UUID_INSTANCE_A,
            "event_id": UUID_EVENT_1,
            "event_type": "create",
            "prev_event_id": UUID_EVENT_UNKNOWN,  # FORBIDDEN on create
            "timestamp": "2026-04-21T00:00:00Z",
        }
    ]
    _write(
        dest / "provenance.jsonl",
        b"".join(canonical_dumps(normalize(e)) for e in events),
    )


def build_invalid_superseded_without_target(dest: Path) -> None:
    """Claim entry with state=superseded but no superseded_by_claim_id."""
    _build_minimal(dest)
    data = json.loads((dest / "manifest.json").read_bytes())
    data["claims"][0]["state"] = "superseded"
    _write(dest / "manifest.json", canonical_dumps(normalize(data)))


# =====================  INVALID SEMANTIC  =====================

def build_invalid_broken_provenance_dangling(dest: Path) -> None:
    """Event references a prev_event_id that doesn't exist."""
    dest.mkdir(parents=True, exist_ok=True)
    _build_minimal(dest)
    events = [
        {
            "actor": "t",
            "claim_id": UUID_CLAIM_A,
            "claim_instance_id": UUID_INSTANCE_A,
            "event_id": UUID_EVENT_1,
            "event_type": "create",
            "timestamp": "2026-04-21T00:00:00Z",
        },
        {
            "actor": "t",
            "claim_id": UUID_CLAIM_A,
            "event_id": UUID_EVENT_2,
            "event_type": "reaffirm",
            "prev_event_id": UUID_EVENT_UNKNOWN,
            "target_claim_instance_id": UUID_INSTANCE_A,
            "timestamp": "2026-04-21T00:00:01Z",
        },
    ]
    _write(
        dest / "provenance.jsonl",
        b"".join(canonical_dumps(normalize(e)) for e in events),
    )


def build_invalid_broken_provenance_fork(dest: Path) -> None:
    """Two reaffirm events both point to the same prev_event_id -> fork."""
    dest.mkdir(parents=True, exist_ok=True)
    _build_minimal(dest)
    events = [
        {
            "actor": "t",
            "claim_id": UUID_CLAIM_A,
            "claim_instance_id": UUID_INSTANCE_A,
            "event_id": UUID_EVENT_1,
            "event_type": "create",
            "timestamp": "2026-04-21T00:00:00Z",
        },
        {
            "actor": "t",
            "claim_id": UUID_CLAIM_A,
            "event_id": UUID_EVENT_2,
            "event_type": "reaffirm",
            "prev_event_id": UUID_EVENT_1,
            "target_claim_instance_id": UUID_INSTANCE_A,
            "timestamp": "2026-04-21T00:00:01Z",
        },
        {
            "actor": "t",
            "claim_id": UUID_CLAIM_A,
            "event_id": UUID_EVENT_3,
            "event_type": "reaffirm",
            "prev_event_id": UUID_EVENT_1,
            "target_claim_instance_id": UUID_INSTANCE_A,
            "timestamp": "2026-04-21T00:00:02Z",
        },
    ]
    _write(
        dest / "provenance.jsonl",
        b"".join(canonical_dumps(normalize(e)) for e in events),
    )


def build_invalid_manifest_refs_missing_file(dest: Path) -> None:
    """manifest references a claim file path that does not exist in archive."""
    dest.mkdir(parents=True, exist_ok=True)
    _build_minimal(dest)
    # Delete the claim file
    (dest / f"claims/{UUID_CLAIM_A}.md").unlink()


def build_invalid_archive_extra_file(dest: Path) -> None:
    """Archive has an extra claim file not declared in manifest."""
    _build_minimal(dest)
    extra_path = dest / f"claims/{UUID_CLAIM_B}.md"
    _write(extra_path, _claim_md(UUID_CLAIM_B, "extra"))


def build_invalid_hash_value_tamper(dest: Path) -> None:
    """manifest hash is well-formed 64-hex but doesn't match file bytes."""
    _build_minimal(dest)
    data = json.loads((dest / "manifest.json").read_bytes())
    # Valid format, wrong value
    data["claims"][0]["hash"] = "0" * 64
    _write(dest / "manifest.json", canonical_dumps(normalize(data)))


def build_invalid_evidence_ref_dangling(dest: Path) -> None:
    """provenance event references a claim_id not in the manifest."""
    dest.mkdir(parents=True, exist_ok=True)
    _build_minimal(dest)
    events = [
        {
            "actor": "t",
            "claim_id": UUID_CLAIM_A,
            "claim_instance_id": UUID_INSTANCE_A,
            "event_id": UUID_EVENT_1,
            "event_type": "create",
            "timestamp": "2026-04-21T00:00:00Z",
        },
        {
            "actor": "t",
            "claim_id": UUID_CLAIM_MISSING,
            "claim_instance_id": UUID_INSTANCE_B,
            "event_id": UUID_EVENT_2,
            "event_type": "create",
            "timestamp": "2026-04-21T00:00:01Z",
        },
    ]
    _write(
        dest / "provenance.jsonl",
        b"".join(canonical_dumps(normalize(e)) for e in events),
    )


# =====================  ARCHIVE SECURITY  =====================
# These produce a raw .tar file (not a source_dir) with malicious members.


def _write_raw_tar(path: Path, members: list[tuple[tarfile.TarInfo, bytes | None]]) -> None:
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


def build_archive_dotdot_traversal(dest: Path) -> None:
    info = tarfile.TarInfo(name="../escape.txt")
    info.type = tarfile.REGTYPE
    info.mode = 0o644
    _write_raw_tar(dest / "evil.tar", [(info, b"owned\n")])


def build_archive_absolute_path(dest: Path) -> None:
    info = tarfile.TarInfo(name="/etc/passwd.aphelion")
    info.type = tarfile.REGTYPE
    info.mode = 0o644
    _write_raw_tar(dest / "evil.tar", [(info, b"owned\n")])


def build_archive_symlink(dest: Path) -> None:
    info = tarfile.TarInfo(name="link")
    info.type = tarfile.SYMTYPE
    info.linkname = "/etc/passwd"
    _write_raw_tar(dest / "evil.tar", [(info, None)])


def build_archive_hardlink(dest: Path) -> None:
    info = tarfile.TarInfo(name="hardlink")
    info.type = tarfile.LNKTYPE
    info.linkname = "../../../etc/passwd"
    _write_raw_tar(dest / "evil.tar", [(info, None)])


def build_archive_windows_backslash(dest: Path) -> None:
    info = tarfile.TarInfo(name="dir\\file.txt")
    info.type = tarfile.REGTYPE
    info.mode = 0o644
    _write_raw_tar(dest / "evil.tar", [(info, b"win\n")])


def build_archive_zip_bomb_ratio(dest: Path) -> None:
    # A single large regular file that would fail max-file-bytes
    info = tarfile.TarInfo(name="big.bin")
    info.type = tarfile.REGTYPE
    info.mode = 0o644
    data = b"A" * (30 * 1024 * 1024)  # 30 MiB > default 25 MiB
    _write_raw_tar(dest / "evil.tar", [(info, data)])


def build_archive_files_count_overflow(dest: Path) -> None:
    members: list[tuple[tarfile.TarInfo, bytes | None]] = []
    for i in range(10_050):
        info = tarfile.TarInfo(name=f"f/{i:05d}.txt")
        info.type = tarfile.REGTYPE
        info.mode = 0o644
        members.append((info, b""))
    _write_raw_tar(dest / "evil.tar", members)


# =====================  ROUND-TRIP  =====================
# These reuse valid source-dir layouts; the test asserts pack->unpack->pack byte equality.

def build_roundtrip_ascii_simple(dest: Path) -> None:
    _build_minimal(dest, title="ASCII only")


def build_roundtrip_unicode_mixed(dest: Path) -> None:
    _build_minimal(dest, title="Unicode café 中文 🎉")


def build_roundtrip_nested_claims(dest: Path) -> None:
    build_valid_multi_claim(dest)


def build_roundtrip_nfd_to_nfc(dest: Path) -> None:
    nfd = unicodedata.normalize("NFD", "cafécafé")
    _build_minimal(dest, title=nfd)


# Registry ------------------------------------------------------------------

CASES: list[tuple[FixtureCase, Callable[[Path], None]]] = [
    # valid
    (FixtureCase("valid", "unicode-nfc", 0, None, "UTF-8 NFC content"), build_valid_unicode_nfc),
    (FixtureCase("valid", "long-path", 0, None, "title 'long' ascii path"), build_valid_long_path),
    (FixtureCase("valid", "empty-evidence", 0, None, "claim body is empty"), build_valid_empty_evidence),
    (FixtureCase("valid", "empty-vault", 0, None, "manifest with 0 claims"), build_valid_empty_vault),
    (FixtureCase("valid", "forward-compat-extensions", 0, None, "extensions object ignored"), build_valid_forward_compat),
    (FixtureCase("valid", "nfd-string", 0, None, "NFD input normalized at insert time"), build_valid_nfd_string),
    (FixtureCase("valid", "minimal-single-claim", 0, None, "single claim baseline"), build_valid_minimal_single_claim),
    (FixtureCase("valid", "multi-claim", 0, None, "two claims, two events"), build_valid_multi_claim),
    (FixtureCase("valid", "init-generated", 0, None, "skeleton produced by `aphelion init`"), build_valid_init_generated),
    (FixtureCase("valid", "notice-path", 0, None, "manifest with optional notice_path"), build_valid_notice_path),
    # invalid-syntax
    (FixtureCase("invalid-syntax", "malformed-trailing-comma", 3, "PX_E_4006", ""), build_invalid_malformed_trailing_comma),
    (FixtureCase("invalid-syntax", "malformed-unclosed", 3, "PX_E_4006", ""), build_invalid_malformed_unclosed),
    (FixtureCase("invalid-syntax", "hash-format-wrong-length", 3, "PX_E_4001", ""), build_invalid_hash_format_wrong_length),
    (FixtureCase("invalid-syntax", "duplicate-json-keys", 3, "PX_E_4007", ""), build_invalid_duplicate_json_keys),
    (FixtureCase("invalid-syntax", "wrong-type", 3, "PX_E_1001", ""), build_invalid_wrong_type),
    (FixtureCase("invalid-syntax", "json-parse-error", 3, "PX_E_4006", ""), build_invalid_json_parse_error),
    (FixtureCase("invalid-syntax", "schema-version-future", 3, "PX_E_3003", ""), build_invalid_schema_version_future),
    (FixtureCase("invalid-syntax", "schema-version-legacy", 3, "PX_E_3003", "v0.3 format rejected by v0.4 validator"), build_invalid_schema_version_legacy),
    (FixtureCase("invalid-syntax", "missing-required", 3, "PX_E_2001", ""), build_invalid_missing_required),
    (FixtureCase("invalid-syntax", "invalid-enum", 3, "PX_E_4002", ""), build_invalid_enum),
    (FixtureCase("invalid-syntax", "nan-literal", 3, "PX_E_4009", ""), build_invalid_nan),
    (FixtureCase("invalid-syntax", "empty-producer", 3, "PX_E_2003", "producer='' triggers EMPTY_VALUE"), build_invalid_empty_producer),
    (FixtureCase("invalid-syntax", "extra-manifest-field", 3, "PX_E_2002", "unknown top-level key"), build_invalid_extra_manifest_field),
    (FixtureCase("invalid-syntax", "forbidden-create-prev", 3, "PX_E_2004", "create event with prev_event_id"), build_invalid_forbidden_create_prev),
    (FixtureCase("invalid-syntax", "superseded-without-target", 3, "PX_E_2001", "state=superseded missing superseded_by_claim_id"), build_invalid_superseded_without_target),
    # invalid-semantic
    (FixtureCase("invalid-semantic", "dangling-prev", 3, "PX_E_5003", ""), build_invalid_broken_provenance_dangling),
    (FixtureCase("invalid-semantic", "fork", 3, "PX_E_5003", ""), build_invalid_broken_provenance_fork),
    (FixtureCase("invalid-semantic", "manifest-refs-missing-file", 3, "PX_E_5002", ""), build_invalid_manifest_refs_missing_file),
    (FixtureCase("invalid-semantic", "archive-extra-file", 3, "PX_E_5002", ""), build_invalid_archive_extra_file),
    (FixtureCase("invalid-semantic", "hash-value-tamper", 3, "PX_E_5001", ""), build_invalid_hash_value_tamper),
    (FixtureCase("invalid-semantic", "evidence-ref-dangling", 3, "PX_E_5004", ""), build_invalid_evidence_ref_dangling),
    # archive-security
    (FixtureCase("archive-security", "dotdot-traversal", 3, "PX_E_6001", ""), build_archive_dotdot_traversal),
    (FixtureCase("archive-security", "absolute-path", 3, "PX_E_6002", ""), build_archive_absolute_path),
    (FixtureCase("archive-security", "symlink", 3, "PX_E_6008", ""), build_archive_symlink),
    (FixtureCase("archive-security", "hardlink", 3, "PX_E_6008", ""), build_archive_hardlink),
    (FixtureCase("archive-security", "windows-backslash", 3, "PX_E_6004", ""), build_archive_windows_backslash),
    (FixtureCase("archive-security", "zip-bomb", 3, "PX_E_6010", ""), build_archive_zip_bomb_ratio),
    (FixtureCase("archive-security", "files-count-overflow", 3, "PX_E_6009", ""), build_archive_files_count_overflow),
    # round-trip
    (FixtureCase("round-trip", "ascii-simple", 0, None, ""), build_roundtrip_ascii_simple),
    (FixtureCase("round-trip", "unicode-mixed", 0, None, ""), build_roundtrip_unicode_mixed),
    (FixtureCase("round-trip", "nested-claims", 0, None, ""), build_roundtrip_nested_claims),
    (FixtureCase("round-trip", "nfd-to-nfc", 0, None, ""), build_roundtrip_nfd_to_nfc),
]


def materialize_all(root: Path) -> list[FixtureCase]:
    """Write every fixture under root/<category>/<name>/ and return metadata."""
    meta: list[FixtureCase] = []
    for case, builder in CASES:
        dest = root / case.category / case.name
        if dest.exists():
            shutil.rmtree(dest)
        dest.mkdir(parents=True, exist_ok=True)
        builder(dest)
        readme = (
            f"# {case.category}/{case.name}\n"
            f"expected_exit: {case.expected_exit}\n"
            f"expected_code: {case.expected_code or '-'}\n"
            f"description: {case.description}\n"
        )
        (dest / "README.md").write_text(readme, encoding="utf-8", newline="\n")
        meta.append(case)
    return meta
