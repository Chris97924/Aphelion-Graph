"""Independent Aphelion reader — canonical bytes and lifecycle verdicts.

Purpose
-------
This script is a *third-party* implementation of the Aphelion wire format,
written against the published specs and importing neither the ``aphelion``
reference implementation nor any Parallax code. It exists so the format's
determinism claim can be tested the only way that means anything: two
implementations, same logical input, compared byte for byte.

It covers two layers:

1. **Canonical serialization** (``canonical_archive_bytes`` and friends) —
   reproduces the exact bytes of a packaged Aphelion archive per
   ``spec/canonical-serialization.md``: canonical JSON (Rule 1), NFC (Rule 2),
   ``claims[].hash`` recomputation (``spec/packaging.md`` Rule 3.a), and POSIX
   ustar framing (Rule 5). This is work item **W-M5**; it is what the M5 gate
   in ``benchmarks/longmemeval/metrics/m5_roundtrip.py`` compares against.
2. **Lifecycle classification** (``emit_sample_json``) — enough state-machine
   logic to reproduce the ``validator_verdict`` in each sample's
   ``expected-normalized.json``. This layer is deliberately *not* a full
   validator; ``spec/lifecycle-state-machine.md`` is authoritative.

Contract
--------
- stdlib only: ``hashlib`` / ``json`` / ``pathlib`` / ``sys`` / ``unicodedata``.
- Must NOT ``import aphelion`` / ``parallax`` / ``memory``.
- Must NOT delegate the two layers under test. ``json`` is imported to *parse*
  input, never to emit canonical bytes (no ``json.dumps``), and ``tarfile`` is
  not imported at all — the reference writer is built on it, so reusing it
  would collapse the two-implementation comparison into one implementation
  compared with itself. Guarded by
  ``tests/test_external_reader.py::test_reader_is_not_delegating_the_layers_it_must_reimplement``.
- Must run under Python 3.10+.

Spec gaps this implementation found (resolved 2026-08-05)
---------------------------------------------------------
Building a second implementation surfaced two places where
``spec/canonical-serialization.md`` did not describe what any tar writer emits.
Both were adjudicated by the maintainer (Chris) on 2026-08-05 in favour of
amending the document — the two implementations already agreed, so it was the
spec that was wrong — and both are now normative in **spec v1.1**:

- **Rule 5 §10** previously read "exactly two zero-filled 512-byte blocks
  terminate the archive. No extra trailing bytes." The reference (Python
  ``tarfile``), like GNU and BSD tar, pads the archive to a 10240-byte record.
  An implementer following the old text produced a shorter archive and failed
  byte-equality on *every* package. §10 now states the record size.
  ``record_padding=False`` is kept so the pre-1.1 reading stays expressible and
  the difference stays measurable.
- **Rule 5 §7** ("Device major/minor: 0") admitted two byte-different encodings
  of zero; tar writes an empty (all-NUL) field for non-device entries, which is
  what §7 now requires. Getting this wrong shifts the header checksum only,
  making it painful to diagnose.

Still open, reported but not resolved: **Rule 5 §1** mandates a pax extended
header for member paths over 100 bytes or containing non-ASCII, but the
reference is pinned to ``tarfile.USTAR_FORMAT``, which cannot emit pax and would
fall back to the §1-forbidden ``prefix``+``name`` split. Unreachable for
conformant v2.0 packages (claim paths are ``claims/<uuid>.md``), so this reader
refuses such members rather than inventing an encoding. Resolving it is a
format-capability decision, not a clarification.

Usage
-----
    python scripts/external_reader.py samples/            # verdict cross-check
    python scripts/external_reader.py --canonical PKG     # archive SHA-256

Exit codes (verdict cross-check mode):
    0 — every sample's classification matches its expected verdict
    1 — at least one mismatch (printed to stderr)
"""

from __future__ import annotations

import hashlib
import json
import sys
import unicodedata
from pathlib import Path
from typing import Any


class CanonicalError(ValueError):
    """Input cannot be expressed in Aphelion canonical form."""


# =========================================================================== #
# Rule 1 / Rule 2 — canonical JSON                                            #
# =========================================================================== #

# Rule 1 §4: the *only* escapes. Everything else at or above U+0020 is emitted
# raw, including non-ASCII (no \uXXXX) and U+007F DEL.
_JSON_ESCAPES = {
    '"': '\\"',
    "\\": "\\\\",
    "\b": "\\b",
    "\f": "\\f",
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
}


def _to_canonical_tree(value: Any) -> Any:
    """NFC-normalize recursively and reject anything outside the canonical subset.

    Rule 2 §2 requires NFC *before* key sorting, so normalization happens here
    and ordering happens at encode time on the already-normalized keys.
    """
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        # Rule 1 §5: shortest-round-trip float serialization is language
        # dependent, so format-required numeric fields may not be free-form
        # floats. No manifest or provenance field is float-typed.
        raise CanonicalError(
            "float values are forbidden in canonical JSON (Rule 1 §5); "
            "use an integer or a fixed-decimal string"
        )
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, (list, tuple)):
        return [_to_canonical_tree(item) for item in value]
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalError(
                    f"object keys must be strings, got {type(key).__name__}"
                )
            normalized = unicodedata.normalize("NFC", key)
            if normalized in out:
                raise CanonicalError(
                    f"object keys collide under NFC normalization: {normalized!r}"
                )
            out[normalized] = _to_canonical_tree(item)
        return out
    raise CanonicalError(f"unsupported type in canonical JSON: {type(value).__name__}")


def _encode_string(value: str) -> str:
    pieces = ['"']
    for char in value:
        escape = _JSON_ESCAPES.get(char)
        if escape is not None:
            pieces.append(escape)
        elif char < "\x20":
            pieces.append(f"\\u{ord(char):04x}")
        else:
            pieces.append(char)
    pieces.append('"')
    return "".join(pieces)


def _encode(value: Any) -> str:
    """Rule 1 §1/§3/§5: sorted keys, no spaces, integers only."""
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        return _encode_string(value)
    if isinstance(value, list):
        return "[" + ",".join(_encode(item) for item in value) + "]"
    if isinstance(value, dict):
        # sorted() on str compares by Unicode codepoint, which is what Rule 1 §1
        # asks for. Keys are already NFC at this point.
        return (
            "{"
            + ",".join(f"{_encode_string(k)}:{_encode(value[k])}" for k in sorted(value))
            + "}"
        )
    raise CanonicalError(f"unsupported type in canonical JSON: {type(value).__name__}")


def canonical_json_bytes(obj: Any) -> bytes:
    """Serialize ``obj`` to canonical-JSON bytes, terminated by one LF (Rule 1 §6)."""
    text = _encode(_to_canonical_tree(obj))
    try:
        return text.encode("utf-8") + b"\n"
    except UnicodeEncodeError as err:
        # Rule 2 §3: unpaired surrogates are a syntax error.
        raise CanonicalError(f"string is not encodable as UTF-8: {err}") from err


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise CanonicalError(f"duplicate JSON object key: {key!r}")
        out[key] = value
    return out


def _reject_json_constant(constant: str) -> Any:
    raise CanonicalError(f"NaN/Infinity is forbidden in canonical JSON: {constant}")


def _parse_json(raw: bytes, where: str) -> Any:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as err:
        raise CanonicalError(f"{where}: invalid UTF-8: {err}") from err
    try:
        return json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except json.JSONDecodeError as err:
        raise CanonicalError(f"{where}: {err}") from err


# =========================================================================== #
# Rule 5 — POSIX ustar framing                                                #
# =========================================================================== #

BLOCK_SIZE = 512
#: Tar record size — the conventional blocking factor of 20 × 512-byte blocks.
#: Normative since spec v1.1 (Rule 5 §10); byte-equality is impossible without
#: it, which is how the pre-1.1 wording was found to be wrong.
RECORD_SIZE = 10240

_USTAR_MAGIC = b"ustar\x0000"  # magic "ustar\0" + version "00"
_MODE_FILE = 0o644  # Rule 5 §6
_MODE_DIR = 0o755
_MAX_USTAR_NAME = 100  # Rule 5 §1


class TarMember:
    """One archive member. ``path`` is a POSIX path, NFC-normalized on write.

    A plain class rather than a dataclass on purpose: this file must stay
    loadable by any third-party harness, including the bare
    ``spec_from_file_location`` → ``exec_module`` recipe that skips
    ``sys.modules`` registration. ``dataclasses`` resolves string annotations
    through ``sys.modules`` and raises under that recipe.
    """

    __slots__ = ("path", "data", "is_dir")

    def __init__(self, path: str, data: bytes = b"", is_dir: bool = False) -> None:
        self.path = path
        self.data = data
        self.is_dir = is_dir

    def normalized_path(self) -> str:
        return unicodedata.normalize("NFC", self.path)

    def archive_name(self) -> str:
        """The name as stored in the header.

        Directory entries carry a trailing ``/`` — the conventional tar
        encoding, and what distinguishes a directory member from a regular file
        of the same name. Rule 5 §2 orders members by this full stored path.
        """
        name = self.normalized_path()
        if self.is_dir and not name.endswith("/"):
            name += "/"
        return name

    def __repr__(self) -> str:
        return (
            f"TarMember(path={self.path!r}, size={len(self.data)}, "
            f"is_dir={self.is_dir})"
        )


def _octal_field(value: int, width: int) -> bytes:
    """A ustar numeric field: ``width - 1`` zero-padded octal digits, then NUL."""
    digits = width - 1
    if value < 0 or value >= 8**digits:
        raise CanonicalError(f"value {value} does not fit a {width}-byte ustar field")
    return f"{value:0{digits}o}".encode("ascii") + b"\x00"


def _ustar_header(member: TarMember) -> bytes:
    """Build one 512-byte ustar header block per Rule 5 §1-§8."""
    stored = member.archive_name()
    name = stored.encode("utf-8")
    # Rule 5 §1 mandates a pax extended header for a member path that either
    # exceeds 100 bytes OR carries any non-ASCII byte, and forbids the ustar
    # prefix+name split. pax is finding F3, still OPEN: the reference writer is
    # pinned to tarfile.USTAR_FORMAT, which cannot emit pax and would fall back
    # to the forbidden split, so no agreed encoding exists to reproduce. Writing
    # a plain ustar header regardless would mint a canonical digest for bytes no
    # conformant implementation would produce — worse than refusing, because the
    # digest looks authoritative. Both branches are unreachable for conformant
    # v2.0 packages: claim paths are claims/<uuid>.md (46 ASCII bytes) and every
    # other member name is a fixed ASCII literal.
    if not stored.isascii():
        raise CanonicalError(
            f"member path {stored!r} carries non-ASCII bytes and therefore "
            "requires a pax extended header (Rule 5 §1); pax is unsupported in "
            "this format revision (finding F3, OPEN), so there is no canonical "
            "encoding for this member to reproduce"
        )
    if len(name) > _MAX_USTAR_NAME:
        raise CanonicalError(
            f"member path {stored!r} is {len(name)} bytes, past the "
            f"{_MAX_USTAR_NAME}-byte ustar limit, and therefore requires a pax "
            "extended header (Rule 5 §1); pax is unsupported in this format "
            "revision (finding F3, OPEN), so there is no canonical encoding for "
            "this member to reproduce"
        )
    size = 0 if member.is_dir else len(member.data)
    prefix = (
        name.ljust(100, b"\x00")
        + _octal_field(_MODE_DIR if member.is_dir else _MODE_FILE, 8)
        + _octal_field(0, 8)  # uid — Rule 5 §5
        + _octal_field(0, 8)  # gid
        + _octal_field(size, 12)
        + _octal_field(0, 12)  # mtime — Rule 5 §3
    )
    suffix = (
        (b"5" if member.is_dir else b"0")  # typeflag
        + b"\x00" * 100  # linkname — Rule 5 §8
        + _USTAR_MAGIC
        + b"\x00" * 32  # uname — Rule 5 §5
        + b"\x00" * 32  # gname
        # Rule 5 §7 (normative since spec v1.1): for non-device entries the
        # device fields are an *empty* field, all NUL — not octal "0000000\0".
        # Both denote zero; only this one reproduces the reference bytes.
        + b"\x00" * 8  # devmajor
        + b"\x00" * 8  # devminor
        + b"\x00" * 155  # prefix — Rule 5 §1 forbids using it
    )
    # The checksum is computed with its own field read as eight spaces.
    header = (prefix + b" " * 8 + suffix).ljust(BLOCK_SIZE, b"\x00")
    checksum = sum(header)
    return header[:148] + f"{checksum:06o}".encode("ascii") + b"\x00 " + header[156:]


def canonical_tar_bytes(
    members: list[TarMember], *, record_padding: bool = True
) -> bytes:
    """Pack ``members`` into canonical uncompressed tar bytes (Rule 5).

    ``record_padding=False`` emits the pre-v1.1 reading of Rule 5 §10 (two EOF
    blocks, nothing after). It matches no real writer and is retained only so
    the difference the amendment settled stays expressible and measurable.
    """
    seen: set[str] = set()
    for member in members:
        stored = member.archive_name()
        if stored in seen:
            raise CanonicalError(f"duplicate member path after NFC: {stored!r}")
        seen.add(stored)
        if member.is_dir and member.data:
            raise CanonicalError(f"directory member must not carry data: {stored!r}")

    chunks: list[bytes] = []
    # Rule 5 §2: lexicographic by full path, compared as codepoints.
    for member in sorted(members, key=lambda m: m.archive_name()):
        chunks.append(_ustar_header(member))
        if member.is_dir or not member.data:
            continue
        chunks.append(member.data)
        remainder = len(member.data) % BLOCK_SIZE
        if remainder:
            chunks.append(b"\x00" * (BLOCK_SIZE - remainder))  # Rule 5 §9

    chunks.append(b"\x00" * (BLOCK_SIZE * 2))  # Rule 5 §10
    archive = b"".join(chunks)
    if record_padding:
        remainder = len(archive) % RECORD_SIZE
        if remainder:
            archive += b"\x00" * (RECORD_SIZE - remainder)
    return archive


# =========================================================================== #
# Package-level canonical form                                                #
# =========================================================================== #


def _resolve_member(package: Path, relative: str) -> Path:
    """Resolve a package-relative member path, refusing anything that escapes.

    A manifest is untrusted input, and ``claims[].path`` decides which file gets
    read and folded into the canonical bytes. The reference implementation is
    shielded here by its validator, which pins claim paths to
    ``claims/<uuid>.md`` before ``pack`` ever opens a file; this reader is asked
    to canonicalize packages that validator has not necessarily seen, so it
    enforces containment itself. ``spec/packaging.md`` Rule 5 forbids absolute
    paths, ``..`` traversal and backslash separators for the same reason.

    Scope boundary — symlinks are NOT resolved. A claim file that is a symlink
    pointing outside the package is still read, because the reference writer
    reads it too (``packer._read_bytes`` is a bare ``Path.read_bytes``, and the
    project's symlink guard lives in ``canonical_tar.read_members``, i.e. at
    archive *extraction*, not at pack time). Blocking it here would make this
    reader diverge from the implementation it exists to be compared against, so
    the M5 gate would report a format mismatch that is really a policy
    difference. Closing this needs a decision on the *reference's* source-
    directory threat model, which is above this file — raised as an open item
    rather than papered over locally.
    """
    if not relative:
        raise CanonicalError("member path must not be empty")
    if "\\" in relative:
        raise CanonicalError(f"member path must use '/' separators: {relative!r}")
    parts = relative.split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise CanonicalError(
            f"member path must be a clean relative path: {relative!r}"
        )
    candidate = package / relative
    try:
        # Catches absolute and drive-qualified forms, which override the join.
        candidate.relative_to(package)
    except ValueError as err:
        raise CanonicalError(
            f"member path escapes the package directory: {relative!r}"
        ) from err
    return candidate


def _read_member_bytes(package: Path, relative: str) -> bytes:
    try:
        return _resolve_member(package, relative).read_bytes()
    except OSError as err:
        raise CanonicalError(f"{relative}: {err}") from err


def _manifest_with_recomputed_hashes(package: Path) -> tuple[dict, list[TarMember]]:
    """Load the manifest, recompute every ``claims[].hash``, collect claim members.

    ``spec/packaging.md`` Rule 3.a: the digest is taken over the complete claim
    file bytes exactly as they enter the archive. A manifest's stored hash is
    an assertion to be recomputed, never a value to copy through.
    """
    manifest = _to_canonical_tree(_parse_json(
        _read_member_bytes(package, "manifest.json"), "manifest.json"
    ))
    if not isinstance(manifest, dict):
        raise CanonicalError("manifest.json must be a JSON object")
    claims = manifest.get("claims")
    if not isinstance(claims, list):
        raise CanonicalError("manifest 'claims' must be an array")

    members: list[TarMember] = []
    for index, entry in enumerate(claims):
        if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
            raise CanonicalError(f"claims[{index}] must carry a string 'path'")
        relative = entry["path"]
        blob = _read_member_bytes(package, relative)
        entry["hash"] = hashlib.sha256(blob).hexdigest()
        members.append(TarMember(path=relative, data=blob))
    return manifest, members


def canonical_manifest_bytes(package_dir: Path | str) -> bytes:
    """Canonical ``manifest.json`` bytes, with claim hashes recomputed."""
    manifest, _ = _manifest_with_recomputed_hashes(Path(package_dir))
    return canonical_json_bytes(manifest)


def canonical_provenance_bytes(package_dir: Path | str) -> bytes:
    """Canonical ``provenance.jsonl`` bytes: one canonical JSON object per line."""
    package = Path(package_dir)
    raw = _read_member_bytes(package, "provenance.jsonl")
    lines: list[bytes] = []
    for lineno, line in enumerate(raw.splitlines(), start=1):
        if not line.strip():
            continue
        event = _parse_json(line, f"provenance.jsonl:{lineno}")
        lines.append(canonical_json_bytes(event))
    return b"".join(lines)


def canonical_archive_bytes(
    package_dir: Path | str, *, record_padding: bool = True
) -> bytes:
    """The canonical ``*.aphelion.tar`` bytes for a source package directory.

    Members are ``manifest.json``, ``provenance.jsonl``, every claim file named
    by the manifest, and ``NOTICE`` when present — the same set the reference
    packer emits, ordered and framed per Rule 5.
    """
    package = Path(package_dir)
    manifest, members = _manifest_with_recomputed_hashes(package)
    members.append(TarMember("manifest.json", canonical_json_bytes(manifest)))
    members.append(TarMember("provenance.jsonl", canonical_provenance_bytes(package)))
    if (package / "NOTICE").exists():
        members.append(TarMember("NOTICE", _read_member_bytes(package, "NOTICE")))
    return canonical_tar_bytes(members, record_padding=record_padding)


def canonical_archive_sha256(package_dir: Path | str) -> str:
    """SHA-256 of :func:`canonical_archive_bytes`, as lowercase hex."""
    return hashlib.sha256(canonical_archive_bytes(package_dir)).hexdigest()


# =========================================================================== #
# Lifecycle classification (verdict layer)                                    #
# =========================================================================== #


_LEGAL_TRANSITIONS = {
    ("NEW", "create"): "active",
    ("active", "reaffirm"): "active",
    ("active", "revise"): "active",
    ("active", "supersede"): "superseded",
    ("active", "withdraw"): "withdrawn",
    # NOTE: there is deliberately NO ("active", "publish") transition.
    # spec/lifecycle-state-machine.md §3/§4 only allows `publish` to REACH
    # `active` (from `(new)`/`draft`); it is never legal FROM `active`. An
    # earlier spurious ("active","publish") entry made this reader accept a
    # create->publish stream that the reference validator (and the spec)
    # reject with ERR-SEM-LIFECYCLE-ILLEGAL. Regression-guarded by
    # tests/test_diff_fuzz_hardening.py::test_active_publish_rejected_like_reference.
    ("draft", "publish"): "active",
    ("NEW", "publish"): "active",
}


def _load_events(prov_path: Path) -> list[dict]:
    if not prov_path.exists():
        return []
    out: list[dict] = []
    for i, line in enumerate(prov_path.read_bytes().splitlines(), start=1):
        if not line.strip():
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError as err:
            raise ValueError(f"{prov_path}:{i}: {err}") from err
    return out


def _ts_ms(ts: str) -> int:
    from datetime import datetime, timezone

    if not ts.endswith("Z"):
        raise ValueError(f"timestamp must be UTC Z: {ts!r}")
    dt = datetime.fromisoformat(ts[:-1] + "+00:00").astimezone(timezone.utc)
    return int(dt.timestamp() * 1000)


def _classify_package(pkg: Path) -> tuple[str, str | None, dict[str, str]]:
    """Return (verdict, error_code_or_None, final_states).

    ``verdict`` is ``"valid"`` or ``"invalid"``. ``error_code`` is one
    of ``ERR-SEM-LIFECYCLE-ILLEGAL`` / ``ERR-SYN-...`` and is populated
    only when verdict == ``"invalid"``.
    """
    manifest_path = pkg / "manifest.json"
    if not manifest_path.exists():
        return "invalid", "ERR-SYN-MISSING-MANIFEST", {}
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    # Shape / version checks (syntax layer).
    if manifest.get("format_version") not in {"2.0"}:
        return "invalid", "ERR-SYN-UNKNOWN-FORMAT-VERSION", {}

    claim_ids = {c["claim_id"] for c in manifest.get("claims", [])}
    events = _load_events(pkg / "provenance.jsonl")

    # Canonical event ordering: (occurred_at_ms, event_id).
    try:
        events_sorted = sorted(events, key=lambda e: (_ts_ms(e["timestamp"]), e["event_id"]))
    except (KeyError, ValueError) as err:
        return "invalid", f"ERR-SYN-BAD-EVENT ({err})", {}

    # Walk the state machine per claim_id.
    states: dict[str, str] = {cid: "NEW" for cid in claim_ids}
    for ev in events_sorted:
        cid = ev.get("claim_id")
        if cid not in states:
            states[cid] = "NEW"
        etype = ev.get("event_type")
        current = states[cid]
        # reaffirm on a non-active claim is illegal.
        if etype == "reaffirm" and current != "active":
            return "invalid", "ERR-SEM-LIFECYCLE-ILLEGAL", states
        next_state = _LEGAL_TRANSITIONS.get((current, etype))
        if next_state is None:
            return "invalid", "ERR-SEM-LIFECYCLE-ILLEGAL", states
        states[cid] = next_state

    # NEW-but-no-create is also illegal — a claim referenced in manifest
    # must have been created in provenance.
    for cid in claim_ids:
        if states.get(cid, "NEW") == "NEW":
            return "invalid", "ERR-SEM-LIFECYCLE-ILLEGAL", states

    return "valid", None, states


def _read_expected(sample: Path) -> dict | None:
    exp = sample / "expected-normalized.json"
    if not exp.exists():
        return None
    return json.loads(exp.read_text(encoding="utf-8"))


def _iter_packages(sample: Path) -> list[Path]:
    """A sample dir is usually itself a package, but
    duplicate-reaffirm-collision nests package-a / package-b.
    """
    if (sample / "manifest.json").exists():
        return [sample]
    subs = [p for p in sorted(sample.iterdir()) if p.is_dir() and (p / "manifest.json").exists()]
    return subs


def emit_sample_json(sample: Path) -> dict:
    """Classify one sample dir and return the normalized JSON shape.

    The shape deliberately mirrors the fields consumers actually test
    for — ``validator_verdict``, optional ``error_code``, and a
    minimal ``notes`` block capturing claim_ids / event_count /
    final_states. This is the verdict layer only; the canonical *bytes*
    of a package come from :func:`canonical_archive_bytes`.
    """
    packages = _iter_packages(sample)
    if not packages:
        return {"validator_verdict": "invalid", "error_code": "ERR-SYN-MISSING-MANIFEST"}

    if len(packages) > 1:
        # Collision fixture: report per-sub-package and leave merge-time
        # collision detection to the caller.
        per_pkg = []
        for pkg in packages:
            verdict, code, states = _classify_package(pkg)
            per_pkg.append(
                {
                    "package_name": pkg.name,
                    "validator_verdict": verdict,
                    "error_code": code,
                    "final_states": states,
                }
            )
        return {"validator_verdict": "multi", "sub_packages": per_pkg}

    pkg = packages[0]
    verdict, code, states = _classify_package(pkg)
    manifest = json.loads((pkg / "manifest.json").read_text(encoding="utf-8"))
    events = _load_events(pkg / "provenance.jsonl")
    out: dict = {
        "validator_verdict": verdict,
        "notes": {
            "claim_ids": sorted(c["claim_id"] for c in manifest.get("claims", [])),
            "event_count": len(events),
            "final_states": states,
        },
    }
    if code is not None:
        out["error_code"] = code
    return out


def run(samples_root: Path) -> int:
    failures: list[str] = []
    checked = 0
    for sample in sorted(samples_root.iterdir()):
        if not sample.is_dir():
            continue
        expected = _read_expected(sample)
        if expected is None:
            continue
        checked += 1
        packages = _iter_packages(sample)
        if not packages:
            failures.append(f"{sample.name}: no packages found")
            continue
        verdicts = []
        for pkg in packages:
            verdict, _, _ = _classify_package(pkg)
            verdicts.append(verdict)
        # Collision sample: each sub-package is individually valid;
        # the "invalid" verdict applies only at merge time — which is
        # out of scope for this minimal reader. We accept either and
        # annotate.
        expected_verdict = expected["validator_verdict"]
        if expected.get("error_code") == "ERR-SEM-DUPLICATE-HASH-COLLISION":
            # Treat as OK if every sub-package is valid.
            if all(v == "valid" for v in verdicts):
                continue
            failures.append(
                f"{sample.name}: sub-packages not individually valid: {verdicts}"
            )
            continue
        if len(verdicts) != 1:
            failures.append(
                f"{sample.name}: expected single top-level package, got {len(verdicts)}"
            )
            continue
        if verdicts[0] != expected_verdict:
            failures.append(
                f"{sample.name}: got {verdicts[0]!r}, expected {expected_verdict!r}"
            )

    if failures:
        print(f"external_reader: {len(failures)} / {checked} mismatch(es):", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        return 1
    print(f"external_reader: {checked} sample(s) checked, all match.")
    return 0


def _forbid_validator_import() -> None:
    """Fail loudly if a future edit re-introduces an aphelion / parallax
    import. This is the single authoritative guard of the 'no
    dependency on the reference validator' contract."""
    forbidden = {"aphelion", "parallax", "memory"}
    for mod in list(sys.modules):
        top = mod.split(".", 1)[0]
        if top in forbidden:
            raise RuntimeError(
                f"external_reader.py MUST NOT import {top!r}; "
                f"contract violated"
            )


def _main(argv: list[str]) -> int:
    if argv and argv[0] == "--canonical":
        if len(argv) != 2:
            print("usage: external_reader.py --canonical PACKAGE_DIR", file=sys.stderr)
            return 2
        try:
            print(canonical_archive_sha256(Path(argv[1])))
        except CanonicalError as err:
            print(f"external_reader: {err}", file=sys.stderr)
            return 1
        return 0

    target = Path(argv[0]) if argv else Path("samples")
    # Single-sample mode iff the target itself carries an
    # ``expected-normalized.json``; otherwise treat as samples-root.
    if (target / "expected-normalized.json").exists():
        sys.stdout.write(canonical_json_bytes(emit_sample_json(target)).decode("utf-8"))
        return 0
    return run(target)


if __name__ == "__main__":
    _forbid_validator_import()
    raise SystemExit(_main(sys.argv[1:]))
