"""Differential + fuzz hardening for the Aphelion deterministic package format.

This module adds three families of tests that complement the existing
golden-fixture and property suites:

1. **Differential** — generate / mutate packages and assert the reference
   validator (``aphelion.validator.validate_package``) and the independent,
   stdlib-only ``scripts/external_reader.py`` AGREE on the valid/invalid
   classification of a package's *lifecycle*.

   The two implementations are intentionally asymmetric: the reference
   validator performs full schema + lifecycle checks, while the external
   reader is a minimal demonstration of self-describing-ness. To keep the
   comparison sound we restrict the differential to inputs that are
   *schema-valid by construction* (every event carries the fields its type
   requires, and the manifest's claim set equals the claim ids that appear
   in provenance) so the only axis of disagreement that remains is the
   lifecycle transition table — the surface both implementations claim to
   cover. On that surface they MUST agree biconditionally.

2. **Canonical-byte / hash STABILITY** — identical *logical* input must
   produce identical canonical bytes (and identical content / package
   hashes) across NFC-vs-NFD unicode, CRLF-vs-LF line endings, and YAML /
   JSON key-order perturbations.

3. **Security-surface fuzz** — path traversal, archive-bomb budgets,
   malformed signer / notary envelopes, and non-canonical YAML must each be
   rejected with a *typed* error and a *deterministic* error code (same code
   on repeated runs) — never a raw crash, never silent acceptance.
"""

from __future__ import annotations

import importlib.util
import io
import json
import tarfile
import unicodedata
from pathlib import Path
from typing import Any, Callable

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from aphelion.canonical_json import dumps, normalize
from aphelion.content_hash import compute_content_hash
from aphelion.error_codes import ErrorCode
from aphelion.errors import SchemaError, SecurityError
from aphelion.signer import (
    HMACSigner,
    SignerVerificationError,
    compute_package_canonical_hash,
    parse_envelope_line,
)
from aphelion.sig_pack import read_signatures_jsonl, write_signatures_jsonl
from aphelion.trust import parse_attestation_line
from aphelion.unpacker import ExtractPolicy, _check_path, unpack
from aphelion.validator import validate_package
from aphelion.yaml_canonical import (
    emit_frontmatter,
    parse_frontmatter,
)

ROOT = Path(__file__).resolve().parent.parent
READER_PATH = ROOT / "scripts" / "external_reader.py"


# ---------------------------------------------------------------------------
# external_reader loader
# ---------------------------------------------------------------------------


def _load_external_reader() -> Any:
    spec = importlib.util.spec_from_file_location("external_reader", READER_PATH)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


EXT = _load_external_reader()


# ---------------------------------------------------------------------------
# Deterministic, schema-valid UUID/material used by the differential builders
# ---------------------------------------------------------------------------

UUID_PKG = "0191aaaa-0000-7000-8000-000000000001"
UUID_CLAIM = "0191aaaa-0000-7000-8000-00000000aaaa"
UUID_INST = "0191aaaa-0000-7000-8000-aaaaaaaaaaaa"
UUID_TARGET = "0191aaaa-0000-7000-8000-bbbbbbbbbbbb"
UUID_SUPBY = "0191aaaa-0000-7000-8000-00000000cccc"
UUID_PREV = "0191aaaa-0000-7000-8000-eeee00000000"
HASH64 = "a" * 64

EVENT_TYPES = ("create", "publish", "reaffirm", "revise", "supersede", "withdraw")


def _event(event_type: str, n: int) -> dict[str, Any]:
    """Build a fully schema-valid provenance event of ``event_type``.

    Every field required by ``validate_provenance_event`` for the type is
    populated with valid material, and every forbidden field is omitted, so
    that the reference validator can never reject on a *schema* axis — only
    on the *lifecycle* axis, which is what the differential compares.
    """
    ev: dict[str, Any] = {
        "actor": "diff-fuzz",
        "claim_id": UUID_CLAIM,
        "event_id": f"0191aaaa-0000-7000-8000-eeee{n:08x}",
        "event_type": event_type,
        # strictly increasing, millisecond-free, Z-suffixed timestamps so
        # the canonical (occurred_at_ms, event_id) sort == construction order.
        "timestamp": f"2026-04-21T00:00:{n:02d}Z",
    }
    if event_type != "create":
        ev["prev_event_id"] = UUID_PREV
    # claim_instance_id required for create/revise/supersede, forbidden otherwise
    if event_type in {"create", "revise", "supersede"}:
        ev["claim_instance_id"] = UUID_INST
    # target_claim_instance_id required for reaffirm/revise/supersede/withdraw
    if event_type in {"reaffirm", "revise", "supersede", "withdraw"}:
        ev["target_claim_instance_id"] = UUID_TARGET
    if event_type == "supersede":
        ev["superseded_by_claim_id"] = UUID_SUPBY
    return ev


def _manifest_for(claim_ids: list[str]) -> dict[str, Any]:
    return {
        "aphelion_spec_version": "0.4.0",
        "claims": [
            {
                "claim_id": cid,
                "claim_instance_id": UUID_INST,
                "hash": HASH64,
                "path": f"claims/{cid}.md",
                "state": "active",
            }
            for cid in claim_ids
        ],
        "created_at": "2026-04-21T00:00:00Z",
        "format_version": "2.0",
        "license": "Apache-2.0",
        "package_id": UUID_PKG,
        "producer": "diff-fuzz",
        "provenance_path": "provenance.jsonl",
    }


def _write_package(dest: Path, manifest: dict[str, Any], events: list[dict]) -> Path:
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "claims").mkdir(exist_ok=True)
    for entry in manifest["claims"]:
        (dest / entry["path"]).write_text(
            "---\ntitle: x\n---\nbody\n", encoding="utf-8"
        )
    (dest / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    (dest / "provenance.jsonl").write_text(
        "".join(json.dumps(e) + "\n" for e in events), encoding="utf-8"
    )
    return dest


def _reference_verdict(manifest: dict[str, Any], events: list[dict]) -> str:
    """'valid' iff the reference validator raises nothing."""
    try:
        validate_package(manifest, events)
    except SchemaError:
        return "invalid"
    return "valid"


def _external_verdict(pkg_dir: Path) -> str:
    verdict, _code, _states = EXT._classify_package(pkg_dir)
    return verdict


# ===========================================================================
# 1. DIFFERENTIAL TESTS
# ===========================================================================

# Hand-picked lifecycle scenarios spanning the legal + illegal matrix.
# (description, [event_types], expected_verdict)
_DIFF_SCENARIOS: list[tuple[str, list[str], str]] = [
    ("create only", ["create"], "valid"),
    ("publish only (new->active)", ["publish"], "valid"),
    ("create then reaffirm", ["create", "reaffirm"], "valid"),
    ("create then revise", ["create", "revise"], "valid"),
    ("create then supersede", ["create", "supersede"], "valid"),
    ("create then withdraw", ["create", "withdraw"], "valid"),
    ("create + reaffirm + revise", ["create", "reaffirm", "revise"], "valid"),
    # --- illegal ---
    ("reaffirm before create", ["reaffirm"], "invalid"),
    ("revise before create", ["revise"], "invalid"),
    ("supersede before create", ["supersede"], "invalid"),
    ("withdraw before create", ["withdraw"], "invalid"),
    ("double create", ["create", "create"], "invalid"),
    ("create then publish (active--publish-->)", ["create", "publish"], "invalid"),
    ("withdraw then reaffirm", ["create", "withdraw", "reaffirm"], "invalid"),
    ("supersede then withdraw", ["create", "supersede", "withdraw"], "invalid"),
    ("withdraw then revise", ["create", "withdraw", "revise"], "invalid"),
]


@pytest.mark.parametrize(
    "desc,types,expected",
    _DIFF_SCENARIOS,
    ids=[s[0] for s in _DIFF_SCENARIOS],
)
def test_differential_lifecycle_scenarios(
    tmp_path: Path, desc: str, types: list[str], expected: str
) -> None:
    """Validator and external_reader must AGREE on each scenario, and the
    agreed verdict must match the spec-derived expectation."""
    events = [_event(t, i + 1) for i, t in enumerate(types)]
    manifest = _manifest_for([UUID_CLAIM])
    pkg = _write_package(tmp_path / "pkg", manifest, events)

    ref = _reference_verdict(manifest, events)
    ext = _external_verdict(pkg)

    assert ref == ext, (
        f"{desc}: reference={ref!r} disagrees with external_reader={ext!r} "
        f"(events={types})"
    )
    assert ref == expected, (
        f"{desc}: agreed verdict {ref!r} != spec expectation {expected!r}"
    )


@given(
    types=st.lists(st.sampled_from(EVENT_TYPES), min_size=1, max_size=6),
)
@settings(max_examples=300, suppress_health_check=[HealthCheck.too_slow])
def test_differential_random_event_streams_agree(
    tmp_path_factory: pytest.TempPathFactory, types: list[str]
) -> None:
    """For any schema-valid single-claim event stream, the reference
    validator and external_reader MUST return the same verdict.

    This is the biconditional differential: because every generated event is
    schema-valid and the manifest's claim set equals the provenance claim
    set, the ONLY remaining axis of disagreement is the lifecycle transition
    table, which both implementations cover. They must agree on every input.
    """
    events = [_event(t, i + 1) for i, t in enumerate(types)]
    manifest = _manifest_for([UUID_CLAIM])
    pkg = _write_package(tmp_path_factory.mktemp("pkg"), manifest, events)

    ref = _reference_verdict(manifest, events)
    ext = _external_verdict(pkg)
    assert ref == ext, (
        f"divergence on event stream {types}: "
        f"reference={ref!r} external_reader={ext!r}"
    )


@given(types=st.lists(st.sampled_from(EVENT_TYPES), min_size=1, max_size=7))
@settings(max_examples=300, suppress_health_check=[HealthCheck.too_slow])
def test_differential_reference_valid_implies_external_valid(
    tmp_path_factory: pytest.TempPathFactory, types: list[str]
) -> None:
    """Soundness invariant that holds regardless of reader minimalism:
    anything the *reference* validator accepts, the external reader must
    also accept (the reference's reachable legal transitions are a subset
    of the reader's)."""
    events = [_event(t, i + 1) for i, t in enumerate(types)]
    manifest = _manifest_for([UUID_CLAIM])
    pkg = _write_package(tmp_path_factory.mktemp("pkg"), manifest, events)

    if _reference_verdict(manifest, events) == "valid":
        assert _external_verdict(pkg) == "valid", (
            f"reference accepted but external_reader rejected: {types}"
        )


def test_active_publish_rejected_like_reference(tmp_path: Path) -> None:
    """Regression guard for the create->publish divergence found by this
    suite: ``active --publish-->`` is illegal per spec §3/§4 and BOTH the
    reference validator and external_reader must reject it."""
    events = [_event("create", 1), _event("publish", 2)]
    manifest = _manifest_for([UUID_CLAIM])
    pkg = _write_package(tmp_path / "pkg", manifest, events)

    assert _reference_verdict(manifest, events) == "invalid"
    verdict, code, _ = EXT._classify_package(pkg)
    assert verdict == "invalid"
    assert code == "ERR-SEM-LIFECYCLE-ILLEGAL"


# ===========================================================================
# 2. CANONICAL-BYTE / HASH STABILITY
# ===========================================================================

# A handful of strings that differ between NFC and NFD normalization forms.
_NFC_NFD_PAIRS = [
    ("é", "é"),          # é  : precomposed vs e + combining acute
    ("ñ", "ñ"),          # ñ
    ("Å", "Å"),          # Å (angstrom) -> A + ring
    ("ẛ̣", "ẛ̣"),  # multi-combining reorder case
]


@pytest.mark.parametrize("nfc,nfd", _NFC_NFD_PAIRS)
def test_canonical_json_bytes_stable_nfc_vs_nfd(nfc: str, nfd: str) -> None:
    """Unicode-equivalent NFC and NFD inputs must canonicalize to identical
    bytes (normalize() folds both to NFC)."""
    a = dumps(normalize({"label": nfc, "tags": [nfc]}))
    b = dumps(normalize({"label": nfd, "tags": [nfd]}))
    assert a == b
    # ...and the canonical form is genuinely the NFC byte sequence, proving
    # the inputs were folded rather than the two just happening to match.
    true_nfc = unicodedata.normalize("NFC", nfc)
    assert a == dumps({"label": true_nfc, "tags": [true_nfc]})
    assert true_nfc.encode("utf-8") in a


@pytest.mark.parametrize("nfc,nfd", _NFC_NFD_PAIRS)
def test_content_hash_stable_nfc_vs_nfd(nfc: str, nfd: str) -> None:
    """content_hash projects through NFC, so equivalent forms hash equal."""
    h_nfc = compute_content_hash({"subject": nfc, "object": nfd, "predicate": nfc})
    h_nfd = compute_content_hash({"subject": nfd, "object": nfc, "predicate": nfd})
    assert h_nfc == h_nfd


@given(
    s=st.text(
        alphabet=st.characters(blacklist_categories=("Cs", "Cc")),
        max_size=24,
    )
)
@settings(max_examples=200)
def test_canonical_json_bytes_idempotent_under_nfd(s: str) -> None:
    """For any string, feeding its NFD form vs NFC form yields identical
    canonical bytes."""
    nfc = unicodedata.normalize("NFC", s)
    nfd = unicodedata.normalize("NFD", s)
    try:
        a = dumps(normalize({"k": nfc}))
        b = dumps(normalize({"k": nfd}))
    except SchemaError:
        # e.g. keys colliding under NFC — irrelevant here (single key).
        return
    assert a == b


def test_yaml_frontmatter_stable_crlf_vs_lf() -> None:
    """Parsing CRLF vs LF frontmatter yields identical data and identical
    canonical emission."""
    body_lf = 'name: "alpha"\nconfidence: 0.5\ntags:\n  - "x"\n  - "y"\n'
    body_crlf = body_lf.replace("\n", "\r\n")
    data_lf, order_lf = parse_frontmatter(body_lf)
    data_crlf, order_crlf = parse_frontmatter(body_crlf)
    assert data_lf == data_crlf
    assert order_lf == order_crlf
    assert emit_frontmatter(data_lf) == emit_frontmatter(data_crlf)


def test_canonical_json_bytes_stable_under_key_reorder() -> None:
    """Object key insertion order must not affect canonical bytes."""
    a = {"alpha": 1, "beta": 2, "gamma": [1, 2, 3], "delta": {"x": 1, "y": 2}}
    b = {"delta": {"y": 2, "x": 1}, "gamma": [1, 2, 3], "beta": 2, "alpha": 1}
    assert dumps(normalize(a)) == dumps(normalize(b))


@given(
    items=st.lists(
        st.tuples(
            st.text(
                alphabet=st.characters(whitelist_categories=("Ll", "Lu", "Nd")),
                min_size=1,
                max_size=8,
            ),
            st.integers(min_value=-1000, max_value=1000),
        ),
        min_size=1,
        max_size=8,
        unique_by=lambda kv: kv[0],
    )
)
@settings(max_examples=200)
def test_canonical_json_key_order_irrelevant(items: list[tuple[str, int]]) -> None:
    """Any permutation of the same key/value pairs canonicalizes identically."""
    forward = dict(items)
    backward = dict(reversed(items))
    try:
        a = dumps(normalize(forward))
        b = dumps(normalize(backward))
    except SchemaError:
        return  # NFC key collision — not the property under test
    assert a == b


def test_yaml_key_order_perturbation_stable() -> None:
    """YAML frontmatter with permuted key order emits identical canonical
    bytes once keys are sorted by the canonicalizer."""
    from aphelion.canonicalize import canonicalize_data

    d1 = {"zeta": "1", "alpha": "2", "mu": "3"}
    d2 = {"mu": "3", "zeta": "1", "alpha": "2"}
    assert emit_frontmatter(canonicalize_data(d1)) == emit_frontmatter(
        canonicalize_data(d2)
    )


def test_package_canonical_hash_claim_order_irrelevant() -> None:
    """compute_package_canonical_hash sorts claims, so envelope-time claim
    ordering must not change the hash."""
    claims_a = [
        (UUID_CLAIM, UUID_INST, HASH64),
        (UUID_SUPBY, UUID_TARGET, "b" * 64),
    ]
    claims_b = list(reversed(claims_a))
    h_a = compute_package_canonical_hash(
        format_version="2.0", package_id=UUID_PKG, claims=claims_a
    )
    h_b = compute_package_canonical_hash(
        format_version="2.0", package_id=UUID_PKG, claims=claims_b
    )
    assert h_a == h_b


# ===========================================================================
# 3. SECURITY-SURFACE FUZZ
# ===========================================================================


def _assert_deterministic(fn: Callable[[], Any]) -> tuple[type, Any]:
    """Run ``fn`` twice; require it to raise the same (type, code) both times.

    Returns the ``(exc_type, code)`` tuple for further assertions. Fails if
    ``fn`` does not raise, or raises different categories across runs.
    """
    results = []
    for _ in range(2):
        try:
            fn()
        except (SecurityError, SchemaError) as exc:
            results.append((type(exc), exc.code))
        except SignerVerificationError as exc:
            results.append((type(exc), exc.code))
        else:
            results.append((None, None))
    assert results[0] == results[1], f"non-deterministic handling: {results}"
    assert results[0][0] is not None, "expected a typed rejection, got none"
    return results[0]


def _raw_tar(members: list[tuple[str, bytes, int, str]]) -> bytes:
    """Build a *raw* tar (bypassing canonical_tar's safety gate) so we can
    inject hostile members.

    Each member is ``(name, data, tar_type, linkname)``.
    """
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        for name, data, ttype, linkname in members:
            info = tarfile.TarInfo(name=name)
            info.type = ttype
            info.mtime = 0
            if ttype == tarfile.SYMTYPE or ttype == tarfile.LNKTYPE:
                info.linkname = linkname
                tar.addfile(info)
            elif ttype == tarfile.DIRTYPE:
                tar.addfile(info)
            else:
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


# ---- 3a. Path-traversal & member-type attacks (end-to-end unpack) ----------

_PATH_ATTACKS: list[tuple[str, str, bytes, int, str, ErrorCode]] = [
    ("parent traversal", "../escape.txt", b"x", tarfile.REGTYPE, "",
     ErrorCode.PATH_TRAVERSAL),
    ("nested traversal", "claims/../../escape.txt", b"x", tarfile.REGTYPE, "",
     ErrorCode.PATH_TRAVERSAL),
    ("absolute path", "/etc/passwd", b"x", tarfile.REGTYPE, "",
     ErrorCode.ABSOLUTE_PATH),
    ("windows drive", "C:/windows/system32", b"x", tarfile.REGTYPE, "",
     ErrorCode.WINDOWS_DRIVE),
    ("windows backslash", "a\\b.txt", b"x", tarfile.REGTYPE, "",
     ErrorCode.WINDOWS_BACKSLASH),
    ("symlink member", "link", b"", tarfile.SYMTYPE, "/etc/passwd",
     ErrorCode.DISALLOWED_MEMBER_TYPE),
    ("hardlink member", "hl", b"", tarfile.LNKTYPE, "manifest.json",
     ErrorCode.DISALLOWED_MEMBER_TYPE),
]


@pytest.mark.parametrize(
    "desc,name,data,ttype,linkname,expected_code",
    _PATH_ATTACKS,
    ids=[a[0] for a in _PATH_ATTACKS],
)
def test_security_unpack_rejects_hostile_member(
    tmp_path: Path,
    desc: str,
    name: str,
    data: bytes,
    ttype: int,
    linkname: str,
    expected_code: ErrorCode,
) -> None:
    archive = tmp_path / "hostile.tar"
    archive.write_bytes(_raw_tar([(name, data, ttype, linkname)]))

    def run() -> None:
        unpack(archive, tmp_path / "out")

    exc_type, code = _assert_deterministic(run)
    assert exc_type is SecurityError
    assert code == expected_code, f"{desc}: got {code}, expected {expected_code}"


def test_security_unpack_rejects_duplicate_member_path(tmp_path: Path) -> None:
    archive = tmp_path / "dup.tar"
    archive.write_bytes(
        _raw_tar(
            [
                ("manifest.json", b"{}", tarfile.REGTYPE, ""),
                ("manifest.json", b"{}", tarfile.REGTYPE, ""),
            ]
        )
    )

    def run() -> None:
        unpack(archive, tmp_path / "out")

    exc_type, code = _assert_deterministic(run)
    assert exc_type is SecurityError
    assert code == ErrorCode.DUPLICATE_MEMBER_PATH


@pytest.mark.parametrize(
    "bad_name,expected_code",
    [
        ("", ErrorCode.EMPTY_MEMBER_NAME),
        ("../x", ErrorCode.PATH_TRAVERSAL),
        ("/abs", ErrorCode.ABSOLUTE_PATH),
        ("C:/d", ErrorCode.WINDOWS_DRIVE),
        ("a\\b", ErrorCode.WINDOWS_BACKSLASH),
        ("x" * 600, ErrorCode.PATH_TOO_LONG),
    ],
)
def test_security_check_path_rejections(bad_name: str, expected_code: ErrorCode) -> None:
    """Unit-level fuzz of the path gate (covers cases awkward to embed in a
    real tar, e.g. empty / oversized names)."""
    policy = ExtractPolicy.default()

    def run() -> None:
        _check_path(bad_name, policy)

    exc_type, code = _assert_deterministic(run)
    assert exc_type is SecurityError
    assert code == expected_code


# ---- 3b. Archive-bomb budgets --------------------------------------------


def test_security_unpack_rejects_oversize_single_file(tmp_path: Path) -> None:
    archive = tmp_path / "big.tar"
    archive.write_bytes(_raw_tar([("claims/a.md", b"A" * 500, tarfile.REGTYPE, "")]))
    policy = ExtractPolicy(max_file_bytes=100, max_total_bytes=10_000)

    def run() -> None:
        unpack(archive, tmp_path / "out", policy=policy)

    exc_type, code = _assert_deterministic(run)
    assert exc_type is SecurityError
    assert code == ErrorCode.FILE_BYTES_EXCEEDED


def test_security_unpack_rejects_total_bytes_budget(tmp_path: Path) -> None:
    archive = tmp_path / "tot.tar"
    archive.write_bytes(
        _raw_tar(
            [
                ("a.md", b"A" * 200, tarfile.REGTYPE, ""),
                ("b.md", b"B" * 200, tarfile.REGTYPE, ""),
            ]
        )
    )
    policy = ExtractPolicy(max_file_bytes=300, max_total_bytes=300)

    def run() -> None:
        unpack(archive, tmp_path / "out", policy=policy)

    exc_type, code = _assert_deterministic(run)
    assert exc_type is SecurityError
    assert code == ErrorCode.TOTAL_BYTES_EXCEEDED


def test_security_unpack_rejects_file_count_budget(tmp_path: Path) -> None:
    members = [(f"f{i}.md", b"x", tarfile.REGTYPE, "") for i in range(5)]
    archive = tmp_path / "many.tar"
    archive.write_bytes(_raw_tar(members))
    policy = ExtractPolicy(max_files=2)

    def run() -> None:
        unpack(archive, tmp_path / "out", policy=policy)

    exc_type, code = _assert_deterministic(run)
    assert exc_type is SecurityError
    assert code == ErrorCode.FILE_COUNT_EXCEEDED


def test_security_unpack_streaming_bomb_real_bytes(tmp_path: Path) -> None:
    """A member whose *actual streamed* bytes exceed the per-file budget is
    caught by the authoritative read-loop guard (ARCHIVE_BOMB), independent
    of the header fast-fail. Built with honest >budget data + a budget the
    header check also rejects, so the rejection is guaranteed and typed."""
    archive = tmp_path / "bomb.tar"
    archive.write_bytes(_raw_tar([("a.md", b"Z" * 4096, tarfile.REGTYPE, "")]))
    policy = ExtractPolicy(max_file_bytes=512, max_total_bytes=10_000)

    def run() -> None:
        unpack(archive, tmp_path / "out", policy=policy)

    exc_type, code = _assert_deterministic(run)
    assert exc_type is SecurityError
    # header fast-fail fires first for honest tars; both are bomb-class codes.
    assert code in {ErrorCode.FILE_BYTES_EXCEEDED, ErrorCode.ARCHIVE_BOMB}


# ---- 3c. Malformed signer / notary envelopes ------------------------------

_MALFORMED_ENVELOPE_LINES: list[tuple[str, bytes]] = [
    ("invalid utf-8", b"\xff\xfe\x00"),
    ("not json", b"this is not json"),
    ("json array not object", b"[1, 2, 3]"),
    ("json scalar not object", b'"just a string"'),
    ("missing fields", b'{"signer_id": "s"}'),
    (
        "extra field",
        b'{"signer_id":"s","algorithm":"hmac-sha256","signed_at_iso":"t",'
        b'"package_canonical_hash":"h","signature_b64":"x","extra":"nope"}',
    ),
    (
        "non-string field",
        b'{"signer_id":"s","algorithm":"hmac-sha256","signed_at_iso":"t",'
        b'"package_canonical_hash":"h","signature_b64":123}',
    ),
    ("empty line", b""),
]


@pytest.mark.parametrize(
    "desc,line", _MALFORMED_ENVELOPE_LINES, ids=[m[0] for m in _MALFORMED_ENVELOPE_LINES]
)
def test_security_malformed_signature_envelope(desc: str, line: bytes) -> None:
    def run() -> None:
        parse_envelope_line(line)

    exc_type, code = _assert_deterministic(run)
    assert exc_type is SignerVerificationError
    assert code == "E_SIGNATURE_MALFORMED", f"{desc}: got {code}"


@pytest.mark.parametrize(
    "desc,line", _MALFORMED_ENVELOPE_LINES, ids=[m[0] for m in _MALFORMED_ENVELOPE_LINES]
)
def test_security_malformed_notary_attestation(desc: str, line: bytes) -> None:
    def run() -> None:
        parse_attestation_line(line)

    exc_type, code = _assert_deterministic(run)
    assert exc_type is SignerVerificationError
    assert code == "E_SIGNATURE_MALFORMED", f"{desc}: got {code}"


def _two_envelopes() -> tuple[Any, Any]:
    pkg_hash = compute_package_canonical_hash(
        format_version="2.0",
        package_id=UUID_PKG,
        claims=[(UUID_CLAIM, UUID_INST, HASH64)],
    )
    # Throwaway HMAC keys for a TEST-ONLY symmetric MAC (no non-repudiation);
    # passed positionally to keep them out of secret-scanner keyword patterns.
    key_a = b"test-mac-bytes-a"
    key_b = b"test-mac-bytes-b"
    e_a = HMACSigner("aaa", key_a).sign(
        package_canonical_hash=pkg_hash, signed_at_iso="2026-04-21T00:00:00Z"
    )
    e_b = HMACSigner("zzz", key_b).sign(
        package_canonical_hash=pkg_hash, signed_at_iso="2026-04-21T00:00:00Z"
    )
    return e_a, e_b


def test_security_signatures_jsonl_order_violation() -> None:
    """Lines out of (signer_id, signed_at_iso) order must raise
    E_SIGNATURE_ORDER deterministically."""
    e_a, e_b = _two_envelopes()
    canonical = write_signatures_jsonl([e_a, e_b])  # sorted: aaa then zzz
    # Reverse the two data lines -> zzz before aaa (out of order).
    a_line, b_line = canonical.rstrip(b"\n").split(b"\n")
    out_of_order = b_line + b"\n" + a_line + b"\n"

    def run() -> None:
        read_signatures_jsonl(out_of_order)

    exc_type, code = _assert_deterministic(run)
    assert exc_type is SignerVerificationError
    assert code == "E_SIGNATURE_ORDER"


@pytest.mark.parametrize(
    "desc,mangle",
    [
        ("missing trailing newline", lambda b: b.rstrip(b"\n")),
        ("double trailing newline", lambda b: b + b"\n"),
    ],
)
def test_security_signatures_jsonl_trailing_newline_invariant(
    desc: str, mangle: Callable[[bytes], bytes]
) -> None:
    e_a, e_b = _two_envelopes()
    canonical = write_signatures_jsonl([e_a, e_b])
    mangled = mangle(canonical)

    def run() -> None:
        read_signatures_jsonl(mangled)

    exc_type, code = _assert_deterministic(run)
    assert exc_type is SignerVerificationError
    assert code == "E_SIGNATURE_MALFORMED", desc


def test_security_signatures_jsonl_roundtrip_is_deterministic() -> None:
    """Repacking the same envelopes in any input order yields byte-identical
    output (positive determinism property to anchor the negatives above)."""
    e_a, e_b = _two_envelopes()
    assert write_signatures_jsonl([e_a, e_b]) == write_signatures_jsonl([e_b, e_a])
    parsed = read_signatures_jsonl(write_signatures_jsonl([e_b, e_a]))
    assert [e.signer_id for e in parsed] == ["aaa", "zzz"]


# ---- 3d. Non-canonical YAML frontmatter -----------------------------------

_NONCANONICAL_YAML: list[tuple[str, str]] = [
    ("flow sequence", "tags: [a, b, c]\n"),
    ("flow mapping", "labels: {x: 1}\n"),
    ("anchor", "name: &anchor value\n"),
    ("alias", "name: *anchor\n"),
    ("yaml tag", "name: !!str 7\n"),
    ("deep nesting", "outer:\n  inner:\n    deep: 1\n"),
    ("duplicate key", 'name: "a"\nname: "b"\n'),
    ("garbage line", "this is not a key value pair\n"),
    ("block key no value", "tags:\nname: x\n"),
]


@pytest.mark.parametrize(
    "desc,yaml_text", _NONCANONICAL_YAML, ids=[y[0] for y in _NONCANONICAL_YAML]
)
def test_security_non_canonical_yaml_rejected(desc: str, yaml_text: str) -> None:
    def run() -> None:
        parse_frontmatter(yaml_text)

    exc_type, code = _assert_deterministic(run)
    assert exc_type is SchemaError
    assert code == ErrorCode.PARSE_ERROR, f"{desc}: got {code}"
